"""GET /api/config/autonomy reads the effective daemon flags, not a stored tier."""

from __future__ import annotations

import pytest

from core.response.config import ResponseConfig
from services.api.routers.config import (
    OrchestratorSettingsConfig,
    get_autonomy_config,
)
from services.daemon.config import DaemonConfig

pytestmark = pytest.mark.unit


class _Rows:
    def __init__(self, row):
        self.row = row

    def get_system_config(self, key, default=None):
        if key == "approval.force_manual_approval":
            return self.row
        return default

    def read_system_config(self, key):
        return self.row if key == "approval.force_manual_approval" else None


class _Controller:
    """An AutonomyController stand-in: ``matrix()`` from a list of (tier, eligible)."""

    def __init__(self, cells=(), error=None):
        self.cells = list(cells)
        self.error = error

    def matrix(self):
        if self.error:
            raise self.error
        return {
            "entries": [{"tier": t, "eligible": e} for t, e in self.cells]
        }


@pytest.fixture(autouse=True)
def _no_tiers(monkeypatch):
    monkeypatch.setattr("core.autonomy.AutonomyController", lambda: _Controller())


def test_autonomy_config_reads_both_flags_and_the_db_force_overlay(monkeypatch):
    rows = _Rows({"enabled": True})
    monkeypatch.setattr("services.daemon.intent.get_config_service", lambda: rows)
    base = DaemonConfig()
    base.response = ResponseConfig(
        auto_response_enabled=True, force_manual_approval=False
    )
    monkeypatch.setattr(
        "services.api.routers.config.DaemonConfig.from_env", lambda: base
    )

    forced = get_autonomy_config()
    assert forced.auto_response_enabled is True
    assert forced.force_manual_approval is True
    # the overlay returns a copy; the env value itself stays put
    assert base.response.force_manual_approval is False

    base.response = ResponseConfig(
        auto_response_enabled=False, force_manual_approval=False
    )
    rows.row = {"enabled": False}
    plain = get_autonomy_config()
    assert plain.auto_response_enabled is False
    assert plain.force_manual_approval is False

    assert "auto_response_enabled" not in OrchestratorSettingsConfig.model_fields
    assert "force_manual_approval" not in OrchestratorSettingsConfig.model_fields


def test_disabled_db_row_does_not_force_manual(monkeypatch):
    rows = _Rows({"enabled": False})
    monkeypatch.setattr("services.daemon.intent.get_config_service", lambda: rows)
    base = DaemonConfig()
    monkeypatch.setattr(
        "services.api.routers.config.DaemonConfig.from_env", lambda: base
    )

    result = get_autonomy_config()
    assert result.auto_response_enabled is True
    assert result.force_manual_approval is False


def test_no_row_reads_assist(monkeypatch):
    # The GA default (W0.32): no stored choice means a person approves.
    monkeypatch.setattr(
        "services.daemon.intent.get_config_service", lambda: _Rows(None)
    )
    monkeypatch.setattr(
        "services.api.routers.config.DaemonConfig.from_env", lambda: DaemonConfig()
    )
    result = get_autonomy_config()
    assert result.force_manual_approval is True
    assert result.mode == "assist"


def _act_flags(monkeypatch):
    monkeypatch.setattr(
        "services.daemon.intent.get_config_service", lambda: _Rows({"enabled": False})
    )
    monkeypatch.setattr(
        "services.api.routers.config.DaemonConfig.from_env", lambda: DaemonConfig()
    )


def test_act_with_no_autonomous_tier_is_still_assist(monkeypatch):
    # K6-13: Act on the flags with every tier at Approve releases nothing
    # without a person, so the chip must not say Act.
    _act_flags(monkeypatch)
    monkeypatch.setattr(
        "core.autonomy.AutonomyController",
        lambda: _Controller([("approve", True), ("autonomous", False)]),
    )
    result = get_autonomy_config()
    assert result.force_manual_approval is False
    assert result.autonomous_tiers == 0
    assert result.mode == "assist"


def test_act_with_an_eligible_autonomous_tier_is_act(monkeypatch):
    _act_flags(monkeypatch)
    monkeypatch.setattr(
        "core.autonomy.AutonomyController",
        lambda: _Controller([("autonomous", True), ("approve", True)]),
    )
    result = get_autonomy_config()
    assert (result.autonomous_tiers, result.mode) == (1, "act")


def test_unreadable_tiers_never_understate_autonomy(monkeypatch):
    _act_flags(monkeypatch)
    monkeypatch.setattr(
        "core.autonomy.AutonomyController",
        lambda: _Controller(error=RuntimeError("db down")),
    )
    result = get_autonomy_config()
    assert (result.autonomous_tiers, result.mode) == (None, "act")


def test_forced_approval_is_assist_whatever_the_tiers(monkeypatch):
    monkeypatch.setattr(
        "services.daemon.intent.get_config_service", lambda: _Rows({"enabled": True})
    )
    monkeypatch.setattr(
        "services.api.routers.config.DaemonConfig.from_env", lambda: DaemonConfig()
    )
    monkeypatch.setattr(
        "core.autonomy.AutonomyController",
        lambda: _Controller([("autonomous", True)]),
    )
    assert get_autonomy_config().mode == "assist"
