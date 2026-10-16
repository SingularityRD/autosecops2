"""Autonomy controllers for tests (W3.1).

Since W3.1 nothing is released without a person below the ``autonomous`` tier,
and the GA default is ``approve``. Tests written before W3.1 that exercise the
confidence band (auto-approval at or above the threshold) run under
``permissive_autonomy()``: every eligible class autonomous in every category,
with a QA bound that holds, and a missing approval row read as Act. Those tests pass no category, and an alert with
none is ``other``, which is never autonomous (W3.1 round 5); the permissive
controller reads such an action as ``network`` so the band is what decides.
The tier rules themselves are tested in tests/unit/autonomy/.
"""

from __future__ import annotations

from typing import Any, Optional

import pytest

from core.autonomy.bounds import BoundStatus
from core.autonomy.controller import AutonomyController
from core.autonomy.tiers import (
    ACTION_CLASSES,
    AUTONOMOUS,
    AUTONOMOUS_ELIGIBLE,
    NEVER_AUTONOMOUS_CATEGORIES,
    TierEntry,
    normalise_category,
)
from core.contracts.verdict import CATEGORIES


class MemoryTierStore:
    """``TierStore`` in memory, recording every write as an audit row."""

    def __init__(self, entries: Optional[list[TierEntry]] = None) -> None:
        self.rows: dict[tuple[str, str], TierEntry] = {}
        self.audit_rows: list[dict[str, Any]] = []
        for entry in entries or []:
            self.rows[(entry.category, entry.action_type)] = entry

    def entries(self) -> list[TierEntry]:
        return list(self.rows.values())

    def put(
        self,
        entry: TierEntry,
        *,
        old: Optional[TierEntry],
        audit_action: str,
        actor: str,
        reason: str,
        evidence_url: Optional[str] = None,
        detail: Optional[dict[str, Any]] = None,
    ) -> None:
        stored = TierEntry(
            category=entry.category,
            action_type=entry.action_type,
            tier=entry.tier,
            min_confidence=entry.min_confidence,
            max_ttl_seconds=entry.max_ttl_seconds,
            updated_by=actor,
            explicit=True,
        )
        self.rows[(entry.category, entry.action_type)] = stored
        self.audit_rows.append(
            {
                "id": len(self.audit_rows) + 1,
                "key": f"{entry.category}/{entry.action_type}",
                "action": audit_action,
                "old_value": {"tier": old.tier} if old else None,
                "new_value": {"tier": entry.tier, "evidence_url": evidence_url},
                "changed_by": actor,
                "reason": reason,
                "at": None,
            }
        )

    def audit(self, limit: int = 100) -> list[dict[str, Any]]:
        return list(reversed(self.audit_rows))[:limit]


def bounds(holds: bool = True, reviewed: int = 299, misses: int = 0):
    """A bound reader: every category at ``reviewed``/``misses``."""
    upper = 0.00997 if holds else 0.05

    def read() -> dict[str, BoundStatus]:
        return {
            c: BoundStatus(
                c,
                reviewed,
                misses,
                upper,
                holds=holds,
                reason="test bound" if holds else "test bound broken",
            )
            for c in CATEGORIES
        }

    return read


class _UncategorisedAsNetwork(AutonomyController):
    """For pre-W3.1 tests only: an action with no category reads as network."""

    def decide(self, *, category: Any, **kw: Any):  # type: ignore[override]
        if normalise_category(category) in NEVER_AUTONOMOUS_CATEGORIES:
            category = "network"
        return super().decide(category=category, **kw)


def permissive_autonomy(ttl_seconds: int = 3600) -> AutonomyController:
    """Every eligible class autonomous in every category; the bound holds."""
    store = MemoryTierStore(
        [
            TierEntry(
                category=c,
                action_type=a,
                tier=AUTONOMOUS,
                min_confidence=0.0,
                max_ttl_seconds=ttl_seconds,
                explicit=True,
            )
            for c in CATEGORIES
            for a in ACTION_CLASSES
            if a in AUTONOMOUS_ELIGIBLE
        ]
    )
    return _UncategorisedAsNetwork(store=store, bound_reader=bounds(True))


@pytest.fixture
def autonomous_everywhere(monkeypatch):
    """Services built without an explicit controller get ``permissive_autonomy()``.

    For pre-W3.1 tests of the confidence band; use it with
    ``pytestmark = pytest.mark.usefixtures("autonomous_everywhere")``.
    """
    monkeypatch.setattr(
        "core.response.approval_service.AutonomyController", permissive_autonomy
    )
    # Those tests predate the Assist default too (W0.32): a database with no
    # approval row reads Act for them, as it did then. A stored row, and a
    # failed read, decide as in production.
    monkeypatch.setattr(
        "core.response.approval_service.ApprovalService._stored_force_manual_approval",
        _absent_row_is_act,
    )


def _absent_row_is_act(self) -> bool:
    from core.response import approval_service as module

    try:
        value = module.get_config_service().read_system_config(
            module.APPROVAL_CONFIG_KEY
        )
    except Exception:  # noqa: BLE001
        return True
    return False if value is None else module.stored_force_manual(value)
