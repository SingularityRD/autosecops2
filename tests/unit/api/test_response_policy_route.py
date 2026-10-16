"""/api/response/policy (W0.36, SOC4-11 / KS-19): RBAC, validation, what is stored.

The built-in roles' grants come from the seed SQL (as the route matrix reads
them), so "an Analyst cannot change the policy" is checked against the real
Analyst role, not a hand-typed permission set.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

from core.response.policy import PolicyConfig  # noqa: E402
from core.storage.models import User  # noqa: E402
from services.api import main as backend_main  # noqa: E402
from services.api.middleware import auth as auth_module  # noqa: E402
from tests.security.route_matrix import load_role_grants  # noqa: E402

pytestmark = pytest.mark.unit

GRANTS = load_role_grants()
STORED = {
    "protected_targets": ["dc01.corp.local"],
    "distinct_role_types": ["disable_user"],
    "undo_types": ["lift_quarantine"],
}


def _body(**kw):
    body = {
        "protected_targets": ["dc01.corp.local", "10.20.0.0/16"],
        "protected_tags": ["Crown_Jewel"],
        "asset_tags": {"fs01.corp.local": ["tier0"]},
        "hourly_limits": {"block_ip": 3},
        "default_hourly_limit": 15,
        "four_eyes_types": ["isolate_host"],
        "reason": "tier0 inventory",
    }
    body.update(kw)
    return body


@pytest.fixture
def client(monkeypatch):
    user = User(
        user_id="u-1",
        username="carol",
        email="c@test.local",
        password_hash="",
        role_id="role-manager",
        is_active=True,
        mfa_enabled=False,
    )
    state = {"role": "role-manager", "raw": dict(STORED), "writes": []}
    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.check_permission",
        lambda user_id, perm, session=None: bool(
            GRANTS[state["role"]].get(perm, False)
        ),
    )

    class _Config:
        def __init__(self, user_id):
            self.user_id = user_id

        def read_system_config(self, key):
            if state.get("unreadable"):
                raise RuntimeError("db down")
            return dict(state["raw"]) if state["raw"] is not None else None

        def set_system_config(self, key, value, **kw):
            state["writes"].append(
                {"key": key, "value": value, "by": self.user_id, **kw}
            )
            state["raw"] = value
            return True

    monkeypatch.setattr(
        "core.storage.config_service.get_config_service",
        lambda user_id="system": _Config(user_id),
    )
    app = backend_main.app
    app.dependency_overrides[auth_module.get_current_active_user] = lambda: user
    app.dependency_overrides[auth_module.get_current_user] = lambda: user
    try:
        yield TestClient(app), state
    finally:
        app.dependency_overrides.pop(auth_module.get_current_active_user, None)
        app.dependency_overrides.pop(auth_module.get_current_user, None)


@pytest.mark.parametrize("role", ["role-analyst", "role-viewer"])
def test_analyst_and_viewer_cannot_change_the_policy(client, role):
    http, state = client
    state["role"] = role
    assert http.put("/api/response/policy", json=_body()).status_code == 403
    assert state["writes"] == []


def test_analyst_may_read_viewer_may_not(client):
    http, state = client
    state["role"] = "role-analyst"
    assert http.get("/api/response/policy").status_code == 200
    state["role"] = "role-viewer"
    assert http.get("/api/response/policy").status_code == 403


@pytest.mark.parametrize("role", ["role-manager", "role-admin"])
def test_settings_write_holders_save_with_an_audited_reason(client, role):
    http, state = client
    state["role"] = role
    response = http.put("/api/response/policy", json=_body())
    assert response.status_code == 200, response.text
    [write] = state["writes"]
    assert write["by"] == "carol"
    assert write["change_reason"] == "tier0 inventory"
    assert write["config_type"] == "response_policy"
    stored = write["value"]
    assert stored == {
        "protected_targets": ["10.20.0.0/16", "dc01.corp.local"],
        "protected_tags": ["crown_jewel"],
        "asset_tags": {"fs01.corp.local": ["tier0"]},
        "hourly_limits": {"block_ip": 3},
        "default_hourly_limit": 15,
        "four_eyes_types": ["isolate_host"],
        # Keys this route does not own are kept.
        "distinct_role_types": ["disable_user"],
        "undo_types": ["lift_quarantine"],
    }
    body = response.json()
    assert "crown_jewel" in body["effective"]["protected_tags"]
    assert "domain_controller" in body["effective"]["protected_tags"]
    assert set(body["effective"]["four_eyes_types"]) >= {
        "isolate_host",
        "disable_user",
        "revoke_sessions",
    }
    assert body["effective"]["hourly_limits"]["block_ip"] == 3
    policy = PolicyConfig.from_mapping(stored)
    assert policy.needs_second_approver("isolate_host")
    assert policy.limit_for("block_ip") == 3


def test_an_unchanged_policy_writes_no_audit_row(client):
    http, state = client
    assert http.put("/api/response/policy", json=_body()).status_code == 200
    assert (
        http.put("/api/response/policy", json=_body(reason="again")).status_code == 200
    )
    assert len(state["writes"]) == 1


def test_built_in_protection_cannot_be_removed(client):
    """Clearing every list still leaves the built-in tags and four-eyes types."""
    http, state = client
    response = http.put(
        "/api/response/policy",
        json={"reason": "clear", "default_hourly_limit": 20},
    )
    assert response.status_code == 200, response.text
    eff = response.json()["effective"]
    assert {"domain_controller", "break_glass", "tier0"} <= set(eff["protected_tags"])
    assert {"disable_user", "revoke_sessions"} <= set(eff["four_eyes_types"])


@pytest.mark.parametrize(
    "patch, needle",
    [
        ({"reason": "   "}, "reason"),
        ({"protected_targets": [""]}, "blank"),
        ({"protected_targets": ["unknown"]}, "names nothing"),
        ({"protected_targets": ["dc01\x00evil"]}, "not a host"),
        ({"protected_targets": ["x" * 300]}, "not a host"),
        ({"protected_tags": ["has space"]}, "not a tag"),
        ({"asset_tags": {"fs01": []}}, "no tags"),
        ({"asset_tags": {"none": ["tier0"]}}, "names nothing"),
        ({"hourly_limits": {"launch_missiles": 1}}, "unknown action type"),
        ({"hourly_limits": {"block_ip": -1}}, ""),
        ({"hourly_limits": {"block_ip": 5000}}, ""),
        ({"hourly_limits": {"block_ip": True}}, ""),
        ({"hourly_limits": {"block_ip": "5"}}, ""),
        ({"default_hourly_limit": 1001}, ""),
        ({"four_eyes_types": ["workflow_phase"]}, "unknown action type"),
        ({"distinct_role_types": ["block_ip"]}, ""),  # not this route's key
    ],
)
def test_invalid_input_is_refused_and_nothing_is_written(client, patch, needle):
    http, state = client
    response = http.put("/api/response/policy", json=_body(**patch))
    assert response.status_code == 422, response.text
    assert needle in str(response.json()["detail"])
    assert state["writes"] == []


def test_an_unreadable_policy_is_503_not_an_empty_one(client):
    http, state = client
    state["unreadable"] = True
    assert http.get("/api/response/policy").status_code == 503
    assert http.put("/api/response/policy", json=_body()).status_code == 503
    assert state["writes"] == []


def test_get_shows_stored_values_and_defaults(client):
    http, state = client
    state["role"] = "role-admin"
    body = http.get("/api/response/policy").json()
    assert body["protected_targets"] == ["dc01.corp.local"]
    assert body["defaults"]["four_eyes_types"] == ["disable_user", "revoke_sessions"]
    assert body["effective"]["distinct_role_types"] == ["disable_user"]
    assert "workflow_phase" not in body["action_types"]
    assert "isolate_host" in body["action_types"]
