"""/api/response/segregation and /api/response/four-eyes (W3.2): RBAC and shapes."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

from core.deps import provide_approvals  # noqa: E402
from core.response import segregation_router  # noqa: E402
from core.response.approval_service import (  # noqa: E402
    SecondApproverRoleConflict,
)
from core.response.policy import PolicyConfig  # noqa: E402
from core.storage.models import User  # noqa: E402
from services.api import main as backend_main  # noqa: E402
from services.api.middleware import auth as auth_module  # noqa: E402

pytestmark = pytest.mark.unit

REPORT = {
    "since": None,
    "until": None,
    "action_type": None,
    "policy": {
        "four_eyes_types": ["disable_user"],
        "distinct_role_types": ["disable_user"],
    },
    "summary": {"total": 1, "with_violations": 1, "by_kind": {"same_role": 1}},
    "rows": [
        {
            "action_id": "a-1",
            "action_type": "disable_user",
            "target": "=cmd",
            "status": "executed",
            "proposed_by": "agent",
            "approved_by": "alice",
            "approved_role": "Senior Analyst",
            "second_approver": "bob",
            "second_role": "Senior Analyst",
            "executed_by": "system:dispatcher",
            "four_eyes": True,
            "distinct_role": True,
            "role_source": "recorded",
            "violations": ["same_role"],
        }
    ],
}


class _Approvals:
    def __init__(self):
        self.raw = {"distinct_role_types": ["disable_user"]}
        self.conflict = None

    def policy_config(self):
        return PolicyConfig.from_mapping(self.raw)

    def get_action(self, action_id):
        from core.response.approval_service import PendingAction

        return PendingAction(
            action_id=action_id,
            action_type="disable_user",
            title="t",
            description="d",
            target="x",
            confidence=0.9,
            reason="r",
            evidence=[],
            created_at="",
            created_by="agent",
            requires_approval=True,
            status="pending",
            approved_by="alice",
        )

    def approve_action(self, action_id, approved_by):
        raise SecondApproverRoleConflict("same role")


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
    granted = {"perms": None}
    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.check_permission",
        lambda user_id, perm, session=None: granted["perms"] is None
        or perm in granted["perms"],
    )
    calls = {}

    def fake_report(session, policy, **kw):
        calls["policy"] = policy
        calls["kw"] = kw
        return REPORT

    monkeypatch.setattr(segregation_router.segregation, "build_report", fake_report)

    class _Scope:
        def __enter__(self):
            return None

        def __exit__(self, *a):
            return False

    class _Db:
        def session_scope(self):
            return _Scope()

    monkeypatch.setattr(segregation_router, "get_db_manager", lambda: _Db())

    saved = {}

    def fake_update(actor, reason, change, expected_version=None):
        key = "response.policy"
        new = change(dict(saved.get(key) or {"protected_targets": ["dc01"]}))
        saved[key] = new
        saved["reason"] = reason
        return new, "v", True

    monkeypatch.setattr("core.response.policy_store.update_policy", fake_update)
    approvals = _Approvals()
    app = backend_main.app
    app.dependency_overrides[auth_module.get_current_active_user] = lambda: user
    app.dependency_overrides[auth_module.get_current_user] = lambda: user
    app.dependency_overrides[provide_approvals] = lambda: approvals
    try:
        yield TestClient(app), granted, calls, saved
    finally:
        for dep in (
            auth_module.get_current_active_user,
            auth_module.get_current_user,
            provide_approvals,
        ):
            app.dependency_overrides.pop(dep, None)


def test_the_report_needs_users_read(client):
    http, granted, calls, _ = client
    granted["perms"] = {"settings.read"}
    assert http.get("/api/response/segregation").status_code == 403
    assert http.get("/api/response/segregation/export").status_code == 403
    granted["perms"] = {"users.read"}
    response = http.get(
        "/api/response/segregation",
        params={"violations_only": "true", "action_type": "disable_user"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["rows"][0]["violations"] == ["same_role"]
    assert calls["kw"]["violations_only"] is True
    assert calls["kw"]["action_type"] == "disable_user"
    assert calls["policy"].needs_distinct_role("disable_user")


def test_csv_export_is_a_download_with_safe_cells(client):
    http, *_ = client
    response = http.get("/api/response/segregation/export")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment;" in response.headers["content-disposition"]
    assert ".csv" in response.headers["content-disposition"]
    body = response.text
    assert body.splitlines()[0].startswith("action_id,action_type,target")
    assert "'=cmd" in body and "same_role" in body


def test_json_export(client):
    http, *_ = client
    response = http.get("/api/response/segregation/export", params={"format": "json"})
    assert response.status_code == 200
    assert response.json()["summary"]["with_violations"] == 1


def test_four_eyes_read_and_toggle(client):
    http, granted, _, saved = client
    assert http.get("/api/response/four-eyes").json()["distinct_role_types"] == [
        "disable_user"
    ]
    response = http.put(
        "/api/response/four-eyes/block_ip",
        json={"distinct_role": True, "reason": "SoD audit finding"},
    )
    assert response.status_code == 200, response.text
    assert "block_ip" in response.json()["four_eyes_types"]
    assert saved["response.policy"]["distinct_role_types"] == ["block_ip"]
    # Other policy keys are kept.
    assert saved["response.policy"]["protected_targets"] == ["dc01"]
    assert saved["reason"] == "SoD audit finding"
    response = http.put(
        "/api/response/four-eyes/block_ip",
        json={"distinct_role": False, "reason": "undo"},
    )
    assert saved["response.policy"]["distinct_role_types"] == []


def test_four_eyes_refusals(client):
    http, granted, _, saved = client
    assert (
        http.put(
            "/api/response/four-eyes/nuke", json={"distinct_role": True, "reason": "x"}
        ).status_code
        == 422
    )
    assert (
        http.put(
            "/api/response/four-eyes/block_ip",
            json={"distinct_role": True, "reason": " "},
        ).status_code
        == 422
    )
    granted["perms"] = {"users.read"}
    assert (
        http.put(
            "/api/response/four-eyes/block_ip",
            json={"distinct_role": True, "reason": "x"},
        ).status_code
        == 403
    )
    assert "response.policy" not in saved


def test_a_same_role_second_approval_is_a_409_naming_the_role_rule(client):
    http, *_ = client
    response = http.post("/api/v1/approvals/a-1/approve", json={})
    assert response.status_code == 409
    assert "different role" in response.json()["detail"]
