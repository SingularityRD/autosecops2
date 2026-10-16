"""The response policy edited through the API, against Postgres (W0.36).

A change made with ``PUT /api/response/policy`` writes a ``config_audit_log``
row (who, reason, old and new value) and is what the dispatcher
(``AutonomousResponseService``, the daemon's executor path) and the approval
flow apply at their next decision, with no restart.

DB-backed: the throwaway database (tests/unit/conftest.py) plus
``61_approval_decisions.sql`` for the approval steps.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

from core.response.approval_service import (  # noqa: E402
    ActionStatus,
    ActionType,
    ApprovalService,
    SecondApproverConflict,
)
from core.response.autonomous_response_service import (  # noqa: E402
    AutonomousResponseService,
)
from core.response.config import ResponseConfig  # noqa: E402
from core.response.executors.base import TypedAction  # noqa: E402
from core.response.policy import POLICY_CONFIG_KEY  # noqa: E402
from core.storage.connection import get_db_manager  # noqa: E402
from core.storage.models import ConfigAuditLog, SystemConfig, User  # noqa: E402
from services.api import main as backend_main  # noqa: E402
from services.api.middleware import auth as auth_module  # noqa: E402

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

INIT_SQL = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "61_approval_decisions.sql"
)
TAG = uuid.uuid4().hex[:6]


def _purge():
    with get_db_manager().session_scope() as s:
        s.query(SystemConfig).filter(SystemConfig.key == POLICY_CONFIG_KEY).delete()
        s.query(ConfigAuditLog).filter(
            ConfigAuditLog.config_key == POLICY_CONFIG_KEY
        ).delete()


@pytest.fixture(scope="module")
def decisions_table(throwaway_database):
    with get_db_manager().engine.begin() as conn:
        conn.execute(text(INIT_SQL.read_text(encoding="utf-8")))
    return True


@pytest.fixture
def http(decisions_table, monkeypatch):
    _purge()
    user = User(
        user_id=f"u-admin-{TAG}",
        username=f"admin-{TAG}",
        email=f"admin-{TAG}@test.local",
        password_hash="",
        role_id="role-admin",
        is_active=True,
        mfa_enabled=False,
    )
    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.check_permission",
        lambda user_id, perm, session=None: perm in {"settings.read", "settings.write"},
    )
    app = backend_main.app
    app.dependency_overrides[auth_module.get_current_active_user] = lambda: user
    app.dependency_overrides[auth_module.get_current_user] = lambda: user
    try:
        yield TestClient(app), user
    finally:
        app.dependency_overrides.pop(auth_module.get_current_active_user, None)
        app.dependency_overrides.pop(auth_module.get_current_user, None)
        _purge()


def _put(client, reason, **kw):
    version = client.get("/api/response/policy").json()["version"]
    body = {"reason": reason, "default_hourly_limit": 20, "version": version, **kw}
    response = client.put("/api/response/policy", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def _audit_rows():
    with get_db_manager().session_scope() as s:
        return [
            (r.action, r.changed_by, r.change_reason, r.old_value, r.new_value)
            for r in s.query(ConfigAuditLog)
            .filter(ConfigAuditLog.config_key == POLICY_CONFIG_KEY)
            .order_by(ConfigAuditLog.id)
            .all()
        ]


def test_every_change_is_audited_with_who_and_old_to_new(http):
    client, user = http
    _put(client, "first list", protected_targets=["dc01.corp.local"])
    _put(
        client,
        "add the jump host",
        protected_targets=["dc01.corp.local", "jump01.corp.local"],
    )
    rows = _audit_rows()
    assert [r[:3] for r in rows] == [
        ("create", user.username, "first list"),
        ("update", user.username, "add the jump host"),
    ]
    assert rows[0][3] is None
    assert rows[1][3]["protected_targets"] == ["dc01.corp.local"]
    assert rows[1][4]["protected_targets"] == ["dc01.corp.local", "jump01.corp.local"]
    stored = client.get("/api/response/policy").json()
    assert stored["protected_targets"] == ["dc01.corp.local", "jump01.corp.local"]


def test_a_refused_change_leaves_no_row(http):
    client, _ = http
    response = client.put(
        "/api/response/policy",
        json={"reason": "x", "hourly_limits": {"nope": 1}, "version": "x"},
    )
    assert response.status_code == 422
    assert _audit_rows() == []


def _dispatcher():
    return AutonomousResponseService(config=ResponseConfig())


def test_the_dispatcher_refuses_a_newly_protected_target(http):
    client, _ = http
    action = TypedAction(action_type="isolate_host", target="FS01.corp.local")
    before = _dispatcher().evaluate(action)
    assert not any("protected asset" in r for r in before.reasons)
    _put(client, "file server is tier0", asset_tags={"fs01.corp.local": ["tier0"]})
    after = _dispatcher().evaluate(action)
    assert not after.allowed
    assert "tagged tier0" in after.reasons[0]
    _put(client, "listed", protected_targets=["10.9.0.0/24"])
    verdict = _dispatcher().evaluate(
        TypedAction(action_type="block_ip", target="10.9.0.7")
    )
    assert not verdict.allowed and "protected_targets" in verdict.reasons[0]


def test_the_dispatcher_applies_an_edited_hourly_limit(http):
    client, _ = http
    _put(client, "no automatic blocks this week", hourly_limits={"block_ip": 0})
    verdict = _dispatcher().evaluate(
        TypedAction(action_type="block_ip", target="203.0.113.9")
    )
    assert not verdict.allowed
    assert "blast radius" in verdict.reasons[0] and "limit 0" in verdict.reasons[0]


def _create(svc, action_type):
    return svc.create_action(
        action_type=action_type,
        title="t",
        description="d",
        target="203.0.113.10",
        confidence=0.99,
        reason="r",
        evidence=["ev"],
        created_by="pytest",
    )


def test_the_approval_flow_needs_a_second_approver_for_an_added_type(http):
    client, _ = http
    # Reads the policy row at each decision, as the API's own service does.
    svc = ApprovalService(config=ResponseConfig())
    svc.force_manual_approval = False
    _put(client, "two people for blocks", four_eyes_types=["block_ip"])
    row = _create(svc, ActionType.BLOCK_IP)
    first = svc.approve_action(row.action_id, f"alice-{TAG}")
    assert first.status == ActionStatus.PENDING.value
    with pytest.raises(SecondApproverConflict):
        svc.approve_action(row.action_id, f"ALICE-{TAG}")
    done = svc.approve_action(row.action_id, f"bob-{TAG}")
    assert done.status == ActionStatus.APPROVED.value

    _put(client, "back to one", four_eyes_types=[])
    other = _create(svc, ActionType.BLOCK_IP)
    assert (
        svc.approve_action(other.action_id, f"alice-{TAG}").status
        == ActionStatus.APPROVED.value
    )


# --- concurrent writers (W0.36 verifier: lost update) -------------------------


def test_two_interleaved_puts_the_second_gets_409(http):
    client, user = http
    v0 = client.get("/api/response/policy").json()["version"]
    first = {"reason": "a", "default_hourly_limit": 20, "version": v0}
    second = {"reason": "b", "default_hourly_limit": 20, "version": v0}
    a = client.put(
        "/api/response/policy", json={**first, "protected_targets": ["dc01"]}
    )
    assert a.status_code == 200, a.text
    b = client.put(
        "/api/response/policy", json={**second, "protected_targets": ["dc02"]}
    )
    assert b.status_code == 409
    assert client.get("/api/response/policy").json()["protected_targets"] == ["dc01"]
    assert [r[2] for r in _audit_rows()] == ["a"]


def test_a_four_eyes_change_in_between_is_not_lost(http):
    client, _ = http
    _put(client, "base", protected_targets=["dc01"])
    stale = client.get("/api/response/policy").json()["version"]
    r = client.put(
        "/api/response/four-eyes/block_ip",
        json={"distinct_role": True, "reason": "SoD"},
    )
    assert r.status_code == 200, r.text
    body = {
        "reason": "stale editor",
        "default_hourly_limit": 20,
        "version": stale,
        "protected_targets": [],
    }
    assert client.put("/api/response/policy", json=body).status_code == 409
    after = client.get("/api/response/policy").json()
    assert after["effective"]["distinct_role_types"] == ["block_ip"]
    assert after["protected_targets"] == ["dc01"]
    # Re-read and saved again: the four-eyes change survives the full PUT.
    _put(client, "fresh editor", protected_targets=[])
    assert client.get("/api/response/policy").json()["effective"][
        "distinct_role_types"
    ] == ["block_ip"]


def test_writers_serialise_on_the_row_lock(http):
    """A second writer waits for the first and applies its change on top."""
    import threading

    from core.response.policy_store import read_policy, update_policy

    client, _ = http
    _put(client, "base", protected_targets=["dc01"])
    inside, release = threading.Event(), threading.Event()
    errors = []

    def slow(raw):
        inside.set()
        assert release.wait(10)
        raw["protected_targets"] = ["dc01", "dc02"]
        return raw

    def first():
        try:
            update_policy("alice", "slow", slow)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    def second():
        try:
            update_policy(
                "bob",
                "four eyes",
                lambda raw: {**raw, "distinct_role_types": ["block_ip"]},
            )
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    t1 = threading.Thread(target=first)
    t1.start()
    assert inside.wait(10)
    t2 = threading.Thread(target=second)
    t2.start()
    t2.join(0.5)
    assert t2.is_alive(), "the second writer must wait for the row lock"
    release.set()
    t1.join(10)
    t2.join(10)
    assert errors == []
    raw, _ = read_policy()
    assert raw["protected_targets"] == ["dc01", "dc02"]
    assert raw["distinct_role_types"] == ["block_ip"]
