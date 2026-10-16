"""W0.35 in a real Postgres: who did what is recorded, chained and exported.

K1   Login and user-management events are case_audit_logs rows (entity_type
     ``auth``) whether or not the SIEM export is on, each chained by the W1.10
     triggers, and the export's ``auth`` source reads them from there.
G5   Settings changes land in config_audit_log with old -> new, redacted.
G7   A bulk findings export is a chained case_audit_logs row.

Rows written here are committed (the paths under test commit on their own),
so the shared chain keeps them; every test checks it still verifies.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.audit.chain import check_sources, walk_audit_chain
from core.audit.config_changes import record_change
from core.compliance.audit_export import (
    AuthAuditSource,
    CaseAuditSource,
    record_auth_event,
)
from core.storage.models import ConfigAuditLog

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]


def _request(ip="198.51.100.20"):
    # No app.state.audit_export: export is not configured at all.
    return SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace()),
        client=SimpleNamespace(host=ip),
        headers={"user-agent": "pytest-w035"},
    )


def _auth_rows(conn, event, entity_id):
    return (
        conn.execute(
            text(
                "SELECT * FROM case_audit_logs WHERE entity_type = 'auth' "
                "AND field_name = :e AND entity_id = :i ORDER BY audit_id"
            ),
            {"e": event, "i": entity_id},
        )
        .mappings()
        .all()
    )


def _chained(conn, audit_id):
    return conn.execute(
        text(
            "SELECT event, payload FROM audit_chain WHERE "
            "source_table = 'case_audit_logs' AND source_id = :s ORDER BY seq"
        ),
        {"s": str(audit_id)},
    ).all()


def _verifies(conn):
    assert walk_audit_chain(conn).ok
    assert check_sources(conn).ok


def test_auth_events_are_chained_with_export_off(audit_db):
    """Fails before W0.35: with no export service nothing was recorded."""
    assert record_auth_event(
        _request(),
        "role_change",
        actor="w035-admin",
        actor_id="u-w035-admin",
        target_id="u-w035-bob",
        details={"old_role_id": "role-viewer", "new_role_id": "role-admin"},
    )
    assert record_auth_event(
        _request(),
        "login",
        outcome="failure",
        actor=None,
        target_id="u-w035-bob",
        details={"unknown_identifier": True, "identifier_digest": "abc"},
    )

    with audit_db.engine.connect() as conn:
        (role,) = _auth_rows(conn, "role_change", "u-w035-bob")
        assert role["action"] == "success"
        assert role["changed_by"] == "w035-admin"
        assert role["ip_address"] == "198.51.100.20"
        assert role["user_agent"] == "pytest-w035"
        body = json.loads(role["new_value"])
        assert body["details"]["new_role_id"] == "role-admin"
        assert body["actor_id"] == "u-w035-admin"
        (failed,) = _auth_rows(conn, "login", "u-w035-bob")
        assert failed["action"] == "failure" and failed["changed_by"] == "anonymous"

        chained = _chained(conn, role["audit_id"])
        assert [c.event for c in chained] == ["insert"]
        assert chained[0].payload["row"]["field_name"] == "role_change"
        assert chained[0].payload["row"]["entity_type"] == "auth"
        _verifies(conn)


def test_an_auth_event_in_a_rolled_back_transaction_leaves_nothing(audit_db):
    """User changes join the request's transaction: no change, no record."""
    with Session(audit_db.engine) as session:
        assert record_auth_event(
            _request(),
            "user_delete",
            actor="w035-admin",
            target_id="u-w035-rolled-back",
            session=session,
        )
        session.rollback()
    with audit_db.engine.connect() as conn:
        assert _auth_rows(conn, "user_delete", "u-w035-rolled-back") == []
        _verifies(conn)


def test_the_export_reads_auth_events_from_the_table(audit_db):
    record_auth_event(
        _request(),
        "mfa_disable",
        actor="w035-carol",
        actor_id="u-w035-carol",
    )

    @contextlib.contextmanager
    def scope():
        with Session(audit_db.engine) as session:
            yield session

    auth = AuthAuditSource(scope)
    events = [e for e, _ in auth.fetch(auth.initial_cursor("beginning"), 10_000)]
    mine = [e for e in events if e.actor == "w035-carol"]
    assert [e.action for e in mine] == ["auth.mfa_disable"]
    assert mine[0].severity == 7 and mine[0].src_ip == "198.51.100.20"
    assert all(e.source == "auth" for e in events)

    case = CaseAuditSource(scope)
    rows = case.fetch(case.initial_cursor("beginning"), 10_000)
    assert all(not e.action.startswith("case.auth.") for e, _ in rows)


def test_a_findings_export_is_chained(audit_db, monkeypatch):
    from services.api.routers import findings as findings_api

    user = SimpleNamespace(user_id="u-w035-ana", username="w035-ana")
    findings_api._record_export(
        user, _request(), "jsonl", 42, Path("/x/findings_export_w035.jsonl")
    )
    with audit_db.engine.connect() as conn:
        row = (
            conn.execute(
                text(
                    "SELECT * FROM case_audit_logs WHERE entity_type = "
                    "'findings_export' AND entity_id = 'findings_export_w035.jsonl'"
                )
            )
            .mappings()
            .one()
        )
        assert row["changed_by"] == "w035-ana" and row["action"] == "export"
        assert json.loads(row["new_value"])["rows"] == 42
        assert [c.event for c in _chained(conn, row["audit_id"])] == ["insert"]
        _verifies(conn)


def test_a_settings_change_is_audited_old_to_new_and_redacted(audit_db):
    with Session(audit_db.engine) as session:
        record_change(
            session,
            config_type="llm_provider",
            config_key="w035-openai",
            action="update",
            old={"default_model": "gpt-4o", "config": {"api_key": "sk-old-123456789"}},
            new={
                "default_model": "gpt-4.1",
                "base_url": "https://u:p4ss@api.example.com/v1",
                "config": {"api_key": "sk-new-123456789", "max_tokens": 4096},
            },
            actor="w035-mgr",
        )
        session.commit()
    with Session(audit_db.engine) as session:
        row = (
            session.query(ConfigAuditLog)
            .filter(ConfigAuditLog.config_key == "w035-openai")
            .one()
        )
        assert row.changed_by == "w035-mgr"
        assert row.old_value["default_model"] == "gpt-4o"
        assert row.new_value["default_model"] == "gpt-4.1"
        assert row.new_value["config"] == {"api_key": "[REDACTED]", "max_tokens": 4096}
        assert row.new_value["base_url"] == "https://[REDACTED]@api.example.com/v1"
        assert "sk-" not in json.dumps([row.old_value, row.new_value])


def test_sla_policy_changes_are_audited(audit_db):
    from core.cases import sla_policies_router as sla

    mgr = SimpleNamespace(user_id="u-w035-mgr", username="w035-mgr")
    with Session(audit_db.engine) as session:
        sla.create_sla_policy(
            sla.SLAPolicyCreate(
                policy_id="w035-p1",
                name="W035",
                priority_level="high",
                response_time_hours=1,
                resolution_time_hours=8,
                is_default=False,
            ),
            session=session,
            current_user=mgr,
        )
        sla.update_sla_policy(
            "w035-p1",
            sla.SLAPolicyUpdate(resolution_time_hours=4),
            session=session,
            current_user=mgr,
        )
        sla.delete_sla_policy("w035-p1", session=session, current_user=mgr)
        session.commit()
    with Session(audit_db.engine) as session:
        rows = (
            session.query(ConfigAuditLog)
            .filter(ConfigAuditLog.config_type == "sla_policy")
            .filter(ConfigAuditLog.config_key == "w035-p1")
            .order_by(ConfigAuditLog.id)
            .all()
        )
        assert [(r.action, r.changed_by) for r in rows] == [
            ("create", "w035-mgr"),
            ("update", "w035-mgr"),
            ("delete", "w035-mgr"),
        ]
        assert rows[1].old_value["resolution_time_hours"] == 8
        assert rows[1].new_value["resolution_time_hours"] == 4
        assert rows[2].new_value is None


def test_custom_workflow_changes_are_audited_as_the_actor(audit_db):
    from core.workflows.custom_workflow_service import CustomWorkflowService

    service = CustomWorkflowService()
    created = service.create(
        {
            "workflow_id": "w035-wf",
            "name": "W035 flow",
            "description": "d",
            "created_by": "SOC Analyst",  # a client-sent name, ignored
        },
        actor="w035-ana",
    )
    assert created["created_by"] == "w035-ana"
    service.update("w035-wf", {"description": "d2"}, actor="w035-ana")
    service.delete("w035-wf", actor="w035-ana")
    with Session(audit_db.engine) as session:
        rows = (
            session.query(ConfigAuditLog)
            .filter(ConfigAuditLog.config_type == "custom_workflow")
            .filter(ConfigAuditLog.config_key == "w035-wf")
            .order_by(ConfigAuditLog.id)
            .all()
        )
        assert [r.action for r in rows] == ["create", "update", "delete"]
        assert {r.changed_by for r in rows} == {"w035-ana"}
        assert rows[1].old_value["description"] == "d"
        assert rows[1].new_value["description"] == "d2"
        assert rows[2].new_value["is_active"] is False
