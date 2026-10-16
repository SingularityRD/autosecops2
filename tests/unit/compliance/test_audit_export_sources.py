"""The database sources read their tables in order and respect the settle window.

Runs on SQLite with the columns the exporter selects (the Postgres schemas are
in infra/database/init/04, 13+30+49, 19+31 and the CaseAuditLog model), so it
needs no database server.
"""

from __future__ import annotations

import contextlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from core.audit.auth_events import build_row
from core.compliance.audit_export import (
    AgentEventsSource,
    ApprovalTransitionSource,
    AuditExportConfig,
    AuthAuditSource,
    CaseAuditSource,
    auth_record,
    ConfigAuditSource,
    build_sources,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)

DDL = [
    """CREATE TABLE config_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, config_type TEXT, config_key TEXT,
        action TEXT, old_value TEXT, new_value TEXT, changed_by TEXT,
        change_reason TEXT, timestamp DATETIME)""",
    """CREATE TABLE case_audit_logs (
        audit_id INTEGER PRIMARY KEY AUTOINCREMENT, entity_type TEXT,
        entity_id TEXT, action TEXT, field_name TEXT, old_value TEXT,
        new_value TEXT, change_summary TEXT, changed_by TEXT, user_agent TEXT,
        ip_address TEXT, timestamp DATETIME)""",
    """CREATE TABLE approval_actions (
        action_id TEXT PRIMARY KEY, action_type TEXT, title TEXT, target TEXT,
        confidence NUMERIC, created_by TEXT, status TEXT, approved_by TEXT,
        rejection_reason TEXT, reversibility TEXT, workflow_run_id TEXT,
        verify_status TEXT, reverse_of TEXT, second_approver TEXT,
        parameters TEXT, created_at DATETIME, approved_at DATETIME,
        executed_at DATETIME, verified_at DATETIME, reversed_at DATETIME)""",
    """CREATE TABLE agent_events (
        run_id TEXT, seq INTEGER, ts DATETIME, run_kind TEXT, kind TEXT,
        payload TEXT, schema_version INTEGER, prev_hash TEXT, event_hash TEXT,
        PRIMARY KEY (run_id, seq))""",
]


def _ts(minutes_ago: float) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S.%f")


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    with engine.begin() as conn:
        for stmt in DDL:
            conn.execute(text(stmt))

    @contextlib.contextmanager
    def scope():
        with Session(engine) as session:
            yield session
            session.commit()

    scope.engine = engine
    return scope


def _exec(db, sql, rows):
    with db.engine.begin() as conn:
        for row in rows:
            conn.execute(text(sql), row)


def _clock():
    return NOW


def test_config_audit_source_reads_in_id_order_and_waits_for_settle(db):
    _exec(
        db,
        "INSERT INTO config_audit_log (config_type, config_key, action, old_value,"
        " new_value, changed_by, change_reason, timestamp) VALUES"
        " ('system', :k, 'update', :o, :n, 'alice', 'why', :ts)",
        [
            {"k": "a", "o": None, "n": json.dumps({"api_key": "x"}), "ts": _ts(10)},
            {"k": "compliance.audit_export", "o": "{}", "n": "{}", "ts": _ts(5)},
            {"k": "c", "o": None, "n": "1", "ts": _ts(0.01)},  # inside settle
        ],
    )
    src = ConfigAuditSource(db, settle_s=5, clock=_clock)
    rows = src.fetch(src.initial_cursor("beginning"), 10)
    assert [c for _, c in rows] == [{"id": 1}, {"id": 2}]
    first, second = (e for e, _ in rows)
    assert first.id == "config:1" and first.action == "config.update"
    assert first.actor == "alice" and first.target_id == "a"
    assert first.details["new_value"] == {"api_key": "x"}  # parsed; redacted later
    assert second.severity == 6  # changes to the exporter itself stand out
    assert src.fetch({"id": 2}, 10) == []  # row 3 still settling
    assert src.initial_cursor("now") == {"id": 3}


def test_case_audit_source(db):
    _exec(
        db,
        "INSERT INTO case_audit_logs (entity_type, entity_id, action, field_name,"
        " old_value, new_value, change_summary, changed_by, user_agent, ip_address,"
        " timestamp) VALUES ('case', 'c-1', :a, 'status', 'open', 'closed', :s,"
        " 'bob', 'ua', '203.0.113.9', :ts)",
        [
            {"a": "update", "s": "closed the case", "ts": _ts(3)},
            {"a": "delete", "s": None, "ts": _ts(2)},
        ],
    )
    src = CaseAuditSource(db, settle_s=1, clock=_clock)
    (a, ca), (b, cb) = src.fetch({"id": 0}, 10)
    assert a.id == "case_audit:1" and a.action == "case.case.update"
    assert a.message == "closed the case" and a.src_ip == "203.0.113.9"
    assert b.message == "case c-1 delete" and b.severity == 4
    assert cb == {"id": 2}


def _auth_rows(db, *records):
    with db() as session:
        for record in records:
            session.add(build_row(record))


def test_auth_source_reads_auth_rows_and_case_audit_skips_them(db):
    """K1 (W0.35): auth events are case_audit_logs rows, exported once, as auth."""
    _exec(
        db,
        "INSERT INTO case_audit_logs (entity_type, entity_id, action, changed_by,"
        " timestamp) VALUES ('case', 'c-1', 'update', 'bob', :ts)",
        [{"ts": _ts(4)}],
    )
    _auth_rows(
        db,
        auth_record(
            "login",
            outcome="failure",
            actor=None,
            src_ip="198.51.100.4",
            user_agent="pytest",
            details={"unknown_identifier": True, "identifier_digest": "ab"},
            now=NOW - timedelta(minutes=3),
        ),
        auth_record(
            "role_change",
            actor="admin",
            actor_id="u-admin",
            target_id="u-bob",
            details={"old_role_id": "role-viewer", "new_role_id": "role-admin"},
            now=NOW - timedelta(minutes=2),
        ),
    )
    auth = AuthAuditSource(db, settle_s=1, clock=_clock)
    events = auth.fetch(auth.initial_cursor("beginning"), 10)
    assert [c for _, c in events] == [{"id": 2}, {"id": 3}]
    (failed, _), (role, _) = events
    assert failed.source == "auth" and failed.action == "auth.login"
    assert failed.outcome == "failure" and failed.actor is None
    assert failed.src_ip == "198.51.100.4" and failed.user_agent == "pytest"
    assert failed.id.startswith("auth:") and failed.severity == 5
    assert failed.details["identifier_digest"] == "ab"
    assert role.action == "auth.role_change" and role.severity == 7
    assert role.actor == "admin" and role.actor_id == "u-admin"
    assert role.target_type == "user" and role.target_id == "u-bob"
    assert role.details["new_role_id"] == "role-admin"
    assert role.timestamp == NOW - timedelta(minutes=2)
    # Stable ids: a re-read sends the same event ids.
    assert [e.id for e, _ in auth.fetch({"id": 0}, 10)] == [failed.id, role.id]
    case = CaseAuditSource(db, settle_s=1, clock=_clock)
    assert [c for _, c in case.fetch({"id": 0}, 10)] == [{"id": 1}]


def test_approval_transitions_each_get_an_event_and_cursor(db):
    _exec(
        db,
        "INSERT INTO approval_actions (action_id, action_type, title, target,"
        " confidence, created_by, status, approved_by, rejection_reason,"
        " reversibility, parameters, created_at, approved_at, executed_at)"
        " VALUES (:id, 'block_ip', 't', '198.51.100.1', 0.9, 'agent', :st, :by,"
        " :rr, :rev, '{\"ttl\": 60}', :c, :ap, :ex)",
        [
            {
                "id": "a1",
                "st": "executed",
                "by": "alice",
                "rr": None,
                "rev": "irreversible",
                "c": _ts(30),
                "ap": _ts(20),
                "ex": _ts(10),
            },
            {
                "id": "a2",
                "st": "rejected",
                "by": "bob",
                "rr": "no",
                "rev": "reversible",
                "c": _ts(30),
                "ap": _ts(15),
                "ex": None,
            },
        ],
    )
    created = ApprovalTransitionSource("created", db, settle_s=1, clock=_clock)
    rows = created.fetch(created.initial_cursor("beginning"), 10)
    assert [e.id for e, _ in rows] == ["approvals:a1:created", "approvals:a2:created"]
    assert rows[0][0].severity == 6  # irreversible request
    # same timestamp: the keyset continues by action_id, without skipping
    assert [e.id for e, _ in created.fetch(rows[0][1], 10)] == ["approvals:a2:created"]

    decided = ApprovalTransitionSource("decided", db, settle_s=1, clock=_clock)
    d = {e.id: e for e, _ in decided.fetch({"ts": "1970-01-01T00:00:00Z", "id": ""}, 9)}
    assert d["approvals:a1:decided"].action == "approval.approved"
    assert d["approvals:a1:decided"].actor == "alice"
    assert d["approvals:a2:decided"].action == "approval.rejected"
    assert d["approvals:a2:decided"].details["parameters"] == {"ttl": 60}

    executed = ApprovalTransitionSource("executed", db, settle_s=1, clock=_clock)
    ((ev, _),) = executed.fetch({"ts": "1970-01-01T00:00:00Z", "id": ""}, 9)
    assert ev.action == "response.executed" and ev.severity == 8
    assert (
        ApprovalTransitionSource("verified", db, clock=_clock).fetch(
            {"ts": "1970-01-01T00:00:00Z", "id": ""}, 9
        )
        == []
    )
    # "now" starts at the settle cutoff: nothing older is exported
    assert executed.fetch(executed.initial_cursor("now"), 9) == []


def test_agent_events_keyset_paging_and_kind_filter(db):
    rows = []
    for run, seqs in (("r-b", (0, 1)), ("r-a", (0, 1, 2))):
        for seq in seqs:
            rows.append(
                {
                    "r": run,
                    "s": seq,
                    "ts": _ts(10) if seq < 2 else _ts(8),
                    "k": "terminal" if seq == 2 else "tool_call",
                    "p": json.dumps({"tool": "x", "args": {"deep": 1}, "n": seq}),
                    "ph": "0" * 64,
                    "eh": f"{seq:064x}",
                }
            )
    rows.append({**rows[0], "s": 9, "ts": _ts(0.01)})  # settling
    _exec(
        db,
        "INSERT INTO agent_events (run_id, seq, ts, run_kind, kind, payload,"
        " schema_version, prev_hash, event_hash) VALUES"
        " (:r, :s, :ts, 'hunt', :k, :p, 1, :ph, :eh)",
        rows,
    )
    src = AgentEventsSource(db, settle_s=5, clock=_clock)
    cursor = src.initial_cursor("beginning")
    seen = []
    for _ in range(5):
        page = src.fetch(cursor, 2)
        if not page:
            break
        seen += [e.id for e, _ in page]
        cursor = page[-1][1]
    assert seen == [
        "agent_events:r-a:0",
        "agent_events:r-a:1",
        "agent_events:r-b:0",
        "agent_events:r-b:1",
        "agent_events:r-a:2",
    ]
    (ev, _), *_ = src.fetch(src.initial_cursor("beginning"), 1)
    assert ev.hash == f"{0:064x}" and ev.details["prev_hash"] == "0" * 64
    assert ev.details["payload"] == {"tool": "x", "n": 0}  # nested content stays home

    terminal = AgentEventsSource(db, settle_s=5, clock=_clock, kinds=["terminal"])
    assert [
        e.id for e, _ in terminal.fetch(terminal.initial_cursor("beginning"), 9)
    ] == ["agent_events:r-a:2"]


def test_build_sources_honours_toggles():
    cfg = AuditExportConfig.model_validate(
        {"sources": {"approvals": False, "auth": False}}
    )
    names = [s.name for s in build_sources(cfg, lambda: None)]
    assert names == ["agent_events", "config", "case_audit", "audit_checkpoints"]
    every = [s.name for s in build_sources(AuditExportConfig(), lambda: None)]
    assert "approvals.decided" in every and "approvals.reversed" in every
    assert every[-1] == "auth"  # read from the database (W0.35)
