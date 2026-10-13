"""On real Postgres, a long-open transaction is waited for, never skipped (W3.6).

The verifier's scenario: a transaction takes a lower id (or an older
timestamp), stays open longer than ``settle_s``; a later one commits a higher
id; the exporter must not move its cursor past the first one's row, which
would then commit behind the cursor and never be exported. ``settle_s`` is 0
here, so only the transaction-id bound protects the cursor.

Needs a local PostgreSQL (skipped without one). Creates and drops a scratch
database of its own.
"""

from __future__ import annotations

import contextlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from core.compliance.audit_export import (
    AgentEventsSource,
    ApprovalTransitionSource,
    CaseAuditSource,
    ConfigAuditSource,
)

pytestmark = [pytest.mark.database]


def _url(database: str) -> str:
    user = os.getenv("POSTGRES_USER", "deeptempo")
    pw = os.getenv("POSTGRES_PASSWORD", "deeptempo_secure_password_change_me")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    return (
        f"postgresql+psycopg2://{quote(user, safe='')}:{quote(pw, safe='')}"
        f"@{host}:{port}/{database}"
    )


def _postgres_available() -> bool:
    try:
        with create_engine(_url("postgres")).connect():
            return True
    except Exception:
        return False


pytestmark.append(
    pytest.mark.skipif(not _postgres_available(), reason="requires a local PostgreSQL")
)

DDL = [
    """CREATE TABLE config_audit_log (
        id SERIAL PRIMARY KEY, config_type TEXT, config_key TEXT, action TEXT,
        old_value JSONB, new_value JSONB, changed_by TEXT, change_reason TEXT,
        timestamp TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'))""",
    """CREATE TABLE case_audit_logs (
        audit_id SERIAL PRIMARY KEY, entity_type TEXT, entity_id TEXT,
        action TEXT, field_name TEXT, old_value TEXT, new_value TEXT,
        change_summary TEXT, changed_by TEXT, user_agent TEXT, ip_address TEXT,
        timestamp TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'))""",
    """CREATE TABLE approval_actions (
        action_id TEXT PRIMARY KEY, action_type TEXT, title TEXT, target TEXT,
        confidence NUMERIC, created_by TEXT, status TEXT, approved_by TEXT,
        rejection_reason TEXT, reversibility TEXT, workflow_run_id TEXT,
        verify_status TEXT, reverse_of TEXT, second_approver TEXT,
        parameters JSONB, created_at TIMESTAMP, approved_at TIMESTAMP,
        executed_at TIMESTAMP, verified_at TIMESTAMP, reversed_at TIMESTAMP)""",
    """CREATE TABLE agent_events (
        run_id UUID, seq INTEGER, ts TIMESTAMPTZ NOT NULL DEFAULT now(),
        run_kind TEXT, kind TEXT, payload JSONB, schema_version INTEGER,
        prev_hash TEXT, event_hash TEXT, PRIMARY KEY (run_id, seq))""",
    "CREATE TABLE unrelated (x INTEGER)",
]


@pytest.fixture(scope="module")
def engine():
    name = f"vigil_test_audit_export_{uuid.uuid4().hex[:10]}"
    admin = create_engine(_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    eng = create_engine(_url(name), pool_size=6)
    try:
        with eng.begin() as conn:
            for stmt in DDL:
                conn.execute(text(stmt))
        yield eng
    finally:
        eng.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture
def clean(engine):
    with engine.begin() as conn:
        conn.execute(
            text(
                "TRUNCATE config_audit_log, case_audit_logs, approval_actions, "
                "agent_events, unrelated RESTART IDENTITY"
            )
        )
    return engine


def _scope(engine):
    @contextlib.contextmanager
    def scope():
        with Session(engine) as session:
            yield session
            session.commit()

    return scope


def _drain(source, cursor, rounds: int = 5) -> tuple[list[str], dict]:
    """Read until nothing new, advancing the cursor as the pipeline would."""
    seen: list[str] = []
    for _ in range(rounds):
        rows = source.fetch(cursor, 2)  # small pages: exercise the keyset
        if not rows:
            break
        for event, after in rows:
            seen.append(event.id)
            cursor = after
    return seen, cursor


def _config_row(conn, key: str) -> None:
    conn.execute(
        text(
            "INSERT INTO config_audit_log (config_type, config_key, action, "
            "changed_by) VALUES ('system', :k, 'update', 'admin')"
        ),
        {"k": key},
    )


def test_the_verifier_scenario_loses_nothing(clean):
    """T1 takes id 1 and stays open; T2 commits id 2; T1 commits later."""
    source = ConfigAuditSource(_scope(clean), settle_s=0)
    cursor = source.initial_cursor("beginning")
    t1 = clean.connect()
    tx1 = t1.begin()
    _config_row(t1, "slow")  # id 1, uncommitted
    with clean.begin() as t2:
        _config_row(t2, "fast")  # id 2, committed
    try:
        seen, cursor = _drain(source, cursor)
        # The committed row is behind the open transaction: not read yet, and
        # the cursor has not moved past either row.
        assert seen == []
        tx1.commit()
    finally:
        t1.close()
    seen, cursor = _drain(source, cursor)
    assert sorted(seen) == ["config:1", "config:2"]
    assert _drain(source, cursor)[0] == []


def test_an_older_xid_with_a_higher_id_is_not_passed_either(clean):
    """T1 gets its xid first, T2 takes id 1 and stays open, T1 commits id 2.

    Ordering by id alone with an xid filter per row would read id 2 and pass
    id 1; paging on (xid, id) cannot.
    """
    source = ConfigAuditSource(_scope(clean), settle_s=0)
    cursor = source.initial_cursor("beginning")
    t1, t2 = clean.connect(), clean.connect()
    tx1, tx2 = t1.begin(), t2.begin()
    try:
        t1.execute(text("INSERT INTO unrelated VALUES (1)"))  # T1's xid first
        _config_row(t2, "held-open")  # id 1, T2 (younger xid), open
        _config_row(t1, "committed-first")  # id 2, T1
        tx1.commit()
        seen, cursor = _drain(source, cursor)
        assert seen == ["config:2"]
        tx2.commit()
    finally:
        t1.close()
        t2.close()
    seen, cursor = _drain(source, cursor)
    assert seen == ["config:1"]  # read after the cursor passed id 2


def test_case_audit_and_start_from_now(clean):
    source = CaseAuditSource(_scope(clean), settle_s=0)
    with clean.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO case_audit_logs (entity_type, entity_id, "
                "action) VALUES ('case', 'c-old', 'update')"
            )
        )
    cursor = source.initial_cursor("now")
    t1 = clean.connect()
    tx1 = t1.begin()
    t1.execute(
        text(
            "INSERT INTO case_audit_logs (entity_type, entity_id, action) "
            "VALUES ('case', 'c-slow', 'update')"
        )
    )
    with clean.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO case_audit_logs (entity_type, entity_id, "
                "action) VALUES ('case', 'c-fast', 'update')"
            )
        )
    try:
        assert _drain(source, cursor)[0] == []
        tx1.commit()
    finally:
        t1.close()
    seen, _ = _drain(source, cursor)
    assert sorted(seen) == ["case_audit:2", "case_audit:3"]  # not the old one


def test_agent_events_with_an_old_timestamp_committed_late(clean):
    source = AgentEventsSource(_scope(clean), settle_s=0)
    cursor = source.initial_cursor("beginning")
    old = datetime.now(timezone.utc) - timedelta(hours=1)
    run_a, run_b = str(uuid.uuid4()), str(uuid.uuid4())
    insert = text(
        "INSERT INTO agent_events (run_id, seq, ts, run_kind, kind, payload, "
        "schema_version) VALUES (CAST(:r AS uuid), :s, :ts, 'triage', 'step', "
        "'{}', 1)"
    )
    t1 = clean.connect()
    tx1 = t1.begin()
    t1.execute(insert, {"r": run_a, "s": 0, "ts": old})  # an hour old, open
    with clean.begin() as conn:
        conn.execute(insert, {"r": run_b, "s": 0, "ts": datetime.now(timezone.utc)})
    try:
        seen, cursor = _drain(source, cursor)
        assert seen == []
        tx1.commit()
    finally:
        t1.close()
    seen, cursor = _drain(source, cursor)
    assert sorted(seen) == sorted(
        [f"agent_events:{run_a}:0", f"agent_events:{run_b}:0"]
    )


def test_an_approval_decided_in_a_long_transaction_is_exported(clean):
    source = ApprovalTransitionSource("decided", _scope(clean), settle_s=0)
    cursor = source.initial_cursor("beginning")
    with clean.begin() as conn:
        for aid in ("a-1", "a-2"):
            conn.execute(
                text(
                    "INSERT INTO approval_actions (action_id, action_type, "
                    "target, status, created_at) VALUES (:a, 'block_ip', "
                    "'10.0.0.1', 'pending', now())"
                ),
                {"a": aid},
            )
    early = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=5)
    decide = text(
        "UPDATE approval_actions SET status = 'approved', "
        "approved_by = 'bob', approved_at = :t WHERE action_id = :a"
    )
    t1 = clean.connect()
    tx1 = t1.begin()
    t1.execute(decide, {"a": "a-1", "t": early})  # decided early, still open
    with clean.begin() as conn:
        conn.execute(
            decide, {"a": "a-2", "t": datetime.now(timezone.utc).replace(tzinfo=None)}
        )
    try:
        seen, cursor = _drain(source, cursor)
        assert seen == []
        tx1.commit()
    finally:
        t1.close()
    seen, cursor = _drain(source, cursor)
    assert sorted(seen) == ["approvals:a-1:decided", "approvals:a-2:decided"]


def test_a_cursor_ahead_of_the_database_rereads_instead_of_waiting_forever(clean):
    source = ConfigAuditSource(_scope(clean), settle_s=0)
    with clean.begin() as conn:
        _config_row(conn, "after-restore")
    seen, _ = _drain(source, {"xid": 2**40, "id": 10**6})
    assert seen == ["config:1"]
