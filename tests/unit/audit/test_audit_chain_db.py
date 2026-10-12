"""audit_chain in a real Postgres: capture, append-only, tamper, concurrency.

Tamper steps run as the superuser the tests connect as, with
``session_replication_role = replica`` so the append-only and capture triggers
do not fire -- the attacker the chain exists to expose. Each one runs in a
transaction that is rolled back, so the shared chain stays intact for the
next test.
"""

from __future__ import annotations

import importlib.util
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from core.audit.chain import check_sources, walk_agent_events, walk_audit_chain
from core.storage import connection as connection_module
from core.storage.audit_chain import attach_table, triggers_attached
from tests.unit.audit.conftest import (
    PRE_ACTION,
    insert_action,
    insert_audit_log,
    run_sql_file,
)

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

REPO = Path(__file__).resolve().parents[3]


def _tamper(conn):
    conn.execute(text("SET LOCAL session_replication_role = replica"))


def _chain_rows(conn, source_id):
    return conn.execute(
        text(
            "SELECT seq, event, payload FROM audit_chain WHERE source_id = :s "
            "ORDER BY seq"
        ),
        {"s": source_id},
    ).all()


def _rolled_back(engine):
    conn = engine.connect()
    tx = conn.begin()
    return conn, tx


# --- capture -----------------------------------------------------------------


def test_attach_snapshots_rows_that_predate_it(audit_db):
    with audit_db.engine.connect() as conn:
        events = {
            (row.source_table, row.event)
            for row in conn.execute(
                text(
                    "SELECT source_table, event FROM audit_chain WHERE source_id IN (:a, :b)"
                ),
                {"a": PRE_ACTION, "b": str(audit_db.pre_audit_id)},
            )
        }
        assert ("approval_actions", "snapshot") in events
        assert ("case_audit_logs", "snapshot") in events
        for table in ("approval_actions", "case_audit_logs"):
            assert triggers_attached(conn, table)
            installs = conn.execute(
                text(
                    "SELECT count(*) FROM audit_chain "
                    "WHERE source_table = :t AND event = 'install'"
                ),
                {"t": table},
            ).scalar()
            assert installs == 1


def test_approval_lifecycle_is_chained(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-life")
        conn.execute(
            text(
                "UPDATE approval_actions SET status = 'approved', approved_by = 'alice' "
                "WHERE action_id = 'action-audit-life'"
            )
        )
        # Same values again: no change, no chain row.
        conn.execute(
            text(
                "UPDATE approval_actions SET status = 'approved' "
                "WHERE action_id = 'action-audit-life'"
            )
        )
        conn.execute(
            text("DELETE FROM approval_actions WHERE action_id = 'action-audit-life'")
        )
        rows = _chain_rows(conn, "action-audit-life")
        assert [r.event for r in rows] == ["insert", "update", "delete"]
        assert rows[1].payload["old"] == {"status": "pending", "approved_by": None}
        assert rows[1].payload["row"]["status"] == "approved"
        assert [r.seq for r in rows] == sorted(r.seq for r in rows)
        assert walk_audit_chain(conn).ok
        assert check_sources(conn).ok
    finally:
        tx.rollback()
        conn.close()


def test_case_audit_log_rows_are_chained(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        audit_id = insert_audit_log(conn, "case-audit-chained")
        rows = _chain_rows(conn, str(audit_id))
        assert [r.event for r in rows] == ["insert"]
        assert rows[0].payload["row"]["entity_id"] == "case-audit-chained"
        assert walk_audit_chain(conn).ok
        assert check_sources(conn).ok
    finally:
        tx.rollback()
        conn.close()


def test_truncate_is_chained(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_audit_log(conn, "case-audit-truncated")
        conn.execute(text("TRUNCATE case_audit_logs"))
        last = conn.execute(
            text(
                "SELECT event FROM audit_chain WHERE source_table = 'case_audit_logs' "
                "ORDER BY seq DESC LIMIT 1"
            )
        ).scalar()
        assert last == "truncate"
        assert walk_audit_chain(conn).ok
        assert check_sources(conn).ok
    finally:
        tx.rollback()
        conn.close()


# --- append-only ---------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_chain SET payload = '{}'::jsonb",
        "DELETE FROM audit_chain",
        "TRUNCATE audit_chain",
        "UPDATE audit_checkpoints SET signature = ''",
        "DELETE FROM audit_checkpoints",
        "TRUNCATE audit_checkpoints",
    ],
)
def test_even_the_owner_cannot_change_rows(audit_db, statement):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        # At least one row in each table for the row triggers to refuse.
        insert_action(conn, "action-audit-owner")
        conn.execute(
            text(
                "INSERT INTO audit_checkpoints (key_id, public_key, body, body_hash, "
                "prev_body_hash, signature) VALUES ('k', 'p', '{}', 'h', '', 's')"
            )
        )
        with pytest.raises(DBAPIError, match="append-only"):
            conn.execute(text(statement))
    finally:
        tx.rollback()
        conn.close()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_chain SET payload = '{}'::jsonb",
        "DELETE FROM audit_chain",
        "TRUNCATE audit_chain",
        "INSERT INTO audit_chain (source_table, source_id, event, payload, seq, "
        "prev_hash, event_hash) VALUES ('approval_actions', 'x', 'insert', '{}', 0, '', '')",
        "UPDATE audit_checkpoints SET signature = ''",
        "DELETE FROM audit_checkpoints",
        "TRUNCATE audit_checkpoints",
    ],
)
def test_app_role_cannot_rewrite_the_chain(audit_db, statement):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        conn.execute(text("SET LOCAL ROLE vigil_app"))
        with pytest.raises(DBAPIError, match="permission denied"):
            conn.execute(text(statement))
    finally:
        tx.rollback()
        conn.close()


def test_app_role_writes_are_chained_through_the_trigger(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        conn.execute(text("SET LOCAL ROLE vigil_app"))
        insert_action(conn, "action-audit-app-role")
        assert conn.execute(text("SELECT count(*) FROM audit_chain")).scalar() > 0
        assert [r.event for r in _chain_rows(conn, "action-audit-app-role")] == [
            "insert"
        ]
        assert walk_audit_chain(conn).ok
    finally:
        tx.rollback()
        conn.close()


def test_capture_function_refuses_other_tables(audit_db):
    # Anyone with CREATE on the schema could otherwise chain rows at will.
    conn, tx = _rolled_back(audit_db.engine)
    try:
        conn.execute(text("SET LOCAL ROLE vigil_app"))
        conn.execute(text("CREATE TABLE audit_forgery (id text)"))
        conn.execute(
            text(
                "CREATE TRIGGER forge AFTER INSERT ON audit_forgery FOR EACH ROW "
                "EXECUTE FUNCTION audit_chain_capture('id')"
            )
        )
        with pytest.raises(DBAPIError, match="not an audited table"):
            conn.execute(text("INSERT INTO audit_forgery VALUES ('x')"))
    finally:
        tx.rollback()
        conn.close()


# --- tamper detection ----------------------------------------------------------


def test_modified_payload_is_detected(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-tamper")
        seq = _chain_rows(conn, "action-audit-tamper")[0].seq
        assert walk_audit_chain(conn).ok
        _tamper(conn)
        conn.execute(
            text(
                "UPDATE audit_chain SET payload = jsonb_set(payload, '{row,target}', "
                "'\"198.51.100.1\"') WHERE seq = :s"
            ),
            {"s": seq},
        )
        report = walk_audit_chain(conn)
        assert [(b.reason, b.seq) for b in report.breaks] == [("hash", seq)]
    finally:
        tx.rollback()
        conn.close()


def test_modified_metadata_is_detected(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-meta")
        seq = _chain_rows(conn, "action-audit-meta")[0].seq
        _tamper(conn)
        conn.execute(
            text("UPDATE audit_chain SET event = 'snapshot' WHERE seq = :s"), {"s": seq}
        )
        assert [b.reason for b in walk_audit_chain(conn).breaks] == ["hash"]
    finally:
        tx.rollback()
        conn.close()


def test_deleted_row_is_detected(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-del-1")
        insert_action(conn, "action-audit-del-2")
        seq = _chain_rows(conn, "action-audit-del-1")[0].seq
        _tamper(conn)
        conn.execute(text("DELETE FROM audit_chain WHERE seq = :s"), {"s": seq})
        report = walk_audit_chain(conn)
        assert [(b.reason, b.seq) for b in report.breaks] == [("gap", seq + 1)]
    finally:
        tx.rollback()
        conn.close()


def test_reordered_rows_are_detected(audit_db):
    # Swapping two rows' positions: seq is inside the hashed text, so a moved
    # row no longer matches its event_hash and the links no longer follow.
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-order-1")
        insert_action(conn, "action-audit-order-2")
        a = _chain_rows(conn, "action-audit-order-1")[0].seq
        b = _chain_rows(conn, "action-audit-order-2")[0].seq
        assert walk_audit_chain(conn).ok
        _tamper(conn)
        parked = 10**12
        for frm, to in ((a, parked), (b, a), (parked, b)):
            conn.execute(
                text(
                    "UPDATE audit_chain SET seq = :to "
                    "WHERE seq = :frm"
                ),
                {"frm": frm, "to": to},
            )
        report = walk_audit_chain(conn)
        assert [found.seq for found in report.breaks] == [a]
        assert report.breaks[0].reason in {"prev_hash", "hash"}
    finally:
        tx.rollback()
        conn.close()


def test_rehashed_rewrite_breaks_the_link(audit_db):
    # Recomputing the tampered row's own hash is not enough: the next row's
    # prev_hash still names the old one.
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-rehash-1")
        insert_action(conn, "action-audit-rehash-2")
        seq = _chain_rows(conn, "action-audit-rehash-1")[0].seq
        _tamper(conn)
        conn.execute(
            text(
                "UPDATE audit_chain SET payload = '{}'::jsonb, event_hash = "
                "audit_chain_hash(prev_hash, tenant_id, seq, source_table, source_id, "
                "event, '{}'::jsonb, created_at) WHERE seq = :s"
            ),
            {"s": seq},
        )
        report = walk_audit_chain(conn)
        assert [(b.reason, b.seq) for b in report.breaks] == [("prev_hash", seq + 1)]
    finally:
        tx.rollback()
        conn.close()


def test_source_tampering_is_detected(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-src")
        assert check_sources(conn).ok
        _tamper(conn)
        conn.execute(
            text(
                "UPDATE approval_actions SET approved_by = 'mallory' "
                "WHERE action_id = 'action-audit-src'"
            )
        )
        [found] = check_sources(conn).breaks
        assert found.reason == "source_modified"
        assert "action-audit-src" in found.scope
    finally:
        tx.rollback()
        conn.close()


@pytest.mark.parametrize(
    "statement, reason",
    [
        ("DELETE FROM approval_actions WHERE action_id = :id", "source_deleted"),
        (
            "INSERT INTO approval_actions (action_id, action_type, title, description, "
            "target, reason, created_by, status) "
            "VALUES (:id || '-ghost', 'block_ip', 't', 'd', 'x', 'r', 'm', 'approved')",
            "unchained",
        ),
    ],
)
def test_source_rows_outside_the_chain_are_detected(audit_db, statement, reason):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-gone")
        _tamper(conn)
        conn.execute(text(statement), {"id": "action-audit-gone"})
        breaks = check_sources(conn).breaks
        assert [b.reason for b in breaks] == [reason]
    finally:
        tx.rollback()
        conn.close()


def test_dropped_triggers_are_reported_and_reattached(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        conn.execute(text("DROP TRIGGER audit_chain_capture ON case_audit_logs"))
        insert_audit_log(conn, "case-audit-while-off")
        reasons = {b.reason for b in check_sources(conn).breaks}
        assert reasons == {"triggers_missing", "unchained"}
        # Reattaching records a marker and does not launder the gap.
        assert attach_table(conn, "case_audit_logs") == "reinstall"
        assert attach_table(conn, "case_audit_logs") is None
        assert [b.reason for b in check_sources(conn).breaks] == ["unchained"]
        assert walk_audit_chain(conn).ok
    finally:
        tx.rollback()
        conn.close()


# --- schema setup paths ----------------------------------------------------------


def test_init_database_path_attaches_case_audit_logs(audit_db):
    # Compose / Helm: the SQL ran before create_all built case_audit_logs, so
    # the trigger comes from init_database(). Committed, then restored.
    engine = audit_db.engine
    with engine.begin() as conn:
        for name in (
            "audit_chain_capture",
            "audit_chain_capture_update",
            "audit_chain_capture_truncate",
        ):
            conn.execute(text(f"DROP TRIGGER {name} ON case_audit_logs"))
    connection_module._audit_chain_checked.clear()
    connection_module._ensure_audit_chain(engine)
    with engine.connect() as conn:
        assert triggers_attached(conn, "case_audit_logs")
        last = conn.execute(
            text(
                "SELECT event FROM audit_chain WHERE source_table = 'case_audit_logs' "
                "ORDER BY seq DESC LIMIT 1"
            )
        ).scalar()
        assert last == "reinstall"


def _migration_step():
    spec = importlib.util.spec_from_file_location(
        "vigil_migrate_schema_w110", REPO / "scripts" / "migrate_schema.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.attach_audit_chain


def test_migration_step_creates_and_attaches_and_is_rerunnable(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        for name in (
            "audit_chain_capture",
            "audit_chain_capture_update",
            "audit_chain_capture_truncate",
        ):
            conn.execute(text(f"DROP TRIGGER {name} ON approval_actions"))
        conn.execute(text("DROP FUNCTION audit_chain_attach(regclass, text)"))
        step = _migration_step()
        for _ in range(2):
            step(conn)
        assert triggers_attached(conn, "approval_actions")
        assert triggers_attached(conn, "case_audit_logs")
        assert walk_audit_chain(conn).ok
        # And the init SQL itself runs again cleanly.
        run_sql_file(conn, "51_audit_chain.sql")
    finally:
        tx.rollback()
        conn.close()


# --- concurrency -----------------------------------------------------------------


def _waiting_on_lock(engine, pid) -> bool:
    with engine.connect() as conn:
        return (
            conn.execute(
                text("SELECT wait_event_type FROM pg_stat_activity WHERE pid = :p"),
                {"p": pid},
            ).scalar()
            == "Lock"
        )


def test_a_second_writer_waits_for_the_first(audit_db):
    engine = audit_db.engine
    first = engine.connect()
    tx = first.begin()
    errors: list = []
    second_pid: list = []

    def second_writer():
        try:
            with engine.begin() as conn:
                second_pid.append(
                    conn.execute(text("SELECT pg_backend_pid()")).scalar()
                )
                insert_action(conn, "action-audit-conc-b")
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    try:
        insert_action(first, "action-audit-conc-a")
        worker = threading.Thread(target=second_writer)
        worker.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if second_pid and _waiting_on_lock(engine, second_pid[0]):
                break
            time.sleep(0.05)
        else:
            pytest.fail(f"the second writer never waited for the first: {errors}")
        tx.commit()
    finally:
        if tx.is_active:
            tx.rollback()
        first.close()
    worker.join(timeout=10)
    assert not errors
    with engine.connect() as conn:
        a = _chain_rows(conn, "action-audit-conc-a")[0].seq
        b = _chain_rows(conn, "action-audit-conc-b")[0].seq
        assert b == a + 1
        assert walk_audit_chain(conn).ok


def test_concurrent_writers_keep_one_chain(audit_db):
    engine = audit_db.engine
    writers, per_writer = 4, 15
    start = threading.Barrier(writers)
    errors: list = []

    with engine.connect() as conn:
        before = conn.execute(text("SELECT count(*) FROM audit_chain")).scalar()

    def write(n):
        try:
            start.wait()
            for i in range(per_writer):
                with engine.begin() as conn:
                    insert_action(conn, f"action-audit-many-{n}-{i}")
                    if i % 3 == 0:
                        conn.execute(
                            text(
                                "UPDATE approval_actions SET status = 'approved', "
                                "approved_by = 'w' WHERE action_id = :a"
                            ),
                            {"a": f"action-audit-many-{n}-{i}"},
                        )
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=write, args=(n,)) for n in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors
    with engine.connect() as conn:
        after = conn.execute(text("SELECT count(*) FROM audit_chain")).scalar()
        assert after - before == writers * per_writer + writers * 5
        seqs = (
            conn.execute(
                text(
                    "SELECT seq FROM audit_chain ORDER BY seq"
                )
            )
            .scalars()
            .all()
        )
        assert seqs == list(range(1, len(seqs) + 1))
        report = walk_audit_chain(conn)
        assert report.ok, report.breaks
        assert check_sources(conn).ok


def test_tenants_share_the_one_chain(audit_db):
    # tenant_id is hashed into each row but does not start a chain of its own:
    # rows of different tenants take consecutive seqs and link to each other.
    conn, tx = _rolled_back(audit_db.engine)
    try:
        for tenant in ("tenant-a", "tenant-b", "tenant-a"):
            conn.execute(
                text(
                    "INSERT INTO audit_chain (tenant_id, source_table, source_id, "
                    "event, payload, seq, prev_hash, event_hash) VALUES "
                    "(:t, 'approval_actions', 'x', 'note', '{}', 0, '', '')"
                ),
                {"t": tenant},
            )
        rows = conn.execute(
            text(
                "SELECT tenant_id, seq, prev_hash, event_hash FROM audit_chain "
                "ORDER BY seq DESC LIMIT 3"
            )
        ).all()[::-1]
        assert [r.tenant_id for r in rows] == ["tenant-a", "tenant-b", "tenant-a"]
        first = rows[0].seq
        assert [r.seq for r in rows] == [first, first + 1, first + 2]
        assert rows[1].prev_hash == rows[0].event_hash
        assert rows[2].prev_hash == rows[1].event_hash
        assert walk_audit_chain(conn).ok
    finally:
        tx.rollback()
        conn.close()


# --- agent ledger ----------------------------------------------------------------


def test_agent_events_walk_matches_the_sql_formula(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        run = "00000000-0000-4000-8000-0000000a0d17"
        for seq in (1, 2, 3):
            conn.execute(
                text(
                    "INSERT INTO agent_events (run_id, seq, run_kind, kind, payload, "
                    "schema_version) VALUES (:r, :s, 'hunt', 'note', "
                    "CAST(:p AS jsonb), 1)"
                ),
                {"r": run, "s": seq, "p": f'{{"n": {seq}, "text": "é"}}'},
            )
        assert walk_agent_events(conn, run).ok
        conn.execute(
            text(
                "UPDATE agent_events SET payload = '{\"n\": 9}' "
                "WHERE run_id = :r AND seq = 2"
            ),
            {"r": run},
        )
        [found] = walk_agent_events(conn, run).breaks
        assert (found.reason, found.seq) == ("payload", 2)
    finally:
        tx.rollback()
        conn.close()
