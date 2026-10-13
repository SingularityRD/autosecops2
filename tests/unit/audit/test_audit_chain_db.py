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
from core.storage.audit_chain import attach_table, triggers_attached, triggers_current
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
    """A transaction the test rolls back, with the capture triggers immediate.

    The capture triggers are deferred to commit, and these transactions never
    commit: IMMEDIATE fires each one at the end of its statement so the test
    can read the chain rows it wrote. The deferred behaviour itself is
    covered by the "deferred to commit" tests below.
    """
    conn = engine.connect()
    tx = conn.begin()
    conn.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
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
                text("UPDATE audit_chain SET seq = :to " "WHERE seq = :frm"),
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


def _untamper(conn):
    conn.execute(text("SET LOCAL session_replication_role = origin"))


@pytest.mark.parametrize(
    "follow_up",
    [
        "UPDATE approval_actions SET status = 'executed' WHERE action_id = :id",
        "UPDATE approval_actions SET approved_by = 'alice' WHERE action_id = :id",
        "DELETE FROM approval_actions WHERE action_id = :id",
    ],
    ids=["update-other-column", "update-same-column", "delete"],
)
def test_bypassed_change_hidden_by_a_later_chained_change_is_detected(
    audit_db, follow_up
):
    """The verifier's scenario: an edit under replica role, then a normal one.

    The normal UPDATE/DELETE moves the latest chain row past the bypassed
    edit, so the source check alone sees nothing; the history check does.
    """
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-hidden")
        _tamper(conn)
        conn.execute(
            text(
                "UPDATE approval_actions SET approved_by = 'mallory' "
                "WHERE action_id = 'action-audit-hidden'"
            )
        )
        _untamper(conn)
        conn.execute(text(follow_up), {"id": "action-audit-hidden"})
        assert walk_audit_chain(conn).ok
        [found] = check_sources(conn).breaks
        assert found.reason == "history_modified"
        assert "action-audit-hidden" in found.scope
        assert found.seq is not None
    finally:
        tx.rollback()
        conn.close()


@pytest.mark.parametrize(
    "follow_up",
    [
        "UPDATE approval_actions SET status = 'executed' WHERE action_id = :id",
        "DELETE FROM approval_actions WHERE action_id = :id",
    ],
    ids=["update", "delete"],
)
def test_bypassed_insert_hidden_by_a_later_chained_change_is_detected(
    audit_db, follow_up
):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        _tamper(conn)
        insert_action(conn, "action-audit-ghost-insert")
        _untamper(conn)
        conn.execute(text(follow_up), {"id": "action-audit-ghost-insert"})
        [found] = check_sources(conn).breaks
        assert found.reason == "history_unchained"
    finally:
        tx.rollback()
        conn.close()


def test_chained_history_alone_is_clean(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-clean")
        for status in ("approved", "executed"):
            conn.execute(
                text(
                    "UPDATE approval_actions SET status = :s "
                    "WHERE action_id = 'action-audit-clean'"
                ),
                {"s": status},
            )
        conn.execute(
            text("DELETE FROM approval_actions WHERE action_id = 'action-audit-clean'")
        )
        insert_action(conn, "action-audit-clean")
        conn.execute(
            text("DELETE FROM approval_actions WHERE action_id = 'action-audit-clean'")
        )
        assert check_sources(conn).ok
    finally:
        tx.rollback()
        conn.close()


def _reinsert_audit_log(conn, audit_id: int, entity_id: str) -> None:
    conn.execute(
        text(
            "INSERT INTO case_audit_logs "
            "(audit_id, entity_type, entity_id, action, changed_by) "
            "VALUES (:a, 'case', :e, 'update', 'analyst')"
        ),
        {"a": audit_id, "e": entity_id},
    )


def test_bypassed_delete_then_chained_reinsert_is_detected_approval(audit_db):
    """Round 5: DELETE under replica, then a normal INSERT of the same key.

    The source row matches its (new) latest chain row, so only the history
    check can see that the earlier chain row was never closed by a delete.
    """
    conn, tx = _rolled_back(audit_db.engine)
    try:
        insert_action(conn, "action-audit-redo")
        _tamper(conn)
        conn.execute(
            text("DELETE FROM approval_actions WHERE action_id = 'action-audit-redo'")
        )
        _untamper(conn)
        insert_action(conn, "action-audit-redo", approved_by="mallory")
        assert walk_audit_chain(conn).ok
        [found] = check_sources(conn).breaks
        assert found.reason == "history_deleted"
        assert "action-audit-redo" in found.scope
        assert found.seq is not None
    finally:
        tx.rollback()
        conn.close()


def test_bypassed_delete_then_chained_reinsert_is_detected_case_log(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        audit_id = insert_audit_log(conn, "case-audit-redo")
        _tamper(conn)
        conn.execute(
            text("DELETE FROM case_audit_logs WHERE audit_id = :a"), {"a": audit_id}
        )
        _untamper(conn)
        _reinsert_audit_log(conn, audit_id, "case-audit-redo-forged")
        [found] = check_sources(conn).breaks
        assert found.reason == "history_deleted"
        assert f"audit_id={audit_id}" in found.scope
    finally:
        tx.rollback()
        conn.close()


@pytest.mark.parametrize(
    "table, key",
    [("case_audit_logs", "audit_id"), ("approval_actions", "action_id")],
)
def test_bypassed_truncate_then_chained_reinserts_are_detected(audit_db, table, key):
    """TRUNCATE under replica writes no marker; the rows then reappear."""
    conn, tx = _rolled_back(audit_db.engine)
    try:
        if table == "case_audit_logs":
            insert_audit_log(conn, "case-audit-retrunc")
        else:
            insert_action(conn, "action-audit-retrunc")
        conn.execute(
            text(f"CREATE TEMP TABLE saved ON COMMIT DROP AS SELECT * FROM {table}")
        )
        _tamper(conn)
        conn.execute(text(f"TRUNCATE {table}"))
        _untamper(conn)
        conn.execute(text(f"INSERT INTO {table} SELECT * FROM saved"))
        breaks = check_sources(conn).breaks
        assert [b.reason for b in breaks] == ["history_deleted"]
        assert f"{key}=" in breaks[0].scope
    finally:
        tx.rollback()
        conn.close()


def test_chained_truncate_then_reinsert_is_clean(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        conn.execute(
            text(
                "CREATE TEMP TABLE saved ON COMMIT DROP AS "
                "SELECT * FROM case_audit_logs"
            )
        )
        conn.execute(text("TRUNCATE case_audit_logs"))
        conn.execute(text("INSERT INTO case_audit_logs SELECT * FROM saved"))
        assert check_sources(conn).ok
    finally:
        tx.rollback()
        conn.close()


@pytest.mark.parametrize(
    "table, statement, column",
    [
        (
            "approval_actions",
            "ALTER TABLE approval_actions DROP COLUMN reason",
            "reason",
        ),
        (
            "case_audit_logs",
            "ALTER TABLE case_audit_logs RENAME COLUMN changed_by TO changed_by_x",
            "changed_by",
        ),
    ],
    ids=["drop", "rename"],
)
def test_column_missing_from_the_table_is_reported(audit_db, table, statement, column):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        assert check_sources(conn).ok
        conn.execute(text(statement))
        breaks = check_sources(conn).breaks
        assert [b.reason for b in breaks] == ["schema_column_missing"]
        assert breaks[0].chain == f"source:{table}"
        assert column in breaks[0].detail
    finally:
        tx.rollback()
        conn.close()


def test_added_column_is_not_a_break(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        conn.execute(text("ALTER TABLE approval_actions ADD COLUMN extra text"))
        assert check_sources(conn).ok
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
        # Chains the row now (the trigger is deferred to commit otherwise) and
        # so takes the chain lock until this transaction ends.
        first.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
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
            conn.execute(text("SELECT seq FROM audit_chain ORDER BY seq"))
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


# --- deferred to commit (Round 6) --------------------------------------------------


def test_chain_rows_are_written_at_commit(audit_db):
    engine = audit_db.engine
    writer = engine.connect()
    tx = writer.begin()
    try:
        insert_action(writer, "action-audit-deferred")
        # Not yet chained, not even for the writer, and no chain lock held.
        assert _chain_rows(writer, "action-audit-deferred") == []
        with engine.connect() as other:
            held = other.execute(
                text(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                    "AND pid = :p"
                ),
                {"p": writer.execute(text("SELECT pg_backend_pid()")).scalar()},
            ).scalar()
        assert held == 0
        tx.commit()
    finally:
        if tx.is_active:
            tx.rollback()
        writer.close()
    with engine.connect() as conn:
        assert [r.event for r in _chain_rows(conn, "action-audit-deferred")] == [
            "insert"
        ]
        assert walk_audit_chain(conn).ok
        assert check_sources(conn).ok


@pytest.fixture
def probe_row(audit_db):
    """A committed row in a scratch table both transactions lock."""
    with audit_db.engine.begin() as conn:
        conn.execute(text("CREATE TABLE audit_lock_probe (id int PRIMARY KEY)"))
        conn.execute(text("INSERT INTO audit_lock_probe VALUES (1)"))
    yield
    with audit_db.engine.begin() as conn:
        conn.execute(text("DROP TABLE audit_lock_probe"))


def _crossed_lock_orders(engine, tag: str, immediate: bool) -> list:
    """T1: audited write, then SELECT FOR UPDATE; T2: the reverse order.

    With the chain lock taken at the audited write (the triggers made
    immediate), T1 holds the chain lock and waits for T2's row lock while T2
    waits for the chain lock: Postgres' deadlock detector aborts one. With the
    lock taken at commit nobody waits on the chain lock while holding a row
    lock the other needs. Returns the errors either transaction raised.
    """
    errors: list = []
    t1 = engine.connect()
    t2 = engine.connect()
    tx1, tx2 = t1.begin(), t2.begin()
    for conn in (t1, t2):
        conn.execute(text("SET LOCAL lock_timeout = '30s'"))
        if immediate:
            conn.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
    t2_pid = t2.execute(text("SELECT pg_backend_pid()")).scalar()

    def second():
        try:
            insert_action(t2, f"action-audit-{tag}-t2")
            tx2.commit()
        except Exception as e:  # noqa: BLE001
            errors.append(e)
            tx2.rollback()

    try:
        insert_action(t1, f"action-audit-{tag}-t1")
        t2.execute(text("SELECT id FROM audit_lock_probe WHERE id = 1 FOR UPDATE"))
        worker = threading.Thread(target=second)
        worker.start()
        if immediate:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not _waiting_on_lock(engine, t2_pid):
                time.sleep(0.05)
        try:
            t1.execute(text("SELECT id FROM audit_lock_probe WHERE id = 1 FOR UPDATE"))
            tx1.commit()
        except Exception as e:  # noqa: BLE001
            errors.append(e)
        worker.join(timeout=60)
    finally:
        if tx1.is_active:
            tx1.rollback()
        if tx2.is_active:
            tx2.rollback()
        t1.close()
        t2.close()
    return errors


def test_crossed_row_and_chain_locks_do_not_deadlock(audit_db, probe_row):
    """Round 6 regression: the chain lock is taken at commit, after row locks."""
    engine = audit_db.engine
    errors = _crossed_lock_orders(engine, "xlock", immediate=False)
    assert errors == []
    with engine.connect() as conn:
        assert _chain_rows(conn, "action-audit-xlock-t1")
        assert _chain_rows(conn, "action-audit-xlock-t2")
        assert walk_audit_chain(conn).ok
        assert check_sources(conn).ok


def test_crossed_locks_deadlock_when_chained_immediately(audit_db, probe_row):
    """The hazard the deferral removes (and why app code must not SET
    CONSTRAINTS ALL IMMEDIATE around audited writes)."""
    errors = _crossed_lock_orders(audit_db.engine, "xlock-imm", immediate=True)
    assert len(errors) == 1
    assert "deadlock detected" in str(errors[0])


def test_truncate_marker_is_queued_until_commit(audit_db):
    conn = audit_db.engine.connect()
    tx = conn.begin()
    try:
        before = conn.execute(text("SELECT max(seq) FROM audit_chain")).scalar()
        conn.execute(text("TRUNCATE case_audit_logs"))
        assert conn.execute(text("SELECT max(seq) FROM audit_chain")).scalar() == before
        assert (
            conn.execute(text("SELECT count(*) FROM audit_chain_pending")).scalar()
            == 1
        )
        conn.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))  # what COMMIT runs
        last = conn.execute(
            text("SELECT source_table, event FROM audit_chain ORDER BY seq DESC LIMIT 1")
        ).one()
        assert tuple(last) == ("case_audit_logs", "truncate")
        assert (
            conn.execute(text("SELECT count(*) FROM audit_chain_pending")).scalar()
            == 0
        )
        assert check_sources(conn).ok
    finally:
        tx.rollback()
        conn.close()


def test_truncate_after_a_write_in_the_same_transaction_is_refused(audit_db):
    # Postgres refuses TRUNCATE of a table with pending (deferred) trigger
    # events: the documented cost of chaining at commit.
    conn = audit_db.engine.connect()
    tx = conn.begin()
    try:
        insert_audit_log(conn, "case-audit-then-truncate")
        with pytest.raises(DBAPIError, match="pending trigger events"):
            conn.execute(text("TRUNCATE case_audit_logs"))
    finally:
        tx.rollback()
        conn.close()


def test_app_role_cannot_touch_the_pending_queue(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        conn.execute(text("SET LOCAL ROLE vigil_app"))
        with pytest.raises(DBAPIError, match="permission denied"):
            conn.execute(
                text(
                    "INSERT INTO audit_chain_pending (source_table, event) "
                    "VALUES ('approval_actions', 'truncate')"
                )
            )
    finally:
        tx.rollback()
        conn.close()


@pytest.mark.parametrize(
    "mode, attached",
    [("REPLICA", False), ("ALWAYS", True), ("", True)],
    ids=["replica-only", "always", "origin"],
)
def test_replica_only_or_disabled_triggers_are_not_attached(audit_db, mode, attached):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        conn.execute(
            text(f"ALTER TABLE approval_actions ENABLE {mode} TRIGGER audit_chain_capture")
        )
        assert triggers_attached(conn, "approval_actions") is attached
        reasons = [b.reason for b in check_sources(conn).breaks]
        assert ("triggers_missing" in reasons) is (not attached)
        conn.execute(
            text("ALTER TABLE approval_actions DISABLE TRIGGER audit_chain_capture")
        )
        assert not triggers_attached(conn, "approval_actions")
        assert not triggers_current(conn, "approval_actions")
    finally:
        tx.rollback()
        conn.close()


def test_replica_only_trigger_is_reattached(audit_db):
    # audit_chain_attach() used to accept 'R' as attached and skip the table.
    conn, tx = _rolled_back(audit_db.engine)
    try:
        conn.execute(
            text(
                "ALTER TABLE approval_actions ENABLE REPLICA TRIGGER "
                "audit_chain_capture_update"
            )
        )
        assert attach_table(conn, "approval_actions") == "reinstall"
        assert triggers_current(conn, "approval_actions")
    finally:
        tx.rollback()
        conn.close()


def test_immediate_triggers_of_an_earlier_version_are_upgraded(audit_db):
    conn, tx = _rolled_back(audit_db.engine)
    try:
        for name in ("audit_chain_capture", "audit_chain_capture_update"):
            conn.execute(text(f"DROP TRIGGER {name} ON approval_actions"))
        conn.execute(
            text(
                "CREATE TRIGGER audit_chain_capture AFTER INSERT OR DELETE ON "
                "approval_actions FOR EACH ROW "
                "EXECUTE FUNCTION audit_chain_capture('action_id')"
            )
        )
        conn.execute(
            text(
                "CREATE TRIGGER audit_chain_capture_update AFTER UPDATE ON "
                "approval_actions FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) "
                "EXECUTE FUNCTION audit_chain_capture('action_id')"
            )
        )
        assert triggers_attached(conn, "approval_actions")
        assert not triggers_current(conn, "approval_actions")
        assert attach_table(conn, "approval_actions") == "reinstall"
        assert triggers_current(conn, "approval_actions")
        assert attach_table(conn, "approval_actions") is None
        assert check_sources(conn).ok
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
