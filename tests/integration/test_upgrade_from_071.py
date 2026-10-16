"""Vigil 0.7.1 -> AutoSecOps 2.0: restore a 0.7.1 database, upgrade it, compare (W4.5).

tests/fixtures/upgrade/vigil-0.7.1.sql is a 0.7.1 database (upstream release
tree, provisioned as its Compose stack did, synthetic rows from
seed_0_7_1.sql). It is restored into a scratch database and upgraded with
scripts/upgrade_database.py. Then:

  * the columns equal core/storage/schema.snapshot.json, and equal a database
    a fresh install of this checkout builds -- with defaults, index names,
    constraint names, triggers and functions;
  * every 0.7.1 row is still there, the data corrections ran (the stub
    isolation is failed, unrated findings are marked), and the agent ledger's
    hash chain still verifies;
  * a second run changes nothing;
  * the backup the run took restores to the 0.7.1 database;
  * dry-run writes nothing, and preflight refuses a newer, an empty, or a
    no-backup-decision run.

Scratch databases are CREATEd and DROPped on the POSTGRES_* server, loopback
only. With UPGRADE_TEST_REQUIRED=1 (the CI job) a missing server fails
instead of skipping.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from scripts import upgrade_database as up  # noqa: E402
from scripts.generate_api_v1_contract import serialize  # noqa: E402
from scripts.generate_schema_snapshot import (  # noqa: E402
    _admin_engine,
    _apply_init_sql,
    _init_on,
    _params,
    _quote_ident,
    _url,
    column_listing,
    postgres_skip_reason,
)

pytestmark = [pytest.mark.integration, pytest.mark.database]

FIXTURE = REPO / "tests" / "fixtures" / "upgrade" / "vigil-0.7.1.sql"
LEDGER_RUN = "5f0c4a52-6d2e-4f43-9a63-0a0000000001"

# Same check core/backup/restore.py runs: each row's prev_hash is the previous
# row's event_hash and event_hash is recomputed from it.
BROKEN_LEDGER_ROWS = """
SELECT count(*) FROM (
    SELECT prev_hash, event_hash,
           coalesce(lag(event_hash) OVER (PARTITION BY run_id ORDER BY seq), '') AS expected_prev,
           agent_event_hash(prev_hash, payload) AS expected_hash
    FROM agent_events
) chain
WHERE prev_hash IS DISTINCT FROM expected_prev OR event_hash IS DISTINCT FROM expected_hash
"""


def _skip_or_fail(reason: str):
    if os.getenv("UPGRADE_TEST_REQUIRED") == "1":
        pytest.fail(reason)
    pytest.skip(reason)


def _url_str(name: str) -> str:
    return _url(name).render_as_string(hide_password=False)


def _pg_env(name: str) -> dict:
    user, password, host, port = _params()
    env = os.environ.copy()
    env.update({"PGHOST": host, "PGPORT": port, "PGUSER": user,
                "PGPASSWORD": password, "PGDATABASE": name})
    return env


def _engine(name: str):
    return create_engine(_url(name), connect_args={"connect_timeout": 5})


def _listing(name: str) -> dict:
    engine = _engine(name)
    try:
        with engine.connect() as conn:
            return column_listing(conn)
    finally:
        engine.dispose()


def _query(name: str, sql: str, **params):
    engine = _engine(name)
    try:
        with engine.connect() as conn:
            return conn.execute(text(sql), params).all()
    finally:
        engine.dispose()


def _catalog(name: str) -> dict:
    """Schema facts beyond the column listing. Constraint definitions are left
    out: pg_dump/restore re-deparses an IN-list CHECK into an equivalent but
    differently spelled expression."""
    q = {
        "defaults": """
            SELECT table_name, column_name, coalesce(column_default, '')
            FROM information_schema.columns WHERE table_schema = 'public' ORDER BY 1, 2""",
        "indexes": """
            SELECT tablename, indexname FROM pg_indexes
            WHERE schemaname = 'public' ORDER BY 1, 2""",
        "constraints": """
            SELECT conrelid::regclass::text, conname, contype::text
            FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
            WHERE n.nspname = 'public' ORDER BY 1, 2""",
        "triggers": """
            SELECT event_object_table, trigger_name, event_manipulation
            FROM information_schema.triggers WHERE trigger_schema = 'public' ORDER BY 1, 2, 3""",
        "functions": """
            SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.prokind = 'f'
              AND NOT EXISTS (SELECT 1 FROM pg_depend d
                              WHERE d.objid = p.oid AND d.deptype = 'e')
            ORDER BY 1""",
    }
    return {k: [tuple(r) for r in _query(name, sql)] for k, sql in q.items()}


def _row_counts(name: str, tables) -> dict:
    return {t: _query(name, f"SELECT count(*) FROM {_quote_ident(t)}")[0][0] for t in tables}


def _data_digest(name: str) -> dict:
    """md5 of every table's rows; system_config without the run's own history row."""
    digest = {}
    for table in sorted(_listing(name)):
        where = " WHERE t.key <> 'upgrade.history'" if table == "system_config" else ""
        cols = "t.key, t.value" if table == "system_config" else "t"
        digest[table] = _query(
            name,
            f"SELECT md5(coalesce(string_agg(({cols})::text, '|' ORDER BY ({cols})::text), '')) "
            f"FROM {_quote_ident(table)} t{where}",
        )[0][0]
    return digest


class _Scratch:
    def __init__(self):
        self.admin = _admin_engine()
        self.names: list[str] = []
        self.tag = f"{os.getpid()}_{secrets.token_hex(3)}"

    def create(self, suffix: str, template: str | None = None) -> str:
        name = f"vigil_upg_{suffix}_{self.tag}"
        with self.admin.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {_quote_ident(name)} WITH (FORCE)"))
            tmpl = f" TEMPLATE {_quote_ident(template)}" if template else ""
            conn.execute(text(f"CREATE DATABASE {_quote_ident(name)}{tmpl}"))
        self.names.append(name)
        return name

    def drop_all(self):
        with self.admin.connect() as conn:
            for name in self.names:
                conn.execute(text(f"DROP DATABASE IF EXISTS {_quote_ident(name)} WITH (FORCE)"))
        self.admin.dispose()


@pytest.fixture(scope="module")
def dbs(tmp_path_factory):
    reason = postgres_skip_reason()
    if reason:
        _skip_or_fail(reason)
    for tool in ("psql", "pg_dump", "pg_restore"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            _skip_or_fail(f"{tool} is required")
    scratch = _Scratch()
    try:
        base = scratch.create("base")
        restored = subprocess.run(
            ["psql", "--no-password", "-q", "-v", "ON_ERROR_STOP=1", "-f", str(FIXTURE)],
            env=_pg_env(base), capture_output=True, text=True,
        )
        assert restored.returncode == 0, restored.stderr[-2000:]
        names = {
            "base": base,
            "up": scratch.create("up", template=base),
            "dry": scratch.create("dry", template=base),
            "refuse": scratch.create("refuse", template=base),
        }
        backup = tmp_path_factory.mktemp("upgrade") / "pre-upgrade.dump"
        report = up.upgrade(_url_str(names["up"]), backup=backup)
        yield {"names": names, "report": report, "backup": backup, "scratch": scratch}
    finally:
        scratch.drop_all()


def test_fixture_is_a_071_database(dbs):
    base = dbs["names"]["base"]
    assert _query(base, "SELECT value->>'version' FROM system_config WHERE key='schema_version'") == [("0.7.1",)]
    listing = _listing(base)
    assert "service_account" not in listing["users"]
    assert "skill_reads" not in listing


def test_upgrade_ran_every_step(dbs):
    report = dbs["report"]
    assert not report.failed, [c.line() for c in report.checks if c.status == "FAIL"]
    assert report.steps == ["backup", "sql-1", "orm", "migrate", "sql-2", "verify", "stamp"]
    assert report.plan["pending_files"] == [p.name for p in up.pending_init_files()]


def test_upgraded_schema_equals_committed_snapshot(dbs):
    actual = serialize(_listing(dbs["names"]["up"]))
    assert actual == up.SNAPSHOT.read_text(encoding="utf-8"), (
        "An upgraded 0.7.1 database does not match core/storage/schema.snapshot.json"
    )


def test_upgraded_schema_equals_fresh_install(dbs):
    scratch = dbs["scratch"]
    fresh = scratch.create("fresh")
    engine = _engine(fresh)
    try:
        _apply_init_sql(fresh)
        _init_on(engine)
        _apply_init_sql(fresh)
    finally:
        engine.dispose()
    upgraded = dbs["names"]["up"]
    assert _listing(upgraded) == _listing(fresh)
    want, got = _catalog(fresh), _catalog(upgraded)
    for key in want:
        missing = sorted(set(want[key]) - set(got[key]))
        extra = sorted(set(got[key]) - set(want[key]))
        assert not missing and not extra, f"{key}: missing {missing[:10]}, extra {extra[:10]}"


def test_every_071_row_survived(dbs):
    base, upgraded = dbs["names"]["base"], dbs["names"]["up"]
    tables = sorted(_listing(base))
    before, after = _row_counts(base, tables), _row_counts(upgraded, tables)
    # The run adds its upgrade.history row, and 63_approval_default_assist.sql
    # audits moving the untouched Act seed to Assist (W0.32); nothing else may
    # appear or vanish.
    after["system_config"] -= 1
    after["config_audit_log"] -= 1
    assert after == before


def test_seeded_rows_and_data_corrections(dbs):
    db = dbs["names"]["up"]
    assert _query(db, "SELECT username, role_id, service_account FROM users "
                      "WHERE user_id LIKE 'user-upg-%' ORDER BY 1") == [
        ("upg.admin", "role-admin", False), ("upg.analyst", "role-analyst", False)]
    assert _query(db, "SELECT finding_id, bulk_imported FROM findings ORDER BY 1") == [
        ("f-upg-0001", False), ("f-upg-0002", False), ("f-upg-0003", True), ("f-upg-0004", False)]
    assert _query(db, "SELECT case_id, finding_id FROM case_findings ORDER BY 1, 2") == [
        ("case-upg-0001", "f-upg-0001"), ("case-upg-0001", "f-upg-0002"),
        ("case-upg-0002", "f-upg-0004")]
    actions = {r[0]: r[1:] for r in _query(
        db, "SELECT action_id, status, execution_result FROM approval_actions")}
    assert actions["act-upg-0001"] == ("executed", {"message": "blocked"})
    # The pre-#1276 stub's isolation never contained the host.
    assert actions["act-upg-0002"][0] == "failed"
    assert actions["act-upg-0002"][1]["message"] == "Host isolated (MOCK)"
    assert "error" in actions["act-upg-0002"][1]
    assert actions["act-upg-0003"] == ("pending", None)
    assert _query(db, "SELECT count(*) FROM chat_messages WHERE conversation_id='conv-upg-0001'") == [(2,)]
    assert _query(db, "SELECT value FROM system_config WHERE key='upgrade_fixture.marker'") == [
        ({"from": "0.7.1"},)]
    perms = dict(_query(db, "SELECT role_id, permissions ? 'medic.read' FROM roles"))
    assert perms["role-admin"] and perms["role-manager"] and not perms["role-viewer"]
    # Nobody chose the 0.7.1 Act seed, so the upgrade makes it Assist (W0.32).
    assert _query(db, "SELECT value FROM system_config "
                      "WHERE key='approval.force_manual_approval'") == [({"enabled": True},)]
    assert _query(db, "SELECT changed_by FROM config_audit_log "
                      "WHERE config_key='approval.force_manual_approval'") == [
        ("system:w0.32-default",)]


def test_ledger_chain_still_verifies(dbs):
    db = dbs["names"]["up"]
    assert _query(db, "SELECT count(*) FROM agent_events WHERE run_id = :r", r=LEDGER_RUN) == [(3,)]
    assert _query(db, BROKEN_LEDGER_ROWS) == [(0,)]


def test_stamp_and_history(dbs):
    db = dbs["names"]["up"]
    target = up.target_version()
    assert _query(db, "SELECT value->>'version' FROM system_config WHERE key='schema_version'") == [(target,)]
    (history,) = _query(db, "SELECT value FROM system_config WHERE key='upgrade.history'")[0]
    assert history[-1]["from"] == "0.7.1" and history[-1]["to"] == target
    assert history[-1]["files"] == [p.name for p in up.pending_init_files()]


def test_rerun_changes_nothing(dbs):
    db = dbs["names"]["up"]
    listing, catalog, digest = _listing(db), _catalog(db), _data_digest(db)
    report = up.upgrade(_url_str(db), no_backup=True)
    assert report.steps == ["sql-1", "orm", "migrate", "sql-2", "verify", "stamp"]
    assert report.plan["deferred"] == []
    assert _listing(db) == listing
    assert _catalog(db) == catalog
    assert _data_digest(db) == digest
    (history,) = _query(db, "SELECT value FROM system_config WHERE key='upgrade.history'")[0]
    assert len(history) == 2


def test_backup_restores_the_071_database(dbs):
    backup = dbs["backup"]
    assert backup.is_file() and backup.stat().st_size > 0
    # Round 5: the real pg_dump run leaves the dump owner-only.
    assert backup.stat().st_mode & 0o777 == 0o600
    target = dbs["scratch"].create("rollback")
    restored = subprocess.run(
        ["pg_restore", "--no-password", "--no-owner", "--exit-on-error", "-d", target, str(backup)],
        env=_pg_env(target), capture_output=True, text=True,
    )
    assert restored.returncode == 0, restored.stderr[-2000:]
    base = dbs["names"]["base"]
    assert _listing(target) == _listing(base)
    assert _data_digest(target) == _data_digest(base)


def test_dry_run_writes_nothing(dbs):
    db = dbs["names"]["dry"]
    listing, digest = _listing(db), _data_digest(db)
    report = up.upgrade(_url_str(db), dry_run=True)
    assert not report.failed
    assert report.steps == []
    assert report.plan["pending_files"] == [p.name for p in up.pending_init_files()]
    assert "users.service_account" in report.plan["delta"]["missing_columns"]
    assert _listing(db) == listing
    assert _data_digest(db) == digest


def _status(report, name):
    return {c.name: c.status for c in report.checks}.get(name)


def test_apply_without_a_backup_decision_is_refused(dbs):
    db = dbs["names"]["refuse"]
    listing = _listing(db)
    report = up.upgrade(_url_str(db))
    assert _status(report, "backup") == "FAIL" and report.steps == []
    assert _listing(db) == listing


def test_newer_database_is_refused(dbs):
    db = dbs["names"]["refuse"]
    engine = _engine(db)
    try:
        with engine.begin() as conn:
            conn.execute(text("UPDATE system_config SET value = CAST(:v AS jsonb) "
                              "WHERE key = 'schema_version'"),
                         {"v": json.dumps({"version": "99.0.0"})})
    finally:
        engine.dispose()
    listing = _listing(db)
    report = up.upgrade(_url_str(db), no_backup=True)
    assert _status(report, "source-version") == "FAIL" and report.steps == []
    assert _listing(db) == listing


def test_empty_database_is_refused(dbs):
    db = dbs["scratch"].create("empty")
    report = up.upgrade(_url_str(db), no_backup=True)
    assert _status(report, "vigil-database") == "FAIL" and report.steps == []
    assert _listing(db) == {}
