"""scripts/upgrade_database.py without a database, and the 0.7.1 fixture's hygiene (W4.5).

The upgrade itself runs in tests/integration/test_upgrade_from_071.py. Here:

  * the init files Vigil 0.7.1 shipped are frozen. A 0.7.1 database has run
    them, so an edit to one never reaches an upgrade: a schema change goes in
    a new NN_*.sql (NN > 40). Comment edits are allowed.
  * new files slot in by number with no change to the runner (the files
    unmerged branches carry, e.g. 51/55/58/61, are picked up in order).
  * the committed dump is small, synthetic, and says where it came from.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from scripts import upgrade_database as up  # noqa: E402
from scripts.build_upgrade_fixture import (  # noqa: E402
    DUMP,
    MANIFEST,
    UPSTREAM_071_COMMIT,
    statement_digest,
)

INIT = REPO / "infra" / "database" / "init"


def _frozen_on_disk() -> dict:
    return {
        p.name: p
        for p in sorted(INIT.glob("*.sql"))
        if int(p.name.split("_", 1)[0]) <= up.BASELINE_LAST_INIT
    }


def test_071_init_files_are_frozen():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["version"] == "0.7.1"
    assert manifest["source_commit"] == UPSTREAM_071_COMMIT
    on_disk = _frozen_on_disk()
    assert sorted(on_disk) == sorted(manifest["init_files"]), (
        "The init files numbered <= 40 are the ones 0.7.1 shipped. Add a new "
        "NN_*.sql (NN > 40) instead of adding, renaming or removing one of them."
    )
    changed = [
        name for name, path in on_disk.items()
        if statement_digest(path.read_text(encoding="utf-8")) != manifest["init_files"][name]
    ]
    assert not changed, (
        f"{changed} changed beyond comments. A 0.7.1 database already ran these, "
        "so the change would never reach an upgraded install: put it in a new "
        "NN_*.sql with NN > 40 (forward only)."
    )


def test_statement_digest_ignores_comments_and_whitespace():
    a = "-- one\nCREATE TABLE t (id int);\n\n/* two */ ALTER TABLE t ADD c int;\n"
    b = "CREATE TABLE t (id int);  -- trailing\nALTER   TABLE t ADD c int;"
    assert statement_digest(a) == statement_digest(b)
    assert statement_digest(a) != statement_digest(a.replace("c int", "d int"))


def test_baseline_is_the_last_071_file():
    names = json.loads(MANIFEST.read_text(encoding="utf-8"))["init_files"]
    assert max(int(n.split("_", 1)[0]) for n in names) == up.BASELINE_LAST_INIT


def test_pending_files_are_everything_newer_than_071_in_filename_order():
    pending = [p.name for p in up.pending_init_files()]
    expected = sorted(p.name for p in INIT.glob("*.sql") if int(p.name.split("_", 1)[0]) > 40)
    assert pending == expected
    assert pending and pending[0].startswith("41_")


def test_files_from_unmerged_branches_slot_in(tmp_path):
    for name in ("40_old.sql", "41_a.sql", "50_b.sql", "51_audit_chain.sql",
                 "55_lessons_promotion.sql", "56_c.sql", "58_broadcast.sql",
                 "61_approval_decisions.sql", "README.md"):
        (tmp_path / name).write_text("SELECT 1;\n")
    assert [p.name for p in up.pending_init_files(tmp_path)] == [
        "41_a.sql", "50_b.sql", "51_audit_chain.sql", "55_lessons_promotion.sql",
        "56_c.sql", "58_broadcast.sql", "61_approval_decisions.sql"]


def test_malformed_init_names_are_reported(tmp_path):
    (tmp_path / "41_ok.sql").write_text("SELECT 1;")
    (tmp_path / "fix-later.sql").write_text("SELECT 1;")
    assert up.malformed_init_files(tmp_path) == ["fix-later.sql"]
    assert up.malformed_init_files(INIT) == []


def test_concurrently_detection_skips_comments(tmp_path):
    assert up.uses_concurrently(INIT / "44_findings_bulk_imported.sql")
    assert not up.uses_concurrently(INIT / "41_users_service_account.sql")
    f = tmp_path / "x.sql"
    f.write_text("-- CREATE INDEX CONCURRENTLY would not work here\nCREATE INDEX i ON t (c);\n")
    assert not up.uses_concurrently(f)


def test_required_extensions_include_those_new_files_create(tmp_path):
    f = tmp_path / "60_x.sql"
    f.write_text('CREATE EXTENSION IF NOT EXISTS "vector";\n')
    assert up.required_extensions([f]) == {"pg_trgm", "uuid-ossp", "vector"}


@pytest.mark.parametrize("value, parsed", [
    ("0.7.1", (0, 7, 1)), ("2.0.0-rc.1", (2, 0, 0)), ("0.0.0+unknown", (0, 0, 0)),
    ("garbage", None), (None, None),
])
def test_parse_version(value, parsed):
    assert up.parse_version(value) == parsed


def test_diff_listing_classifies():
    col = {"data_type": "text", "nullable": True}
    expected = {"a": {"x": col, "y": col}, "b": {"z": col}}
    actual = {"a": {"x": {"data_type": "integer", "nullable": True}, "w": col}, "c": {"q": col}}
    assert up.diff_listing(actual, expected) == {
        "missing_tables": ["b"],
        "extra_tables": ["c"],
        "missing_columns": ["a.y"],
        "extra_columns": ["a.w"],
        "changed_columns": ["a.x: integer -> text"],
    }


def test_password_goes_to_the_environment_not_argv():
    env = up.libpq_env("postgresql://u:p%40ss@db.internal:6543/vigil")
    assert (env["PGHOST"], env["PGPORT"], env["PGUSER"], env["PGPASSWORD"], env["PGDATABASE"]) == (
        "db.internal", "6543", "u", "p@ss", "vigil")


TLS_SOCKET_URL = (
    "postgresql://u:p%40ss@/vigil?host=/run/postgresql&sslmode=verify-full"
    "&sslrootcert=/etc/vigil/ca.pem&sslcert=/etc/vigil/c.pem&sslkey=/etc/vigil/c.key"
    "&options=-c%20statement_timeout%3D0&keepalives=1"
)


def test_url_query_options_reach_psql_and_pg_dump_env():
    # Round 5 fix: sslmode/sslrootcert/sslcert/sslkey/host=socket/options were dropped.
    env = up.libpq_env(TLS_SOCKET_URL)
    assert env["PGHOST"] == "/run/postgresql"
    assert env["PGSSLMODE"] == "verify-full"
    assert env["PGSSLROOTCERT"] == "/etc/vigil/ca.pem"
    assert env["PGSSLCERT"] == "/etc/vigil/c.pem"
    assert env["PGSSLKEY"] == "/etc/vigil/c.key"
    assert env["PGOPTIONS"] == "-c statement_timeout=0"
    assert env["PGPASSWORD"] == "p@ss"


def _captured_argv(monkeypatch, tmp_path, url):
    calls = []

    class Done:
        returncode, stderr = 0, ""

    def fake_run(args, **kwargs):
        calls.append((args, kwargs["env"]))
        if args[0] == "pg_dump":
            Path(args[args.index("-f") + 1]).write_bytes(b"x")
        return Done()

    monkeypatch.setattr(up.subprocess, "run", fake_run)
    sql = tmp_path / "99_x.sql"
    sql.write_text("SELECT 1;")
    up.take_backup(url, tmp_path / "b.dump")
    up.run_sql(url, sql, strict=True)
    return calls


def test_url_query_options_reach_psql_and_pg_dump_argv(monkeypatch, tmp_path):
    for args, env in _captured_argv(monkeypatch, tmp_path, TLS_SOCKET_URL):
        conninfo = args[args.index("-d") + 1]
        for part in ("host='/run/postgresql'", "sslmode='verify-full'",
                     "sslrootcert='/etc/vigil/ca.pem'", "sslcert='/etc/vigil/c.pem'",
                     "sslkey='/etc/vigil/c.key'", "options='-c statement_timeout=0'",
                     "keepalives='1'", "dbname='vigil'", "user='u'"):
            assert part in conninfo, (args[0], conninfo)
        assert "p@ss" not in " ".join(args), "password never on argv"
        assert env["PGPASSWORD"] == "p@ss"


def test_postgres_ssl_mode_applies_when_url_has_no_sslmode(monkeypatch, tmp_path):
    from core.config import get_settings

    monkeypatch.setenv("POSTGRES_SSL_MODE", "require")
    get_settings.cache_clear()
    try:
        url = "postgresql://u:p@db.internal/vigil"
        assert up.libpq_env(url)["PGSSLMODE"] == "require"
        assert up.engine_connect_args(url) == {"sslmode": "require"}
        for args, _ in _captured_argv(monkeypatch, tmp_path, url):
            assert "sslmode='require'" in args[args.index("-d") + 1]
        # An explicit ?sslmode= in the URL wins, as in core/storage/connection.py.
        assert up.libpq_env(url + "?sslmode=disable")["PGSSLMODE"] == "disable"
        assert up.engine_connect_args(url + "?sslmode=disable") == {}
    finally:
        get_settings.cache_clear()


class _Refused(Exception):
    pass


def _migrate_connect_kwargs(monkeypatch, url):
    """What scripts/migrate_schema.py hands psycopg2.connect for ``url`` when
    upgrade_database's migrate step runs it."""
    import psycopg2

    seen = []

    def fake_connect(*args, **kwargs):
        seen.append((args, kwargs))
        raise _Refused("no database in a unit test")

    monkeypatch.setattr(psycopg2, "connect", fake_connect)
    with pytest.raises(Exception):
        up.migrate(url)
    assert seen, "migrate never reached psycopg2.connect"
    return seen[0]


def test_migrate_step_honours_postgres_ssl_mode(monkeypatch):
    # Round 6 fix: migrate(url) gave scripts/migrate_schema.py the raw URL, so
    # POSTGRES_SSL_MODE=require/verify-full was dropped for that one step.
    from core.config import get_settings

    monkeypatch.setenv("POSTGRES_SSL_MODE", "verify-full")
    get_settings.cache_clear()
    try:
        url = "postgresql://u:p%40ss@db.internal:6543/vigil?sslrootcert=/etc/vigil/ca.pem"
        args, kwargs = _migrate_connect_kwargs(monkeypatch, url)
        assert kwargs["sslmode"] == "verify-full"
        assert kwargs["sslrootcert"] == "/etc/vigil/ca.pem"
        assert (kwargs["host"], kwargs["port"], kwargs["user"], kwargs["password"],
                kwargs["dbname"]) == ("db.internal", 6543, "u", "p@ss", "vigil")
        # An explicit ?sslmode= still wins over the setting.
        _, kwargs = _migrate_connect_kwargs(monkeypatch, url + "&sslmode=disable")
        assert kwargs["sslmode"] == "disable"
    finally:
        get_settings.cache_clear()


def test_query_password_goes_to_pgpassword_not_conninfo(monkeypatch, tmp_path):
    # Round 6 fix: a ?password= query key was copied into the -d conninfo (argv).
    url = "postgresql://u@db.internal/vigil?password=s3cr%27et&sslmode=require"
    assert "password" not in up.libpq_conninfo(url)
    assert up.libpq_env(url)["PGPASSWORD"] == "s3cr'et"
    for args, env in _captured_argv(monkeypatch, tmp_path, url):
        assert "s3cr" not in " ".join(args) and "password=" not in " ".join(args)
        assert env["PGPASSWORD"] == "s3cr'et"
    # The query key wins over the userinfo one, as libpq applies it last.
    assert up.libpq_env("postgresql://u:old@h/db?password=new")["PGPASSWORD"] == "new"


def test_backup_is_owner_only_whatever_the_umask(monkeypatch, tmp_path):
    # Round 5 fix: the dump holds the whole database; it must not be world-readable.
    old = os.umask(0o002)
    try:
        _captured_argv(monkeypatch, tmp_path, "postgresql://u:p@h/db")
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "b.dump").stat().st_mode) == 0o600


def test_backup_never_overwrites(monkeypatch, tmp_path):
    (tmp_path / "b.dump").write_text("keep")
    monkeypatch.setattr(up.subprocess, "run", lambda *a, **k: pytest.fail("pg_dump ran"))
    with pytest.raises(up.UpgradeError):
        up.take_backup("postgresql://u:p@h/db", tmp_path / "b.dump")
    assert (tmp_path / "b.dump").read_text() == "keep"


def test_upgrade_guide_keeps_backups_private():
    guide = (REPO / "docs" / "upgrade-0.7-to-2.0.md").read_text(encoding="utf-8")
    assert "install -d -m 700 backups" in guide
    assert "777" not in guide


def test_upgrade_guide_keeps_passwords_off_argv():
    # Round 6 fix: -e DATABASE_URL=postgresql://u:${POSTGRES_PASSWORD}@... and
    # --database-url "...:PAROLA@..." put the password on a command line (ps).
    guide = (REPO / "docs" / "upgrade-0.7-to-2.0.md").read_text(encoding="utf-8")
    for line in guide.splitlines():
        code = line.split("#", 1)[0]
        if re.search(r"(^|\s)(-e|--env)\s+\w+=", code) or "--database-url " in code:
            assert not re.search(r"://[^/@\s]*:[^@\s]+@", code), line
    assert "-e DATABASE_URL \\" in guide


def test_backup_flags_are_exclusive():
    with pytest.raises(SystemExit) as e:
        up.main(["--backup", "/tmp/x.dump", "--no-backup"])
    assert e.value.code == 2


def test_dump_fixture_is_small_synthetic_and_attributed():
    text = DUMP.read_text(encoding="utf-8")
    assert len(text.encode()) < 512 * 1024
    assert UPSTREAM_071_COMMIT in text.splitlines()[1]
    assert "PRIVATE KEY" not in text
    assert not re.search(r"\$2[aby]\$\d\d\$", text), "no real bcrypt hash in the fixture"
    users = text.split("COPY public.users ", 1)[1].split("\n\\.\n", 1)[0].splitlines()[1:]
    assert users and all("\tnot-a-hash-upgrade-fixture\t" in row for row in users)
    emails = re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text)
    assert all(e.endswith("@example.com") for e in emails), sorted(set(emails))
    # No grants or owners: restorable by any role allowed to create the extensions.
    assert "OWNER TO" not in text and "\nGRANT " not in text
