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
import re
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
