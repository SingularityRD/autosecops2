"""The Helm backup CronJob's script against a real Postgres, then a restore (W3.9).

infra/helm/vigil/files/backup/pg-backup.sh is what the CronJob runs; here it
runs on this host with the local PostgreSQL client tools. The test dumps a
scratch database, checks the artifacts (verified dump, .sha256, LATEST),
restores the dump into an empty database and compares every table's rows,
then exercises retention.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "infra" / "helm" / "vigil" / "files" / "backup" / "pg-backup.sh"
SOURCE_DB = "vigil_test_w39_backup_src"
TARGET_DB = "vigil_test_w39_backup_dst"


def _parts() -> dict[str, str]:
    return {
        "user": os.getenv("POSTGRES_USER", "deeptempo"),
        "password": os.getenv(
            "POSTGRES_PASSWORD", "deeptempo_secure_password_change_me"
        ),
        "host": os.getenv("POSTGRES_HOST", "localhost"),
        "port": os.getenv("POSTGRES_PORT", "5432"),
    }


def _url(database: str) -> str:
    p = _parts()
    return (
        f"postgresql+psycopg2://{p['user']}:{p['password']}"
        f"@{p['host']}:{p['port']}/{database}"
    )


def _available() -> bool:
    if not (shutil.which("pg_dump") and shutil.which("pg_restore")):
        return False
    try:
        with create_engine(_url("postgres")).connect():
            return True
    except Exception:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _available(), reason="requires PostgreSQL and its client tools"
    ),
]


def _env(backup_dir: Path, database: str = SOURCE_DB, **extra: str) -> dict:
    p = _parts()
    return {
        **os.environ,
        "PGHOST": p["host"],
        "PGPORT": p["port"],
        "PGUSER": p["user"],
        "PGPASSWORD": p["password"],
        "PGDATABASE": database,
        "BACKUP_DIR": str(backup_dir),
        **extra,
    }


def _run(backup_dir: Path, **extra: str) -> subprocess.CompletedProcess:
    database = extra.pop("database", SOURCE_DB)
    return subprocess.run(
        ["sh", str(SCRIPT)],
        env=_env(backup_dir, database, **extra),
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.fixture(scope="module")
def admin():
    engine = create_engine(_url("postgres"), isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        for db in (SOURCE_DB, TARGET_DB):
            conn.execute(text(f"DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
        conn.execute(text(f"CREATE DATABASE {SOURCE_DB}"))
    src = create_engine(_url(SOURCE_DB))
    with src.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE findings (id bigserial PRIMARY KEY, finding_id text "
                "UNIQUE NOT NULL, severity text, entity_context jsonb, "
                "created_at timestamptz DEFAULT now())"
            )
        )
        conn.execute(
            text(
                "CREATE TABLE cases (id serial PRIMARY KEY, title text, "
                "finding_id text REFERENCES findings(finding_id))"
            )
        )
        conn.execute(
            text(
                "INSERT INTO findings (finding_id, severity, entity_context) "
                "SELECT 'f-' || g, (ARRAY['low','high','critical'])[1 + g % 3], "
                "jsonb_build_object('n', g) FROM generate_series(1, 500) g"
            )
        )
        conn.execute(
            text(
                "INSERT INTO cases (title, finding_id) "
                "SELECT 'case ' || g, 'f-' || g FROM generate_series(1, 40) g"
            )
        )
    src.dispose()
    yield engine
    with engine.connect() as conn:
        for db in (SOURCE_DB, TARGET_DB):
            conn.execute(text(f"DROP DATABASE IF EXISTS {db} WITH (FORCE)"))
    engine.dispose()


def _snapshot(database: str) -> dict:
    engine = create_engine(_url(database))
    try:
        with engine.connect() as conn:
            return {
                "findings": conn.execute(
                    text(
                        "SELECT count(*), md5(string_agg(finding_id || severity || "
                        "entity_context::text, ',' ORDER BY id)) FROM findings"
                    )
                ).one(),
                "cases": conn.execute(
                    text(
                        "SELECT count(*), md5(string_agg(title || finding_id, ',' "
                        "ORDER BY id)) FROM cases"
                    )
                ).one(),
                "next_id": conn.execute(
                    text("SELECT last_value FROM findings_id_seq")
                ).scalar(),
            }
    finally:
        engine.dispose()


def test_dump_is_verified_and_restores_to_identical_rows(admin, tmp_path):
    result = _run(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "pg-backup: ok" in result.stdout

    latest = (tmp_path / "LATEST").read_text().strip()
    dump = tmp_path / latest
    assert dump.is_file() and latest.startswith(f"{SOURCE_DB}-")
    assert not list(tmp_path.glob(".*.partial"))
    # The checksum file names the final dump and verifies.
    check = subprocess.run(
        ["sha256sum", "-c", f"{latest}.sha256"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stdout + check.stderr

    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {TARGET_DB} WITH (FORCE)"))
        conn.execute(text(f"CREATE DATABASE {TARGET_DB}"))
    p = _parts()
    restore = subprocess.run(
        [
            "pg_restore",
            "--exit-on-error",
            "--no-owner",
            "-h",
            p["host"],
            "-p",
            p["port"],
            "-U",
            p["user"],
            "-d",
            TARGET_DB,
            str(dump),
        ],
        env={**os.environ, "PGPASSWORD": p["password"]},
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert restore.returncode == 0, restore.stderr
    assert _snapshot(TARGET_DB) == _snapshot(SOURCE_DB)


def test_retention_keeps_the_newest_and_prunes_by_age(admin, tmp_path):
    # Three runs, at least a second apart so the timestamps differ.
    names = []
    for _ in range(3):
        result = _run(tmp_path, BACKUP_KEEP_LAST="2", BACKUP_RETENTION_DAYS="0")
        assert result.returncode == 0, result.stderr
        names.append((tmp_path / "LATEST").read_text().strip())
        time.sleep(1.1)
    kept = sorted(p.name for p in tmp_path.glob("*.dump"))
    assert kept == sorted(names[-2:])
    assert sorted(p.name for p in tmp_path.glob("*.sha256")) == [
        f"{n}.sha256" for n in sorted(names[-2:])
    ]

    # With an age limit, an old dump beyond keep-last goes, a young one stays.
    old = tmp_path / f"{SOURCE_DB}-20000101T000000Z.dump"
    young = tmp_path / f"{SOURCE_DB}-20000102T000000Z.dump"
    for f in (old, young):
        f.write_bytes(b"x")
    long_ago = time.time() - 40 * 86400
    os.utime(old, (long_ago, long_ago))
    result = _run(tmp_path, BACKUP_KEEP_LAST="2", BACKUP_RETENTION_DAYS="30")
    assert result.returncode == 0, result.stderr
    assert not old.exists()
    assert young.exists()
    assert "pruned" in result.stdout


def test_failed_dump_leaves_nothing_behind(admin, tmp_path):
    result = _run(tmp_path, database="vigil_test_w39_no_such_db")
    assert result.returncode != 0
    assert list(tmp_path.iterdir()) == []


def test_bad_settings_are_refused(tmp_path):
    result = _run(tmp_path, BACKUP_KEEP_LAST="0")
    assert result.returncode == 2
    result = _run(tmp_path, BACKUP_RETENTION_DAYS="ten")
    assert result.returncode == 2


def test_truncated_dump_is_rejected(admin, tmp_path):
    """A dump cut short after its TOC passes --list; the full read-back must fail.

    pg_dump is shimmed on PATH: the real one runs, then the tail of the file
    (data blocks) is cut off, as when the disk fills or pg_dump is killed.
    """
    real = shutil.which("pg_dump")
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    shim = shim_dir / "pg_dump"
    shim.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        f'"{real}" "$@"\n'
        'for a in "$@"; do case "$a" in --file=*) f="${a#--file=}" ;; esac; done\n'
        'size=$(wc -c < "$f")\n'
        'truncate -s $((size - 2000)) "$f"\n'
    )
    shim.chmod(0o755)
    backup_dir = tmp_path / "backups"

    # The shim's output still lists: the old --list-only check would accept it.
    listed = subprocess.run(
        [
            "sh",
            "-c",
            'pg_dump --format=custom --file="$1" && pg_restore --list "$1"',
            "sh",
            str(tmp_path / "probe.dump"),
        ],
        env={**_env(backup_dir), "PATH": f"{shim_dir}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert listed.returncode == 0, listed.stderr
    assert "TABLE DATA" in listed.stdout

    result = subprocess.run(
        ["sh", str(SCRIPT)],
        env={**_env(backup_dir), "PATH": f"{shim_dir}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode != 0
    assert "failed the full read-back" in result.stderr
    # Nothing was published: no dump, no checksum, no LATEST.
    assert not list(backup_dir.glob("*.dump"))
    assert not list(backup_dir.glob("*.sha256"))
    assert not (backup_dir / "LATEST").exists()
    assert not list(backup_dir.glob(".*.partial"))


def test_evidence_store_is_archived_beside_the_dump(admin, tmp_path):
    # W0.26: restored case_evidence rows need the files they point at.
    evidence = tmp_path / "evidence"
    (evidence / "CASE-1").mkdir(parents=True)
    (evidence / "CASE-1" / "report.pdf").write_bytes(b"%PDF flash report")
    # What core.backup restore leaves beside a restored copy is not evidence.
    (evidence / ".vigil-pre-restore-20261015T000000Z" / "CASE-0").mkdir(parents=True)
    (evidence / ".vigil-pre-restore-20261015T000000Z" / "CASE-0" / "x").write_text("x")
    (evidence / ".vigil-restore-stage-20261015T000000Z").mkdir()
    backups = tmp_path / "backups"

    names = []
    for _ in range(3):
        result = _run(
            backups,
            EVIDENCE_DIR=str(evidence),
            BACKUP_KEEP_LAST="2",
            BACKUP_RETENTION_DAYS="0",
        )
        assert result.returncode == 0, result.stderr
        names.append((backups / "LATEST_EVIDENCE").read_text().strip())
        time.sleep(1.1)

    latest = names[-1]
    dump = (backups / "LATEST").read_text().strip()
    # Same timestamp as its dump.
    assert latest == "evidence-" + dump.rsplit("-", 1)[1].replace(".dump", ".tar.gz")
    check = subprocess.run(
        ["sha256sum", "-c", f"{latest}.sha256"],
        cwd=backups,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stdout + check.stderr
    out = tmp_path / "out"
    out.mkdir()
    subprocess.run(["tar", "-xzf", str(backups / latest), "-C", str(out)], check=True)
    assert (out / "CASE-1" / "report.pdf").read_bytes() == b"%PDF flash report"
    assert sorted(p.name for p in out.iterdir()) == ["CASE-1"]
    # Case data: owner-only, the archive and the dump alike.
    for name in (latest, f"{latest}.sha256", dump):
        assert stat.S_IMODE((backups / name).stat().st_mode) == 0o600, name
    # Same retention as the dumps.
    assert sorted(p.name for p in backups.glob("evidence-*.tar.gz")) == sorted(
        names[-2:]
    )
    assert not list(backups.glob(".*.partial"))


def test_a_missing_evidence_dir_is_refused(tmp_path):
    result = _run(tmp_path, EVIDENCE_DIR=str(tmp_path / "nope"))
    assert result.returncode == 2
    assert "is not a directory" in result.stderr
