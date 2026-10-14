#!/usr/bin/env python3
"""Rebuild tests/fixtures/upgrade/: a Vigil 0.7.1 database dump and the 0.7.1 init manifest.

The dump is what tests/integration/test_upgrade_from_071.py restores and then
upgrades with scripts/upgrade_database.py. It is built from the upstream 0.7.1
release tree, provisioned the way 0.7.1's Compose stack did it (init SQL
tolerant, 0.7.1's ``init_database()``, init SQL again), seeded with
tests/fixtures/upgrade/seed_0_7_1.sql, and dumped with
``pg_dump --no-owner --no-privileges --no-comments`` (plain SQL, so a review
can read it, and restorable by any role that may create the extensions).

Upstream Vigil-SOC/vigil has no ``v0.7.1`` tag: release-please's 0.7.1 commit
is ``f72243c4`` ("chore(main): release 0.7.1", VERSION 0.7.1, init SQL up to
40_*). ``--ref`` takes it by default; a ``v0.7.1`` tag is used instead when the
repository has one.

The manifest records each 0.7.1 init file's name and a hash of its statements
(comments and blank lines dropped). Those files are frozen: a 0.7.1 database
has already run them, so tests/unit/test_upgrade_database.py fails when one
changes beyond its comments.

Needs a git checkout that contains the ref, a local PostgreSQL the
POSTGRES_* variables reach (CREATE/DROP of a scratch database, loopback only),
psql and pg_dump. Run from the repository root:

    python scripts/build_upgrade_fixture.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE_DIR = ROOT / "tests" / "fixtures" / "upgrade"
DUMP = FIXTURE_DIR / "vigil-0.7.1.sql"
SEED = FIXTURE_DIR / "seed_0_7_1.sql"
MANIFEST = FIXTURE_DIR / "init_0_7_1.manifest.json"
UPSTREAM_071_COMMIT = "f72243c443eb72eb99a333f2da2d3f3aec9dc1e5"
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "postgres"}


def statement_digest(sql: str) -> str:
    """sha256 over the file's statements, comments and whitespace runs dropped."""
    from core.storage.reference_seed import split_statements

    body = "\n".join(" ".join(s.split()) for s in split_statements(sql))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def resolve_ref(ref: str | None) -> str:
    if ref:
        return _git("rev-parse", "--verify", f"{ref}^{{commit}}")
    try:
        return _git("rev-parse", "--verify", "v0.7.1^{commit}")
    except subprocess.CalledProcessError:
        return _git("rev-parse", "--verify", f"{UPSTREAM_071_COMMIT}^{{commit}}")


def export_tree(commit: str, dest: Path) -> None:
    archive = dest.parent / "tree.tar"
    with open(archive, "wb") as fh:
        subprocess.run(["git", "-C", str(ROOT), "archive", commit], check=True, stdout=fh)
    with tarfile.open(archive) as tar:
        tar.extractall(dest, filter="data")
    archive.unlink()
    version = (dest / "VERSION").read_text().strip()
    if version != "0.7.1":
        raise SystemExit(f"{commit[:12]} is VERSION {version}, not 0.7.1")


def _pg_env(database: str) -> dict:
    env = os.environ.copy()
    env.update({
        "PGHOST": os.getenv("POSTGRES_HOST", "localhost"),
        "PGPORT": os.getenv("POSTGRES_PORT", "5432"),
        "PGUSER": os.getenv("POSTGRES_USER", "deeptempo"),
        "PGPASSWORD": os.getenv("POSTGRES_PASSWORD", "deeptempo_secure_password_change_me"),
        "PGDATABASE": database,
    })
    return env


def _psql(database: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["psql", "--no-password", "-q", *args], env=_pg_env(database),
        check=check, capture_output=True, text=True,
    )


def _apply_init(tree: Path, database: str) -> None:
    for path in sorted((tree / "infra" / "database" / "init").glob("*.sql")):
        _psql(database, "-v", "ON_ERROR_STOP=0", "-f", str(path))


def build_dump(tree: Path, out: Path, commit: str) -> None:
    if os.getenv("POSTGRES_HOST", "localhost") not in _LOCAL_HOSTS:
        raise SystemExit("refusing to CREATE/DROP a database on a non-local POSTGRES_HOST")
    name = f"vigil_upgrade_fixture_{secrets.token_hex(3)}"
    _psql("postgres", "-c", f'CREATE DATABASE "{name}"')
    try:
        _apply_init(tree, name)
        env = _pg_env(name)
        env.update({"POSTGRES_DB": name, "PYTHONPATH": str(tree)})
        env.pop("DATABASE_URL", None)
        # 0.7.1's own code builds its ORM-only tables, as its backend did on start.
        subprocess.run(
            [sys.executable, "-c",
             "from core.storage.connection import init_database; init_database()"],
            cwd=tree, env=env, check=True, capture_output=True, text=True,
        )
        _apply_init(tree, name)
        _psql(name, "-v", "ON_ERROR_STOP=1", "-f", str(SEED))
        dumped = subprocess.run(
            ["pg_dump", "--no-password", "--no-owner", "--no-privileges", "--no-comments"],
            env=_pg_env(name), check=True, capture_output=True, text=True,
        ).stdout
    finally:
        _psql("postgres", "-c", f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)', check=False)
    header = (
        "-- Vigil 0.7.1 database for the 0.7.1 -> 2.0 upgrade test (W4.5).\n"
        f"-- Source: upstream Vigil-SOC/vigil {commit} (release 0.7.1), provisioned as its\n"
        "-- Compose stack did, seeded with tests/fixtures/upgrade/seed_0_7_1.sql.\n"
        "-- Regenerate: python scripts/build_upgrade_fixture.py. Synthetic data only.\n"
    )
    # pg_dump's \restrict line carries a random key per run; drop it so a
    # rebuild only differs where the database does.
    lines = [ln for ln in dumped.splitlines() if not ln.startswith(("\\restrict", "\\unrestrict"))]
    out.write_text(header + "\n".join(lines) + "\n", encoding="utf-8")


def build_manifest(tree: Path, commit: str) -> dict:
    files = {
        p.name: statement_digest(p.read_text(encoding="utf-8"))
        for p in sorted((tree / "infra" / "database" / "init").glob("*.sql"))
    }
    return {"source_commit": commit, "version": "0.7.1", "init_files": files}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--ref", help="commit or tag of the 0.7.1 release (default: v0.7.1, else f72243c4)")
    parser.add_argument("--manifest-only", action="store_true", help="rewrite only the init manifest")
    args = parser.parse_args(argv)

    commit = resolve_ref(args.ref)
    with tempfile.TemporaryDirectory(prefix="vigil071-") as tmp:
        tree = Path(tmp) / "tree"
        tree.mkdir()
        export_tree(commit, tree)
        manifest = build_manifest(tree, commit)
        MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {MANIFEST.relative_to(ROOT)}")
        if not args.manifest_only:
            build_dump(tree, DUMP, commit)
            print(f"wrote {DUMP.relative_to(ROOT)} ({DUMP.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
