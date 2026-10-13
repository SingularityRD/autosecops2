#!/usr/bin/env python3
"""Upgrade a Vigil 0.7.x database to the schema this checkout ships (AutoSecOps 2.0).

Forward only. There is no down migration: the way back is the backup this
script takes (``--backup``) or the one the operator took, restored with
``pg_restore`` (docs/upgrade-0.7-to-2.0.md).

What runs, in order, each step only after the one before it succeeded:

  preflight  read-only checks; any FAIL stops here (see ``preflight``)
  backup     ``pg_dump -Fc`` to ``--backup PATH`` (unless ``--no-backup``)
  sql-1      init SQL newer than 0.7.1 (``NN_*.sql`` with NN > 40), tolerant,
             the way a fresh install's first pass is: a file that ALTERs a
             table only create_all builds fails here and succeeds in sql-2
  orm        ``create_all`` for the tables only the models declare, then the
             default reference rows (``seed_empty_tables``)
  migrate    ``scripts/migrate_schema.py``: the column ALTERs create_all never
             makes on an existing table, and the data corrections; every step
             must apply (a skipped or failed step stops the upgrade)
  sql-2      the same files again, strict: ``ON_ERROR_STOP=1`` and one
             transaction per file. A file that cannot run twice fails here
  verify     the columns now in the database against
             ``core/storage/schema.snapshot.json`` (a fresh install's listing):
             a missing table or column, or a type/nullability difference,
             fails; a table or column the snapshot does not have is reported
  stamp      ``system_config.schema_version`` := this checkout's VERSION, and
             the run appended to ``system_config['upgrade.history']``

``--dry-run`` runs preflight and prints the plan (pending files, tables and
columns the upgrade will add) and writes nothing.

Re-running on an upgraded database is safe: every step is idempotent, and
the run ends at the same schema (tests/integration/test_upgrade_from_071.py).

New init SQL slots in by number: a file ``NN_name.sql`` with NN > 40 under
infra/database/init/ is picked up in filename order with no change here. It
must be idempotent (``IF NOT EXISTS``, ``ON CONFLICT``, ``DROP ... IF EXISTS``
before ``CREATE``), because sql-2 runs it after sql-1 and every re-run runs it
again.

Usage:
    python scripts/upgrade_database.py --dry-run
    python scripts/upgrade_database.py --backup /var/backups/vigil-pre-2.0.dump
    DATABASE_URL=postgresql://user:pass@host:5432/db python scripts/upgrade_database.py --no-backup

Exit status: 0 upgraded (or dry-run with no FAIL), 1 preflight FAIL or a step
failed, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.engine import Engine, make_url  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402

logger = logging.getLogger("upgrade_database")

# A checkout keeps the SQL under infra/; the backend image copies it to
# /app/database/init (infra/docker/Dockerfile.backend), where this script runs
# when scripts/ is mounted into that image (docs/upgrade-0.7-to-2.0.md).
INIT_DIR = next(
    (d for d in (ROOT / "infra" / "database" / "init", ROOT / "database" / "init") if d.is_dir()),
    ROOT / "infra" / "database" / "init",
)
SNAPSHOT = ROOT / "core" / "storage" / "schema.snapshot.json"

# The highest init file number Vigil 0.7.1 shipped (40_drop_custom_workflow_graph_layout.sql).
# Files at or below it are frozen: a 0.7.1 database already ran them, so a
# change to one never reaches an upgrade. tests/unit/test_upgrade_database.py
# holds them to tests/fixtures/upgrade/init_0_7_1.manifest.json.
BASELINE_LAST_INIT = 40
# Oldest stamped version this path is tested from. Older: go to 0.7.1 first.
MIN_SOURCE = (0, 7, 0)
MIN_SERVER_VERSION_NUM = 140000
RECOMMENDED_SERVER_VERSION_NUM = 160000
# Tables a Vigil database has had since well before 0.7.0; their absence means
# this is not a Vigil database, or an empty one (install, not upgrade).
REQUIRED_TABLES = ("system_config", "users", "roles", "findings", "cases")
# Tables an install may carry that a fresh Compose install does not:
# the Helm db-init Job's marker table.
KNOWN_EXTRA_TABLES = frozenset({"_vigil_schema_versions"})
HISTORY_KEY = "upgrade.history"
SCHEMA_VERSION_KEY = "schema_version"

_INIT_NAME = re.compile(r"^(\d+)_[A-Za-z0-9_]+\.sql$")
_CREATE_EXTENSION = re.compile(
    r"CREATE\s+EXTENSION\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?([\w-]+)\"?", re.IGNORECASE
)
_CONCURRENTLY = re.compile(r"\bCONCURRENTLY\b", re.IGNORECASE)
_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


class UpgradeError(RuntimeError):
    """A step failed; the message says which and what to do."""


@dataclass
class Check:
    name: str
    status: str  # OK | WARN | FAIL
    detail: str

    def line(self) -> str:
        return f"[{self.status:4}] {self.name}: {self.detail}"


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    plan: dict = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return any(c.status == "FAIL" for c in self.checks)

    def add(self, name: str, status: str, detail: str) -> None:
        check = Check(name, status, detail)
        self.checks.append(check)
        log = logger.error if status == "FAIL" else (
            logger.warning if status == "WARN" else logger.info
        )
        log(check.line())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def parse_version(value: Optional[str]) -> Optional[tuple[int, int, int]]:
    if not value:
        return None
    match = _VERSION.match(value.strip())
    return tuple(int(p) for p in match.groups()) if match else None  # type: ignore[return-value]


def target_version() -> str:
    from core.version import __version__

    return __version__


def pending_init_files(init_dir: Path = INIT_DIR) -> list[Path]:
    """Init SQL newer than 0.7.1, in the order Compose applies the directory."""
    files = []
    for path in sorted(init_dir.glob("*.sql")):
        match = _INIT_NAME.match(path.name)
        if match and int(match.group(1)) > BASELINE_LAST_INIT:
            files.append(path)
    return files


def malformed_init_files(init_dir: Path = INIT_DIR) -> list[str]:
    return sorted(p.name for p in init_dir.glob("*.sql") if not _INIT_NAME.match(p.name))


def required_extensions(files: Iterable[Path]) -> set[str]:
    names = {"pg_trgm", "uuid-ossp"}
    for path in files:
        names.update(m.group(1) for m in _CREATE_EXTENSION.finditer(path.read_text()))
    return names


def uses_concurrently(path: Path) -> bool:
    from core.storage.reference_seed import split_statements

    return any(
        _CONCURRENTLY.search(stmt) for stmt in split_statements(path.read_text())
    )


def normalize_url(url: str) -> str:
    # SQLAlchemy 2.1 maps bare postgresql:// to psycopg3; this repo ships psycopg2.
    return re.sub(r"^postgres(ql)?://", "postgresql+psycopg2://", url)


# URL query keys libpq also reads from the environment. pg_dump and psql get
# them as PG* variables so a ?sslmode=verify-full&sslrootcert=... or a
# ?host=/run/postgresql socket URL reaches them the same as the Python engine.
_LIBPQ_QUERY_ENV = {
    "host": "PGHOST",
    "hostaddr": "PGHOSTADDR",
    "port": "PGPORT",
    "dbname": "PGDATABASE",
    "user": "PGUSER",
    "passfile": "PGPASSFILE",
    "options": "PGOPTIONS",
    "application_name": "PGAPPNAME",
    "connect_timeout": "PGCONNECT_TIMEOUT",
    "sslmode": "PGSSLMODE",
    "sslrootcert": "PGSSLROOTCERT",
    "sslcert": "PGSSLCERT",
    "sslkey": "PGSSLKEY",
    "sslcrl": "PGSSLCRL",
    "sslcrldir": "PGSSLCRLDIR",
    "sslsni": "PGSSLSNI",
    "sslcompression": "PGSSLCOMPRESSION",
    "sslnegotiation": "PGSSLNEGOTIATION",
    "ssl_min_protocol_version": "PGSSLMINPROTOCOLVERSION",
    "ssl_max_protocol_version": "PGSSLMAXPROTOCOLVERSION",
    "requirepeer": "PGREQUIREPEER",
    "gssencmode": "PGGSSENCMODE",
    "krbsrvname": "PGKRBSRVNAME",
    "gsslib": "PGGSSLIB",
    "channel_binding": "PGCHANNELBINDING",
    "target_session_attrs": "PGTARGETSESSIONATTRS",
    "load_balance_hosts": "PGLOADBALANCEHOSTS",
    "service": "PGSERVICE",
    "tcp_user_timeout": "PGTCPUSERTIMEOUT",
}


def default_ssl_mode() -> str:
    """POSTGRES_SSL_MODE (core/config.py), as core/backup/create.py uses it."""
    try:
        from core.config import get_settings

        return get_settings().postgres_ssl_mode or "prefer"
    except Exception:  # settings unavailable outside a configured install
        return os.environ.get("POSTGRES_SSL_MODE") or "prefer"


def _query_value(value) -> str:
    # make_url turns a repeated key (multi-host URLs) into a tuple.
    return ",".join(map(str, value)) if isinstance(value, (tuple, list)) else str(value)


def libpq_params(url: str) -> dict:
    """libpq keyword -> value for ``url``: host, port, database, user, every
    query option, and sslmode from POSTGRES_SSL_MODE when the URL has none."""
    u = make_url(normalize_url(url))
    params = {
        "host": u.host or "localhost",
        "port": str(u.port or 5432),
        "dbname": u.database or "",
    }
    if u.username:
        params["user"] = u.username
    for key, value in u.query.items():
        params[key] = _query_value(value)
    params.setdefault("sslmode", default_ssl_mode())
    return params


def engine_connect_args(url: str) -> dict:
    """Extra psycopg2 connect args: sslmode from POSTGRES_SSL_MODE when the
    URL does not set one (query options already reach psycopg2 via the URL)."""
    u = make_url(normalize_url(url))
    return {} if "sslmode" in u.query else {"sslmode": default_ssl_mode()}


def libpq_conninfo(url: str) -> str:
    """``-d`` argument for psql / pg_dump: every libpq parameter of ``url``
    except the password, so options without a PG* variable (keepalives, ...)
    are not lost either. Quoted as core/backup/create.py does."""
    def quote(value: str) -> str:
        return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"

    return " ".join(f"{k}={quote(v)}" for k, v in libpq_params(url).items())


def libpq_env(url: str) -> dict:
    """PG* variables for psql / pg_dump. The password goes in the environment,
    never on a command line another user could read in ps. The other
    parameters are also on the command line (libpq_conninfo), which wins over
    any PG* variable the operator's shell already exports."""
    u = make_url(normalize_url(url))
    env = os.environ.copy()
    for key, value in libpq_params(url).items():
        name = _LIBPQ_QUERY_ENV.get(key)
        if name is not None:
            env[name] = value
    if u.password is not None:
        env["PGPASSWORD"] = str(u.password)
    return env


def column_listing(conn) -> dict:
    from scripts.generate_schema_snapshot import column_listing as _listing

    return _listing(conn)


def load_snapshot(path: Path = SNAPSHOT) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def diff_listing(actual: dict, expected: dict) -> dict:
    """What separates ``actual`` from ``expected`` (both column listings)."""
    missing_tables = sorted(set(expected) - set(actual))
    extra_tables = sorted(set(actual) - set(expected))
    missing_columns, extra_columns, changed = [], [], []
    for table in sorted(set(expected) & set(actual)):
        exp, act = expected[table], actual[table]
        missing_columns += [f"{table}.{c}" for c in sorted(set(exp) - set(act))]
        extra_columns += [f"{table}.{c}" for c in sorted(set(act) - set(exp))]
        for column in sorted(set(exp) & set(act)):
            if exp[column] != act[column]:
                changed.append(
                    f"{table}.{column}: {act[column]['data_type']}"
                    f"{'' if act[column]['nullable'] else ' NOT NULL'} -> "
                    f"{exp[column]['data_type']}"
                    f"{'' if exp[column]['nullable'] else ' NOT NULL'}"
                )
    return {
        "missing_tables": missing_tables,
        "extra_tables": extra_tables,
        "missing_columns": missing_columns,
        "extra_columns": extra_columns,
        "changed_columns": changed,
    }


def _read_stamp(conn) -> Optional[str]:
    if conn.execute(text("SELECT to_regclass('system_config')")).scalar() is None:
        return None
    value = conn.execute(
        text("SELECT value FROM system_config WHERE key = :key"),
        {"key": SCHEMA_VERSION_KEY},
    ).scalar()
    return value.get("version") if isinstance(value, dict) else None


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------


def preflight(
    engine: Engine,
    url: str,
    *,
    backup: Optional[Path],
    no_backup: bool,
    apply: bool,
    init_dir: Path = INIT_DIR,
    snapshot: Path = SNAPSHOT,
) -> Report:
    """Read-only checks. Nothing here writes to the database or the disk."""
    report = Report()
    target = target_version()
    files = pending_init_files(init_dir)

    try:
        conn = engine.connect()
    except Exception as e:  # noqa: BLE001
        report.add("connect", "FAIL", f"cannot connect: {e.__class__.__name__}")
        return report
    with conn:
        u = make_url(normalize_url(url))
        report.add("connect", "OK", f"{u.host or 'localhost'}:{u.port or 5432}/{u.database}")

        num = int(conn.execute(text("SHOW server_version_num")).scalar())
        if num < MIN_SERVER_VERSION_NUM:
            report.add("server-version", "FAIL", f"PostgreSQL {num} < 14 is not supported")
        elif num < RECOMMENDED_SERVER_VERSION_NUM:
            report.add("server-version", "WARN", f"PostgreSQL {num}; 16 is the tested version")
        else:
            report.add("server-version", "OK", f"PostgreSQL {num}")

        missing = [
            t for t in REQUIRED_TABLES
            if conn.execute(text("SELECT to_regclass(:t)"), {"t": f"public.{t}"}).scalar() is None
        ]
        if missing:
            report.add(
                "vigil-database", "FAIL",
                f"missing {', '.join(missing)}: not a Vigil 0.7.x database "
                "(an empty database is an install, not an upgrade)",
            )
            return report
        report.add("vigil-database", "OK", "core tables present")

        stamp = _read_stamp(conn)
        source, tgt = parse_version(stamp), parse_version(target)
        if stamp is None:
            report.add(
                "source-version", "WARN",
                "no schema_version stamp (a database no 0.5+ backend ever started on); "
                "continuing on the table checks alone",
            )
        elif source is None:
            report.add("source-version", "FAIL", f"unreadable schema_version stamp {stamp!r}")
        elif tgt is not None and source > tgt:
            report.add(
                "source-version", "FAIL",
                f"database is at {stamp}, newer than this release ({target}). Upgrades are "
                "forward only: run the matching release or restore a backup taken at "
                f"{target} or earlier",
            )
        elif source < MIN_SOURCE:
            report.add(
                "source-version", "FAIL",
                f"database is at {stamp}; upgrade to Vigil 0.7.1 first, then to {target}",
            )
        elif tgt is not None and source == tgt:
            report.add("source-version", "OK", f"{stamp} (already at {target}; re-run is a no-op)")
        else:
            report.add("source-version", "OK", f"{stamp} -> {target}")
        report.plan["source_version"] = stamp
        report.plan["target_version"] = target

        is_super = conn.execute(
            text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
        ).scalar()
        if is_super:
            report.add("privileges", "OK", "superuser")
        else:
            rows = conn.execute(text("""
                SELECT c.relname, pg_get_userbyid(c.relowner)
                FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
                  AND NOT pg_has_role(current_user, c.relowner, 'USAGE')
                ORDER BY 1
            """)).all()
            if rows:
                owners = sorted({o for _, o in rows})
                report.add(
                    "privileges", "FAIL",
                    f"{len(rows)} object(s) this role cannot alter (owned by "
                    f"{', '.join(owners)}), e.g. {rows[0][0]}. Run as a superuser or a "
                    "role that is a member of every owner",
                )
            else:
                report.add("privileges", "OK", "owns (or is a member of the owner of) every object")
            can_create = conn.execute(
                text("SELECT has_database_privilege(current_database(), 'CREATE')")
            ).scalar()
            if not can_create:
                report.add("privileges-create", "FAIL", "no CREATE on the database")

        needed = required_extensions(files)
        available = {
            r[0] for r in conn.execute(text("SELECT name FROM pg_available_extensions")).all()
        }
        absent = sorted(needed - available)
        if absent:
            report.add("extensions", "FAIL", f"not available on the server: {', '.join(absent)}")
        else:
            report.add("extensions", "OK", ", ".join(sorted(needed)))

        others = conn.execute(text("""
            SELECT count(*) FROM pg_stat_activity
            WHERE datname = current_database() AND pid <> pg_backend_pid()
        """)).scalar()
        if others:
            report.add(
                "sessions", "WARN",
                f"{others} other session(s) on this database; stop the backend, daemon, "
                "agent and LLM worker before upgrading",
            )
        else:
            report.add("sessions", "OK", "no other sessions")

        malformed = malformed_init_files(init_dir)
        if malformed:
            report.add("init-files", "FAIL", f"not NN_name.sql: {', '.join(malformed)}")
        else:
            report.add(
                "init-files", "OK",
                f"{len(files)} pending: {', '.join(p.name for p in files) or 'none'}",
            )
        report.plan["pending_files"] = [p.name for p in files]

        if snapshot.is_file():
            delta = diff_listing(column_listing(conn), load_snapshot(snapshot))
            report.plan["delta"] = delta
            report.add(
                "schema-delta", "OK",
                f"{len(delta['missing_tables'])} table(s) and "
                f"{len(delta['missing_columns'])} column(s) to add, "
                f"{len(delta['changed_columns'])} column(s) to change",
            )
        else:
            report.add("schema-delta", "FAIL", f"{snapshot} is missing")

    if shutil.which("psql") is None:
        report.add("psql", "FAIL", "psql is not on PATH")
    if apply:
        if backup is None and not no_backup:
            report.add(
                "backup", "FAIL",
                "pass --backup PATH (this script runs pg_dump) or --no-backup after taking one",
            )
        elif backup is not None:
            if backup.exists():
                report.add("backup", "FAIL", f"{backup} already exists; refusing to overwrite")
            elif not backup.parent.is_dir():
                report.add("backup", "FAIL", f"{backup.parent} is not a directory")
            elif shutil.which("pg_dump") is None:
                report.add("backup", "FAIL", "pg_dump is not on PATH")
            else:
                report.add("backup", "OK", f"pg_dump -Fc to {backup}")
        else:
            report.add("backup", "WARN", "--no-backup: the operator is responsible for the backup")
    return report


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def take_backup(url: str, path: Path) -> None:
    """pg_dump -Fc into a new 0600 file: the dump holds the whole database
    (password hashes, integration secrets), whatever the caller's umask."""
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except FileExistsError as e:
        raise UpgradeError(f"{path} already exists; refusing to overwrite") from e
    os.chmod(path, 0o600)
    completed = subprocess.run(
        ["pg_dump", "-Fc", "--no-password", "-f", str(path), "-d", libpq_conninfo(url)],
        env=libpq_env(url), capture_output=True, text=True, check=False,
    )
    if completed.returncode != 0 or not path.is_file() or path.stat().st_size == 0:
        if path.is_file() and path.stat().st_size == 0:
            path.unlink()  # so a re-run's preflight does not trip on it
        raise UpgradeError(f"pg_dump failed: {completed.stderr.strip()[:500]}")
    logger.info("backup written: %s (%d bytes)", path, path.stat().st_size)


def run_sql(url: str, path: Path, *, strict: bool) -> tuple[bool, str]:
    """psql -f, as the Compose hook runs it (tolerant) or one transaction that stops at the first error."""
    args = ["psql", "--no-password", "-q", "-v", f"ON_ERROR_STOP={1 if strict else 0}"]
    # CREATE INDEX CONCURRENTLY refuses a transaction block; such a file runs
    # statement by statement and still stops at its first error.
    if strict and not uses_concurrently(path):
        args.append("--single-transaction")
    args += ["-d", libpq_conninfo(url), "-f", str(path)]
    completed = subprocess.run(args, env=libpq_env(url), capture_output=True, text=True, check=False)
    errors = [ln for ln in completed.stderr.splitlines() if "ERROR:" in ln]
    if completed.returncode != 0:
        return False, (errors[0] if errors else completed.stderr.strip()[:500])
    return (not errors), (errors[0] if errors else "")


def sql_pass(url: str, files: list[Path], *, strict: bool) -> list[str]:
    deferred = []
    for path in files:
        ok, detail = run_sql(url, path, strict=strict)
        if ok:
            logger.info("  %s: applied", path.name)
            continue
        if strict:
            raise UpgradeError(
                f"{path.name} failed on the strict pass: {detail}. Every step before "
                "it is committed and re-runnable; fix the cause and run the script again, "
                "or restore the backup"
            )
        logger.info("  %s: deferred to the strict pass (%s)", path.name, detail)
        deferred.append(path.name)
    return deferred


def orm_tables(engine: Engine) -> None:
    from core.storage.models import Base
    from core.storage.reference_seed import seed_empty_tables

    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        inserted, failed = seed_empty_tables(conn)
    for table, rows in inserted.items():
        logger.info("  seeded %d default row(s) into %s", rows, table)
    if failed:
        raise UpgradeError(f"reference seed failed: {failed}")


def migrate(url: str) -> None:
    from scripts.migrate_schema import run_migrations

    result = run_migrations(url)
    if result["failed"] or result["skipped"]:
        names = [d for _, d in result["failed"]] + [d for _, d, _ in result["skipped"]]
        raise UpgradeError(f"migrate_schema did not apply: {'; '.join(names)}")


def verify(engine: Engine, snapshot: Path = SNAPSHOT) -> dict:
    with engine.connect() as conn:
        delta = diff_listing(column_listing(conn), load_snapshot(snapshot))
    hard = delta["missing_tables"] + delta["missing_columns"] + delta["changed_columns"]
    if hard:
        raise UpgradeError(
            "schema after upgrade differs from a fresh install: " + "; ".join(hard[:20])
        )
    extra = [t for t in delta["extra_tables"] if t not in KNOWN_EXTRA_TABLES]
    if extra or delta["extra_columns"]:
        logger.warning(
            "not part of a fresh install (left in place): %s",
            ", ".join(extra + delta["extra_columns"]),
        )
    return delta


def stamp(engine: Engine, source: Optional[str], target: str, files: list[str]) -> None:
    entry = {
        "from": source,
        "to": target,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": files,
    }
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO system_config (key, value, description, config_type)
            VALUES (:key, CAST(:value AS jsonb), :description, 'system')
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
        """), {
            "key": SCHEMA_VERSION_KEY,
            "value": json.dumps({"version": target}),
            "description": "Vigil version this schema was last provisioned at",
        })
        conn.execute(text("""
            INSERT INTO system_config (key, value, description, config_type)
            VALUES (:key, CAST(:value AS jsonb), :description, 'system')
            ON CONFLICT (key) DO UPDATE
            SET value = system_config.value || EXCLUDED.value, updated_at = now()
        """), {
            "key": HISTORY_KEY,
            "value": json.dumps([entry]),
            "description": "Runs of scripts/upgrade_database.py, oldest first",
        })
        # A Helm install's db-init Job records files it applied; marking these
        # spares it re-applying them on the next helm upgrade.
        if conn.execute(text("SELECT to_regclass('public._vigil_schema_versions')")).scalar():
            for name in files:
                conn.execute(text(
                    "INSERT INTO _vigil_schema_versions (filename) VALUES (:f) "
                    "ON CONFLICT (filename) DO NOTHING"
                ), {"f": name})


def upgrade(
    url: str,
    *,
    dry_run: bool = False,
    backup: Optional[Path] = None,
    no_backup: bool = False,
    init_dir: Path = INIT_DIR,
    snapshot: Path = SNAPSHOT,
) -> Report:
    """Preflight, then (unless ``dry_run``) every step. Raises UpgradeError on a failed step."""
    engine = create_engine(
        normalize_url(url), poolclass=NullPool,
        connect_args={"connect_timeout": 5, **engine_connect_args(url)},
    )
    try:
        report = preflight(
            engine, url, backup=backup, no_backup=no_backup, apply=not dry_run,
            init_dir=init_dir, snapshot=snapshot,
        )
        if report.failed or dry_run:
            return report
        files = pending_init_files(init_dir)
        if backup is not None:
            logger.info("== backup")
            take_backup(url, backup)
            report.steps.append("backup")
        logger.info("== sql-1: %d file(s), tolerant", len(files))
        report.plan["deferred"] = sql_pass(url, files, strict=False)
        report.steps.append("sql-1")
        logger.info("== orm: create_all + reference rows")
        orm_tables(engine)
        report.steps.append("orm")
        logger.info("== migrate: scripts/migrate_schema.py")
        migrate(url)
        report.steps.append("migrate")
        logger.info("== sql-2: %d file(s), strict", len(files))
        sql_pass(url, files, strict=True)
        report.steps.append("sql-2")
        logger.info("== verify against %s", snapshot.name)
        report.plan["after"] = verify(engine, snapshot)
        report.steps.append("verify")
        stamp(engine, report.plan.get("source_version"), report.plan["target_version"],
              [p.name for p in files])
        report.steps.append("stamp")
        logger.info("upgrade complete: %s -> %s",
                    report.plan.get("source_version"), report.plan["target_version"])
        return report
    finally:
        engine.dispose()


def _print_plan(report: Report) -> None:
    plan = report.plan
    print("\nPlan (dry run, nothing written):")
    print(f"  from {plan.get('source_version')} to {plan.get('target_version')}")
    print("  steps: backup, sql-1 (tolerant), orm, migrate, sql-2 (strict), verify, stamp")
    for name in plan.get("pending_files", []):
        print(f"  init SQL: {name}")
    delta = plan.get("delta") or {}
    for key in ("missing_tables", "missing_columns", "changed_columns"):
        for item in delta.get(key, []):
            print(f"  {key.replace('_', ' ')[:-1]}: {item}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--database-url", help="default: DATABASE_URL, as scripts/migrate_schema.py")
    parser.add_argument("--dry-run", action="store_true", help="preflight and plan only; write nothing")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--backup", type=Path, help="pg_dump -Fc to this new file before changing anything")
    group.add_argument("--no-backup", action="store_true", help="skip the backup (take one yourself first)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON at the end")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    if args.database_url:
        url = args.database_url
    else:
        from scripts.migrate_schema import get_connection_url

        url = get_connection_url()
    try:
        report = upgrade(url, dry_run=args.dry_run, backup=args.backup, no_backup=args.no_backup)
    except UpgradeError as e:
        logger.error("UPGRADE FAILED: %s", e)
        logger.error("Restore the backup to return to the previous version "
                     "(docs/upgrade-0.7-to-2.0.md, 'Geri alma').")
        return 1
    if args.dry_run and not report.failed:
        _print_plan(report)
    if args.json:
        print(json.dumps({
            "checks": [c.__dict__ for c in report.checks],
            "steps": report.steps,
            "plan": report.plan,
        }, indent=2, default=str))
    if report.failed:
        logger.error("preflight failed; nothing was changed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
