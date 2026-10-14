"""Refuse schema-destroying SQL against the configured database (W0.17).

Tests that need to drop things provision a scratch database (``vigil_test_*``
in ``tests/unit/conftest.py``, ``SCRATCH_DB`` in the integration tests) or a
prefixed scratch schema. The configured database -- the one ``POSTGRES_DB``,
``POSTGRESQL_CONNECTION_STRING`` or ``DATABASE_URL`` names when pytest starts,
i.e. a developer's own stack or the shared dev database -- must never lose its
schema to a test run. This listener sits on every SQLAlchemy engine in the
pytest process and raises before such a statement reaches the server.

Scope: SQLAlchemy only. ``psql``/``pg_restore`` subprocesses are not seen;
those tests already target scratch names passed explicitly.
"""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

_DEFAULT_DB = "deeptempo_soc"  # core.config.Settings.postgres_db

_IDENT = r'"?([A-Za-z0-9_$]+)"?'
_DROP_DATABASE = re.compile(
    r"\bDROP\s+DATABASE(?:\s+IF\s+EXISTS)?\s+" + _IDENT, re.IGNORECASE
)
_RENAME_DATABASE = re.compile(
    r"\bALTER\s+DATABASE\s+" + _IDENT + r"\s+RENAME\b", re.IGNORECASE
)
_DROP_PUBLIC = re.compile(
    r"\bDROP\s+SCHEMA(?:\s+IF\s+EXISTS)?\s+(?:[^;]*?[\s,])?\"?public\"?\b",
    re.IGNORECASE,
)
_DROP_OWNED = re.compile(r"\bDROP\s+OWNED\b", re.IGNORECASE)
_DROP_TABLE = re.compile(r"\bDROP\s+TABLE(?:\s+IF\s+EXISTS)?\s+([^;]+)", re.IGNORECASE)


class ConfiguredDatabaseDestroyed(RuntimeError):
    """A test tried to destroy the configured (non-scratch) database."""


def _db_from_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        path = urlsplit(url).path.lstrip("/")
    except ValueError:
        return None
    return path.split("?")[0] or None


def protected_databases(environ=None) -> frozenset[str]:
    env = os.environ if environ is None else environ
    names = {env.get("POSTGRES_DB") or _DEFAULT_DB}
    for key in ("POSTGRESQL_CONNECTION_STRING", "DATABASE_URL"):
        name = _db_from_url(env.get(key))
        if name:
            names.add(name)
    return frozenset(names)


def _orm_tables() -> frozenset[str]:
    try:
        from core.storage.models import Base
    except Exception:  # noqa: BLE001 - AST-only environments have no app deps
        return frozenset({"users", "roles", "system_config"})
    return frozenset(Base.metadata.tables)


def check_statement(statement: str, database: str | None, protected) -> None:
    """Raise when ``statement`` run on ``database`` would destroy a protected one."""
    for match in (
        *_DROP_DATABASE.finditer(statement),
        *_RENAME_DATABASE.finditer(statement),
    ):
        if match.group(1) in protected:
            raise ConfiguredDatabaseDestroyed(
                f"refusing {match.group(0)!r}: {match.group(1)} is the configured "
                "database, not a scratch one"
            )
    if database not in protected:
        return
    if _DROP_PUBLIC.search(statement) or _DROP_OWNED.search(statement):
        raise ConfiguredDatabaseDestroyed(
            f"refusing schema drop on the configured database {database}: "
            f"{statement[:120]!r}"
        )
    names: set[str] = set()
    for match in _DROP_TABLE.finditer(statement):
        listed = re.split(r"\s+(?:CASCADE|RESTRICT)\b", match.group(1))[0]
        names |= {part.strip().split(".")[-1].strip('"') for part in listed.split(",")}
    hit = names & _orm_tables()
    if hit:
        raise ConfiguredDatabaseDestroyed(
            f"refusing DROP TABLE {sorted(hit)} on the configured database "
            f"{database}; use a scratch database"
        )


_installed = False


def install(protected=None) -> None:
    """Listen on every SQLAlchemy engine, existing and future (idempotent)."""
    global _installed
    if _installed:
        return
    try:
        from sqlalchemy import event
        from sqlalchemy.engine import Engine
    except ImportError:
        return
    names = protected_databases() if protected is None else frozenset(protected)

    def _guard(conn, cursor, statement, parameters, context, executemany):
        check_statement(statement, conn.engine.url.database, names)

    event.listen(Engine, "before_cursor_execute", _guard)
    _installed = True
