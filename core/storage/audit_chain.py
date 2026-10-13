"""Attach the audit-chain capture triggers at schema setup time.

``infra/database/init/51_audit_chain.sql`` creates ``audit_chain`` and the
functions, and attaches ``approval_actions``. ``case_audit_logs`` belongs to the
ORM: on a first Compose boot and on Helm's db-init Job it does not exist yet
when the SQL runs, and on Helm it is then built by ``create_all`` as vigil_app,
which the SQL's role cannot put a trigger on. So ``init_database()`` calls
:func:`ensure_audit_chain_triggers` after ``create_all``, as the role that built
the tables, and ``scripts/migrate_schema.py`` does the same for an existing
bare-metal database.

``audit_chain_attach()`` is a no-op when its triggers are in place (and
current: deferred to commit), so this is
one catalog query per table on every start. Nothing here raises: a database
without the SQL functions (bare-metal before the init SQL is applied) or a role
that may not attach a table is logged and left for the next start.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine

logger = logging.getLogger(__name__)

# Source table -> the key column its chain rows carry as source_id.
AUDITED_TABLES: Dict[str, str] = {
    "approval_actions": "action_id",
    "case_audit_logs": "audit_id",
}

TRIGGERS = (
    "audit_chain_capture",
    "audit_chain_capture_update",
    "audit_chain_capture_truncate",
)


def _functions_present(conn: Connection) -> bool:
    return (
        conn.execute(
            text("SELECT to_regprocedure('audit_chain_attach(regclass, text)')")
        ).scalar()
        is not None
    )


# Fires for ordinary sessions: 'O' (origin, the default) or 'A' (always).
# 'R' fires only under session_replication_role = replica and 'D' never, so
# both count as not attached.
_FIRING = ("O", "A")


def _trigger_rows(conn: Connection, table: str):
    return conn.execute(
        text(
            "SELECT tgname, CAST(tgenabled AS text), tgdeferrable, tginitdeferred "
            "FROM pg_trigger WHERE tgrelid = to_regclass(:table) "
            "AND tgname = ANY(:names)"
        ),
        {"table": table, "names": list(TRIGGERS)},
    ).all()


def triggers_attached(conn: Connection, table: str) -> bool:
    """Whether all of the capture triggers are on table and fire in ordinary sessions."""
    rows = _trigger_rows(conn, table)
    return len(rows) == len(TRIGGERS) and all(r[1] in _FIRING for r in rows)


def triggers_current(conn: Connection, table: str) -> bool:
    """Attached, and the row triggers are deferred to commit (this version's form).

    Triggers attached by an earlier version fire immediately, taking the chain
    lock mid-transaction; ``attach_table`` recreates them.
    """
    rows = _trigger_rows(conn, table)
    return (
        len(rows) == len(TRIGGERS)
        and all(r[1] in _FIRING for r in rows)
        and all(
            name == "audit_chain_capture_truncate" or (deferrable and deferred)
            for name, _, deferrable, deferred in rows
        )
    )


def attach_table(conn: Connection, table: str) -> Optional[str]:
    """Attach one audited table on ``conn``; the caller owns the transaction.

    Returns ``None`` when nothing was needed (or the table or the SQL functions
    are absent), else ``'install'`` / ``'reinstall'``.
    """
    key = AUDITED_TABLES[table]
    if not _functions_present(conn):
        return None
    if conn.execute(text("SELECT to_regclass(:t)"), {"t": table}).scalar() is None:
        return None
    if triggers_current(conn, table):
        return None
    return conn.execute(
        text("SELECT audit_chain_attach(CAST(:t AS regclass), :k)"),
        {"t": table, "k": key},
    ).scalar()


def ensure_audit_chain_triggers(engine: Engine) -> Dict[str, str]:
    """Attach every audited table that lacks its triggers. Never raises.

    Returns what was recorded per table (``install`` / ``reinstall``); tables
    that needed nothing are absent. Each table is its own transaction.
    """
    done: Dict[str, str] = {}
    for table in AUDITED_TABLES:
        try:
            with engine.begin() as conn:
                outcome = attach_table(conn, table)
        except Exception as e:  # noqa: BLE001
            # Typically "must be owner of table": another role built it. The
            # verifier reports the rows written meanwhile as unchained.
            logger.warning(
                "audit_chain: could not attach %s, its changes are not being "
                "chained: %s",
                table,
                str(e).strip().splitlines()[0] if str(e).strip() else type(e).__name__,
            )
            continue
        if outcome:
            done[table] = outcome
            if outcome == "reinstall":
                logger.warning(
                    "audit_chain: capture triggers on %s were missing, disabled or "
                    "of an earlier version and have been recreated; changes made "
                    "while they were missing or disabled are unchained",
                    table,
                )
            else:
                logger.info("audit_chain: attached %s", table)
    return done
