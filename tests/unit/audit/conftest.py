"""The throwaway test database, with the init SQL the audit chain needs.

The unit conftest builds the bare ORM schema. The audit tests add, once per
session and committed: the agent ledger (19, 31), the vigil_app grants (30) and
51_audit_chain.sql. One approval_actions row and one case_audit_logs row are
written first, with no triggers yet, so the attach has rows to snapshot.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import text

INIT = Path(__file__).resolve().parents[3] / "infra" / "database" / "init"
FILES = (
    "19_agent_ledger.sql",
    "31_agent_ledger_hash_chain.sql",
    "30_vigil_app_role.sql",
    "51_audit_chain.sql",
)

PRE_ACTION = "action-audit-pre-attach"


def run_sql_file(conn, name: str) -> None:
    """Run an init SQL file verbatim on the connection's transaction.

    Raw DB-API: the files hold ':' and '%' that SQLAlchemy and psycopg2 would
    read as parameters.
    """
    cursor = conn.connection.cursor()
    try:
        cursor.execute((INIT / name).read_text(encoding="utf-8"))
    finally:
        cursor.close()


def insert_action(conn, action_id: str, **extra) -> None:
    cols = {
        "action_id": action_id,
        "action_type": "block_ip",
        "title": "t",
        "description": "d",
        "target": "203.0.113.7",
        "reason": "r",
        "created_by": "test",
        "status": "pending",
        **extra,
    }
    names = ", ".join(cols)
    binds = ", ".join(f":{c}" for c in cols)
    conn.execute(text(f"INSERT INTO approval_actions ({names}) VALUES ({binds})"), cols)


def insert_audit_log(conn, entity_id: str) -> int:
    return conn.execute(
        text(
            "INSERT INTO case_audit_logs (entity_type, entity_id, action, changed_by) "
            "VALUES ('case', :e, 'update', 'analyst') RETURNING audit_id"
        ),
        {"e": entity_id},
    ).scalar_one()


@pytest.fixture(scope="session")
def audit_db(throwaway_database):
    """The throwaway database's engine, with the audit chain installed."""
    from core.storage.connection import get_db_manager

    engine = get_db_manager().engine
    with engine.begin() as conn:
        insert_action(conn, PRE_ACTION)
        pre_audit_id = insert_audit_log(conn, "case-pre-attach")
        for name in FILES:
            run_sql_file(conn, name)
    return SimpleNamespace(engine=engine, pre_audit_id=pre_audit_id)
