"""approval_actions lifecycle columns (W0.5) in a real Postgres.

A fresh install gets the columns from create_all; Compose and Helm get them
from ``49_approval_action_lifecycle.sql``; an existing bare-metal database from
``scripts/migrate_schema.py``. Both paths must be rerunnable and leave the same
columns and constraints. Each change runs in a transaction that is rolled back.
"""

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from core.storage.connection import get_db_manager
from core.storage.models import ApprovalAction

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

REPO = Path(__file__).resolve().parents[3]
MIGRATE_SCHEMA = REPO / "scripts" / "migrate_schema.py"
INIT_SQL = REPO / "infra" / "database" / "init" / "49_approval_action_lifecycle.sql"

COLUMNS = {
    "expires_at": "timestamp without time zone",
    "verified_at": "timestamp without time zone",
    "verify_status": "character varying",
    "reversed_at": "timestamp without time zone",
    "reverse_of": "character varying",
    "before_state": "jsonb",
    "after_state": "jsonb",
    "second_approver": "character varying",
}


def _columns(conn):
    rows = conn.execute(
        text(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
            "WHERE table_schema = current_schema() AND table_name = 'approval_actions'"
        )
    ).all()
    return {name: (data_type, nullable) for name, data_type, nullable in rows}


def _step():
    spec = importlib.util.spec_from_file_location(
        "vigil_migrate_schema", MIGRATE_SCHEMA
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.add_approval_action_lifecycle


def _insert(conn, action_id, **extra):
    cols = {
        "action_id": action_id,
        "action_type": "block_ip",
        "title": "t",
        "description": "d",
        "target": "203.0.113.7",
        "reason": "r",
        "created_by": "test",
        "status": "executed",
        **extra,
    }
    names = ", ".join(cols)
    binds = ", ".join(f":{c}" for c in cols)
    conn.execute(text(f"INSERT INTO approval_actions ({names}) VALUES ({binds})"), cols)


def test_the_model_declares_every_lifecycle_column():
    assert set(COLUMNS) <= set(ApprovalAction.__table__.columns.keys())


def test_create_all_builds_the_columns_nullable():
    with get_db_manager().engine.connect() as conn:
        present = _columns(conn)
    for name, data_type in COLUMNS.items():
        assert present[name] == (data_type, "YES"), name


@pytest.mark.parametrize("apply", ["migration", "init_sql"])
def test_an_old_table_gains_the_columns_and_constraints(apply):
    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            for name in COLUMNS:
                conn.execute(text(f"ALTER TABLE approval_actions DROP COLUMN {name}"))
            _insert(conn, "action-old")
            for _ in range(2):  # rerunnable
                if apply == "migration":
                    _step()(conn)
                else:
                    conn.execute(text(INIT_SQL.read_text(encoding="utf-8")))
            present = _columns(conn)
            for name, data_type in COLUMNS.items():
                assert present[name] == (data_type, "YES"), name
            for index in (
                "idx_approval_actions_expiry",
                "idx_approval_actions_reverse_of",
            ):
                assert conn.execute(
                    text("SELECT to_regclass(:n)"), {"n": index}
                ).scalar()

            _insert(
                conn,
                "action-undo",
                reverse_of="action-old",
                approved_by="a",
                second_approver="b",
            )
            sp = conn.begin_nested()
            with pytest.raises(IntegrityError):
                _insert(conn, "action-bad-verify", verify_status="maybe")
            sp.rollback()
            sp = conn.begin_nested()
            with pytest.raises(IntegrityError):
                _insert(
                    conn, "action-same-approver", approved_by="a", second_approver="a"
                )
            sp.rollback()
            sp = conn.begin_nested()
            with pytest.raises(IntegrityError):
                _insert(conn, "action-dangling", reverse_of="no-such-action")
            sp.rollback()
        finally:
            tx.rollback()
