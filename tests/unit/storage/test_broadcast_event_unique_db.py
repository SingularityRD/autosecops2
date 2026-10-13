"""One broadcast row per case event: the unique index and its migration (W0.10).

create_all builds the index from the model; ``scripts/migrate_schema.py`` and
``58_broadcast_unique_and_clock_heads.sql`` add it to a table built before,
keeping the first row of any event the old race already duplicated. Each
change runs inside a transaction that is rolled back.
"""

import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from core.storage.connection import get_db_manager

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

ROOT = Path(__file__).resolve().parents[3]
MIGRATE_SCHEMA = ROOT / "scripts" / "migrate_schema.py"
INIT_SQL = ROOT / "infra" / "database" / "init" / "58_broadcast_unique_and_clock_heads.sql"
INDEX = "uq_case_notification_broadcast_event"

INSERT = (
    "INSERT INTO case_notifications (user_id, notification_type, title, message, "
    "delivery_channel, priority, notification_metadata, is_read, is_sent) "
    "VALUES (:u, 'sla_warning', 't', 'm', 'broadcast', 'high', "
    "CAST(:meta AS jsonb), false, false)"
)


def _step():
    spec = importlib.util.spec_from_file_location("vigil_migrate_schema", MIGRATE_SCHEMA)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.create_case_notification_broadcast_unique


def _exists(conn):
    return conn.execute(text("SELECT to_regclass(:n)"), {"n": INDEX}).scalar() is not None


def _broadcasts(conn, key):
    return conn.execute(
        text(
            "SELECT count(*) FROM case_notifications WHERE user_id = 'system:broadcast' "
            "AND notification_metadata ->> 'event_key' = :k"
        ),
        {"k": key},
    ).scalar()


def test_create_all_builds_the_index_and_it_refuses_a_second_broadcast():
    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            assert _exists(conn)
            meta = '{"event_key": "sla:W010:response:90"}'
            conn.execute(text(INSERT), {"u": "system:broadcast", "meta": meta})
            # Per-person copies share the key and are not limited.
            conn.execute(text(INSERT), {"u": "alice", "meta": meta})
            conn.execute(text(INSERT), {"u": "bob", "meta": meta})
            sp = conn.begin_nested()
            with pytest.raises(IntegrityError):
                conn.execute(text(INSERT), {"u": "system:broadcast", "meta": meta})
            sp.rollback()
        finally:
            tx.rollback()


@pytest.mark.parametrize("apply", ["migration", "init_sql"])
def test_the_index_is_added_after_removing_duplicates(apply):
    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            conn.execute(text(f"DROP INDEX {INDEX}"))
            meta = '{"event_key": "sla:W010:resolution:100"}'
            for _ in range(3):
                conn.execute(text(INSERT), {"u": "system:broadcast", "meta": meta})
            assert _broadcasts(conn, "sla:W010:resolution:100") == 3

            if apply == "migration":
                _step()(conn)
                _step()(conn)  # rerunnable
            else:
                # 58 also builds on 50's regulatory tables, as on an install.
                for sql in (INIT_SQL.with_name("50_regulatory_clocks.sql"), INIT_SQL):
                    conn.execute(text(sql.read_text(encoding="utf-8")))

            assert _exists(conn)
            assert _broadcasts(conn, "sla:W010:resolution:100") == 1
        finally:
            tx.rollback()
