"""Two processes creating the schema at once on a fresh database (W0.61).

Found on a live first boot: the backend's two uvicorn workers both ran
create_all and one failed with a pg_type unique violation ("Fatal: could not
initialize database schema"). create_tables now takes an advisory lock.
"""

from __future__ import annotations

import threading
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, inspect, text

from core.storage.connection import DatabaseManager, get_db_manager

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]


@pytest.fixture()
def fresh_url():
    base = get_db_manager()
    if base.engine is None:
        base.initialize()
    name = f"w061_race_{uuid.uuid4().hex[:8]}"
    admin = create_engine(base.engine.url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{name}"'))
            conn.execute(text(f'GRANT ALL ON DATABASE "{name}" TO CURRENT_USER'))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"cannot create a database: {type(exc).__name__}")
    url = base.engine.url.set(database=name)
    with create_engine(url, isolation_level="AUTOCOMMIT").connect() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
    yield url
    with admin.connect() as conn:
        conn.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
                " WHERE datname = :n AND pid <> pg_backend_pid()"
            ),
            {"n": name},
        )
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
    admin.dispose()


def test_concurrent_create_tables_both_succeed(fresh_url):
    # DatabaseManager is a process singleton; create_tables only needs _engine.
    managers = [SimpleNamespace(_engine=create_engine(fresh_url)) for _ in range(3)]
    errors = []
    start = threading.Barrier(len(managers))

    def run(m):
        try:
            start.wait()
            DatabaseManager.create_tables(m)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(m,)) for m in managers]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    assert errors == []
    tables = inspect(managers[0]._engine).get_table_names()
    assert "findings" in tables and "cases" in tables
    for m in managers:
        m._engine.dispose()
