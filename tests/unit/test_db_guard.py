"""W0.17: no test may destroy the configured database's schema."""

import pytest

from tests import _db_guard as guard

PROTECTED = frozenset({"deeptempo_soc"})


@pytest.mark.parametrize(
    "statement,database",
    [
        ("DROP SCHEMA public CASCADE", "deeptempo_soc"),
        ('DROP SCHEMA IF EXISTS "public" CASCADE', "deeptempo_soc"),
        ("DROP OWNED BY deeptempo", "deeptempo_soc"),
        ("DROP TABLE users", "deeptempo_soc"),
        ("DROP TABLE IF EXISTS skills;\nDROP TABLE users;", "deeptempo_soc"),
        ('DROP TABLE IF EXISTS public."system_config", foo CASCADE', "deeptempo_soc"),
        ("DROP DATABASE IF EXISTS deeptempo_soc WITH (FORCE)", "postgres"),
        ('DROP DATABASE "deeptempo_soc"', "postgres"),
        ("ALTER DATABASE deeptempo_soc RENAME TO x", "postgres"),
    ],
)
def test_destroying_the_configured_database_is_refused(statement, database):
    with pytest.raises(guard.ConfiguredDatabaseDestroyed):
        guard.check_statement(statement, database, PROTECTED)


@pytest.mark.parametrize(
    "statement,database",
    [
        ("DROP SCHEMA public CASCADE", "vigil_test_1_ab"),
        ("DROP TABLE users", "vigil_test_1_ab"),
        ("DROP DATABASE IF EXISTS vigil_test_1_ab WITH (FORCE)", "postgres"),
        ('DROP SCHEMA "w311_race_ab12" CASCADE', "deeptempo_soc"),
        ("DROP SCHEMA episodic_snap_x CASCADE", "deeptempo_soc"),
        ("DROP TABLE IF EXISTS skills", "deeptempo_soc"),  # 34_drop_skills.sql
        ("DROP INDEX IF EXISTS idx_users_email", "deeptempo_soc"),
        ("SELECT * FROM users", "deeptempo_soc"),
    ],
)
def test_scratch_and_routine_statements_pass(statement, database):
    guard.check_statement(statement, database, PROTECTED)


def test_protected_names_come_from_every_dsn_source():
    env = {
        "POSTGRES_DB": "a",
        "POSTGRESQL_CONNECTION_STRING": "postgresql://u:p@h:5432/b?sslmode=x",
        "DATABASE_URL": "postgresql://u:p@h/c",
    }
    assert guard.protected_databases(env) == {"a", "b", "c"}
    assert guard.protected_databases({}) == {"deeptempo_soc"}


def test_the_guard_is_on_every_engine():
    from sqlalchemy import create_engine

    engine = create_engine("sqlite://")
    with engine.connect() as conn, pytest.raises(guard.ConfiguredDatabaseDestroyed):
        conn.exec_driver_sql(
            "DROP DATABASE IF EXISTS " + sorted(guard.protected_databases())[0]
        )
