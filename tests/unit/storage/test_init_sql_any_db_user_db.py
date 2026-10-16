"""Init SQL applies for a database user of any name (W0.39, G16 / K6-44).

04/07/09/10/12/13 (frozen since 0.7.1, so they cannot be edited) end with
``GRANT ... TO deeptempo``. On a Helm install whose ``postgresql.*.username``
is something else, a bank's own Postgres say, that role does not exist: the
GRANTs failed, the db-init Job never recorded the six files and warned about
them on every upgrade. Both runners (the Job and compose's 00_apply.sh) now
feed those GRANTs to psql as ``TO CURRENT_USER``, the user that owns the
tables anyway.

The ``deeptempo`` role is cluster wide and the shared test server has it, so
these tests start a private cluster (initdb, as tests/perf does) where it does
not exist. There a non-superuser ``soc_owner`` owns the database and runs the
whole init sequence: init SQL, scripts/init_schema.py, init SQL again,
scripts/seed_reference_data.py. Then ``vigil_app``, the role the apps log in
as, reads and writes.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml
from sqlalchemy import create_engine, text

from tests.perf.stack import PrivatePostgres, StackError, _as_postgres, _pg_bin
from tests.unit.storage.test_helm_db_init_job_db import CHART, SQL_DIR, job_script

pytestmark = [
    pytest.mark.unit,
    pytest.mark.external_service,
    pytest.mark.database,
    pytest.mark.skipif(
        shutil.which("psql") is None or PrivatePostgres.available() is not None,
        reason="needs psql, initdb and pg_ctl for a private cluster",
    ),
]

REPO = Path(__file__).resolve().parents[3]
INIT_DIR = REPO / "infra" / "database" / "init"
APPLY_SH = REPO / "infra" / "docker" / "initdb" / "00_apply.sh"
OWNER = "soc_owner"
OWNER_PASSWORD = "init-sql-any-user-local-only"
DB = "autosecops_bank"
GRANTING_FILES = (
    "04_config_tables.sql",
    "07_custom_agents.sql",
    "09_llm_providers.sql",
    "10_ai_model_configs.sql",
    "12_workflow_runs.sql",
    "13_approval_actions.sql",
)
# The tables those files GRANT on, which the app must be able to use.
GRANTED_TABLES = (
    "system_config",
    "user_preferences",
    "integration_configs",
    "custom_agents",
    "llm_provider_configs",
    "ai_model_configs",
    "workflow_runs",
    "workflow_run_phases",
    "approval_actions",
)
# What the Job did before this fix: each file to psql as it is.
OLD_INIT_SQL = re.compile(r"(init_sql\(\) \{\n)\s*sed .*?(\n\s*\})", re.DOTALL)


class Cluster(PrivatePostgres):
    """A private cluster with password auth over TCP, so vigil_app's login
    really checks the password the Job set."""

    def init(self) -> None:
        os.chmod(self.dir, 0o755)
        pwfile = self.dir / "pw"
        pwfile.write_text(self.password + "\n")
        if os.geteuid() == 0:
            shutil.chown(self.dir, user="postgres")
            shutil.chown(pwfile, user="postgres")
        argv = _as_postgres([
            _pg_bin("initdb"), "-D", str(self.data), "-U", self.user,
            "--auth-local=trust", "--auth-host=scram-sha-256", f"--pwfile={pwfile}",
        ])  # fmt: skip
        done = subprocess.run(argv, capture_output=True, text=True, timeout=300)
        if done.returncode != 0:
            raise StackError(f"initdb failed: {done.stdout}{done.stderr}")

    def role_url(self, user: str, password: str, database: str = DB) -> str:
        return f"postgresql+psycopg2://{user}:{password}@127.0.0.1:{self.port}/{database}"


@pytest.fixture(scope="module")
def cluster():
    pg = Cluster(Path(tempfile.gettempdir()))
    try:
        pg.init()
        pg.start()
    except StackError as e:
        pg.destroy()
        pytest.skip(f"private cluster unavailable: {e}")
    try:
        yield pg
    finally:
        pg.destroy()


@pytest.fixture
def bank_db(cluster):
    """A database owned by a non-superuser that is not called deeptempo, as a
    DBA hands it over: CREATEROLE (30_vigil_app_role.sql creates vigil_app) and
    nothing else. 01 creates pg_trgm and uuid-ossp, trusted extensions the
    database owner may create."""
    admin = create_engine(cluster.url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)"))
        conn.execute(text("DROP ROLE IF EXISTS vigil_app"))
        conn.execute(text(f"DROP ROLE IF EXISTS {OWNER}"))
        conn.execute(text(
            f"CREATE ROLE {OWNER} LOGIN NOSUPERUSER CREATEROLE PASSWORD '{OWNER_PASSWORD}'"
        ))
        conn.execute(text(f"CREATE DATABASE {DB} OWNER {OWNER}"))
        assert not conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = 'deeptempo'")
        ).scalar()
    admin.dispose()
    yield cluster
    admin = create_engine(cluster.url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)"))
    admin.dispose()


def _pg_env(cluster) -> dict:
    return {
        **{k: v for k, v in os.environ.items() if not k.startswith("PG")},
        "PGHOST": "127.0.0.1",
        "PGPORT": str(cluster.port),
        "PGUSER": OWNER,
        "PGPASSWORD": OWNER_PASSWORD,
        "PGDATABASE": DB,
    }


def run_job(cluster, script: str | None = None) -> subprocess.CompletedProcess:
    env = {**_pg_env(cluster), "APP_SCHEMA_WAIT_SECONDS": "0"}
    return subprocess.run(
        ["sh", "-ec", script or job_script(SQL_DIR)],
        env=env, capture_output=True, text=True, timeout=600,
    )  # fmt: skip


def run_apply_sh(cluster) -> subprocess.CompletedProcess:
    script = APPLY_SH.read_text(encoding="utf-8")
    assert "/db-init/*.sql" in script
    script = script.replace("/db-init/*.sql", f"{INIT_DIR}/*.sql")
    env = {**_pg_env(cluster), "POSTGRES_PASSWORD": OWNER_PASSWORD}
    return subprocess.run(
        ["sh", "-c", script], env=env, capture_output=True, text=True, timeout=600
    )


def run_script(cluster, script: str, tmp_path: Path) -> None:
    """scripts/init_schema.py or scripts/seed_reference_data.py as the owner."""
    (tmp_path / "home").mkdir(exist_ok=True)
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PG", "POSTGRES"))
        and k not in ("DATABASE_URL", "POSTGRESQL_CONNECTION_STRING")
    }
    env.update({
        "PYTHONPATH": str(REPO),
        "HOME": str(tmp_path / "home"),
        "VIGIL_DIR": str(tmp_path / "vigil"),
        "VIGIL_DISABLE_DOTENV": "1",
        "POSTGRES_HOST": "127.0.0.1",
        "POSTGRES_PORT": str(cluster.port),
        "POSTGRES_USER": OWNER,
        "POSTGRES_PASSWORD": OWNER_PASSWORD,
        "POSTGRES_DB": DB,
        "POSTGRES_SSL_MODE": "disable",
    })  # fmt: skip
    done = subprocess.run(
        [sys.executable, script], cwd=REPO, env=env,
        capture_output=True, text=True, timeout=600,
    )  # fmt: skip
    assert done.returncode == 0, f"{script}:\n{done.stdout}\n{done.stderr}"


def _owner(cluster):
    return create_engine(cluster.role_url(OWNER, OWNER_PASSWORD))


def _recorded(cluster) -> set[str]:
    eng = _owner(cluster)
    try:
        with eng.connect() as conn:
            return set(conn.execute(text("SELECT filename FROM _vigil_schema_versions")).scalars())
    finally:
        eng.dispose()


def _errors(output: str) -> list[str]:
    return [line for line in output.splitlines() if "ERROR:" in line]


def _no_deeptempo_role(cluster) -> bool:
    eng = create_engine(cluster.url("postgres"))
    try:
        with eng.connect() as conn:
            return not conn.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = 'deeptempo'")
            ).scalar()
    finally:
        eng.dispose()


def assert_app_reads_and_writes(cluster) -> None:
    """vigil_app logs in with the password the Job set and uses the tables."""
    app = create_engine(cluster.role_url("vigil_app", OWNER_PASSWORD))
    try:
        with app.begin() as conn:
            for table in GRANTED_TABLES:
                assert conn.execute(text(
                    "SELECT has_table_privilege(current_user, :t, "
                    "'SELECT, INSERT, UPDATE, DELETE')"
                ), {"t": table}).scalar(), table  # fmt: skip
                conn.execute(text(f"SELECT count(*) FROM {table}"))
            conn.execute(text(
                "INSERT INTO system_config (key, value) VALUES ('w039.probe', '{\"a\": 1}')"
            ))
            conn.execute(text(
                "UPDATE system_config SET value = '{\"a\": 2}' WHERE key = 'w039.probe'"
            ))
            assert conn.execute(text(
                "SELECT value->>'a' FROM system_config WHERE key = 'w039.probe'"
            )).scalar() == "2"
            conn.execute(text("DELETE FROM system_config WHERE key = 'w039.probe'"))
            # Seeded reference data, from create_all's tables.
            assert conn.execute(text("SELECT count(*) FROM roles")).scalar() > 0
    finally:
        app.dispose()


def test_helm_job_applies_every_file_for_another_db_user(bank_db, tmp_path):
    files = yaml.safe_load((CHART / "values.yaml").read_text())["dbInit"]["sqlFiles"]

    first = run_job(bank_db)
    assert first.returncode == 0, first.stdout + first.stderr
    assert 'role "deeptempo" does not exist' not in first.stdout
    assert set(GRANTING_FILES) <= _recorded(bank_db), first.stdout

    run_script(bank_db, "scripts/init_schema.py", tmp_path)
    second = run_job(bank_db)
    assert second.returncode == 0, second.stdout + second.stderr
    run_script(bank_db, "scripts/seed_reference_data.py", tmp_path)

    # Every file applied cleanly at some point and nothing is left pending.
    assert _recorded(bank_db) == set(files), second.stdout
    assert "not applied:" not in second.stderr, second.stderr
    assert not _errors(second.stdout), second.stdout
    assert _no_deeptempo_role(bank_db)
    assert_app_reads_and_writes(bank_db)


def test_helm_upgrade_records_the_files_an_older_job_left_pending(bank_db, tmp_path):
    """An install made before this fix: the six files ran up to their GRANTs,
    were never recorded, and the next upgrade's Job applies them."""
    old_job, n = OLD_INIT_SQL.subn(r'\1cat "$1"\2', job_script(SQL_DIR))
    assert n == 1, "init_sql() moved; update this test"

    for _ in range(2):
        proc = run_job(bank_db, old_job)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        run_script(bank_db, "scripts/init_schema.py", tmp_path)
    run_script(bank_db, "scripts/seed_reference_data.py", tmp_path)
    assert 'role "deeptempo" does not exist' in proc.stdout
    assert not {*GRANTING_FILES, "30_vigil_app_role.sql"} & _recorded(bank_db)

    proc = run_job(bank_db)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert {*GRANTING_FILES, "30_vigil_app_role.sql"} <= _recorded(bank_db), proc.stdout
    assert "not applied:" not in proc.stderr, proc.stderr
    assert _no_deeptempo_role(bank_db)
    assert_app_reads_and_writes(bank_db)


def test_compose_apply_script_for_another_db_user(bank_db, tmp_path):
    """The sequence a host without the Job runs (compose's db-seed, a fresh
    VM): 00_apply.sh, init_schema.py, 00_apply.sh again, seed_reference_data.py."""
    first = run_apply_sh(bank_db)
    assert first.returncode == 0, first.stdout + first.stderr
    run_script(bank_db, "scripts/init_schema.py", tmp_path)
    second = run_apply_sh(bank_db)
    assert second.returncode == 0, second.stdout + second.stderr
    run_script(bank_db, "scripts/seed_reference_data.py", tmp_path)

    for proc in (first, second):
        assert "deeptempo" not in proc.stderr, proc.stderr
    assert _no_deeptempo_role(bank_db)
    assert_app_reads_and_writes(bank_db)
