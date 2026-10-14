"""The Helm db-init Job must not record a file that failed (W0.13 review).

The Job runs as a post-install hook, before the backend has logged in and run
create_all, so a first install has no ``cases`` table. 50_regulatory_clocks.sql
and 58_broadcast_unique_and_clock_heads.sql reference it; psql exits 0 after a
failed statement without ON_ERROR_STOP, so the Job used to record both files
as applied and a Helm install never got regulatory_clock_events,
regulatory_report_drafts or regulatory_clock_heads (DORA/NIS2 clocks broken).

These tests run the Job's own shell script (taken from the template, with the
range over dbInit.sqlFiles expanded) against a scratch database with psql.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest
import yaml
from sqlalchemy import create_engine, text

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

REPO = Path(__file__).resolve().parents[3]
CHART = REPO / "infra" / "helm" / "vigil"
JOB = CHART / "templates" / "db-init-job.yaml"
SQL_DIR = CHART / "files" / "database-init"
SCRATCH_DB = "vigil_test_helm_db_init_job"
REGULATORY = (
    "regulatory_clock_events",
    "regulatory_report_drafts",
    "regulatory_clock_heads",
)


def _parts() -> dict[str, str]:
    return {
        "user": os.getenv("POSTGRES_USER", "deeptempo"),
        "password": os.getenv(
            "POSTGRES_PASSWORD", "deeptempo_secure_password_change_me"
        ),
        "host": os.getenv("POSTGRES_HOST", "localhost"),
        "port": os.getenv("POSTGRES_PORT", "5432"),
    }


def _url(database: str) -> str:
    p = _parts()
    return (
        f"postgresql+psycopg2://{p['user']}:{p['password']}"
        f"@{p['host']}:{p['port']}/{database}"
    )


def _postgres_available() -> bool:
    try:
        with create_engine(_url("postgres")).connect():
            return True
    except Exception:
        return False


pytestmark.append(
    pytest.mark.skipif(
        shutil.which("psql") is None or not _postgres_available(),
        reason="needs psql and a local PostgreSQL",
    )
)


def job_script(sql_dir: Path) -> str:
    """The Job container's ``sh -ec`` body, as Helm renders it."""
    lines = JOB.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "- |") + 1
    end = next(i for i in range(start, len(lines)) if lines[i].strip() == "volumeMounts:")
    body = "\n".join(line[14:] for line in lines[start:end])
    files = yaml.safe_load((CHART / "values.yaml").read_text())["dbInit"]["sqlFiles"]
    body, n = re.subn(
        r"\{\{- range \.Values\.dbInit\.sqlFiles \}\}\n\s*apply \{\{ \. \| quote \}\}\n\s*\{\{- end \}\}",
        "\n".join(f'apply "{f}"' for f in files),
        body,
    )
    assert n == 1, "the range over dbInit.sqlFiles moved; update this test"
    assert "{{" not in body
    return body.replace('"/sql/$f"', f'"{sql_dir}/$f"')


def run_job(wait_seconds: int = 0) -> subprocess.CompletedProcess:
    p = _parts()
    env = {
        **os.environ,
        "PGHOST": p["host"],
        "PGPORT": p["port"],
        "PGUSER": p["user"],
        "PGPASSWORD": p["password"],
        "PGDATABASE": SCRATCH_DB,
        "APP_SCHEMA_WAIT_SECONDS": str(wait_seconds),
    }
    return subprocess.run(
        ["sh", "-ec", job_script(SQL_DIR)],
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )


def _exists(engine, name: str) -> bool:
    with engine.connect() as conn:
        return conn.execute(text("SELECT to_regclass(:n) IS NOT NULL"), {"n": name}).scalar()


def _recorded(engine) -> set[str]:
    with engine.connect() as conn:
        return set(conn.execute(text("SELECT filename FROM _vigil_schema_versions")).scalars())


def _create_all(engine) -> None:
    """What the backend does at startup once it can log in."""
    from core.storage.models import Base

    Base.metadata.create_all(engine)


def chart_role() -> str:
    """The role the Job logs in as on Helm, which the init SQL GRANTs to by name."""
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    return values["postgresql"]["auth"]["username"]


@pytest.fixture
def scratch():
    # 04/07/09/10/12/13 end with GRANT ... TO <chart user>. A Helm install
    # always has that role (the Job logs in as it); a test cluster whose login is
    # some other name (CI's "test") would fail those GRANTs and the files would
    # never apply, which is not what this test is about. So the role exists here
    # too, as on Helm, and goes again if this fixture made it.
    role = chart_role()
    admin = create_engine(_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        made_role = not conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}
        ).scalar()
        if made_role:
            conn.execute(text(f'CREATE ROLE "{role}" NOLOGIN'))
        conn.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)"))
        conn.execute(text(f"CREATE DATABASE {SCRATCH_DB}"))
    engine = create_engine(_url(SCRATCH_DB))
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)"))
            if made_role:
                conn.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
        admin.dispose()


def test_first_install_does_not_record_files_that_failed_and_upgrade_applies_them(scratch):
    proc = run_job()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    recorded = _recorded(scratch)
    # cases does not exist yet: both files failed and neither is recorded.
    assert "50_regulatory_clocks.sql" not in recorded, proc.stdout
    assert "58_broadcast_unique_and_clock_heads.sql" not in recorded, proc.stdout
    assert "01_init_schema.sql" in recorded
    assert not _exists(scratch, "regulatory_clock_events")
    assert "not applied:" in proc.stderr

    # The backend starts and builds its tables; the next upgrade re-runs the Job.
    _create_all(scratch)
    proc = run_job()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for table in REGULATORY:
        assert _exists(scratch, table), f"{table} missing after upgrade\n{proc.stdout}"
    recorded = _recorded(scratch)
    assert {"50_regulatory_clocks.sql", "58_broadcast_unique_and_clock_heads.sql"} <= recorded


def test_second_pass_applies_them_once_the_backend_has_built_its_tables(scratch):
    def backend():
        # The backend gets in late in the first pass (here: once 56 is recorded),
        # after 50 has already failed for want of cases.
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                if "56_alert_lane_decisions.sql" in _recorded(scratch):
                    break
            except Exception:
                pass
            time.sleep(0.2)
        _create_all(scratch)

    t = threading.Thread(target=backend, daemon=True)
    t.start()
    proc = run_job(wait_seconds=120)
    t.join(timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Not yet applied:" in proc.stdout
    for table in REGULATORY:
        assert _exists(scratch, table), f"{table} missing after the second pass\n{proc.stdout}"
    assert "not applied:" not in proc.stderr, proc.stderr


def test_upgrade_heals_ghost_markers_from_older_releases(scratch):
    """Round 3: an install made before this fix recorded 50/58 although they
    failed. The Job drops such a marker when the file's tables are missing and
    applies the file again, so no manual DELETE is needed."""
    # Install, backend start, upgrade: a healthy install with every file recorded.
    assert run_job().returncode == 0
    _create_all(scratch)
    proc = run_job()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    # Reproduce the old state: markers present, tables gone.
    with scratch.begin() as conn:
        conn.execute(text("DROP TABLE regulatory_clock_heads CASCADE"))
        conn.execute(text("DROP TABLE regulatory_report_drafts CASCADE"))
        conn.execute(text("DROP TABLE regulatory_clock_events CASCADE"))
    assert {"50_regulatory_clocks.sql", "58_broadcast_unique_and_clock_heads.sql"} <= _recorded(scratch)

    proc = run_job()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "HEAL 50_regulatory_clocks.sql" in proc.stdout
    assert "HEAL 58_broadcast_unique_and_clock_heads.sql" in proc.stdout
    for table in REGULATORY:
        assert _exists(scratch, table), f"{table} missing after heal\n{proc.stdout}"
    assert {"50_regulatory_clocks.sql", "58_broadcast_unique_and_clock_heads.sql"} <= _recorded(scratch)

    # A healthy install is left alone on the next run.
    proc = run_job()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "HEAL" not in proc.stdout
    assert "SKIP 50_regulatory_clocks.sql" in proc.stdout
