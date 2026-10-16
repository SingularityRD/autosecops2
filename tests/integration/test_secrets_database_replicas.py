"""Two "replicas" share console-entered secrets through Postgres, and no file holds them.

PY-19/PY-20: on Helm the State Directory is an emptyDir per pod and the chart
wrote console secrets to a plain ``.env`` there, so a secret lived in one replica
until it restarted. With ``SECRETS_BACKEND=database`` (the chart default) each
process here stands in for a pod: its own empty State Directory and HOME, one
shared scratch database, the same ``VIGIL_DATA_KEY``. A secret set on one is read
on the other, survives that process exiting (a restart), and its plaintext is in
no file under either pod's directories and not in the row.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

pytestmark = [pytest.mark.integration, pytest.mark.database]

REPO = Path(__file__).resolve().parents[2]
INIT_SQL = REPO / "infra" / "database" / "init" / "63_platform_secrets.sql"
DATA_KEY = "integration-replica-data-key-0000000001"

_POD = r"""
import sys, time
from core.storage.connection import get_db_manager
from core.secrets import get_secret, set_secret, delete_secret
from core.secrets_manager import get_secrets_manager

get_db_manager().initialize()
manager = get_secrets_manager()
assert manager.write_backend_name == "database", manager.write_backend_name
command, key = sys.argv[1], sys.argv[2]
if command == "set":
    print("ok" if set_secret(key, sys.argv[3]) else "failed")
elif command == "get":
    print("value=" + (get_secret(key) or ""))
elif command == "delete":
    print("ok" if delete_secret(key) else "failed")
elif command == "watch":
    # A long-running replica: reads once, then waits for another one to change it.
    print("value=" + (get_secret(key) or ""), flush=True)
    sys.stdin.readline()
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        value = get_secret(key) or ""
        if value != sys.argv[3]:
            break
        time.sleep(0.5)
    print("value=" + value)
"""


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
        not _postgres_available(),
        reason="requires a local PostgreSQL (docker compose up -d postgres)",
    )
)


@pytest.fixture
def scratch_database():
    name = f"vigil_sdb_{os.getpid()}_{secrets.token_hex(4)}"
    admin = create_engine(_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    owner = create_engine(_url(name))
    with owner.begin() as conn:
        conn.exec_driver_sql(INIT_SQL.read_text(encoding="utf-8"))
    owner.dispose()
    try:
        yield name
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def _pod_env(root: Path, database: str) -> dict[str, str]:
    (root / "state").mkdir(parents=True)
    (root / "home").mkdir()
    p = _parts()
    env = os.environ.copy()
    # The keys under test too: a shell that sourced an .env would answer for them
    # from the environment once the row is gone.
    for name in (
        "POSTGRESQL_CONNECTION_STRING",
        "DATABASE_URL",
        "SPLUNK_PASSWORD",
        "OIDC_CLIENT_SECRET_CORP",
        "KAFKA_SASL_PASSWORD",
    ):
        env.pop(name, None)
    env.update(
        {
            "POSTGRES_HOST": p["host"],
            "POSTGRES_PORT": p["port"],
            "POSTGRES_USER": p["user"],
            "POSTGRES_PASSWORD": p["password"],
            "POSTGRES_DB": database,
            "VIGIL_DIR": str(root / "state"),
            "HOME": str(root / "home"),
            "VIGIL_DISABLE_DOTENV": "1",
            "SECRETS_BACKEND": "database",
            "VIGIL_DATA_KEY": DATA_KEY,
        }
    )
    return env


def _run(env: dict[str, str], *args: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-c", _POD, *args],
        cwd=REPO,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip().splitlines()[-1]


def _files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*") if p.is_file()]


def test_secret_set_on_one_replica_is_read_on_the_other_and_never_on_disk(
    scratch_database, tmp_path
):
    pod_a = _pod_env(tmp_path / "pod-a", scratch_database)
    pod_b = _pod_env(tmp_path / "pod-b", scratch_database)
    first = "splunk-" + secrets.token_hex(12)
    second = "splunk-" + secrets.token_hex(12)
    repo_env = REPO / ".env"
    repo_env_before = repo_env.read_bytes() if repo_env.exists() else None

    assert _run(pod_a, "set", "SPLUNK_PASSWORD", first) == "ok"
    assert _run(pod_a, "set", "OIDC_CLIENT_SECRET_CORP", "oidc-" + first) == "ok"
    # Another pod, started after the first one exited: shared and persistent.
    assert _run(pod_b, "get", "SPLUNK_PASSWORD") == f"value={first}"
    assert _run(pod_b, "get", "OIDC_CLIENT_SECRET_CORP") == f"value=oidc-{first}"

    # A replica that is already running sees a change made on the other.
    watcher = subprocess.Popen(
        [sys.executable, "-c", _POD, "watch", "SPLUNK_PASSWORD", first],
        cwd=REPO,
        env=pod_b,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert watcher.stdout.readline().strip() == f"value={first}"
        assert _run(pod_a, "set", "SPLUNK_PASSWORD", second) == "ok"
        out, err = watcher.communicate("go\n", timeout=60)
    finally:
        watcher.kill()
    assert watcher.returncode == 0, err
    assert out.strip().splitlines()[-1] == f"value={second}"

    # Ciphertext only: the row does not hold the value, and no file does.
    engine = create_engine(_url(scratch_database))
    with engine.connect() as conn:
        found = conn.execute(text("SELECT name, ciphertext FROM platform_secrets"))
        rows = {name: ciphertext for name, ciphertext in found}
    engine.dispose()
    assert set(rows) == {"SPLUNK_PASSWORD", "OIDC_CLIENT_SECRET_CORP"}
    for ciphertext in rows.values():
        assert first not in ciphertext and second not in ciphertext
    for path in _files(tmp_path):
        content = path.read_bytes()
        for value in (first, second):
            assert value.encode() not in content, path
    for pod in ("pod-a", "pod-b"):
        state = tmp_path / pod / "state"
        assert not (state / ".env").exists()
        assert not (state / "secrets.enc").exists()
    assert (repo_env.read_bytes() if repo_env.exists() else None) == repo_env_before

    # Deleting on one replica removes it for both.
    assert _run(pod_b, "delete", "SPLUNK_PASSWORD") == "ok"
    assert _run(pod_a, "get", "SPLUNK_PASSWORD") == "value="


def test_a_replica_with_another_data_key_cannot_read_the_secrets(
    scratch_database, tmp_path
):
    pod_a = _pod_env(tmp_path / "pod-a", scratch_database)
    stranger = _pod_env(tmp_path / "pod-x", scratch_database)
    stranger["VIGIL_DATA_KEY"] = "a-different-data-key-for-this-pod-00001"
    value = "kafka-" + secrets.token_hex(12)

    assert _run(pod_a, "set", "KAFKA_SASL_PASSWORD", value) == "ok"
    assert _run(stranger, "get", "KAFKA_SASL_PASSWORD") == "value="
