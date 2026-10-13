"""Runtime proof: with the air-gap profile, the API and daemon dial nothing outside.

The backend (uvicorn) and the daemon run as subprocesses with
``infra/airgap/airgap.env`` applied and ``tests/airgap/guard`` first on
PYTHONPATH, so every socket they open goes through the guard
(``guard/sitecustomize.py``), which logs and refuses anything that is not this
machine. A stub model server on localhost stands in for Bifrost.

The test drives the flows an air-gapped analyst uses -- start-up, health,
first-admin bootstrap and login, ingesting a finding from the eval corpus,
AI triage of it (answered by the stub), creating a case from it -- lets the
daemon run its start-up and polling loops meanwhile, and then asserts the guard
log holds no refused attempt.

Needs a local PostgreSQL and Redis (the POSTGRES_* variables and REDIS_URL of
the environment, as for tests/integration); it creates and drops its own
scratch database. Skips without them, except under ``CI``/``AIRGAP_REQUIRED``,
where a missing service is a failure.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import httpx
import pytest

from tests.airgap.stub_llm import StubLLM
from tests.airgap.test_egress_inventory import PROFILE, parse_env

REPO = Path(__file__).resolve().parents[2]
GUARD_DIR = Path(__file__).resolve().parent / "guard"
CORPUS = REPO / "eval" / "corpus" / "v1" / "dev.jsonl"
ADMIN = {
    "username": "airgap-admin",
    "email": "airgap-admin@example.com",
    "password": "airgap-harbour-quartz-77",
    "full_name": "Air-gap Admin",
}
_LOCAL_DB_HOSTS = {"localhost", "127.0.0.1", "::1", "postgres"}
# Variables that would route a request through a proxy on this machine, which
# the guard would then see as a local connection.
_PROXY_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
    "all_proxy", "NO_PROXY", "no_proxy",
)  # fmt: skip
# A DSN would outrank POSTGRES_DB and send the run to another database.
_DSN_VARS = ("DATABASE_URL", "POSTGRESQL_CONNECTION_STRING")
STARTUP_TIMEOUT = float(os.environ.get("AIRGAP_STARTUP_TIMEOUT", "240"))


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _pg_url(database: str) -> str:
    user = os.getenv("POSTGRES_USER", "deeptempo")
    password = os.getenv("POSTGRES_PASSWORD", "deeptempo_secure_password_change_me")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"


def _env_redis_url(profile: Dict[str, str]) -> str:
    # The environment's Redis (credentials included), on a database index of
    # its own so the run does not mix keys with a developer's stack.
    base = (
        os.getenv("REDIS_URL") or profile.get("REDIS_URL") or "redis://127.0.0.1:6379/0"
    )
    parts = urlparse(base)
    return urlunparse(parts._replace(path="/14"))


def _postgres_unavailable() -> Optional[str]:
    host = os.getenv("POSTGRES_HOST", "localhost")
    if host not in _LOCAL_DB_HOSTS:
        return (
            f"refusing to create a scratch database on non-local POSTGRES_HOST {host!r}"
        )
    try:
        from sqlalchemy import create_engine

        engine = create_engine(_pg_url("postgres"), connect_args={"connect_timeout": 5})
        with engine.connect():
            pass
        engine.dispose()
    except Exception as e:  # noqa: BLE001
        return f"requires a local PostgreSQL: {e}"
    return None


def _skip_or_fail(reason: str) -> None:
    if os.getenv("CI") or os.getenv("AIRGAP_REQUIRED"):
        pytest.fail(f"the air-gap runtime proof must run here: {reason}")
    pytest.skip(reason)


@pytest.fixture(scope="module")
def profile() -> Dict[str, str]:
    return parse_env(PROFILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def scratch_db():
    reason = _postgres_unavailable()
    if reason:
        _skip_or_fail(reason)
    from sqlalchemy import create_engine, text

    name = f"airgap_{os.getpid()}_{secrets.token_hex(4)}"
    admin = create_engine(
        _pg_url("postgres"),
        isolation_level="AUTOCOMMIT",
        connect_args={"connect_timeout": 5},
    )
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
    scratch = create_engine(_pg_url(name), isolation_level="AUTOCOMMIT")
    with scratch.connect() as c:
        for ext in ("pg_trgm", "uuid-ossp", "vector"):
            try:
                c.execute(text(f'CREATE EXTENSION IF NOT EXISTS "{ext}"'))
            except Exception:  # noqa: BLE001 - optional on this server
                pass
    scratch.dispose()
    try:
        yield name
    finally:
        with admin.connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


@pytest.fixture(scope="module")
def redis_url(tmp_path_factory, profile):
    """A private redis-server on a free port when one is installed, else the
    environment's Redis (database 14)."""
    server = shutil.which("redis-server")
    if server:
        port = _free_port()
        workdir = tmp_path_factory.mktemp("redis")
        proc = Proc(
            "redis",
            [server, "--port", str(port), "--bind", "127.0.0.1", "--save", "",
             "--appendonly", "no", "--dir", str(workdir)],
            {"PATH": os.environ.get("PATH", "")},
            workdir / "redis.log",
        )  # fmt: skip
        url = f"redis://127.0.0.1:{port}/0"
    else:
        proc, url = None, _env_redis_url(profile)
    try:
        import redis

        deadline = time.monotonic() + 20
        while True:
            try:
                redis.Redis.from_url(url, socket_connect_timeout=2).ping()
                break
            except Exception as e:  # noqa: BLE001
                if time.monotonic() > deadline:
                    _skip_or_fail(f"requires Redis ({url}): {e}")
                time.sleep(0.5)
        yield url
    finally:
        if proc:
            proc.stop()


@pytest.fixture(scope="module")
def stub():
    server = StubLLM().start()
    try:
        yield server
    finally:
        server.stop()


class Proc:
    """A subprocess we started; stopped by its own PID, never by name."""

    def __init__(self, name: str, argv: List[str], env: Dict[str, str], log: Path):
        self.name = name
        self.log = log
        self._fh = open(log, "wb")
        self.p = subprocess.Popen(
            argv,
            cwd=REPO,
            env=env,
            stdout=self._fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # its own group, so its children stop with it
        )

    def alive(self) -> bool:
        return self.p.poll() is None

    def stop(self) -> None:
        if self.alive():
            try:
                os.killpg(self.p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.p.wait(timeout=10)
        self._fh.close()

    def tail(self, n: int = 60) -> str:
        try:
            lines = self.log.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        return "\n".join(lines[-n:])


@pytest.fixture(scope="module")
def run(tmp_path_factory, profile, scratch_db, redis_url, stub):
    """Start backend + daemon under the guard; yield their handles and log."""
    tmp = tmp_path_factory.mktemp("airgap")
    guard_log = tmp / "guard.jsonl"
    api_port, health_port, webhook_port, agent_port = (_free_port() for _ in range(4))
    webhook_token = secrets.token_hex(16)

    env = {
        k: v
        for k, v in os.environ.items()
        if k not in _PROXY_VARS and k not in _DSN_VARS
    }
    env.update(profile)
    env.update(
        {
            # The guard, and the code under test from this checkout.
            "PYTHONPATH": os.pathsep.join([str(GUARD_DIR), str(REPO)]),
            "AIRGAP_GUARD_LOG": str(guard_log),
            "PYTHONUNBUFFERED": "1",
            # An install of its own: no developer state, no .env.
            "HOME": str(tmp / "home"),
            "VIGIL_DIR": str(tmp / "vigil"),
            "VIGIL_DISABLE_DOTENV": "1",
            "JWT_SECRET_KEY": secrets.token_hex(32),
            "DEV_MODE": "false",
            "POSTGRES_DB": scratch_db,
            "POSTGRES_HOST": os.getenv("POSTGRES_HOST", "localhost"),
            "REDIS_URL": redis_url,
            # Bifrost is the stub; the agent service is not running (its port
            # is free), which the API must survive as it would a stopped agent.
            "BIFROST_URL": stub.url,
            "AGENT_URL": f"http://127.0.0.1:{agent_port}",
            "VIGIL_RUNS_URL": f"http://127.0.0.1:{api_port}/internal/runs",
            "VIGIL_PLAYBOOKS_URL": f"http://127.0.0.1:{api_port}/internal/playbooks",
            "VIGIL_PRICING_URL": f"http://127.0.0.1:{api_port}/internal/pricing",
            "VIGIL_TOOLS_URL": f"http://127.0.0.1:{api_port}/internal/tools/invoke",
            "DAEMON_HEALTH_HOST": "127.0.0.1",
            "DAEMON_HEALTH_PORT": str(health_port),
            "DAEMON_WEBHOOK_PORT": str(webhook_port),
            "DAEMON_AUTO_TRIAGE": "true",
            "DAEMON_WEBHOOK_TOKEN": webhook_token,
            "DAEMON_AUTO_RESPONSE": "false",
            "VIGIL_LOG_FORMAT": "text",
        }
    )
    (tmp / "home").mkdir()
    (tmp / "vigil").mkdir()
    py = sys.executable
    # What start.sh does before launching: schema, then roles/reference rows
    # (so first-run bootstrap can assign role-admin). Guarded like the rest.
    for script in ("scripts/init_schema.py", "scripts/seed_reference_data.py"):
        done = subprocess.run(
            [py, script], cwd=REPO, env=env, capture_output=True, text=True,
            timeout=STARTUP_TIMEOUT,
        )  # fmt: skip
        assert done.returncode == 0, f"{script} failed:\n{done.stdout}\n{done.stderr}"
    api = Proc(
        "api",
        [py, "-m", "uvicorn", "services.api.main:app", "--host", "127.0.0.1",
         "--port", str(api_port), "--loop", "asyncio", "--no-access-log"],
        env,
        tmp / "api.log",
    )  # fmt: skip
    daemon = Proc("daemon", [py, "services/daemon/main.py"], env, tmp / "daemon.log")
    # The daemon's AI triage goes through the LLM gateway queue to this worker.
    worker = Proc("worker", [py, "-m", "services.worker"], env, tmp / "worker.log")
    procs = [api, daemon, worker]
    try:
        base = f"http://127.0.0.1:{api_port}"
        deadline = time.monotonic() + STARTUP_TIMEOUT
        while True:
            if not api.alive():
                pytest.fail(f"API exited during start-up:\n{api.tail()}")
            try:
                if httpx.get(f"{base}/api/health", timeout=5).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                pytest.fail(f"API not healthy after {STARTUP_TIMEOUT}s:\n{api.tail()}")
            time.sleep(2)
        yield {
            "base": base,
            "api": api,
            "daemon": daemon,
            "worker": worker,
            "guard_log": guard_log,
            "health": f"http://127.0.0.1:{health_port}",
            "webhook": f"http://127.0.0.1:{webhook_port}",
            "webhook_token": webhook_token,
        }
    finally:
        for proc in procs:
            proc.stop()


def _guard_events(path: Path) -> List[dict]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _corpus_alert() -> dict:
    with CORPUS.open(encoding="utf-8") as fh:
        for line in fh:
            alert = json.loads(line)["alert"]
            # One that names a public-looking IP and a hash: enrichment would
            # reach for VirusTotal/Shodan here if anything were switched on.
            if alert["entity_context"].get("file_hashes"):
                return alert
    raise AssertionError("no corpus alert with a file hash")


# Needs PostgreSQL/Redis; the guard's self-test below runs everywhere.
@pytest.mark.integration
@pytest.mark.external_service
def test_flows_make_no_outbound_connection(run, stub):
    base = run["base"]
    client = httpx.Client(base_url=base, timeout=120)

    # --- first admin, login -------------------------------------------------
    assert client.get("/api/auth/bootstrap").json() == {"required": True}
    created = client.post("/api/auth/bootstrap", json=ADMIN)
    assert created.status_code == 201, created.text
    login = client.post(
        "/api/auth/login",
        json={"username_or_email": ADMIN["username"], "password": ADMIN["password"]},
    )
    assert login.status_code == 200, login.text
    client.cookies.clear()
    client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
    assert client.get("/api/auth/me").status_code == 200

    # --- a local model, as an air-gapped operator configures one ------------
    provider = client.post(
        "/api/llm/providers",
        json={
            "provider_type": "ollama",
            "name": "Local model",
            "base_url": stub.url,
            "default_model": "llama3.1:8b",
            "is_default": True,
        },
    )
    assert provider.status_code == 201, provider.text

    # --- ingest a finding from the eval corpus ------------------------------
    alert = _corpus_alert()
    finding_id = alert["finding_id"]
    ingested = client.post(
        "/api/ingest/ingest-string",
        data={"data": json.dumps([alert]), "format": "json", "data_type": "finding"},
    )
    assert ingested.status_code == 200, ingested.text
    got = client.get(f"/api/v1/findings/{finding_id}")
    assert got.status_code == 200, got.text

    # --- AI triage, answered by the local stub ------------------------------
    before = len(stub.model_calls())
    triaged = client.post(f"/api/findings/{finding_id}/enrich")
    assert triaged.status_code == 200, triaged.text
    assert len(stub.model_calls()) > before, "triage never asked the model"

    # --- the daemon's own webhook ingest + auto-triage ----------------------
    enrich_calls = len(stub.model_calls())
    second = dict(alert, finding_id=f"{finding_id}-wh", external_id="airgap-wh")
    hook = httpx.post(
        f"{run['webhook']}/webhook",
        json=second,
        headers={"Authorization": f"Bearer {run['webhook_token']}"},
        timeout=30,
    )
    assert hook.status_code == 200, hook.text
    assert hook.json().get("ingested") == 1, hook.text

    # --- a case from the finding --------------------------------------------
    case = client.post(
        "/api/v1/cases",
        json={
            "title": "Air-gap check",
            "description": "W3.4",
            "finding_ids": [finding_id],
        },
    )
    assert case.status_code in (200, 201), case.text

    # Let the daemon store, enrich and triage the pushed finding and run its
    # periodic jobs meanwhile.
    soak_until = time.monotonic() + float(os.environ.get("AIRGAP_SOAK_SECONDS", "30"))
    stored = triaged_by_daemon = False
    while time.monotonic() < soak_until:
        if not stored:
            stored = (
                client.get(f"/api/v1/findings/{second['finding_id']}").status_code
                == 200
            )
        triaged_by_daemon = triaged_by_daemon or len(stub.model_calls()) > enrich_calls
        time.sleep(2)
    assert stored, f"daemon never stored the webhook finding:\n{run['daemon'].tail()}"
    assert triaged_by_daemon, (
        "the daemon's triage never reached the model:\n"
        f"{run['daemon'].tail(30)}\n--- worker ---\n{run['worker'].tail(30)}"
    )
    assert run["api"].alive(), run["api"].tail()
    assert run["daemon"].alive(), run["daemon"].tail()
    assert run["worker"].alive(), run["worker"].tail()

    events = _guard_events(run["guard_log"])
    # The guard was live in every process this run started: the two set-up
    # scripts, the API, the daemon and the LLM worker (and any child of theirs).
    armed = [e for e in events if e["event"] == "armed"]
    started = {p.p.pid for p in (run["api"], run["daemon"], run["worker"])}
    assert started <= {e["pid"] for e in armed}, f"guard not armed in all of {started}"
    assert {"scripts/init_schema.py", "scripts/seed_reference_data.py"} <= {
        (e["argv"] or [""])[0] for e in armed
    }
    blocked = [e for e in events if e["event"] != "armed"]
    assert not blocked, "outbound attempts under the air-gap profile:\n" + "\n".join(
        json.dumps(e) for e in blocked
    )


def test_guard_refuses_and_records(tmp_path):
    """The guard itself: an external connect is refused and logged; loopback is not."""
    log = tmp_path / "g.jsonl"
    code = (
        "import socket\n"
        "try:\n"
        "    socket.socket().connect(('203.0.113.7', 443))\n"
        "except ConnectionRefusedError as e:\n"
        "    print('refused', e.errno)\n"
        "try:\n"
        "    socket.getaddrinfo('api.openai.com', 443)\n"
        "except socket.gaierror:\n"
        "    print('nodns')\n"
        "s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen()\n"
        "socket.create_connection(s.getsockname(), timeout=2).close()\n"
        "print('loopback ok')\n"
    )
    env = {k: v for k, v in os.environ.items() if k not in _PROXY_VARS}
    env.update(PYTHONPATH=str(GUARD_DIR), AIRGAP_GUARD_LOG=str(log))
    out = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert (
        "refused" in out.stdout
        and "nodns" in out.stdout
        and "loopback ok" in out.stdout
    )
    events = _guard_events(log)
    kinds = [(e["event"], e["target"]) for e in events if e["event"] != "armed"]
    assert ("connect", "203.0.113.7:443") in kinds
    assert ("dns", "api.openai.com:443") in kinds
    assert all("127.0.0.1" not in t for _, t in kinds)
