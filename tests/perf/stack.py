"""A local AutoSecOps stack for smoke-sized load and chaos runs.

Everything it starts is its own, on free ports, stopped by PID:

* PostgreSQL -- a private cluster (``initdb`` into a scratch directory, run as
  the ``postgres`` user when we are root) so a chaos scenario can restart it
  without touching anyone else's database. Without ``initdb`` it falls back to
  a scratch database on the environment's server (as tests/airgap does), and
  ``restart_postgres`` is then unavailable.
* Redis -- a private ``redis-server`` (no persistence, like a pod restart
  without a volume).
* A switchable stub model (tests/perf/faulty_llm.py) standing in for Bifrost.
* API (uvicorn), daemon and LLM worker from this checkout, with the air-gap
  profile applied (nothing dials out), alert lanes on, and a short enrichment
  backfill interval so recovery is observable within minutes.

Pieces are reused from the air-gap runtime harness (tests/airgap): the process
wrapper, the profile parser and the stub model.

Use from Python (tests/perf/test_*.py, tests/perf/chaos.py) or bring one up by
hand: ``python -m tests.perf.stack --hold`` prints the endpoints and waits.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import httpx

from tests.airgap.test_egress_inventory import PROFILE, parse_env
from tests.airgap.test_runtime_egress import _DSN_VARS, _PROXY_VARS, Proc, _free_port
from tests.perf.faulty_llm import FaultyLLM

REPO = Path(__file__).resolve().parents[2]
ADMIN = {
    "username": "loadtest-admin",
    "email": "loadtest-admin@example.com",
    "password": "loadtest-harbour-quartz-77",
    "full_name": "Load Test Admin",
}
PG_BIN_CANDIDATES = sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True)
STARTUP_TIMEOUT = float(os.environ.get("PERF_STARTUP_TIMEOUT", "300"))


class StackError(RuntimeError):
    pass


def _pg_bin(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    for d in PG_BIN_CANDIDATES:
        if (d / name).exists():
            return str(d / name)
    return None


def _as_postgres(argv: List[str]) -> List[str]:
    """initdb/pg_ctl refuse to run as root: drop to the postgres user."""
    if os.geteuid() == 0:
        runuser = shutil.which("runuser")
        if not runuser:
            raise StackError("running as root without runuser: cannot start PG")
        return [runuser, "-u", "postgres", "--", *argv]
    return argv


class PrivatePostgres:
    """A throwaway PostgreSQL cluster on a free port."""

    def __init__(self, workdir: Path):
        self.dir = workdir / "pg"
        self.data = self.dir / "data"
        self.log = self.dir / "postgres.log"
        self.port = _free_port()
        self.user = "postgres"
        self.password = "loadtest-local-only"
        self.db = "autosecops_load"

    @staticmethod
    def available() -> Optional[str]:
        if not (_pg_bin("initdb") and _pg_bin("pg_ctl")):
            return "initdb/pg_ctl not found"
        if os.geteuid() == 0 and not shutil.which("runuser"):
            return "root without runuser"
        return None

    def _pg_ctl(self, *args: str, timeout: float = 120) -> None:
        argv = _as_postgres([_pg_bin("pg_ctl"), "-D", str(self.data), *args])
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if done.returncode != 0:
            raise StackError(f"pg_ctl {args[0]} failed: {done.stdout}{done.stderr}")

    def init(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        if os.geteuid() == 0:
            shutil.chown(self.dir, user="postgres")
            os.chmod(self.dir.parent, 0o755)
        argv = _as_postgres(
            [_pg_bin("initdb"), "-D", str(self.data), "-A", "trust", "-U", self.user]
        )
        done = subprocess.run(argv, capture_output=True, text=True, timeout=300)
        if done.returncode != 0:
            raise StackError(f"initdb failed: {done.stdout}{done.stderr}")

    def start(self) -> None:
        opts = (
            f"-p {self.port} -k {self.dir} -c listen_addresses=127.0.0.1 "
            "-c fsync=off -c max_connections=200"
        )
        self._pg_ctl("-o", opts, "-l", str(self.log), "-w", "-t", "120", "start")

    def stop(self, mode: str = "fast") -> None:
        self._pg_ctl("-m", mode, "-w", "-t", "120", "stop")

    def restart(self, down_seconds: float = 0.0) -> None:
        self.stop("fast")
        if down_seconds:
            time.sleep(down_seconds)
        self.start()

    def url(self, database: Optional[str] = None) -> str:
        return (
            f"postgresql+psycopg2://{self.user}:{self.password}@127.0.0.1:"
            f"{self.port}/{database or self.db}"
        )

    def create_db(self) -> None:
        from sqlalchemy import create_engine, text

        admin = create_engine(self.url("postgres"), isolation_level="AUTOCOMMIT")
        with admin.connect() as c:
            c.execute(text(f'CREATE DATABASE "{self.db}"'))
        admin.dispose()
        eng = create_engine(self.url(), isolation_level="AUTOCOMMIT")
        with eng.connect() as c:
            for ext in ("pg_trgm", "uuid-ossp", "vector", "pgcrypto"):
                try:
                    c.execute(text(f'CREATE EXTENSION IF NOT EXISTS "{ext}"'))
                except Exception:  # noqa: BLE001 - optional on this server
                    pass
        eng.dispose()

    def destroy(self) -> None:
        try:
            self.stop("immediate")
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(self.dir, ignore_errors=True)


class PrivateRedis:
    def __init__(self, workdir: Path):
        self.dir = workdir / "redis"
        self.port = _free_port()
        self.proc: Optional[Proc] = None

    @property
    def url(self) -> str:
        return f"redis://127.0.0.1:{self.port}/0"

    def start(self) -> None:
        server = shutil.which("redis-server")
        if not server:
            raise StackError("redis-server not installed")
        self.dir.mkdir(parents=True, exist_ok=True)
        self.proc = Proc(
            "redis",
            [server, "--port", str(self.port), "--bind", "127.0.0.1", "--save", "",
             "--appendonly", "no", "--dir", str(self.dir)],
            {"PATH": os.environ.get("PATH", "")},
            self.dir / f"redis-{int(time.time())}.log",
        )  # fmt: skip
        import redis

        deadline = time.monotonic() + 20
        while True:
            try:
                redis.Redis.from_url(self.url, socket_connect_timeout=1).ping()
                return
            except Exception as e:  # noqa: BLE001
                if time.monotonic() > deadline:
                    raise StackError(f"redis did not start: {e}") from e
                time.sleep(0.3)

    def stop(self) -> None:
        if self.proc:
            self.proc.stop()
            self.proc = None

    def restart(self, down_seconds: float = 0.0) -> None:
        self.stop()
        if down_seconds:
            time.sleep(down_seconds)
        self.start()


@dataclass
class Endpoints:
    api_base: str
    webhooks: List[str]
    webhook_token: str
    health: List[str]
    db_url: str
    api_token: str = ""


class LocalStack:
    """Start/stop the stack and break pieces of it on demand."""

    def __init__(
        self,
        workdir: Path,
        *,
        daemons: int = 1,
        leader_election: bool = False,
        backfill_interval: int = 30,
        triage_timeout: int = 30,
        extra_env: Optional[Dict[str, str]] = None,
    ):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.n_daemons = daemons
        self.leader_election = leader_election
        self.backfill_interval = backfill_interval
        self.triage_timeout = triage_timeout
        self.extra_env = dict(extra_env or {})
        self.pg: Optional[PrivatePostgres] = None
        self.redis = PrivateRedis(self.workdir)
        self.llm = FaultyLLM()
        self.api: Optional[Proc] = None
        self.worker: Optional[Proc] = None
        self.daemons: List[Optional[Proc]] = []
        self.daemon_ports: List[Dict[str, int]] = []
        self.env: Dict[str, str] = {}
        self.endpoints: Optional[Endpoints] = None
        self._restarts = 0

    # -- lifecycle -----------------------------------------------------------

    @staticmethod
    def unavailable() -> Optional[str]:
        reason = PrivatePostgres.available()
        if reason:
            return f"private PostgreSQL unavailable: {reason}"
        if not shutil.which("redis-server"):
            return "redis-server not installed"
        return None

    @staticmethod
    def leader_election_supported() -> bool:
        """W3.9 (daemon hot standby) merged into this checkout?"""
        return (REPO / "services" / "daemon" / "leadership.py").exists()

    def _base_env(self) -> Dict[str, str]:
        env = {
            k: v
            for k, v in os.environ.items()
            if k not in _PROXY_VARS and k not in _DSN_VARS
        }
        env.update(parse_env(PROFILE.read_text(encoding="utf-8")))
        api_port = self._api_port
        env.update(
            {
                "PYTHONPATH": str(REPO),
                "PYTHONUNBUFFERED": "1",
                "HOME": str(self.workdir / "home"),
                "VIGIL_DIR": str(self.workdir / "vigil"),
                "VIGIL_DISABLE_DOTENV": "1",
                "JWT_SECRET_KEY": self._jwt,
                "DEV_MODE": "false",
                # Plain http on loopback: the csrf_token cookie must not be
                # Secure or no client sends it back.
                "VIGIL_COOKIE_SECURE": "false",
                "POSTGRES_HOST": "127.0.0.1",
                "POSTGRES_PORT": str(self.pg.port),
                "POSTGRES_USER": self.pg.user,
                "POSTGRES_PASSWORD": self.pg.password,
                "POSTGRES_DB": self.pg.db,
                "REDIS_URL": self.redis.url,
                "BIFROST_URL": self.llm.url,
                "AGENT_URL": f"http://127.0.0.1:{_free_port()}",
                "VIGIL_RUNS_URL": f"http://127.0.0.1:{api_port}/internal/runs",
                "VIGIL_PLAYBOOKS_URL": f"http://127.0.0.1:{api_port}/internal/playbooks",
                "VIGIL_PRICING_URL": f"http://127.0.0.1:{api_port}/internal/pricing",
                "VIGIL_TOOLS_URL": f"http://127.0.0.1:{api_port}/internal/tools/invoke",
                "DAEMON_HEALTH_HOST": "127.0.0.1",
                "DAEMON_AUTO_TRIAGE": "true",
                "DAEMON_AUTO_ENRICH": "true",
                "DAEMON_AUTO_RESPONSE": "false",
                "DAEMON_DRY_RUN": "true",
                "DAEMON_WEBHOOK_TOKEN": self._webhook_token,
                "DAEMON_ENRICH_BACKFILL_INTERVAL": str(self.backfill_interval),
                "DAEMON_ENRICH_BACKFILL_BATCH": "200",
                "DAEMON_TRIAGE_TIMEOUT": str(self.triage_timeout),
                "ALERT_LANES_ENABLED": "true",
                "VIGIL_LOG_FORMAT": "text",
            }
        )
        env.update(self.extra_env)
        return env

    def start(self) -> Endpoints:
        reason = self.unavailable()
        if reason:
            raise StackError(reason)
        (self.workdir / "home").mkdir(exist_ok=True)
        (self.workdir / "vigil").mkdir(exist_ok=True)
        self._jwt = secrets.token_hex(32)
        self._webhook_token = secrets.token_hex(16)
        self._api_port = _free_port()
        self.pg = PrivatePostgres(self.workdir)
        self.pg.init()
        self.pg.start()
        self.pg.create_db()
        self.redis.start()
        self.llm.start()
        self.env = self._base_env()
        py = sys.executable
        for script in ("scripts/init_schema.py", "scripts/seed_reference_data.py"):
            done = subprocess.run(
                [py, script], cwd=REPO, env=self.env, capture_output=True,
                text=True, timeout=STARTUP_TIMEOUT,
            )  # fmt: skip
            if done.returncode != 0:
                raise StackError(f"{script} failed:\n{done.stdout}\n{done.stderr}")
        self.api = Proc(
            "api",
            [py, "-m", "uvicorn", "services.api.main:app", "--host", "127.0.0.1",
             "--port", str(self._api_port), "--loop", "asyncio", "--no-access-log"],
            self.env,
            self.workdir / "api.log",
        )  # fmt: skip
        base = f"http://127.0.0.1:{self._api_port}"
        self._wait_http(f"{base}/api/health", self.api, "API")
        # The model is registered before the daemon starts: a daemon whose
        # start-up probes find no model trips its enrichment breaker for 120 s.
        token = self._bootstrap(base)
        self.worker = Proc(
            "worker",
            [py, "-m", "services.worker"],
            self.env,
            self.workdir / "worker.log",
        )
        self.daemon_ports = [
            {"health": _free_port(), "webhook": _free_port(), "metrics": _free_port()}
            for _ in range(self.n_daemons)
        ]
        self.daemons = [None] * self.n_daemons
        for i in range(self.n_daemons):
            self.start_daemon(i)
        for i in range(self.n_daemons):
            self.wait_daemon_ready(i)
        self.endpoints = Endpoints(
            api_base=base,
            webhooks=[
                f"http://127.0.0.1:{p['webhook']}/webhook" for p in self.daemon_ports
            ],
            webhook_token=self._webhook_token,
            health=[f"http://127.0.0.1:{p['health']}" for p in self.daemon_ports],
            db_url=self.pg.url(),
            api_token=token,
        )
        return self.endpoints

    def _daemon_env(self, i: int) -> Dict[str, str]:
        env = dict(self.env)
        ports = self.daemon_ports[i]
        env.update(
            {
                "DAEMON_HEALTH_PORT": str(ports["health"]),
                "DAEMON_WEBHOOK_PORT": str(ports["webhook"]),
                "DAEMON_METRICS_PORT": str(ports["metrics"]),
            }
        )
        if self.leader_election:
            env.update(
                {
                    "DAEMON_LEADER_ELECTION_ENABLED": "true",
                    "DAEMON_LEADER_LEASE_SECONDS": "6",
                    "DAEMON_LEADER_RETRY_SECONDS": "1",
                }
            )
        return env

    def start_daemon(self, i: int = 0) -> None:
        self._restarts += 1
        self.daemons[i] = Proc(
            f"daemon{i}",
            [sys.executable, "services/daemon/main.py"],
            self._daemon_env(i),
            self.workdir / f"daemon{i}-{self._restarts}.log",
        )

    def kill_daemon(self, i: int = 0, sig: int = signal.SIGKILL) -> None:
        proc = self.daemons[i]
        if proc and proc.alive():
            os.killpg(proc.p.pid, sig)
            proc.p.wait(timeout=30)
            proc._fh.close()

    def daemon_role(self, i: int) -> Optional[str]:
        try:
            r = httpx.get(
                f"http://127.0.0.1:{self.daemon_ports[i]['health']}/health", timeout=3
            )
            return r.json().get("role") or r.json().get("status")
        except Exception:  # noqa: BLE001
            return None

    def wait_daemon_ready(self, i: int = 0, timeout: float = STARTUP_TIMEOUT) -> None:
        self._wait_http(
            f"http://127.0.0.1:{self.daemon_ports[i]['webhook']}/health",
            self.daemons[i],
            f"daemon {i} webhook",
            timeout=timeout,
        )

    def stop(self) -> None:
        for proc in [self.api, self.worker, *self.daemons]:
            if proc:
                try:
                    proc.stop()
                except Exception:  # noqa: BLE001
                    pass
        try:
            self.llm.stop()
        except Exception:  # noqa: BLE001
            pass
        self.redis.stop()
        if self.pg:
            self.pg.destroy()

    def __enter__(self) -> "LocalStack":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- helpers -------------------------------------------------------------

    def _wait_http(
        self,
        url: str,
        proc: Optional[Proc],
        what: str,
        timeout: float = STARTUP_TIMEOUT,
    ) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if proc is not None and not proc.alive():
                raise StackError(f"{what} exited during start-up:\n{proc.tail()}")
            try:
                if httpx.get(url, timeout=5).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:
                tail = proc.tail() if proc else ""
                raise StackError(f"{what} not healthy after {timeout}s:\n{tail}")
            time.sleep(1.5)

    def _bootstrap(self, base: str) -> str:
        """First admin, login, and the stub registered as the default local model."""
        c = httpx.Client(base_url=base, timeout=120)
        # Double-submit CSRF: a GET seeds the csrf_token cookie, POSTs echo it.
        c.get("/api/auth/bootstrap")
        csrf = {"X-CSRF-Token": c.cookies.get("csrf_token", "")}
        created = c.post("/api/auth/bootstrap", json=ADMIN, headers=csrf)
        if created.status_code != 201:
            raise StackError(f"bootstrap failed: {created.status_code} {created.text}")
        login = c.post(
            "/api/auth/login",
            json={
                "username_or_email": ADMIN["username"],
                "password": ADMIN["password"],
            },
            headers=csrf,
        )
        if login.status_code != 200:
            raise StackError(f"login failed: {login.text}")
        token = login.json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        c.headers["X-CSRF-Token"] = c.cookies.get("csrf_token", "")
        provider = c.post(
            "/api/llm/providers",
            json={
                "provider_type": "ollama",
                "name": "Local model (stub)",
                "base_url": self.llm.url,
                "default_model": "llama3.1:8b",
                "is_default": True,
            },
        )
        if provider.status_code != 201:
            raise StackError(f"provider registration failed: {provider.text}")
        return token

    def logs(self) -> Dict[str, str]:
        out = {}
        for p in [self.api, self.worker, *self.daemons]:
            if p:
                out[p.name] = p.tail(40)
        return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Bring up a local stack for load runs.")
    p.add_argument("--workdir", type=Path, default=Path("/tmp/autosecops-perf-stack"))
    p.add_argument("--daemons", type=int, default=1)
    p.add_argument("--leader-election", action="store_true")
    p.add_argument("--hold", action="store_true", help="wait for Ctrl-C")
    args = p.parse_args(argv)
    stack = LocalStack(
        args.workdir, daemons=args.daemons, leader_election=args.leader_election
    )
    try:
        ep = stack.start()
        print(f"API        {ep.api_base}")
        for w in ep.webhooks:
            print(f"webhook    {w}")
        print(f"DB         {ep.db_url}")
        print("tokens are in the process environment only; use the Python API "
              "(tests.perf.chaos) to drive load against this stack")  # fmt: skip
        if args.hold:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        stack.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
