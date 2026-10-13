"""Two real daemon processes against a real Postgres (W3.9).

Each test starts two ``_leader_harness.py`` processes on a scratch database:
one leads (its writer inserts rows), the other waits as standby. Then:

* kill     — SIGKILL the leader; the standby leads within retry + slack.
* graceful — SIGTERM the leader; it exits 0 and releases the lock at once.
* pause    — SIGSTOP the leader past the lease; the server ends its lock
             session, the standby leads, and after SIGCONT the old leader
             commits nothing more and exits 75.
* partition — end the leader's lock session server-side while the process
             keeps running (what idle_session_timeout does when the network
             is cut); the standby leads, the old leader's writes are fenced,
             and it exits 75.

The fence check is on the rows: no row from the old leader may have a higher
id than the new leader's first row.
"""

from __future__ import annotations

import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS = Path(__file__).with_name("_leader_harness.py")
SCRATCH_DB = "vigil_test_w39_leader"
LEASE = 6.0
RETRY = 1.0
# Process start, imports and scheduling on a busy 2-CPU box.
SLACK = 8.0
LOG_DIR = Path(os.getenv("W39_LOG_DIR", "/tmp/w39"))


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
        engine = create_engine(_url("postgres"), isolation_level="AUTOCOMMIT")
        with engine.connect():
            return True
    except Exception:
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _postgres_available(), reason="requires a local PostgreSQL"
    ),
]


@pytest.fixture
def db():
    admin = create_engine(_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)"))
        conn.execute(text(f"CREATE DATABASE {SCRATCH_DB}"))
    engine = create_engine(_url(SCRATCH_DB), isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        conn.execute(
            text(
                "CREATE TABLE leader_writes (id bigserial PRIMARY KEY, "
                "writer text NOT NULL, at timestamptz DEFAULT clock_timestamp())"
            )
        )
    yield engine
    engine.dispose()
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)"))
    admin.dispose()


class Replica:
    def __init__(self, name: str) -> None:
        p = _parts()
        env = {
            **os.environ,
            "POSTGRES_HOST": p["host"],
            "POSTGRES_PORT": p["port"],
            "POSTGRES_USER": p["user"],
            "POSTGRES_PASSWORD": p["password"],
            "POSTGRES_DB": SCRATCH_DB,
            "POSTGRESQL_CONNECTION_STRING": "",
            "DAEMON_LEADER_ELECTION_ENABLED": "true",
            "DAEMON_LEADER_LEASE_SECONDS": str(LEASE),
            "DAEMON_LEADER_RETRY_SECONDS": str(RETRY),
            "VIGIL_OTEL_ENABLED": "false",
            "PYTHONUNBUFFERED": "1",
        }
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.log = open(LOG_DIR / f"{name}-{os.getpid()}.log", "w")
        self.proc = subprocess.Popen(
            [sys.executable, str(HARNESS)],
            cwd=REPO_ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=self.log,
            text=True,
        )
        self.lines: "queue.Queue[tuple[float, str]]" = queue.Queue()
        self.instance_id: str | None = None
        self.led_at: float | None = None
        self.write_failures = 0
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        for line in self.proc.stdout:
            self.lines.put((time.monotonic(), line.strip()))

    def poll_lines(self) -> None:
        while True:
            try:
                at, line = self.lines.get_nowait()
            except queue.Empty:
                return
            if line.startswith("LEADER "):
                self.instance_id = line.split(" ", 1)[1]
                self.led_at = at
            elif line.startswith("WRITE_FAILED"):
                self.write_failures += 1

    def stop(self) -> None:
        if self.proc.poll() is None:
            try:
                os.kill(self.proc.pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
            self.proc.kill()
        self.proc.wait(timeout=30)
        self.log.close()


def _wait_for(predicate, timeout: float, what: str):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}")


@pytest.fixture
def pair(db, request):
    tag = request.node.name.removeprefix("test_")[:30]
    a = Replica(f"{tag}-a")
    # Start b once a leads, so which one leads is deterministic.
    replicas = [a]
    try:

        def a_leads():
            a.poll_lines()
            return a.instance_id

        _wait_for(a_leads, 60, "the first replica to lead")
        b = Replica(f"{tag}-b")
        replicas.append(b)
        # b is standby: give it time to come up and fail the lock at least once.
        _wait_for(lambda: _lock_sessions(db) >= 2, 60, "the standby's lock session")
        yield db, a, b
    finally:
        for r in replicas:
            r.stop()


def _lock_sessions(db) -> int:
    with db.connect() as conn:
        return conn.execute(
            text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = :d "
                "AND application_name LIKE 'vigil-daemon-lock:%'"
            ),
            {"d": SCRATCH_DB},
        ).scalar()


def _sessions(db, application_name: str) -> int:
    with db.connect() as conn:
        return conn.execute(
            text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = :d "
                "AND application_name = :n"
            ),
            {"d": SCRATCH_DB, "n": application_name},
        ).scalar()


def _rows(db, writer: str) -> list[int]:
    with db.connect() as conn:
        return [
            r[0]
            for r in conn.execute(
                text("SELECT id FROM leader_writes WHERE writer = :w ORDER BY id"),
                {"w": writer},
            )
        ]


def _wait_new_leader(b: Replica, timeout: float) -> float:
    def led():
        b.poll_lines()
        return b.led_at

    return _wait_for(led, timeout, "the standby to take over")


def _assert_fenced(db, old: str, new: str) -> None:
    new_rows = _wait_for(lambda: _rows(db, new), 30, "the new leader's first write")
    old_rows = _rows(db, old)
    assert old_rows, "the old leader never wrote: the test proves nothing"
    assert max(old_rows) < min(new_rows), (
        f"old leader committed row {max(old_rows)} after the new leader's "
        f"first row {min(new_rows)}"
    )


def test_kill_leader_standby_takes_over(pair):
    db, a, b = pair
    _wait_for(lambda: _rows(db, a.instance_id), 30, "the leader's writes")
    assert b.instance_id is None

    killed_at = time.monotonic()
    a.proc.send_signal(signal.SIGKILL)
    led_at = _wait_new_leader(b, RETRY + SLACK)

    assert led_at - killed_at <= RETRY + SLACK
    _assert_fenced(db, a.instance_id, b.instance_id)


def test_graceful_shutdown_hands_over(pair):
    db, a, b = pair
    _wait_for(lambda: _rows(db, a.instance_id), 30, "the leader's writes")

    stopped_at = time.monotonic()
    a.proc.send_signal(signal.SIGTERM)
    assert a.proc.wait(timeout=30) == 0
    led_at = _wait_new_leader(b, RETRY + SLACK)

    assert led_at - stopped_at <= RETRY + SLACK
    _assert_fenced(db, a.instance_id, b.instance_id)


def test_paused_leader_is_fenced_and_exits(pair):
    db, a, b = pair
    _wait_for(lambda: _rows(db, a.instance_id), 30, "the leader's writes")
    # The writer's pooled session, named for the fence.
    assert _sessions(db, f"vigil-daemon:{a.instance_id}") >= 1

    paused_at = time.monotonic()
    a.proc.send_signal(signal.SIGSTOP)
    try:
        led_at = _wait_new_leader(b, LEASE + RETRY + SLACK)
        # The lease is server-side: b cannot lead before it runs out.
        assert led_at - paused_at >= LEASE - 1.0
        assert led_at - paused_at <= LEASE + RETRY + SLACK
        _wait_for(lambda: _rows(db, b.instance_id), 30, "the new leader's writes")
        # The takeover terminated the frozen process's pooled sessions.
        assert _sessions(db, f"vigil-daemon:{a.instance_id}") == 0
        old_before = _rows(db, a.instance_id)
    finally:
        a.proc.send_signal(signal.SIGCONT)

    assert a.proc.wait(timeout=30) == 75
    # Nothing committed by the resumed process.
    assert _rows(db, a.instance_id) == old_before
    _assert_fenced(db, a.instance_id, b.instance_id)
    assert b.proc.poll() is None


def test_partitioned_leader_is_fenced_and_exits(pair):
    db, a, b = pair
    _wait_for(lambda: _rows(db, a.instance_id), 30, "the leader's writes")

    # What the server does to a partitioned holder once the lease runs out.
    with db.connect() as conn:
        ended = conn.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = :d AND application_name = :n"
            ),
            {"d": SCRATCH_DB, "n": f"vigil-daemon-lock:{a.instance_id}"},
        ).fetchall()
    assert ended == [(True,)]
    cut_at = time.monotonic()

    led_at = _wait_new_leader(b, RETRY + SLACK)
    assert led_at - cut_at <= RETRY + SLACK
    # The old process notices on its next heartbeat (lease / 3) and exits.
    assert a.proc.wait(timeout=LEASE + SLACK) == 75
    _assert_fenced(db, a.instance_id, b.instance_id)
