"""Daemon hot standby (W3.9): the async driver and SOCDaemon's use of it.

The lock is faked here; tests/integration/test_daemon_leader_election.py and
tests/unit/coordination run the real one against Postgres.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest

from services.daemon import leadership as leadership_mod
from services.daemon.config import DaemonConfig, MetricsConfig
from services.daemon.leadership import (
    DEMOTED_EXIT_CODE,
    DaemonLeadership,
    StandbyWebhook,
)
from services.daemon.main import SOCDaemon
from services.daemon.metrics import MetricsServer

pytestmark = pytest.mark.unit


class FakeLock:
    def __init__(self, acquire=(True,), heartbeat=(True,)):
        self.instance_id = "test-1"
        self._acquire = list(acquire)
        self._heartbeat = list(heartbeat)
        self.acquire_calls = 0
        self.heartbeat_calls = 0
        self.released = False

    def try_acquire(self):
        self.acquire_calls += 1
        if len(self._acquire) > 1:
            value = self._acquire.pop(0)
        else:
            value = self._acquire[0]
        if isinstance(value, Exception):
            raise value
        return value

    def heartbeat(self):
        self.heartbeat_calls += 1
        return (
            self._heartbeat.pop(0) if len(self._heartbeat) > 1 else self._heartbeat[0]
        )

    def release(self):
        self.released = True


def _leadership(lock, *, lease=3.0, retry=0.01, clock=None, hard_exit=None):
    kwargs = {"clock": clock} if clock else {}
    return DaemonLeadership(
        lock, retry_seconds=retry, lease_seconds=lease, hard_exit=hard_exit, **kwargs
    )


# -- DaemonLeadership ---------------------------------------------------------------


def test_settings_are_validated():
    with pytest.raises(ValueError):
        _leadership(FakeLock(), lease=2.0)
    with pytest.raises(ValueError):
        _leadership(FakeLock(), lease=5.0, retry=5.0)
    with pytest.raises(ValueError):
        _leadership(FakeLock(), lease=5.0, retry=0)


@pytest.mark.asyncio
async def test_standby_retries_until_it_wins_and_survives_db_errors():
    lock = FakeLock(acquire=[False, OSError("db down"), False, True])
    lead = _leadership(lock)
    assert lead.role == "standby"

    assert await lead.wait_for_leadership(asyncio.Event()) is True
    assert lock.acquire_calls == 4
    assert lead.role == "leader" and lead.since


@pytest.mark.asyncio
async def test_unsupported_server_is_fatal_not_a_silent_standby():
    from core.coordination.leader import UnsupportedServerError

    lead = _leadership(FakeLock(acquire=[UnsupportedServerError("pg 13")]))
    with pytest.raises(UnsupportedServerError):
        await asyncio.wait_for(lead.wait_for_leadership(asyncio.Event()), 2)


@pytest.mark.asyncio
async def test_standby_stops_waiting_on_shutdown():
    lead = _leadership(FakeLock(acquire=[False]))
    stop = asyncio.Event()
    waiter = asyncio.create_task(lead.wait_for_leadership(stop))
    await asyncio.sleep(0.05)
    stop.set()
    assert await asyncio.wait_for(waiter, 2) is False
    assert lead.role == "standby"


@pytest.mark.asyncio
async def test_failed_heartbeat_demotes():
    lead = _leadership(FakeLock(heartbeat=[True, False]), lease=3.0)
    lead.heartbeat_seconds = 0.01  # do not wait a second per beat
    await asyncio.wait_for(lead.hold(asyncio.Event()), 5)
    assert lead.lost and lead.role == "demoted"
    assert "lost" in lead.lost_reason


@pytest.mark.asyncio
async def test_overdue_heartbeat_demotes_without_asking_the_db():
    """Woken after the deadline (the process was frozen): step down at once."""
    reads = []

    def clock():
        # First read sets the deadline; every later one is a minute on
        # (SIGSTOP for a minute).
        reads.append(1)
        return 100.0 if len(reads) == 1 else 160.0

    lock = FakeLock()
    lead = _leadership(lock, lease=3.0, clock=clock)
    lead.heartbeat_seconds = 0.01
    await asyncio.wait_for(lead.hold(asyncio.Event()), 5)
    assert lead.lost and "overdue" in lead.lost_reason
    assert lock.heartbeat_calls == 0


@pytest.mark.asyncio
async def test_hold_returns_on_shutdown_without_demotion():
    lead = _leadership(FakeLock())
    stop = asyncio.Event()
    stop.set()
    await asyncio.wait_for(lead.hold(stop), 2)
    assert not lead.lost


@pytest.mark.asyncio
async def test_release_skipped_after_demotion():
    lock = FakeLock()
    lead = _leadership(lock)
    lead._demote("test")
    await lead.release()
    assert lock.released is False


# -- health / status / standby webhook ----------------------------------------------


@pytest.mark.asyncio
async def test_standby_health_is_200_with_role():
    server = MetricsServer(MetricsConfig())
    server.leadership = _leadership(FakeLock())
    resp = await server._handle_health(None)
    body = json.loads(resp.body)
    assert resp.status == 200
    assert body["status"] == "standby" and body["role"] == "standby"


@pytest.mark.asyncio
async def test_health_without_election_reports_single():
    server = MetricsServer(MetricsConfig())
    resp = await server._handle_health(None)
    assert json.loads(resp.body)["role"] == "single"


@pytest.mark.asyncio
async def test_status_carries_leadership(monkeypatch):
    server = MetricsServer(MetricsConfig())
    server.leadership = _leadership(FakeLock())
    monkeypatch.setattr(server, "_collect_metrics", lambda: {"vendors": {}})
    resp = await server._handle_status(None)
    leadership = json.loads(resp.body)["leadership"]
    assert leadership["role"] == "standby"
    assert leadership["instance_id"] == "test-1"


@pytest.mark.asyncio
async def test_standby_webhook_answers_503_with_retry_after():
    from aiohttp.test_utils import TestClient, TestServer

    async with TestClient(TestServer(StandbyWebhook.app())) as client:
        resp = await client.post("/ingest", json={"finding_id": "x"})
        assert resp.status == 503
        assert resp.headers["Retry-After"] == "2"
        assert "standby" in (await resp.json())["error"]
        resp = await client.post("/webhook", json=[])
        assert resp.status == 503
        resp = await client.get("/health")
        assert resp.status == 200


# -- SOCDaemon --------------------------------------------------------------------


def _daemon(
    monkeypatch, lock, *, init_seconds=0.0, lease=3.0, heartbeat=0.01, hard_exit=None
):
    daemon = SOCDaemon.__new__(SOCDaemon)
    daemon.config = DaemonConfig()
    daemon.config.metrics.enabled = False
    daemon.config.polling.webhook_enabled = False
    daemon._shutdown_event = asyncio.Event()
    daemon._running = False
    for name in (
        "_poller",
        "_kafka_ingestor",
        "_processor",
        "_responder",
        "_scheduler",
        "_orchestrator",
        "_metrics_server",
        "_mcp_client",
        "_case_automation",
        "_leadership",
    ):
        setattr(daemon, name, None)
    daemon.inits = 0

    class Component:
        def __init__(self):
            self.started = asyncio.Event()

        async def run(self, shutdown):
            self.started.set()
            await shutdown.wait()

    async def init_components():
        daemon.inits += 1
        if init_seconds:
            # Synchronous on purpose: blocks the event loop, as a slow
            # production init (imports, client construction) does.
            time.sleep(init_seconds)
        daemon._scheduler = Component()

    lead = _leadership(lock, lease=lease, hard_exit=hard_exit)
    if heartbeat is not None:
        lead.heartbeat_seconds = heartbeat
    monkeypatch.setattr(daemon, "_init_components", init_components)
    monkeypatch.setattr(daemon, "_setup_signal_handlers", lambda: None)
    monkeypatch.setattr(
        SOCDaemon, "_leader_election_enabled", staticmethod(lambda: True)
    )
    monkeypatch.setattr(leadership_mod, "build_daemon_leadership", lambda: lead)
    return daemon, lead


@pytest.mark.asyncio
async def test_standby_starts_no_component(monkeypatch):
    lock = FakeLock(acquire=[False])
    daemon, _lead = _daemon(monkeypatch, lock)
    run = asyncio.create_task(daemon.run())
    await asyncio.sleep(0.2)
    assert daemon.inits == 0 and lock.acquire_calls >= 2
    daemon._shutdown_event.set()
    await asyncio.wait_for(run, 5)
    assert daemon.inits == 0


@pytest.mark.asyncio
async def test_leader_starts_components_and_releases_on_shutdown(monkeypatch):
    lock = FakeLock(acquire=[False, True])
    daemon, lead = _daemon(monkeypatch, lock)
    run = asyncio.create_task(daemon.run())
    await asyncio.wait_for(_until(lambda: daemon._scheduler is not None), 5)
    await asyncio.wait_for(daemon._scheduler.started.wait(), 5)
    assert daemon.inits == 1 and lead.role == "leader"
    daemon._shutdown_event.set()
    await asyncio.wait_for(run, 5)
    assert lock.released is True


@pytest.mark.asyncio
async def test_lost_leadership_exits_75(monkeypatch):
    lock = FakeLock(acquire=[True], heartbeat=[True, True, False])
    daemon, _lead = _daemon(monkeypatch, lock)
    exits = []

    def fake_exit(code):
        exits.append(code)
        raise SystemExit(code)

    monkeypatch.setattr("services.daemon.main.os._exit", fake_exit)
    with pytest.raises(SystemExit):
        await asyncio.wait_for(daemon.run(), 5)
    assert exits == [DEMOTED_EXIT_CODE]
    assert daemon.inits == 1
    assert lock.released is False


class ServerLikeLock(FakeLock):
    """Behaves like the server's idle_session_timeout: a heartbeat that comes
    more than ``lease`` after the previous contact finds the lock gone."""

    def __init__(self, lease):
        super().__init__()
        self.lease = lease
        self.last = None
        self.beat_times = []

    def try_acquire(self):
        self.last = time.monotonic()
        return super().try_acquire()

    def heartbeat(self):
        now = time.monotonic()
        self.heartbeat_calls += 1
        self.beat_times.append(now)
        ok = self.last is not None and now - self.last <= self.lease
        self.last = now if ok else None
        return ok


@pytest.mark.asyncio
async def test_slow_blocking_init_keeps_leadership(monkeypatch):
    """Round 5: init that blocks the loop for longer than the lease must not
    cost the lock: the heartbeat runs on its own thread from acquisition."""
    lease = 3.0
    lock = ServerLikeLock(lease)
    daemon, lead = _daemon(
        monkeypatch, lock, init_seconds=lease + 1.0, lease=lease, heartbeat=None
    )
    run = asyncio.create_task(daemon.run())
    await asyncio.wait_for(_until(lambda: daemon._scheduler is not None), 15)
    await asyncio.wait_for(daemon._scheduler.started.wait(), 5)
    # Beats kept coming while the loop was blocked in init.
    assert lock.heartbeat_calls >= 3
    assert not lead.lost and lead.role == "leader"
    gaps = [b - a for a, b in zip(lock.beat_times, lock.beat_times[1:])]
    assert max(gaps) < lease
    daemon._shutdown_event.set()
    await asyncio.wait_for(run, 5)
    assert lock.released is True


@pytest.mark.asyncio
async def test_lease_lost_during_slow_init_starts_no_component(monkeypatch):
    """Round 5: the lease is lost while init blocks the loop. The heartbeat
    thread ends the process (hard exit) within the grace, and should the
    loop still get control nothing is started and it exits 75."""
    lock = FakeLock(acquire=[True], heartbeat=[False])
    hard_exits = []
    exited = threading.Event()

    def hard_exit(code):
        hard_exits.append((code, time.monotonic()))
        exited.set()

    daemon, lead = _daemon(
        monkeypatch,
        lock,
        init_seconds=3.0,
        lease=3.0,
        heartbeat=None,  # 1 s: the first beat fails while init still blocks
        hard_exit=hard_exit,
    )
    exits = []

    def fake_exit(code):
        exits.append(code)
        raise SystemExit(code)

    monkeypatch.setattr("services.daemon.main.os._exit", fake_exit)
    started = time.monotonic()
    with pytest.raises(SystemExit):
        await asyncio.wait_for(daemon.run(), 15)
    assert exits == [DEMOTED_EXIT_CODE]
    assert daemon.inits == 1
    # Init finished, but the component was never started.
    assert daemon._scheduler is not None
    assert not daemon._scheduler.started.is_set()
    # The thread did not wait for the blocked loop: it exited inside init,
    # one heartbeat + the grace after acquisition.
    assert exited.is_set()
    code, at = hard_exits[0]
    assert code == DEMOTED_EXIT_CODE
    assert at - started < lead.heartbeat_seconds + lead.exit_grace_seconds + 1.0
    assert lead.lost and lock.released is False


@pytest.mark.asyncio
async def test_start_refuses_once_leadership_is_lost(monkeypatch):
    """ensure_leader is checked before every component start."""
    lock = FakeLock(acquire=[True])
    daemon, lead = _daemon(monkeypatch, lock)

    async def init_components():
        daemon.inits += 1
        lead._demote("lost during init")

    monkeypatch.setattr(daemon, "_init_components", init_components)
    monkeypatch.setattr(
        "services.daemon.main.os._exit",
        lambda code: (_ for _ in ()).throw(SystemExit(code)),
    )
    with pytest.raises(SystemExit) as exc:
        await asyncio.wait_for(daemon.run(), 5)
    assert exc.value.code == DEMOTED_EXIT_CODE
    assert daemon._scheduler is None


def test_ensure_leader():
    from services.daemon.leadership import LeadershipLost

    lead = _leadership(FakeLock())
    with pytest.raises(LeadershipLost):
        lead.ensure_leader()  # standby
    lead.role = "leader"
    lead.ensure_leader()
    lead._demote("x")
    with pytest.raises(LeadershipLost):
        lead.ensure_leader()


async def _until(predicate):
    while not predicate():
        await asyncio.sleep(0.01)


def test_disabled_election_by_default():
    from core.config import Settings

    assert Settings.model_fields["daemon_leader_election_enabled"].default is False
