"""Hot standby for the SOC daemon: one leader runs the loops, the rest wait.

With ``DAEMON_LEADER_ELECTION_ENABLED=true`` every daemon process races for
the Postgres advisory lock :data:`LEADER_KEY` (see
:mod:`core.coordination.leader` for the lock, the lease and the fence). The
winner starts every component; the others serve ``/health`` as ``standby`` and
answer the ingest webhook with 503 + ``Retry-After`` until they win.

A leader that loses the lock (heartbeat failed, or overdue because the process
was frozen) stops at once and exits with :data:`DEMOTED_EXIT_CODE`; its
in-memory state is not trusted again, the orchestrator restarts it as a
standby.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, Optional

from core.coordination.leader import (
    PgLeaderLock,
    connect_args_from_engine,
    install_connection_fence,
    make_instance_id,
)
from core.time import utcnow

logger = logging.getLogger(__name__)

LEADER_KEY = (1287, 3900)  # (1287, 1) is the backup lock (core/backup/create.py)
GROUP = "vigil-daemon"
DEMOTED_EXIT_CODE = 75  # EX_TEMPFAIL
STANDBY_RETRY_AFTER = 2

_leader_gauge: Any = None


def _set_gauge(value: float) -> None:
    global _leader_gauge
    try:
        if _leader_gauge is None:
            from prometheus_client import Gauge

            _leader_gauge = Gauge(
                "soc_daemon_leader", "1 when this daemon process is the leader."
            )
        _leader_gauge.set(value)
    except Exception as exc:  # noqa: BLE001 - metrics never stop election
        logger.debug("leader gauge unavailable: %s", exc)


class DaemonLeadership:
    """Async driver around a :class:`PgLeaderLock`."""

    def __init__(
        self,
        lock: PgLeaderLock,
        *,
        retry_seconds: float,
        lease_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if lease_seconds < 3:
            raise ValueError("DAEMON_LEADER_LEASE_SECONDS must be at least 3")
        if not 0 < retry_seconds < lease_seconds:
            raise ValueError(
                "DAEMON_LEADER_RETRY_SECONDS must be positive and below the lease"
            )
        self.lock = lock
        self.retry_seconds = float(retry_seconds)
        self.lease_seconds = float(lease_seconds)
        self.heartbeat_seconds = self.lease_seconds / 3
        self._clock = clock
        self.role = "standby"
        self.since: Optional[str] = None
        self.lost_reason: Optional[str] = None
        self._remove_fence: Optional[Callable[[], None]] = None
        _set_gauge(0)

    @property
    def instance_id(self) -> str:
        return self.lock.instance_id

    @property
    def lost(self) -> bool:
        return self.lost_reason is not None

    def snapshot(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "instance_id": self.instance_id,
            "since": self.since,
            "lease_seconds": self.lease_seconds,
            "lost_reason": self.lost_reason,
        }

    def install_fence(self) -> None:
        self._remove_fence = install_connection_fence(self.lock)

    def remove_fence(self) -> None:
        if self._remove_fence is not None:
            self._remove_fence()
            self._remove_fence = None

    async def wait_for_leadership(self, stop: asyncio.Event) -> bool:
        """Poll the lock until it is ours (True) or ``stop`` is set (False)."""
        logger.info(
            "Standby %s: waiting for the leader lock (retry %.1fs, lease %.1fs)",
            self.instance_id,
            self.retry_seconds,
            self.lease_seconds,
        )
        while not stop.is_set():
            try:
                got = await asyncio.to_thread(self.lock.try_acquire)
            except Exception as exc:  # noqa: BLE001 - DB down: keep waiting
                logger.warning("Leader lock attempt failed: %s", exc)
                got = False
            if got:
                self.role = "leader"
                self.since = utcnow().isoformat()
                _set_gauge(1)
                logger.warning("Instance %s is now the daemon leader", self.instance_id)
                return True
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.retry_seconds)
            except asyncio.TimeoutError:
                pass
        return False

    async def hold(self, stop: asyncio.Event) -> None:
        """Heartbeat until ``stop`` is set or the lock is lost (sets lost_reason).

        The self-demotion deadline is one heartbeat short of the server's
        idle timeout, measured from when the last good heartbeat was sent,
        so a merely slow leader steps down before a standby can take over.
        """
        margin = self.heartbeat_seconds
        deadline = self._clock() + self.lease_seconds - margin
        while not stop.is_set():
            wait = max(0.0, min(self.heartbeat_seconds, deadline - self._clock()))
            try:
                await asyncio.wait_for(stop.wait(), timeout=wait)
                return
            except asyncio.TimeoutError:
                pass
            sent = self._clock()
            if sent >= deadline:
                # Woken past the deadline: the process was frozen.
                self._demote("heartbeat overdue (process paused or starved)")
                return
            try:
                ok = await asyncio.wait_for(
                    asyncio.to_thread(self.lock.heartbeat),
                    timeout=max(0.1, deadline - sent),
                )
            except asyncio.TimeoutError:
                ok = False
            if not ok:
                self._demote("lost the leader lock")
                return
            deadline = sent + self.lease_seconds - margin

    def _demote(self, reason: str) -> None:
        self.role = "demoted"
        self.lost_reason = reason
        _set_gauge(0)
        logger.critical(
            "Instance %s is no longer the daemon leader: %s", self.instance_id, reason
        )

    async def release(self) -> None:
        """Give the lock up on a clean shutdown so a standby takes over at once."""
        if self.lost:
            return
        try:
            await asyncio.wait_for(asyncio.to_thread(self.lock.release), timeout=5)
        except Exception as exc:  # noqa: BLE001 - exiting closes the session anyway
            logger.warning("Leader lock release failed: %s", exc)
        self.role = "standby"
        _set_gauge(0)


def build_daemon_leadership(settings: Any = None, engine: Any = None) -> DaemonLeadership:
    """Leadership for this process from settings, on the platform DB engine."""
    import psycopg2

    if settings is None:
        from core.config import get_settings

        settings = get_settings()
    if engine is None:
        from core.storage.connection import get_db_manager

        manager = get_db_manager()
        if manager.engine is None:
            manager.initialize()
        engine = manager.engine
    cargs, cparams = connect_args_from_engine(engine)

    def connect(**extra: Any) -> Any:
        return psycopg2.connect(*cargs, **{**cparams, **extra})

    lock = PgLeaderLock(
        connect,
        key=LEADER_KEY,
        group=GROUP,
        instance_id=make_instance_id(),
        lease_seconds=settings.daemon_leader_lease_seconds,
    )
    leadership = DaemonLeadership(
        lock,
        retry_seconds=settings.daemon_leader_retry_seconds,
        lease_seconds=settings.daemon_leader_lease_seconds,
    )
    # Pooled connections opened before the fence (startup checks) are unnamed
    # and unchecked; drop them so every connection from here on is fenced.
    engine.dispose()
    leadership.install_fence()
    return leadership


class StandbyWebhook:
    """Holds the ingest port while standby: 503 + Retry-After, /health 200."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self._runner: Any = None

    @staticmethod
    def app() -> Any:
        from aiohttp import web

        async def standby(request: web.Request) -> web.Response:
            return web.json_response(
                {"error": "standby: not the leader"},
                status=503,
                headers={"Retry-After": str(STANDBY_RETRY_AFTER)},
            )

        async def health(request: web.Request) -> web.Response:
            return web.json_response({"status": "standby"})

        app = web.Application()
        app.router.add_post("/ingest", standby)
        app.router.add_post("/webhook", standby)
        app.router.add_get("/health", health)
        return app

    async def start(self) -> None:
        from aiohttp import web

        runner = web.AppRunner(self.app())
        await runner.setup()
        try:
            await web.TCPSite(runner, self.host, self.port).start()
        except OSError as exc:
            logger.error("Standby webhook failed to bind port %s: %s", self.port, exc)
            await runner.cleanup()
            return
        self._runner = runner

    async def stop(self) -> None:
        runner, self._runner = self._runner, None
        if runner is not None:
            await runner.cleanup()
