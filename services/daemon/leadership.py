"""Hot standby for the SOC daemon: one leader runs the loops, the rest wait.

With ``DAEMON_LEADER_ELECTION_ENABLED=true`` every daemon process races for
the Postgres advisory lock :data:`LEADER_KEY` (see
:mod:`core.coordination.leader` for the lock, the lease and the fence). The
winner starts every component; the others serve ``/health`` as ``standby`` and
answer the ingest webhook with 503 + ``Retry-After`` until they win.

The heartbeat runs on its own OS thread from the moment the lock is taken,
so nothing the event loop does (a slow synchronous ``_init_components``, a
component blocking the loop) can starve it.

A leader that loses the lock (heartbeat failed, or overdue because the process
was frozen) stops at once and exits with :data:`DEMOTED_EXIT_CODE`; its
in-memory state is not trusted again, the orchestrator restarts it as a
standby. The heartbeat thread tells the loop; if the loop does not get the
process out within :attr:`DaemonLeadership.exit_grace_seconds` (it is blocked)
the thread ends the process itself, well before a standby can take over.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any, Callable, Dict, Optional

from core.coordination.leader import (
    PgLeaderLock,
    UnsupportedServerError,
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


class LeadershipLost(RuntimeError):
    """This process is no longer the leader; it must not start or do work."""


def _hard_exit(code: int) -> None:
    logging.shutdown()
    os._exit(code)


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
        hard_exit: Optional[Callable[[int], None]] = None,
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
        # Own thread: the default executor is shared with every component's
        # blocking DB call, and a heartbeat queued behind them would look
        # like a frozen leader.
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="leader-lock"
        )
        # Heartbeat thread (started on acquisition) and its signals.
        self._hb_thread: Optional[threading.Thread] = None
        self._hb_stop = threading.Event()
        self._lost_flag = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._lost_async: Optional[asyncio.Event] = None
        # Last resort when the loop cannot act on a lost lease (it is blocked):
        # None in tests, os._exit in the daemon (build_daemon_leadership).
        self._hard_exit = hard_exit
        self.exit_grace_seconds = min(1.0, self.heartbeat_seconds / 2)
        _set_gauge(0)

    async def _call(self, fn: Callable[[], Any]) -> Any:
        return await asyncio.get_running_loop().run_in_executor(self._executor, fn)

    @property
    def instance_id(self) -> str:
        return self.lock.instance_id

    @property
    def lost(self) -> bool:
        return self._lost_flag.is_set()

    @property
    def is_leader(self) -> bool:
        return self.role == "leader" and not self.lost

    def ensure_leader(self) -> None:
        """Raise :class:`LeadershipLost` unless this process still leads.

        Checked before every side effect the daemon starts (component start);
        thread-safe, no I/O.
        """
        if not self.is_leader:
            raise LeadershipLost(
                f"{self.instance_id} is not the leader "
                f"({self.lost_reason or self.role})"
            )

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
                got = await self._call(self.lock.try_acquire)
            except UnsupportedServerError:
                # Waiting cannot fix this; crash so the pod status shows it.
                raise
            except Exception as exc:  # noqa: BLE001 - DB down: keep waiting
                logger.warning("Leader lock attempt failed: %s", exc)
                got = False
            if got:
                self.role = "leader"
                self.since = utcnow().isoformat()
                _set_gauge(1)
                # Before anything else runs on the loop (component init may
                # block it for longer than the lease).
                self.start_heartbeat()
                logger.warning("Instance %s is now the daemon leader", self.instance_id)
                return True
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.retry_seconds)
            except asyncio.TimeoutError:
                pass
        return False

    def start_heartbeat(self) -> None:
        """Start the heartbeat thread (idempotent). Call from the event loop."""
        if self._hb_thread is not None:
            return
        try:
            self._loop = asyncio.get_running_loop()
            self._lost_async = asyncio.Event()
        except RuntimeError:  # no loop: thread-only use
            self._loop = None
        self._hb_stop.clear()
        self._hb_thread = threading.Thread(
            target=self._heartbeat_loop, name="leader-heartbeat", daemon=True
        )
        self._hb_thread.start()

    def stop_heartbeat(self, timeout: float = 2.0) -> None:
        self._hb_stop.set()
        thread = self._hb_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    def _heartbeat_loop(self) -> None:
        """Heartbeat until stopped or the lock is lost (then demote).

        The self-demotion deadline is one heartbeat short of the server's
        idle timeout, measured from when the last good heartbeat was sent,
        so a merely slow leader steps down before a standby can take over.
        Runs on its own thread: the event loop being blocked does not delay it.
        """
        try:
            deadline = self._clock() + self.lease_seconds - self.heartbeat_seconds
            while not self._hb_stop.is_set():
                wait = max(0.0, min(self.heartbeat_seconds, deadline - self._clock()))
                if self._hb_stop.wait(wait):
                    return
                sent = self._clock()
                if sent >= deadline:
                    # Woken past the deadline: the process was frozen.
                    self._demote("heartbeat overdue (process paused or starved)")
                    return
                future = self._executor.submit(self.lock.heartbeat)
                try:
                    ok = bool(future.result(timeout=max(0.1, deadline - sent)))
                except FutureTimeout:
                    ok = False
                except Exception as exc:  # noqa: BLE001 - a failed beat is a loss
                    logger.warning("leader heartbeat raised: %s", exc)
                    ok = False
                if self._hb_stop.is_set():
                    return
                if not ok:
                    self._demote("lost the leader lock")
                    return
                deadline = sent + self.lease_seconds - self.heartbeat_seconds
        except Exception:  # noqa: BLE001 - never leave a silent leader behind
            logger.exception("leader heartbeat thread failed")
            self._demote("heartbeat thread failed")

    async def hold(self, stop: asyncio.Event) -> None:
        """Wait until ``stop`` is set or the lock is lost (sets lost_reason).

        Starts the heartbeat thread if acquisition did not already.
        """
        self.start_heartbeat()
        if self.lost:
            return
        assert self._lost_async is not None
        stop_wait = asyncio.ensure_future(stop.wait())
        lost_wait = asyncio.ensure_future(self._lost_async.wait())
        try:
            await asyncio.wait(
                {stop_wait, lost_wait}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for fut in (stop_wait, lost_wait):
                fut.cancel()

    def _demote(self, reason: str) -> None:
        """Mark the lease lost; tell the loop; arm the last-resort exit."""
        if self._lost_flag.is_set():
            return
        self.lost_reason = reason
        self.role = "demoted"
        self._lost_flag.set()
        _set_gauge(0)
        logger.critical(
            "Instance %s is no longer the daemon leader: %s", self.instance_id, reason
        )
        loop, lost_async = self._loop, self._lost_async
        if loop is not None and lost_async is not None:
            try:
                loop.call_soon_threadsafe(lost_async.set)
            except RuntimeError:  # loop closed
                pass
        if self._hard_exit is not None and threading.current_thread() is not (
            threading.main_thread()
        ):
            # The loop normally exits with 75 within milliseconds. If it is
            # blocked (slow init, a component stuck in a sync call) nothing
            # that started as leader may keep running into the next leader's
            # term: the standby can take over one heartbeat after this point
            # at the earliest, so end the process before then.
            if not self._hb_stop.wait(self.exit_grace_seconds):
                logger.critical(
                    "Event loop did not stop within %.1fs of losing leadership; "
                    "exiting %d",
                    self.exit_grace_seconds,
                    DEMOTED_EXIT_CODE,
                )
                self._hard_exit(DEMOTED_EXIT_CODE)

    async def release(self) -> None:
        """Give the lock up on a clean shutdown so a standby takes over at once."""
        if self.lost:
            return
        self.stop_heartbeat()
        try:
            await asyncio.wait_for(self._call(self.lock.release), timeout=5)
        except Exception as exc:  # noqa: BLE001 - exiting closes the session anyway
            logger.warning("Leader lock release failed: %s", exc)
        self.role = "standby"
        _set_gauge(0)
        self._executor.shutdown(wait=False)


def _db_config(engine: Any) -> Any:
    """The platform DatabaseConfig behind ``engine``, when there is one."""
    try:
        from core.storage.connection import get_db_manager

        manager = get_db_manager()
        if manager.engine is engine:
            return manager.config
    except Exception:  # noqa: BLE001 - only used to spot a pooler
        pass
    return None


def leader_connect_factory(
    settings: Any, *, manager_config: Any = None
) -> Optional[Callable[..., Any]]:
    """Connect function for the lock session, or None to use the platform DB.

    ``DAEMON_LEADER_DATABASE_URL`` (a direct Postgres DSN) wins. Without it, a
    platform DB reached through the PgBouncer proxy is refused here: the lock
    needs one real server session (see core.coordination.leader); the probe in
    PgLeaderLock catches a pooler the configuration does not name.
    """
    import psycopg2

    dsn = (getattr(settings, "daemon_leader_database_url", "") or "").strip()
    if dsn:
        # Accept a SQLAlchemy URL too.
        for prefix in ("postgresql+psycopg2://", "postgres+psycopg2://"):
            if dsn.startswith(prefix):
                dsn = "postgresql://" + dsn[len(prefix) :]

        def connect(**extra: Any) -> Any:
            return psycopg2.connect(dsn, **extra)

        return connect
    proxy = getattr(manager_config, "proxy", None)
    if proxy is not None and getattr(proxy, "proxy_type", "") == "pgbouncer":
        raise UnsupportedServerError(
            "the platform database is reached through PgBouncer; leader "
            "election needs a direct session for its advisory lock. Set "
            "DAEMON_LEADER_DATABASE_URL to a direct Postgres DSN (or turn "
            "DAEMON_LEADER_ELECTION_ENABLED off)."
        )
    return None


def build_daemon_leadership(
    settings: Any = None, engine: Any = None
) -> DaemonLeadership:
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
    connect = leader_connect_factory(settings, manager_config=_db_config(engine))
    if connect is None:
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
        hard_exit=_hard_exit,
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
