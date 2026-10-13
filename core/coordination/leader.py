"""Leader election on a Postgres session advisory lock, with write fencing.

Several replicas of a process race for one advisory lock; the holder is the
leader. The lock lives on a dedicated connection, so it is released the moment
that session ends:

* the process dies or closes the connection — the server sees the socket close
  and drops the lock at once;
* the process freezes (SIGSTOP, a long GC, a VM pause) or the network between
  it and the server goes away — nothing closes the socket, so the lock session
  carries ``idle_session_timeout = lease``. The leader heartbeats every
  ``lease / 3``; after ``lease`` seconds of silence the server terminates the
  session and the lock is free.

A frozen leader that resumes may still believe it leads for a moment, so the
lock alone does not stop it writing. Fencing closes that gap at the database:

1. Every SQLAlchemy connection the process opens is named
   ``<group>:<instance>`` (``application_name``) and, on connect, checks that
   the lock is held by ``<group>-lock:<instance>``. Anyone else, or nobody,
   holding it refuses the connection (:class:`FencedError`).
2. A new leader, right after taking the lock, terminates every
   ``<group>:*`` session that is not its own and waits for them to exit, so
   transactions the old leader had in flight are rolled back.

A connection that passed the check did so while its owner held the lock, so it
existed before the new leader could take the lock and is caught by step 2; a
connection opened afterwards fails step 1. Effects outside this database
(Redis, vendor APIs) are not fenced; see docs/operations/rpo-rto.md.

Requires PostgreSQL 14+ (``idle_session_timeout`` and the waiting form of
``pg_terminate_backend``), reached directly or through a session-pooling
proxy. A transaction- or statement-pooling proxy (PgBouncer's default
``pool_mode = transaction``) hands each statement whatever server session is
free, so a session advisory lock and ``SET idle_session_timeout`` stop
meaning anything; :meth:`PgLeaderLock._open` probes for that and refuses
(:class:`PooledConnectionError`).
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import uuid
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# NAMEDATALEN - 1: Postgres truncates application_name to 63 bytes.
_APP_NAME_MAX = 63
MIN_SERVER_VERSION_NUM = 140000

_HOLDER_SQL = """
SELECT a.application_name
FROM pg_catalog.pg_locks l
JOIN pg_catalog.pg_stat_activity a ON a.pid = l.pid
WHERE l.locktype = 'advisory'
  AND l.granted
  AND l.database = (SELECT oid FROM pg_catalog.pg_database
                    WHERE datname = current_database())
  AND l.classid = %s::oid
  AND l.objid = %s::oid
  AND l.objsubid = 2
"""

# Sessions of the same group that are not ours, in this database.
_SWEEP_SQL = """
SELECT pid, application_name, pg_catalog.pg_terminate_backend(pid, %s)
FROM pg_catalog.pg_stat_activity
WHERE datname = current_database()
  AND pid <> pg_catalog.pg_backend_pid()
  AND application_name LIKE %s
  AND application_name <> %s
"""


class UnsupportedServerError(RuntimeError):
    """The server cannot enforce the lease (PostgreSQL older than 14)."""


class PooledConnectionError(UnsupportedServerError):
    """The lock connection goes through a transaction/statement-pooling proxy."""


class FencedError(RuntimeError):
    """This process does not hold the leader lock, so it may not open a connection."""


def make_instance_id() -> str:
    """Host name plus a random suffix: unique per process start."""
    host = socket.gethostname().split(".")[0] or "host"
    return f"{host[:30]}-{os.getpid()}-{uuid.uuid4().hex[:6]}"


def _app_name(prefix: str, instance_id: str) -> str:
    name = f"{prefix}:{instance_id}"
    if len(name.encode()) > _APP_NAME_MAX:
        raise ValueError(f"application_name {name!r} is longer than 63 bytes")
    return name


def data_app_name(group: str, instance_id: str) -> str:
    return _app_name(group, instance_id)


def lock_app_name(group: str, instance_id: str) -> str:
    return _app_name(f"{group}-lock", instance_id)


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def connect_args_from_engine(engine: Any) -> Tuple[tuple, Dict[str, Any]]:
    """psycopg2 ``connect`` arguments for the engine's target (proxy included).

    Used to open the lock connection outside the engine's pool, so the fence
    listener and pool recycling never touch it.
    """
    cargs, cparams = engine.dialect.create_connect_args(engine.url)
    return tuple(cargs), dict(cparams)


class PgLeaderLock:
    """One replica's handle on the leader lock. Blocking; call from a thread.

    ``connect`` returns a new psycopg2 connection (any target); the lock
    session is configured here. Methods are serialized by an internal mutex.
    """

    def __init__(
        self,
        connect: Callable[..., Any],
        *,
        key: Tuple[int, int],
        group: str,
        instance_id: str,
        lease_seconds: float,
        terminate_wait_ms: int = 5000,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self._connect = connect
        self.key = (int(key[0]), int(key[1]))
        self.group = group
        self.instance_id = instance_id
        self.lease_seconds = float(lease_seconds)
        self.terminate_wait_ms = int(terminate_wait_ms)
        self.lock_name = lock_app_name(group, instance_id)
        self.data_name = data_app_name(group, instance_id)
        self._conn: Any = None
        self._held = False
        self._mutex = threading.Lock()

    # -- connection -----------------------------------------------------------

    def _open(self) -> Any:
        lease_ms = max(1, int(self.lease_seconds * 1000))
        conn = self._connect(
            application_name=self.lock_name,
            # Client side: notice a dead server instead of waiting on the OS.
            keepalives=1,
            keepalives_idle=max(1, int(self.lease_seconds / 3)),
            keepalives_interval=max(1, int(self.lease_seconds / 6)),
            keepalives_count=3,
            connect_timeout=max(2, int(self.lease_seconds / 3)),
        )
        try:
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute("SELECT current_setting('server_version_num')::int")
            version = int(cur.fetchone()[0])
            if version < MIN_SERVER_VERSION_NUM:
                raise UnsupportedServerError(
                    f"leader election needs PostgreSQL 14+ (server is {version})"
                )
            self._refuse_pooled(conn, cur)
            # Server side: a frozen or partitioned holder loses the lock after
            # `lease` seconds without a heartbeat.
            cur.execute("SET idle_session_timeout = %s", (lease_ms,))
            # A heartbeat stuck behind a lock must not outlive the lease.
            cur.execute("SET statement_timeout = %s", (lease_ms,))
            cur.close()
        except BaseException:
            _close_quietly(conn)
            raise
        return conn

    def _refuse_pooled(self, conn: Any, cur: Any) -> None:
        """Raise :class:`PooledConnectionError` if ``conn`` is not one session.

        A second client connection runs one statement (it does not hold a
        transaction, so a pool of one cannot deadlock). Directly on Postgres
        the two always have different backends and ``conn`` keeps its own
        backend and session setting. Behind a transaction pooler the second
        connection is usually handed the backend ``conn`` just released (LIFO),
        and ``conn``'s next statement then sees a foreign backend pid or loses
        its session setting.
        """
        token = uuid.uuid4().hex
        cur.execute(
            "SELECT pg_catalog.pg_backend_pid(), "
            "pg_catalog.set_config('vigil.leader_probe', %s, false)",
            (token,),
        )
        pid_before = int(cur.fetchone()[0])
        other = self._connect(
            application_name=self.lock_name,
            connect_timeout=max(2, int(self.lease_seconds / 3)),
        )
        try:
            other.autocommit = True
            ocur = other.cursor()
            ocur.execute(
                "SELECT pg_catalog.pg_backend_pid(), "
                "pg_catalog.set_config('vigil.leader_probe', 'other', false)"
            )
            pid_other = int(ocur.fetchone()[0])
            ocur.close()
        finally:
            _close_quietly(other)
        cur.execute(
            "SELECT pg_catalog.pg_backend_pid(), "
            "pg_catalog.current_setting('vigil.leader_probe', true)"
        )
        pid_after, seen = cur.fetchone()
        if pid_other == pid_before or int(pid_after) != pid_before or seen != token:
            raise PooledConnectionError(
                "leader election needs a dedicated Postgres session, but this "
                "connection is pooled per transaction or statement (PgBouncer "
                "pool_mode=transaction?): session advisory locks and "
                "idle_session_timeout do not work there. Point "
                "DAEMON_LEADER_DATABASE_URL at Postgres directly (or at a "
                "session-mode pool)."
            )

    def _drop(self) -> None:
        conn, self._conn = self._conn, None
        self._held = False
        if conn is not None:
            _close_quietly(conn)

    # -- public ----------------------------------------------------------------

    @property
    def held(self) -> bool:
        return self._held

    def try_acquire(self) -> bool:
        """Take the lock if free. True when this replica is (now) the leader.

        On success the previous holder's sessions are terminated (fencing)
        before this returns.
        """
        with self._mutex:
            if self._held:
                return True
            try:
                if self._conn is None:
                    self._conn = self._open()
                cur = self._conn.cursor()
                cur.execute("SELECT pg_try_advisory_lock(%s, %s)", self.key)
                got = bool(cur.fetchone()[0])
                cur.close()
            except Exception:
                self._drop()
                raise
            if not got:
                return False
            self._held = True
            try:
                self._sweep()
            except Exception:
                # Leading without having fenced the old holder is not safe.
                logger.exception("leader lock taken but fencing sweep failed")
                self._drop()
                raise
            return True

    def _sweep(self) -> None:
        pattern = _like_escape(f"{self.group}:") + "%"
        cur = self._conn.cursor()
        cur.execute(_SWEEP_SQL, (self.terminate_wait_ms, pattern, self.data_name))
        rows = cur.fetchall()
        cur.close()
        for pid, name, done in rows:
            if done:
                logger.warning("fenced previous session pid=%s (%s)", pid, name)
            else:
                raise RuntimeError(
                    f"session pid={pid} ({name}) did not exit within "
                    f"{self.terminate_wait_ms} ms"
                )

    def heartbeat(self) -> bool:
        """Keep the lock session alive; False when the lock has been lost."""
        with self._mutex:
            if not self._held or self._conn is None:
                return False
            try:
                cur = self._conn.cursor()
                cur.execute(_HOLDER_SQL, self.key)
                row = cur.fetchone()
                cur.close()
            except Exception as exc:  # noqa: BLE001 - a dead session is a lost lock
                logger.warning("leader heartbeat failed: %s", exc)
                self._drop()
                return False
            if not row or row[0] != self.lock_name:
                logger.warning("leader lock is no longer ours (holder=%s)", row)
                self._drop()
                return False
            return True

    def release(self) -> None:
        with self._mutex:
            if self._conn is not None and self._held:
                try:
                    cur = self._conn.cursor()
                    cur.execute("SELECT pg_advisory_unlock(%s, %s)", self.key)
                    cur.close()
                except Exception:  # noqa: BLE001 - closing drops it anyway
                    pass
            self._drop()


def _close_quietly(conn: Any) -> None:
    try:
        conn.close()
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Connection fence
# ---------------------------------------------------------------------------


def check_holder(cursor: Any, key: Tuple[int, int]) -> Optional[str]:
    """application_name of the session holding ``key``, or None."""
    cursor.execute(_HOLDER_SQL, (int(key[0]), int(key[1])))
    row = cursor.fetchone()
    return row[0] if row else None


def install_connection_fence(lock: PgLeaderLock) -> Callable[[], None]:
    """Fence every new SQLAlchemy connection in this process on ``lock``.

    Returns a function that removes the listener. Non-psycopg2 connections
    (SQLite in tests) are left alone.
    """
    from sqlalchemy import event
    from sqlalchemy.pool import Pool

    def on_connect(dbapi_connection: Any, _record: Any) -> None:
        if not type(dbapi_connection).__module__.startswith("psycopg2"):
            return
        try:
            cur = dbapi_connection.cursor()
            # Name first: the sweep must see this session from here on.
            cur.execute(
                "SELECT set_config('application_name', %s, false)", (lock.data_name,)
            )
            holder = check_holder(cur, lock.key)
            cur.close()
            dbapi_connection.commit()
        except BaseException:
            _close_quietly(dbapi_connection)
            raise
        if holder != lock.lock_name:
            _close_quietly(dbapi_connection)
            raise FencedError(
                f"{lock.data_name}: not the leader (lock holder: {holder or 'none'})"
            )

    event.listen(Pool, "connect", on_connect)

    def remove() -> None:
        if event.contains(Pool, "connect", on_connect):
            event.remove(Pool, "connect", on_connect)

    return remove
