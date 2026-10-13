"""core.coordination.leader: the lock, the lease and the connection fence (W3.9).

The pure tests run everywhere. The ``external_service`` ones need a local
PostgreSQL 14+ and create their own scratch database.
"""

from __future__ import annotations

import os
import time
import uuid

import psycopg2
import pytest
from sqlalchemy import create_engine, text

from core.coordination.leader import (
    FencedError,
    PgLeaderLock,
    _like_escape,
    check_holder,
    connect_args_from_engine,
    data_app_name,
    install_connection_fence,
    lock_app_name,
    make_instance_id,
)

pytestmark = pytest.mark.unit

KEY = (1287, 3999)
GROUP = "w39-test"
SCRATCH_DB = "vigil_test_w39_fence"


# -- pure ---------------------------------------------------------------------


def test_names_fit_application_name_and_differ_by_role():
    iid = make_instance_id()
    assert len(lock_app_name("vigil-daemon", iid)) <= 63
    assert data_app_name("vigil-daemon", iid) == f"vigil-daemon:{iid}"
    assert lock_app_name("vigil-daemon", iid) == f"vigil-daemon-lock:{iid}"
    # The sweep pattern "<group>:%" must not match lock sessions.
    assert not lock_app_name("g", iid).startswith("g:")


def test_overlong_name_is_refused():
    with pytest.raises(ValueError):
        data_app_name("x" * 40, "y" * 30)


def test_like_escape():
    assert _like_escape("a_b%c\\") == "a\\_b\\%c\\\\"


def test_lease_must_be_positive():
    with pytest.raises(ValueError):
        PgLeaderLock(
            lambda **_: None, key=KEY, group=GROUP, instance_id="i", lease_seconds=0
        )


class _OldServer:
    """A psycopg2-like connection to PostgreSQL 13."""

    autocommit = False
    closed = False

    def cursor(self):
        conn = self

        class Cur:
            def execute(self, sql, params=None):
                conn.last = sql

            def fetchone(self):
                return (130012,)

            def close(self):
                pass

        return Cur()

    def close(self):
        self.closed = True


def test_server_older_than_14_is_refused():
    from core.coordination.leader import UnsupportedServerError

    conn = _OldServer()
    lock = PgLeaderLock(
        lambda **_: conn, key=KEY, group=GROUP, instance_id="i", lease_seconds=5
    )
    with pytest.raises(UnsupportedServerError):
        lock.try_acquire()
    assert conn.closed and not lock.held


def test_fence_ignores_non_postgres_connections():
    lock = PgLeaderLock(
        lambda **_: None, key=KEY, group=GROUP, instance_id="i", lease_seconds=5
    )
    remove = install_connection_fence(lock)
    try:
        engine = create_engine("sqlite://")
        with engine.connect() as conn:
            assert conn.execute(text("SELECT 1")).scalar() == 1
    finally:
        remove()


# -- pooler detection (Round 5) ---------------------------------------------------


class _Backend:
    def __init__(self, pid):
        self.pid = pid
        self.gucs = {}


class _Pool:
    """A PgBouncer stand-in: ``session`` pins one backend per client;
    ``transaction`` hands each autocommit statement the most recently
    released idle backend (PgBouncer's LIFO default)."""

    def __init__(self, mode, size=4):
        self.mode = mode
        self.idle = [_Backend(1000 + i) for i in range(size)]
        self.connections = []

    def connect(self, **_):
        conn = _PoolConn(self)
        self.connections.append(conn)
        return conn


class _PoolConn:
    autocommit = False

    def __init__(self, pool):
        self.pool = pool
        self.closed = False
        self.pinned = pool.idle.pop() if pool.mode == "session" else None
        self._row = None

    def _run(self, sql, params):
        backend = self.pinned or self.pool.idle.pop()
        try:
            if "server_version_num" in sql:
                return (160000,)
            if "set_config('vigil.leader_probe'" in sql:
                value = params[0] if params else "other"
                backend.gucs["vigil.leader_probe"] = value
                return (backend.pid, value)
            if "current_setting('vigil.leader_probe'" in sql:
                return (backend.pid, backend.gucs.get("vigil.leader_probe"))
            return (None,)
        finally:
            if self.pinned is None:
                self.pool.idle.append(backend)

    def cursor(self):
        conn = self

        class Cur:
            def execute(self, sql, params=None):
                conn._row = conn._run(sql, params)

            def fetchone(self):
                return conn._row

            def close(self):
                pass

        return Cur()

    def close(self):
        self.closed = True
        if self.pinned is not None:
            self.pool.idle.append(self.pinned)
            self.pinned = None


def test_transaction_pooler_is_refused():
    from core.coordination.leader import PooledConnectionError

    pool = _Pool("transaction")
    lock = PgLeaderLock(
        pool.connect, key=KEY, group=GROUP, instance_id="i", lease_seconds=5
    )
    with pytest.raises(PooledConnectionError, match="DAEMON_LEADER_DATABASE_URL"):
        lock.try_acquire()
    assert not lock.held
    assert all(c.closed for c in pool.connections)


def test_transaction_pooler_with_one_server_connection_is_refused():
    from core.coordination.leader import PooledConnectionError

    pool = _Pool("transaction", size=1)
    lock = PgLeaderLock(
        pool.connect, key=KEY, group=GROUP, instance_id="i", lease_seconds=5
    )
    with pytest.raises(PooledConnectionError):
        lock.try_acquire()


def test_session_pool_passes_the_probe():
    pool = _Pool("session")
    lock = PgLeaderLock(
        pool.connect, key=KEY, group=GROUP, instance_id="i", lease_seconds=5
    )
    conn = pool.connect()
    lock._refuse_pooled(conn, conn.cursor())  # no exception


def test_leader_dsn_setting_and_pgbouncer_refusal():
    from types import SimpleNamespace

    from core.coordination.leader import UnsupportedServerError
    from services.daemon.leadership import leader_connect_factory

    pgbouncer = SimpleNamespace(proxy=SimpleNamespace(proxy_type="pgbouncer"))
    direct = SimpleNamespace(proxy=SimpleNamespace(proxy_type="none"))
    no_dsn = SimpleNamespace(daemon_leader_database_url="")
    with pytest.raises(UnsupportedServerError, match="DAEMON_LEADER_DATABASE_URL"):
        leader_connect_factory(no_dsn, manager_config=pgbouncer)
    assert leader_connect_factory(no_dsn, manager_config=direct) is None
    with_dsn = SimpleNamespace(
        daemon_leader_database_url="postgresql+psycopg2://u:p@db:5432/vigil"
    )
    assert callable(leader_connect_factory(with_dsn, manager_config=pgbouncer))


def test_leader_dsn_setting_defaults_empty():
    from core.config import Settings

    assert Settings.model_fields["daemon_leader_database_url"].default == ""


# -- against Postgres -----------------------------------------------------------


def _url(database: str) -> str:
    user = os.getenv("POSTGRES_USER", "deeptempo")
    password = os.getenv("POSTGRES_PASSWORD", "deeptempo_secure_password_change_me")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"


def _pg_available() -> bool:
    try:
        with create_engine(_url("postgres")).connect():
            return True
    except Exception:
        return False


@pytest.fixture(scope="module")
def engine():
    admin = create_engine(_url("postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)"))
        conn.execute(text(f"CREATE DATABASE {SCRATCH_DB}"))
    eng = create_engine(_url(SCRATCH_DB))
    yield eng
    eng.dispose()
    with admin.connect() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)"))
    admin.dispose()


def _lock(engine, lease: float = 5.0, instance: str | None = None) -> PgLeaderLock:
    cargs, cparams = connect_args_from_engine(engine)
    return PgLeaderLock(
        lambda **kw: psycopg2.connect(*cargs, **{**cparams, **kw}),
        key=KEY,
        group=GROUP,
        instance_id=instance or uuid.uuid4().hex[:12],
        lease_seconds=lease,
    )


def _raw(engine, **kw):
    cargs, cparams = connect_args_from_engine(engine)
    conn = psycopg2.connect(*cargs, **{**cparams, **kw})
    conn.autocommit = True
    return conn


@pytest.mark.external_service
@pytest.mark.skipif(not _pg_available(), reason="requires a local PostgreSQL")
class TestAgainstPostgres:
    def test_only_one_holder_and_release_hands_over(self, engine):
        a, b = _lock(engine), _lock(engine)
        try:
            assert a.try_acquire() is True
            assert b.try_acquire() is False
            assert a.heartbeat() is True
            assert b.heartbeat() is False  # not held
            a.release()
            assert b.try_acquire() is True
        finally:
            a.release()
            b.release()

    def test_closed_session_frees_the_lock(self, engine):
        a, b = _lock(engine), _lock(engine)
        try:
            assert a.try_acquire()
            a._conn.close()  # the process died
            assert b.try_acquire()
            assert a.heartbeat() is False
        finally:
            a.release()
            b.release()

    def test_silent_holder_loses_the_lock_after_the_lease(self, engine):
        a, b = _lock(engine, lease=3.0), _lock(engine)
        try:
            assert a.try_acquire()
            assert b.try_acquire() is False
            time.sleep(4.5)  # no heartbeat: idle_session_timeout ends a's session
            assert b.try_acquire() is True
            assert a.heartbeat() is False
        finally:
            a.release()
            b.release()

    def test_fence_admits_the_holder_and_refuses_everyone_else(self, engine):
        a, b = _lock(engine), _lock(engine)
        remove = install_connection_fence(b)
        fenced = create_engine(_url(SCRATCH_DB))
        try:
            # Nobody holds the lock: refused.
            with pytest.raises(FencedError):
                fenced.connect()
            assert a.try_acquire()
            # Someone else holds it: refused.
            with pytest.raises(FencedError):
                fenced.connect()
            a.release()
            assert b.try_acquire()
            with fenced.connect() as conn:
                name = conn.execute(text("SHOW application_name")).scalar()
                assert name == b.data_name
        finally:
            remove()
            fenced.dispose()
            a.release()
            b.release()

    def test_takeover_terminates_the_old_holders_sessions(self, engine):
        old_iid = "old-" + uuid.uuid4().hex[:6]
        old_data = _raw(engine, application_name=data_app_name(GROUP, old_iid))
        old_tx = _raw(engine, application_name=data_app_name(GROUP, old_iid))
        old_tx.autocommit = False
        cur = old_tx.cursor()
        cur.execute("CREATE TEMP TABLE t (x int)")  # an open transaction
        bystander = _raw(engine, application_name="someone-else")
        new = _lock(engine)
        try:
            assert new.try_acquire()
            for conn in (old_data, old_tx):
                with pytest.raises(psycopg2.Error):
                    conn.cursor().execute("SELECT 1")
            # Other applications are left alone.
            bystander.cursor().execute("SELECT 1")
        finally:
            new.release()
            for conn in (old_data, old_tx, bystander):
                try:
                    conn.close()
                except Exception:
                    pass

    def test_direct_connection_passes_the_pooler_probe(self, engine):
        lock = _lock(engine)
        conn = _raw(engine)
        try:
            lock._refuse_pooled(conn, conn.cursor())
        finally:
            conn.close()

    def test_leader_dsn_connects_directly(self, engine):
        from types import SimpleNamespace

        from services.daemon.leadership import leader_connect_factory

        settings = SimpleNamespace(daemon_leader_database_url=_url(SCRATCH_DB))
        connect = leader_connect_factory(settings)
        lock = PgLeaderLock(
            connect,
            key=KEY,
            group=GROUP,
            instance_id=uuid.uuid4().hex[:12],
            lease_seconds=5,
        )
        try:
            assert lock.try_acquire() is True
            assert lock.heartbeat() is True
        finally:
            lock.release()

    def test_check_holder_reports_the_lock_session(self, engine):
        a = _lock(engine)
        conn = _raw(engine)
        try:
            assert check_holder(conn.cursor(), KEY) is None
            assert a.try_acquire()
            assert check_holder(conn.cursor(), KEY) == a.lock_name
        finally:
            a.release()
            conn.close()
