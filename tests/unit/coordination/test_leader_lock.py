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
        PgLeaderLock(lambda **_: None, key=KEY, group=GROUP, instance_id="i", lease_seconds=0)


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
