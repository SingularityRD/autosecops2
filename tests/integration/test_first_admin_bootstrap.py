"""A clean install can create its first admin, sign in, and reach an
authenticated route (#914).

``POST /api/auth/bootstrap`` and the login screen that calls it were wired long
before anything exercised them: every development environment ran with the
``DEV_MODE`` bypass, so the authenticated first-run had never been proven. This
drives the chain a browser performs against an **empty** database — bootstrap
status, first-admin creation, login, an authenticated call — and checks the two
doors close behind it: bootstrap refuses once an account exists, and the same
route answers 401 without a session.

Since W0.33 the bootstrap also demands the one-time setup token
(core/auth/setup_token.py). The tests here read it where an operator would: the
``setup-token`` file the backend writes to its State Directory (a temporary
one for this module) and the backend log.

The database is a scratch one created here (``roles`` seeded, ``users`` empty)
so the test never depends on, or truncates, whatever the configured database
holds. The app's shared ``DatabaseManager`` is retargeted at it for the module
and restored afterwards; the request unit of work and ``AuthService``'s own
sessions all go through that manager, so overriding a single dependency would
not have been enough.

Skips when no local Postgres or Redis answers (token revocation is fail-closed,
so a session cannot be verified without Redis) — except under ``CI``, where a
missing service is a provisioning failure and must fail rather than pass by
skipping.
"""

from __future__ import annotations

import logging
import os
import stat
import threading
from pathlib import Path

import pytest
import redis
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from core import redis_client
from core.config import DEFAULT_REDIS_URL, get_settings
from core.storage.connection import DatabaseConfig, get_db_manager
from core.auth import setup_token
from core.storage.models import Base, Role, SystemConfig, User
from services.api.middleware.rate_limit import limiter

pytestmark = [pytest.mark.integration, pytest.mark.database]

SCRATCH_DB = "vigil_test_first_admin"

# These fixtures CREATE/DROP DATABASE; only ever against a loopback host.
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "postgres", "0.0.0.0"}
_CONNECT_ARGS = {"connect_timeout": 5}

ADMIN = {
    "username": "first-admin",
    "email": "first-admin@example.com",
    "password": "harbour-lantern-quartz-91",
    "full_name": "First Admin",
}


def _url(database: str) -> str:
    """DSN from the POSTGRES_* variables CI sets, else the compose defaults."""
    user = os.getenv("POSTGRES_USER", "deeptempo")
    password = os.getenv("POSTGRES_PASSWORD", "deeptempo_secure_password_change_me")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    return f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{database}"


def _admin_engine():
    return create_engine(
        _url("postgres"), isolation_level="AUTOCOMMIT", connect_args=_CONNECT_ARGS
    )


def _unavailable_reason():
    host = os.getenv("POSTGRES_HOST", "localhost")
    if host not in _LOCAL_HOSTS:
        return f"refusing to CREATE/DROP a database on non-local POSTGRES_HOST {host!r}"
    try:
        with _admin_engine().connect():
            pass
    except Exception as e:  # noqa: BLE001
        return f"requires a local PostgreSQL (docker compose up -d postgres): {e}"
    try:
        redis.Redis.from_url(
            get_settings().redis_url or DEFAULT_REDIS_URL, socket_connect_timeout=5
        ).ping()
    except Exception as e:  # noqa: BLE001
        return f"requires a local Redis (docker compose up -d redis): {e}"
    return None


@pytest.fixture(scope="module")
def empty_database():
    """A freshly provisioned database with roles and no users, wired into the app."""
    reason = _unavailable_reason()
    if reason:
        if os.getenv("CI"):
            pytest.fail(f"CI must run the bootstrap proof: {reason}")
        pytest.skip(reason)
    # The shared redis.asyncio client binds to the event loop that first uses
    # it; an earlier module's TestClient loop is closed by now, so start fresh.
    redis_client._client = None

    admin = _admin_engine()
    with admin.connect() as c:
        c.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)"))
        c.execute(text(f"CREATE DATABASE {SCRATCH_DB}"))

    scratch = create_engine(_url(SCRATCH_DB), connect_args=_CONNECT_ARGS)
    with scratch.begin() as c:
        # The findings GIN index needs pg_trgm before create_all can build it.
        c.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
        c.execute(text('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'))
    Base.metadata.create_all(scratch)
    # What scripts/seed_reference_data.py provides on a real install: the role
    # the first admin is created with. users stays empty on purpose.
    with Session(scratch) as s:
        s.add(
            Role(
                role_id="role-admin",
                name="Admin",
                description="Full system access",
                permissions={"users.read": True, "users.write": True},
                is_system_role=True,
            )
        )
        s.commit()
    scratch.dispose()

    manager = get_db_manager()
    manager.retarget(DatabaseConfig(connection_string=_url(SCRATCH_DB)))
    # DatabaseConfig falls back to POSTGRES_* on an unparsable DSN; the chain
    # below must never run against the configured database by accident.
    assert manager.config.database == SCRATCH_DB
    try:
        yield
    finally:
        # Back to the configured database before the scratch one disappears, so
        # later tests in the session do not inherit a dead engine.
        manager.retarget(DatabaseConfig(), validate=False)
        with admin.connect() as c:
            c.execute(text(f"DROP DATABASE IF EXISTS {SCRATCH_DB} WITH (FORCE)"))
        admin.dispose()


@pytest.fixture(scope="module")
def state_dir(tmp_path_factory):
    """A State Directory of the module's own, so the token file is ours to read."""
    path = tmp_path_factory.mktemp("state")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("VIGIL_DIR", str(path))
        yield path


@pytest.fixture(scope="module")
def client(empty_database, state_dir):
    from services.api.main import app  # after retarget: startup may touch the DB

    # bootstrap and login are rate-limited per client IP, in Redis when one is
    # configured, so a second run inside a minute would 429 on nothing to do
    # with what this proves.
    was_enabled = limiter.enabled
    limiter.enabled = False
    # https: the auth cookies are Secure, and the cookie jar withholds those
    # over plain http.
    with TestClient(app, base_url="https://testserver") as c:
        yield c
    limiter.enabled = was_enabled


def _csrf(client: TestClient) -> dict:
    # What the SPA does: echo the csrf_token cookie the first response seeded.
    # Sent whether or not CSRF is enabled in this process (other modules turn it
    # off at collection), so the chain holds either way.
    return {"X-CSRF-Token": client.cookies.get("csrf_token", "")}


def _token_file(state_dir: Path) -> Path:
    return state_dir / setup_token.TOKEN_FILENAME


def _token(state_dir: Path) -> str:
    return _token_file(state_dir).read_text().strip()


def _bootstrap(client: TestClient, token=None, **over):
    headers = _csrf(client)
    if token is not None:
        headers[setup_token.HEADER_NAME] = token
    return client.post("/api/auth/bootstrap", json={**ADMIN, **over}, headers=headers)


def _session() -> Session:
    return get_db_manager().get_session()


def _empty_the_instance() -> None:
    """Back to a fresh install: no users, no outstanding token."""
    with get_db_manager().session_scope() as s:
        s.execute(text("TRUNCATE users CASCADE"))
        s.query(SystemConfig).filter(SystemConfig.key == setup_token.SETUP_TOKEN_KEY).delete()


def test_startup_issued_a_token_to_the_log_and_a_0600_file(client, state_dir):
    path = _token_file(state_dir)
    assert path.is_file(), "startup on an empty install must write the setup token"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    token = _token(state_dir)
    assert len(token) >= 40
    # Only its digest is stored, so every replica checks the same token.
    with _session() as s:
        row = s.get(SystemConfig, setup_token.SETUP_TOKEN_KEY)
        assert row is not None and token not in str(row.value)
        assert setup_token.matches(s, token)


def test_without_the_token_or_with_a_wrong_one_bootstrap_is_refused(client, state_dir):
    assert client.get("/api/auth/bootstrap").json() == {"required": True}
    missing = _bootstrap(client)
    assert missing.status_code == 401, missing.text
    assert "Setup token" in missing.json()["detail"]
    wrong = _bootstrap(client, token="not-the-token")
    assert wrong.status_code == 401, wrong.text
    empty = _bootstrap(client, token="")
    assert empty.status_code == 401, empty.text
    # Nothing was created; the instance still needs its first admin.
    assert client.get("/api/auth/bootstrap").json() == {"required": True}
    with _session() as s:
        assert s.query(User).count() == 0


def test_wrong_tokens_are_rate_limited(client, state_dir):
    limiter.enabled = True
    limiter.reset()
    try:
        codes = [_bootstrap(client, token=f"guess-{i}").status_code for i in range(6)]
    finally:
        limiter.reset()
        limiter.enabled = False
    assert codes[:5] == [401] * 5
    assert codes[5] == 429


def test_the_token_never_appears_in_a_response_or_a_log_line(client, state_dir, caplog):
    token = _token(state_dir)
    caplog.set_level(logging.DEBUG)
    responses = [
        client.get("/api/auth/bootstrap"),
        _bootstrap(client),
        _bootstrap(client, token="wrong"),
        # a 422 echoes the body back; the token is not in the body
        client.post(
            "/api/auth/bootstrap",
            json={"email": "x@example.com"},
            headers={**_csrf(client), setup_token.HEADER_NAME: token},
        ),
        client.get("/api/health"),
    ]
    for r in responses:
        assert token not in r.text
        assert all(token not in v for v in r.headers.values())
    assert responses[3].status_code == 422
    # Every log line the requests produced, the app's and any access log alike.
    # (The capture works: the refusals above are in it.)
    assert any("setup token missing" in r.getMessage() for r in caplog.records)
    assert all(token not in record.getMessage() for record in caplog.records)
    # The token travels in a header, so a request line (what an access log
    # records) never carries it.
    assert all(token not in str(r.request.url) for r in responses)


def test_regenerate_replaces_the_token_and_the_old_one_stops_working(client, state_dir, capsys):
    old = _token(state_dir)
    assert setup_token.main(["regenerate"]) == setup_token.EX_OK
    new = capsys.readouterr().out.strip()
    assert new and new != old
    assert _token(state_dir) == new
    assert _bootstrap(client, token=old).status_code == 401


def test_first_admin_can_bootstrap_login_and_reach_an_authenticated_route(client, state_dir):
    # An empty instance advertises first-run, and refuses to run open.
    assert client.get("/api/auth/bootstrap").json() == {"required": True}
    assert client.get("/api/auth/me").status_code == 401

    created = _bootstrap(client, token=_token(state_dir))
    assert created.status_code == 201, created.text
    assert created.json()["username"] == ADMIN["username"]
    assert client.get("/api/auth/bootstrap").json() == {"required": False}

    login = client.post(
        "/api/auth/login",
        json={
            "username_or_email": ADMIN["username"],
            "password": ADMIN["password"],
        },
        headers=_csrf(client),
    )
    assert login.status_code == 200, login.text
    body = login.json()
    assert body["user"]["role_id"] == "role-admin"
    assert "users.write" in body["user"]["permissions"]

    # Browser flow: the HttpOnly access_token cookie set by /login.
    me = client.get("/api/auth/me")
    assert me.status_code == 200, me.text
    assert me.json()["username"] == ADMIN["username"]

    # API-client flow: the same token as a bearer, with no cookies at all. (Same
    # client rather than a second one: the shared async Redis client used for
    # revocation checks is bound to the first TestClient's event loop.)
    client.cookies.clear()
    bearer = client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert bearer.status_code == 200, bearer.text
    assert bearer.json()["username"] == ADMIN["username"]


def test_bootstrap_closes_once_an_account_exists(client, state_dir):
    client.get("/api/auth/bootstrap")  # re-seed the csrf cookie the last test cleared
    again = _bootstrap(
        client, token="anything", username="second-admin", email="second@example.com"
    )
    assert again.status_code == 403, again.text
    assert "already exists" in again.json()["detail"]


def test_a_used_token_is_retired_and_cannot_be_reused(client, state_dir):
    # The successful bootstrap above deleted the row and the file.
    with _session() as s:
        assert s.get(SystemConfig, setup_token.SETUP_TOKEN_KEY) is None
    assert not _token_file(state_dir).exists()
    # Regenerating is refused once an account exists.
    assert setup_token.main(["regenerate"]) == setup_token.EX_REFUSED


def test_reusing_a_token_after_success_fails_even_on_an_emptied_instance(client, state_dir):
    _empty_the_instance()
    client.get("/api/auth/bootstrap")  # issues a fresh token for the empty install
    used = _token(state_dir)
    assert _bootstrap(client, token=used).status_code == 201
    _empty_the_instance()
    client.get("/api/auth/bootstrap")  # and another one
    replay = _bootstrap(client, token=used)
    assert replay.status_code == 401, replay.text
    assert _bootstrap(client, token=_token(state_dir)).status_code == 201


def test_concurrent_first_admin_attempts_create_exactly_one_admin(client, state_dir):
    _empty_the_instance()
    client.get("/api/auth/bootstrap")
    token = _token(state_dir)
    csrf = _csrf(client)
    start = threading.Barrier(6)
    codes: list = []

    def attempt(i: int) -> None:
        start.wait()
        r = client.post(
            "/api/auth/bootstrap",
            json={**ADMIN, "username": f"racer-{i}", "email": f"racer-{i}@example.com"},
            headers={**csrf, setup_token.HEADER_NAME: token},
        )
        codes.append(r.status_code)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert sorted(codes) == [201] + [403] * 5, codes
    with _session() as s:
        assert s.query(User).filter(User.service_account.is_(False)).count() == 1


def test_a_new_token_is_printed_to_the_log_once(client, state_dir, caplog):
    _empty_the_instance()
    caplog.set_level(logging.WARNING, logger="core.auth.setup_token")
    client.get("/api/auth/bootstrap")
    client.get("/api/auth/bootstrap")
    token = _token(state_dir)
    printed = [r for r in caplog.records if token in r.getMessage()]
    assert len(printed) == 1, [r.getMessage() for r in caplog.records]
    assert "setup token" in printed[0].getMessage()


# --- the setup wizard's progress and readiness are the install's (W0.33) -----


def _sign_in(client: TestClient, username: str, password: str) -> dict:
    client.cookies.clear()
    client.get("/api/auth/bootstrap")  # seeds the csrf cookie
    r = client.post(
        "/api/auth/login",
        json={"username_or_email": username, "password": password},
        headers=_csrf(client),
    )
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}", **_csrf(client)}


@pytest.fixture
def admin_and_viewer(client, state_dir):
    """A fresh install with its first admin (who may change settings) and a Viewer."""
    from core.auth.auth_service import AuthService

    _empty_the_instance()
    client.get("/api/auth/bootstrap")
    assert _bootstrap(client, token=_token(state_dir)).status_code == 201
    with get_db_manager().session_scope() as s:
        admin_role = s.get(Role, "role-admin")
        admin_role.permissions = {**admin_role.permissions, "settings.write": True,
                                  "settings.read": True}
        if s.get(Role, "role-viewer") is None:
            s.add(Role(role_id="role-viewer", name="Viewer", description="Read only",
                       permissions={}, is_system_role=True))
    AuthService.create_user(
        username="viewer-1", email="viewer-1@example.com", password=ADMIN["password"],
        full_name="Viewer", role_id="role-viewer",
    )
    s = _session()
    s.query(SystemConfig).filter(SystemConfig.key == "setup.progress").delete()
    s.commit()
    s.close()
    return (
        _sign_in(client, ADMIN["username"], ADMIN["password"]),
        _sign_in(client, "viewer-1", ADMIN["password"]),
    )


@pytest.fixture
def no_gateway(monkeypatch):
    """The model gateway does not answer, whatever runs on this machine."""
    from core.llm.bifrost import mirror

    async def unreachable():
        raise OSError("no gateway in this test")

    monkeypatch.setattr(mirror, "routability", unreachable)


def test_wizard_progress_is_kept_for_the_install_and_audited(client, admin_and_viewer):
    admin, viewer = admin_and_viewer
    client.cookies.clear()
    assert client.get("/api/config/setup-progress", headers=admin).json()["started"] is False
    saved = client.put(
        "/api/config/setup-progress",
        json={"furthest": 3, "passed": [1, 2], "status": "in_progress"},
        headers=admin,
    )
    assert saved.status_code == 200, saved.text
    # Another browser, another person: the same progress.
    seen = client.get("/api/config/setup-progress", headers=viewer).json()
    assert (seen["furthest"], seen["passed"], seen["status"]) == (3, [1, 2], "in_progress")
    assert seen["updated_by"] == ADMIN["username"]
    with _session() as s:
        rows = s.execute(
            text("SELECT changed_by FROM config_audit_log WHERE config_key = 'setup.progress'")
        ).all()
    assert rows, "a progress save must leave an audit row"
    # Only someone who may change settings may move it.
    refused = client.put(
        "/api/config/setup-progress",
        json={"furthest": 1, "passed": [], "status": "completed"},
        headers=viewer,
    )
    assert refused.status_code == 403, refused.text


def test_an_empty_install_is_not_ready_and_cannot_be_recorded_as_completed(
    client, admin_and_viewer, no_gateway
):
    admin, _ = admin_and_viewer
    client.cookies.clear()
    verdict = client.get("/api/config/setup-readiness", headers=admin).json()
    assert verdict["ready"] is False
    assert verdict["missing"] == ["data", "model"]
    assert {"executor", "notify"} <= set(verdict["recommended_missing"])
    finished = client.put(
        "/api/config/setup-progress",
        json={"furthest": 5, "passed": [1, 2, 3, 4, 5], "status": "completed"},
        headers=admin,
    )
    assert finished.status_code == 200, finished.text
    assert finished.json()["status"] == "deferred"
    assert finished.json()["completed_at"] is None
