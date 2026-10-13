"""Single sign-on end to end: browser -> AutoSecOps -> provider -> AutoSecOps.

The FastAPI routers are the real ones (``core.auth.oidc_router`` and the
password login in ``services.api.routers.auth``); the database is SQLite (no
rule here is dialect-specific), Redis is an in-memory single-use store, and the
identity provider is ``oidc_mock.MockIdP`` behind respx, with real keys.
"""

from __future__ import annotations

import base64
import os
from contextlib import contextmanager
from urllib.parse import parse_qs, unquote_plus, urlparse

import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

import core.storage.unit_of_work as uow_module  # noqa: E402
from core.auth import oidc, oidc_router  # noqa: E402
from core.auth.auth_service import AuthService  # noqa: E402
from core.auth.current_user import get_current_user  # noqa: E402
from core.auth.oidc_accounts import (  # noqa: E402
    IDENTITY_CONFIG_TYPE,
    SSO_ONLY_PASSWORD_HASH,
    load_providers,
)
from core.routing import request_unit_of_work  # noqa: E402
from core.storage.models import ConfigAuditLog, Role, SystemConfig, User  # noqa: E402
from core.storage.models.base import Base  # noqa: E402
from services.api.middleware.rate_limit import limiter  # noqa: E402
from services.api.routers import auth as auth_router  # noqa: E402
from tests.unit.auth.oidc_mock import CLIENT_ID, ISSUER, MockIdP  # noqa: E402

pytestmark = pytest.mark.unit


@compiles(JSONB, "sqlite")
def _jsonb_is_json_on_sqlite(type_, compiler, **kw):
    return "JSON"


_PERMS = {
    "role-viewer": {"findings.read": True, "cases.read": True},
    "role-analyst": {
        "findings.read": True,
        "findings.write": True,
        "cases.read": True,
        "cases.write": True,
        "settings.read": True,
        "ai_chat.use": True,
    },
    "role-senior-analyst": {
        "findings.read": True,
        "findings.write": True,
        "cases.read": True,
        "cases.write": True,
        "ai_decisions.approve": True,
    },
    "role-manager": {
        "findings.read": True,
        "cases.read": True,
        "users.read": True,
        "users.write": True,
        "users.delete": False,
        "settings.read": True,
        "settings.write": True,
    },
    "role-admin": {
        "findings.read": True,
        "cases.read": True,
        "users.read": True,
        "users.write": True,
        "users.delete": True,
        "settings.read": True,
        "settings.write": True,
    },
}


class MemoryFlowStore:
    def __init__(self):
        self.data: dict[str, str] = {}

    async def put(self, key, value, ttl_seconds):
        self.data[key] = value

    async def take(self, key):
        return self.data.pop(key, None)


class World:
    """Everything one test needs, wired together."""

    def __init__(self, maker, client, idp, store, secrets_box, app):
        self.maker = maker
        self.client = client
        self.idp = idp
        self.store = store
        self.secrets = secrets_box
        self.app = app

    @contextmanager
    def db(self):
        session = self.maker()
        try:
            yield session
            session.commit()
        finally:
            session.close()

    def add_user(self, user_id, username, role_id, **extra):
        with self.db() as s:
            s.add(
                User(
                    user_id=user_id,
                    username=username,
                    email=extra.pop("email", f"{username}@example.com"),
                    password_hash=extra.pop(
                        "password_hash", AuthService.hash_password("Correct-Horse-9!")
                    ),
                    full_name=username,
                    role_id=role_id,
                    is_active=extra.pop("is_active", True),
                    mfa_enabled=False,
                    login_count=0,
                    **extra,
                )
            )

    def set_provider(self, **overrides):
        value = {
            "id": "kc",
            "display_name": "Keycloak",
            "kind": "keycloak",
            "issuer": ISSUER,
            "client_id": CLIENT_ID,
        }
        value.update(overrides)
        with self.db() as s:
            row = s.get(SystemConfig, "auth.oidc.providers")
            if row is None:
                s.add(
                    SystemConfig(
                        key="auth.oidc.providers",
                        value={"providers": [value]},
                        config_type="auth",
                    )
                )
            else:
                row.value = {"providers": [value]}

    def as_user(self, user_id):
        with self.db() as s:
            user = s.get(User, user_id)
            s.expunge(user)
        self.app.dependency_overrides[get_current_user] = lambda: user

    # -- the browser --------------------------------------------------------

    def start(self, provider_id="kc", next_path=None):
        params = {"next": next_path} if next_path else None
        return self.client.get(f"/api/auth/sso/{provider_id}/login", params=params)

    def login(self, provider_id="kc", next_path=None):
        """Full round trip; returns (callback response, code, state)."""
        started = self.start(provider_id, next_path)
        assert started.status_code == 302, started.text
        code, state = self.idp.authorize(started.headers["location"])
        done = self.client.get(
            f"/api/auth/sso/{provider_id}/callback",
            params={"code": code, "state": state},
        )
        return done, code, state

    def sso_error(self, response):
        assert response.status_code == 302, response.text
        location = urlparse(response.headers["location"])
        return parse_qs(location.query).get("sso_error", [None])[0]

    def audit(self, action):
        with self.db() as s:
            return [
                r.new_value
                for r in s.query(ConfigAuditLog)
                .filter(ConfigAuditLog.config_type == "auth_event")
                .filter(ConfigAuditLog.action == action)
                .all()
            ]

    def user_by_email(self, email):
        with self.db() as s:
            user = s.query(User).filter(User.email == email).first()
            if user is not None:
                s.expunge(user)
            return user


@pytest.fixture
def world(monkeypatch):
    monkeypatch.setenv("VIGIL_COOKIE_SECURE", "false")
    monkeypatch.setenv("VIGIL_FRONTEND_URL", "")
    monkeypatch.setenv("VIGIL_CONTEXT_PATH", "")
    from core.config import get_settings

    get_settings.cache_clear()

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(
        engine,
        tables=[
            Role.__table__,
            User.__table__,
            SystemConfig.__table__,
            ConfigAuditLog.__table__,
        ],
    )
    maker = sessionmaker(bind=engine, expire_on_commit=False)
    with maker() as s:
        for role_id, perms in _PERMS.items():
            s.add(
                Role(
                    role_id=role_id,
                    name=role_id.removeprefix("role-").title(),
                    description="",
                    permissions=perms,
                    is_system_role=True,
                )
            )
        s.commit()

    # Sessions opened by unit_of_work() (permission checks, the failure audit).
    monkeypatch.setattr(uow_module, "get_db_session", maker)

    def _request_session():
        session = maker()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    secrets_box: dict[str, str] = {}
    monkeypatch.setattr(
        oidc_router, "get_secret", lambda k, d=None: secrets_box.get(k, d)
    )
    monkeypatch.setattr(
        oidc_router, "set_secret", lambda k, v: secrets_box.__setitem__(k, v) or True
    )
    monkeypatch.setattr(
        oidc_router,
        "delete_secret",
        lambda k: secrets_box.pop(k, None) is not None or True,
    )

    async def _not_revoked(payload):
        return False

    monkeypatch.setattr("core.auth.current_user.is_token_revoked", _not_revoked)

    store = MemoryFlowStore()
    previous_store = oidc_router.set_flow_store(store)
    oidc.clear_caches()
    was_enabled = limiter.enabled
    limiter.enabled = False

    app = FastAPI()
    app.state.limiter = limiter
    app.include_router(oidc_router.router, prefix="/api/auth/sso")
    app.include_router(auth_router.router, prefix="/api/auth")
    app.dependency_overrides[request_unit_of_work] = _request_session

    idp = MockIdP()
    with respx.mock(assert_all_called=False) as mock:
        idp.install(mock)
        client = TestClient(app, follow_redirects=False)
        yield World(maker, client, idp, store, secrets_box, app)

    limiter.enabled = was_enabled
    oidc_router.set_flow_store(previous_store)
    oidc.clear_caches()
    get_settings.cache_clear()


# --- the happy path ---------------------------------------------------------


def test_the_sign_in_screen_lists_enabled_providers_only(world):
    world.set_provider()
    body = world.client.get("/api/auth/sso/providers").json()
    assert body == {
        "providers": [{"id": "kc", "display_name": "Keycloak"}],
        "local_login_enabled": True,
    }
    world.set_provider(enabled=False)
    assert world.client.get("/api/auth/sso/providers").json()["providers"] == []


def test_login_redirects_to_the_provider_with_pkce_state_and_nonce(world):
    world.set_provider()
    response = world.start()

    assert response.status_code == 302
    location = urlparse(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == (
        world.idp.discovery()["authorization_endpoint"]
    )
    query = {k: v[0] for k, v in parse_qs(location.query).items()}
    assert query["code_challenge_method"] == "S256"
    assert len(query["state"]) >= 32 and len(query["nonce"]) >= 32
    assert query["redirect_uri"] == "http://testserver/api/auth/sso/kc/callback"
    # The verifier never leaves the server; the state is stored only hashed.
    assert all(query["state"] not in key for key in world.store.data)
    assert "oidc_flow" in response.cookies


def test_a_full_login_issues_the_same_session_as_a_password(world):
    world.set_provider()
    response, code, _ = world.login(next_path="/cases?open=1")

    assert response.status_code == 302
    assert response.headers["location"] == "/cases?open=1"
    access = response.cookies.get("access_token")
    refresh = response.cookies.get("refresh_token")
    assert access and refresh
    payload = AuthService.verify_jwt_token(access)
    assert payload["token_type"] == "access"
    assert AuthService.verify_jwt_token(refresh)["token_type"] == "refresh"

    user = world.user_by_email("alice@example.com")
    assert payload["user_id"] == user.user_id
    # JIT: created on first sign-in, least privilege, no usable password.
    assert user.role_id == "role-viewer"
    assert user.username == "alice"
    assert user.full_name == "Alice Analyst"
    assert user.password_hash == SSO_ONLY_PASSWORD_HASH
    assert not AuthService.verify_password("anything", user.password_hash)

    # The code was redeemed with the PKCE verifier and the client secret-less form.
    token_form = world.idp.token_requests[-1]["form"]
    assert token_form["code"] == code
    assert token_form["code_verifier"]

    [event] = world.audit("sso_login")
    assert event["user_id"] == user.user_id and event["created"] is True
    with world.db() as s:
        links = (
            s.query(SystemConfig)
            .filter(SystemConfig.config_type == IDENTITY_CONFIG_TYPE)
            .all()
        )
        assert len(links) == 1
        assert links[0].value["user_id"] == user.user_id
        assert "subject-alice" not in str(links[0].value)

    # The session works on the regular authenticated endpoint.
    me = world.client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user_id"] == user.user_id


def test_the_second_login_finds_the_same_account(world):
    world.set_provider()
    world.login()
    world.client.cookies.clear()
    response, _, _ = world.login()
    assert response.headers["location"] == "/"
    with world.db() as s:
        assert s.query(User).count() == 1
        assert s.query(User).one().login_count == 2


def test_the_client_secret_goes_to_the_token_endpoint(world):
    world.set_provider()
    world.secrets["OIDC_CLIENT_SECRET_KC"] = "s3:cr%t+"
    world.login()
    authorization = world.idp.token_requests[-1]["authorization"]
    assert authorization and authorization.startswith("Basic ")
    # RFC 6749 §2.3.1: id and secret are form-urlencoded inside Basic.
    decoded = base64.b64decode(authorization.split(" ", 1)[1]).decode()
    _client_id, secret = decoded.split(":", 1)
    assert unquote_plus(secret) == "s3:cr%t+"
    assert ":" not in secret


def test_an_offsite_next_is_ignored(world):
    world.set_provider()
    for evil in ("//evil.test/x", "https://evil.test/", "/\\evil.test"):
        world.client.cookies.clear()
        response, _, _ = world.login(next_path=evil)
        assert response.headers["location"] == "/", evil


# --- state, nonce, replay ---------------------------------------------------


def test_a_replayed_callback_is_refused(world):
    world.set_provider()
    first, code, state = world.login()
    assert first.cookies.get("access_token")

    replay = world.client.get(
        "/api/auth/sso/kc/callback", params={"code": code, "state": state}
    )
    assert world.sso_error(replay) == "state"
    assert "access_token" not in replay.cookies
    assert world.audit("sso_failure")[-1]["reason"] == "state"


def test_an_unknown_state_is_refused(world):
    world.set_provider()
    started = world.start()
    code, _ = world.idp.authorize(started.headers["location"])
    response = world.client.get(
        "/api/auth/sso/kc/callback", params={"code": code, "state": "forged"}
    )
    assert world.sso_error(response) == "state"
    assert world.user_by_email("alice@example.com") is None


def test_a_callback_in_another_browser_is_refused(world):
    """Login CSRF: the victim's browser lacks the flow cookie."""
    world.set_provider()
    started = world.start()
    code, state = world.idp.authorize(started.headers["location"])
    world.client.cookies.clear()
    response = world.client.get(
        "/api/auth/sso/kc/callback", params={"code": code, "state": state}
    )
    assert world.sso_error(response) == "state"
    # And the state is spent: the attacker cannot retry from the right browser.
    assert world.store.data == {}


def test_a_state_issued_for_another_provider_is_refused(world):
    world.set_provider()
    started = world.start()
    code, state = world.idp.authorize(started.headers["location"])
    response = world.client.get(
        "/api/auth/sso/other/callback", params={"code": code, "state": state}
    )
    assert world.sso_error(response) == "state"


def test_a_nonce_mismatch_is_refused(world):
    world.set_provider()
    world.idp.id_token_override = world.idp.sign(world.idp.claims_for("other-nonce"))
    response, _, _ = world.login()
    assert world.sso_error(response) == "nonce"
    assert world.user_by_email("alice@example.com") is None


def test_an_error_from_the_provider_is_refused(world):
    world.set_provider()
    started = world.start()
    _, state = world.idp.authorize(started.headers["location"])
    response = world.client.get(
        "/api/auth/sso/kc/callback",
        params={"error": "access_denied", "state": state},
    )
    assert world.sso_error(response) == "idp_error"


# --- token validation through the flow --------------------------------------


@pytest.mark.parametrize(
    "mutate,code",
    [
        ({"aud": "someone-else"}, "claims"),
        ({"iss": "https://evil.test/realms/soc"}, "claims"),
        ({"exp": 1_000_000, "iat": 999_000}, "expired"),
    ],
)
def test_bad_claims_are_refused(world, mutate, code):
    world.set_provider()
    started = world.start()
    auth_code, state = world.idp.authorize(started.headers["location"])
    nonce = world.idp.codes[auth_code]["nonce"]
    world.idp.id_token_override = world.idp.sign(world.idp.claims_for(nonce, **mutate))
    response = world.client.get(
        "/api/auth/sso/kc/callback", params={"code": auth_code, "state": state}
    )
    assert world.sso_error(response) == code
    assert world.user_by_email("alice@example.com") is None


def test_a_bad_signature_is_refused(world):
    from cryptography.hazmat.primitives.asymmetric import rsa

    world.set_provider()
    started = world.start()
    auth_code, state = world.idp.authorize(started.headers["location"])
    nonce = world.idp.codes[auth_code]["nonce"]
    impostor = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    world.idp.id_token_override = world.idp.sign(
        world.idp.claims_for(nonce), key=impostor
    )
    response = world.client.get(
        "/api/auth/sso/kc/callback", params={"code": auth_code, "state": state}
    )
    assert world.sso_error(response) == "signature"
    assert "access_token" not in response.cookies


def test_a_disabled_provider_cannot_start_a_login(world):
    world.set_provider(enabled=False)
    assert world.start().status_code == 404


# --- accounts and roles -----------------------------------------------------


def test_groups_map_to_roles(world):
    world.set_provider(
        role_mappings=[{"claim": "groups", "value": "soc", "role_id": "role-analyst"}]
    )
    world.idp.claims = {"groups": ["soc", "staff"]}
    world.login()
    assert world.user_by_email("alice@example.com").role_id == "role-analyst"


def test_admin_requires_an_allowed_explicit_mapping(world):
    world.set_provider(
        role_mappings=[{"value": "soc-admins", "role_id": "role-admin"}],
        allow_admin_mapping=False,
    )
    world.idp.claims = {"groups": ["soc-admins"]}
    world.login()
    assert world.user_by_email("alice@example.com").role_id == "role-viewer"

    world.set_provider(
        role_mappings=[{"value": "soc-admins", "role_id": "role-admin"}],
        allow_admin_mapping=True,
    )
    world.client.cookies.clear()
    world.login()
    assert world.user_by_email("alice@example.com").role_id == "role-admin"


def test_a_provisioned_account_follows_its_groups(world):
    world.set_provider(role_mappings=[{"value": "soc", "role_id": "role-analyst"}])
    world.idp.claims = {"groups": ["soc"]}
    world.login()
    assert world.user_by_email("alice@example.com").role_id == "role-analyst"

    world.idp.claims = {"groups": []}  # removed from the group at the provider
    world.client.cookies.clear()
    world.login()
    assert world.user_by_email("alice@example.com").role_id == "role-viewer"


def test_without_jit_an_unknown_identity_is_refused(world):
    world.set_provider(jit_provisioning=False)
    response, _, _ = world.login()
    assert world.sso_error(response) == "account"
    with world.db() as s:
        assert s.query(User).count() == 0


def test_an_existing_email_is_not_linked_unless_enabled(world):
    world.add_user(
        "u-alice", "alice-local", "role-senior-analyst", email="alice@example.com"
    )
    world.set_provider()
    response, _, _ = world.login()
    assert world.sso_error(response) == "account"
    with world.db() as s:
        assert s.query(User).count() == 1


def test_linking_needs_a_verified_email(world):
    world.add_user(
        "u-alice", "alice-local", "role-senior-analyst", email="alice@example.com"
    )
    world.set_provider(link_by_verified_email=True)
    world.idp.claims = {"email_verified": False}
    response, _, _ = world.login()
    assert world.sso_error(response) == "account"


def test_a_verified_email_links_and_keeps_the_local_role(world):
    world.add_user(
        "u-alice", "alice-local", "role-senior-analyst", email="Alice@Example.com"
    )
    world.set_provider(
        link_by_verified_email=True,
        role_mappings=[
            {"value": "soc", "role_id": "role-analyst"},
            {"value": "leads", "role_id": "role-senior-analyst"},
        ],
    )
    world.idp.claims = {"groups": ["soc"]}
    response, _, _ = world.login()

    payload = AuthService.verify_jwt_token(response.cookies["access_token"])
    assert payload["user_id"] == "u-alice"
    user = world.user_by_email("Alice@Example.com")
    assert user.role_id == "role-senior-analyst"
    assert world.audit("sso_login")[-1]["linked"] is True


def test_linking_never_reaches_a_role_above_what_the_provider_may_grant(world):
    world.add_user(
        "u-alice", "alice-local", "role-senior-analyst", email="alice@example.com"
    )
    # The provider can only ever make analysts/viewers; a senior analyst holds
    # ai_decisions.approve, which neither grants.
    world.set_provider(
        link_by_verified_email=True,
        role_mappings=[{"value": "soc", "role_id": "role-analyst"}],
    )
    response, _, _ = world.login()
    assert world.sso_error(response) == "account"
    assert "access_token" not in response.cookies
    assert "exceeds" in world.audit("sso_failure")[-1]["detail"]
    with world.db() as s:
        assert (
            s.query(SystemConfig)
            .filter(SystemConfig.config_type == IDENTITY_CONFIG_TYPE)
            .count()
            == 0
        )


def test_a_manager_cannot_take_over_the_admin_through_email_linking(world):
    """Regression (verifier W1.9 HIGH): Manager -> own IdP -> link -> Admin.

    A Manager (settings.write + users.write, not Admin) adds a provider at an
    identity provider they control, turns linking by verified email on, and
    has their IdP assert the Admin's address. Both steps must fail.
    """
    world.add_user("u-admin", "root", "role-admin", email="root@corp.example")
    world.add_user("u-mgr", "maria", "role-manager")
    world.as_user("u-mgr")

    # 1. The Manager cannot save a provider with linking on...
    body = _provider_body(link_by_verified_email=True)
    response = world.client.put("/api/auth/sso/admin/providers/kc", json=body)
    assert response.status_code == 403, response.text
    assert "linking" in response.json()["detail"]
    # ...nor with "allow mapping to Admin" on (even with no Admin mapping).
    body = _provider_body(allow_admin_mapping=True)
    response = world.client.put("/api/auth/sso/admin/providers/kc", json=body)
    assert response.status_code == 403, response.text
    with world.db() as s:
        assert s.get(SystemConfig, "auth.oidc.providers") is None

    # ...nor re-point an Admin-configured provider that has linking on.
    world.set_provider(link_by_verified_email=True)
    body = _provider_body(link_by_verified_email=True, issuer="https://evil.test/r")
    response = world.client.put("/api/auth/sso/admin/providers/kc", json=body)
    assert response.status_code == 403

    # 2. Even where linking is on (as an Admin set it), a provider that may not
    #    map to Admin never links to the Admin account.
    world.app.dependency_overrides.pop(get_current_user)
    world.set_provider(
        link_by_verified_email=True,
        role_mappings=[{"value": "soc", "role_id": "role-manager"}],
    )
    world.idp.claims = {"email": "root@corp.example", "groups": ["soc"]}
    response, _, _ = world.login()
    assert world.sso_error(response) == "account"
    assert "access_token" not in response.cookies
    with world.db() as s:
        assert s.get(User, "u-admin").login_count == 0

    # 3. Only a provider an Admin allowed to map to Admin may link to one.
    world.set_provider(
        link_by_verified_email=True,
        allow_admin_mapping=True,
        role_mappings=[{"value": "soc-admins", "role_id": "role-admin"}],
    )
    world.client.cookies.clear()
    response, _, _ = world.login()
    payload = AuthService.verify_jwt_token(response.cookies["access_token"])
    assert payload["user_id"] == "u-admin"


def test_an_admin_may_turn_linking_on(world):
    world.add_user("u-admin", "root", "role-admin")
    world.as_user("u-admin")
    body = _provider_body(link_by_verified_email=True, allow_admin_mapping=True)
    response = world.client.put("/api/auth/sso/admin/providers/okta", json=body)
    assert response.status_code == 200, response.text


def test_a_jit_username_never_looks_like_an_email(world):
    world.add_user("u-root", "root", "role-admin", email="root@corp.example")
    world.set_provider()
    world.idp.claims = {"preferred_username": "root@corp.example"}
    world.login()
    user = world.user_by_email("alice@example.com")
    assert "@" not in user.username
    assert user.username.startswith("root-")  # "root" is taken
    with world.db() as s:
        assert s.get(User, "u-root").username == "root"


def test_an_idp_error_cannot_forge_log_lines(world, caplog):
    world.set_provider()
    started = world.start()
    _, state = world.idp.authorize(started.headers["location"])
    response = world.client.get(
        "/api/auth/sso/kc/callback",
        params={"error": "x\r\nINFO forged\u2028line\x1b[31m", "state": state},
    )
    assert world.sso_error(response) == "idp_error"
    detail = world.audit("sso_failure")[-1]["detail"]
    for bad in ("\r", "\n", "\u2028", "\x1b"):
        assert bad not in detail
        assert all(bad not in r.getMessage() for r in caplog.records)
    assert "forged" in detail


def test_a_service_account_cannot_sign_in_with_sso(world):
    world.add_user(
        "u-svc",
        "medic-gateway",
        "role-viewer",
        email="alice@example.com",
        service_account=True,
    )
    world.set_provider(link_by_verified_email=True)
    response, _, _ = world.login()
    assert world.sso_error(response) == "machine_account"
    assert world.audit("sso_failure")[-1]["reason"] == "machine_account"


def test_an_inactive_linked_account_is_refused(world):
    world.set_provider()
    world.login()
    with world.db() as s:
        s.query(User).one().is_active = False
    world.client.cookies.clear()
    response, _, _ = world.login()
    assert world.sso_error(response) == "inactive"


# --- administration ---------------------------------------------------------


def _provider_body(**overrides):
    body = {
        "display_name": "Okta",
        "kind": "okta",
        "issuer": ISSUER,
        "client_id": CLIENT_ID,
        "client_secret": "top-secret",
    }
    body.update(overrides)
    return body


def test_an_admin_saves_a_provider_and_never_reads_the_secret_back(world):
    world.add_user("u-admin", "root", "role-admin")
    world.as_user("u-admin")

    response = world.client.put(
        "/api/auth/sso/admin/providers/okta", json=_provider_body()
    )
    assert response.status_code == 200, response.text
    assert world.secrets == {"OIDC_CLIENT_SECRET_OKTA": "top-secret"}
    assert "top-secret" not in response.text
    [saved] = response.json()["providers"]
    assert saved["has_client_secret"] is True
    assert saved["default_role_id"] == "role-viewer"
    assert saved["effective_redirect_uri"] == (
        "http://testserver/api/auth/sso/okta/callback"
    )

    config = world.client.get("/api/auth/sso/admin/config")
    assert "top-secret" not in config.text

    # Saving again without a secret keeps the stored one.
    body = _provider_body(display_name="Okta SSO")
    del body["client_secret"]
    world.client.put("/api/auth/sso/admin/providers/okta", json=body)
    assert world.secrets == {"OIDC_CLIENT_SECRET_OKTA": "top-secret"}

    assert world.client.delete("/api/auth/sso/admin/providers/okta").status_code == 200
    assert world.secrets == {}
    with world.db() as s:
        actions = [
            r.action
            for r in s.query(ConfigAuditLog)
            .filter(ConfigAuditLog.config_key == "auth.oidc.providers")
            .all()
        ]
    assert actions == ["create", "update", "delete"]


def test_a_viewer_cannot_read_or_change_sso_settings(world):
    world.add_user("u-viewer", "vera", "role-viewer")
    world.as_user("u-viewer")
    assert world.client.get("/api/auth/sso/admin/config").status_code == 403
    response = world.client.put(
        "/api/auth/sso/admin/providers/okta", json=_provider_body()
    )
    assert response.status_code == 403
    assert world.secrets == {}


def test_a_manager_cannot_map_users_to_admin(world):
    world.add_user("u-mgr", "maria", "role-manager")
    world.as_user("u-mgr")
    body = _provider_body(
        allow_admin_mapping=True,
        role_mappings=[{"value": "soc-admins", "role_id": "role-admin"}],
    )
    response = world.client.put("/api/auth/sso/admin/providers/okta", json=body)
    assert response.status_code == 403
    assert "users.delete" in response.json()["detail"]
    # Mapping to a role within the manager's own permissions is fine.
    body["role_mappings"] = [{"value": "soc", "role_id": "role-viewer"}]
    body["allow_admin_mapping"] = False
    assert (
        world.client.put("/api/auth/sso/admin/providers/okta", json=body).status_code
        == 200
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"default_role_id": "role-admin"},
        {"role_mappings": [{"value": "x", "role_id": "role-admin"}]},
        {"issuer": "http://idp.test/realms/soc"},
        {"kind": "entra", "issuer": "https://login.microsoftonline.com/common/v2.0"},
    ],
)
def test_unsafe_provider_settings_are_refused(world, overrides):
    world.add_user("u-admin", "root", "role-admin")
    world.as_user("u-admin")
    response = world.client.put(
        "/api/auth/sso/admin/providers/okta", json=_provider_body(**overrides)
    )
    assert response.status_code == 400, response.text
    assert world.secrets == {}


# --- local sign-in policy ---------------------------------------------------


def _password_login(world, username):
    return world.client.post(
        "/api/auth/login",
        json={"username_or_email": username, "password": "Correct-Horse-9!"},
    )


def test_local_sign_in_can_be_limited_to_break_glass_accounts(world):
    world.add_user("u-admin", "root", "role-admin")
    world.add_user("u-analyst", "ana", "role-analyst")
    world.add_user("u-svc", "medic-gateway", "role-viewer", service_account=True)
    world.set_provider()
    world.as_user("u-admin")

    # Refused without a break-glass Admin...
    refused = world.client.put(
        "/api/auth/sso/admin/login-policy",
        json={"local_login_enabled": False, "break_glass_user_ids": ["u-analyst"]},
    )
    assert refused.status_code == 409
    # ...accepted with one.
    accepted = world.client.put(
        "/api/auth/sso/admin/login-policy",
        json={"local_login_enabled": False, "break_glass_user_ids": ["u-admin"]},
    )
    assert accepted.status_code == 200, accepted.text
    world.app.dependency_overrides.clear()
    world.app.dependency_overrides[request_unit_of_work] = _session_dep(world)

    assert (
        world.client.get("/api/auth/sso/providers").json()["local_login_enabled"]
        is False
    )

    blocked = _password_login(world, "ana")
    assert blocked.status_code == 403
    assert "single sign-on" in blocked.json()["detail"]
    assert "access_token" not in blocked.cookies

    assert _password_login(world, "root").status_code == 200  # break-glass
    assert _password_login(world, "medic-gateway").status_code == 200  # machine

    # A wrong password still reads as a wrong password, not as "use SSO".
    wrong = world.client.post(
        "/api/auth/login", json={"username_or_email": "ana", "password": "nope"}
    )
    assert wrong.status_code == 401


def test_local_sign_in_cannot_be_disabled_without_a_provider(world):
    world.add_user("u-admin", "root", "role-admin")
    world.as_user("u-admin")
    response = world.client.put(
        "/api/auth/sso/admin/login-policy",
        json={"local_login_enabled": False, "break_glass_user_ids": ["u-admin"]},
    )
    assert response.status_code == 409


def test_a_service_account_is_not_a_break_glass_account(world):
    world.add_user("u-admin", "root", "role-admin")
    world.add_user("u-svc", "medic-gateway", "role-viewer", service_account=True)
    world.as_user("u-admin")
    response = world.client.put(
        "/api/auth/sso/admin/login-policy",
        json={"local_login_enabled": True, "break_glass_user_ids": ["u-svc"]},
    )
    assert response.status_code == 400


def test_an_sso_only_account_is_not_a_break_glass_account(world):
    world.add_user(
        "u-sso-admin", "sso-root", "role-admin", password_hash=SSO_ONLY_PASSWORD_HASH
    )
    world.add_user("u-admin", "root", "role-admin")
    world.set_provider()
    world.as_user("u-admin")
    response = world.client.put(
        "/api/auth/sso/admin/login-policy",
        json={"local_login_enabled": False, "break_glass_user_ids": ["u-sso-admin"]},
    )
    assert response.status_code == 400
    assert "password" in response.json()["detail"]


def test_the_last_enabled_provider_cannot_be_disabled_while_local_is_off(world):
    world.add_user("u-admin", "root", "role-admin")
    world.as_user("u-admin")
    assert (
        world.client.put(
            "/api/auth/sso/admin/providers/okta", json=_provider_body()
        ).status_code
        == 200
    )
    assert (
        world.client.put(
            "/api/auth/sso/admin/login-policy",
            json={"local_login_enabled": False, "break_glass_user_ids": ["u-admin"]},
        ).status_code
        == 200
    )
    response = world.client.put(
        "/api/auth/sso/admin/providers/okta", json=_provider_body(enabled=False)
    )
    assert response.status_code == 409
    with world.db() as s:
        stored = s.get(SystemConfig, "auth.oidc.providers").value
    assert stored["providers"][0]["enabled"] is True


def test_an_sso_account_gets_no_password_reset_email(world, monkeypatch):
    sent = []
    monkeypatch.setattr(auth_router, "send_email", lambda **kw: sent.append(kw))
    monkeypatch.setattr(
        auth_router, "generate_reset_token", lambda user_id, *a, **k: "t"
    )
    world.set_provider()
    world.login()
    response = world.client.post(
        "/api/auth/password-reset/request", json={"email": "alice@example.com"}
    )
    assert response.status_code == 200
    assert sent == []

    world.add_user("u-bob", "bob", "role-analyst")
    world.client.post(
        "/api/auth/password-reset/request", json={"email": "bob@example.com"}
    )
    assert len(sent) == 1


def _session_dep(world):
    def _request_session():
        session = world.maker()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    return _request_session


# --- Round 5 verifier fixes -------------------------------------------------


def test_a_manager_cannot_repoint_a_provider_and_receive_its_secret(world):
    """Regression (verifier W1.9 MEDIUM-HIGH): secret exfiltration by re-point.

    An Admin configures a provider with a client secret. A Manager (who may
    edit providers) changes only its issuer to a server they control and
    omits client_secret. The stored secret must not survive the re-point, or
    the next login would send it (HTTP Basic) to evil.test's token endpoint.
    """
    world.add_user("u-admin", "root", "role-admin")
    world.add_user("u-mgr", "maria", "role-manager")
    world.as_user("u-admin")
    created = world.client.put(
        "/api/auth/sso/admin/providers/okta", json=_provider_body()
    )
    assert created.status_code == 200, created.text

    world.as_user("u-mgr")
    for change in (
        {"issuer": "https://evil.test/realms/x"},
        {"client_id": "attacker-client"},
        {"redirect_uri": "https://evil.test/cb"},
        {"kind": "generic"},
    ):
        body = _provider_body(**change)
        del body["client_secret"]
        response = world.client.put("/api/auth/sso/admin/providers/okta", json=body)
        assert response.status_code == 400, (change, response.text)
        assert "client secret" in response.json()["detail"]
    assert world.secrets == {"OIDC_CLIENT_SECRET_OKTA": "top-secret"}
    with world.db() as s:
        [stored] = s.get(SystemConfig, "auth.oidc.providers").value["providers"]
    assert stored["issuer"] == ISSUER

    # Re-pointing with a new secret (or clearing it) is fine: the Admin's
    # secret is replaced, never sent elsewhere.
    body = _provider_body(issuer="https://evil.test/realms/x", client_secret="mine")
    response = world.client.put("/api/auth/sso/admin/providers/okta", json=body)
    assert response.status_code == 200, response.text
    assert world.secrets == {"OIDC_CLIENT_SECRET_OKTA": "mine"}

    body = _provider_body(issuer=ISSUER, clear_client_secret=True)
    del body["client_secret"]
    response = world.client.put("/api/auth/sso/admin/providers/okta", json=body)
    assert response.status_code == 200, response.text
    assert world.secrets == {}

    # Editing harmless fields still keeps the stored secret.
    world.as_user("u-admin")
    world.client.put("/api/auth/sso/admin/providers/okta", json=_provider_body())
    body = _provider_body(display_name="Renamed", enabled=False)
    del body["client_secret"]
    assert (
        world.client.put("/api/auth/sso/admin/providers/okta", json=body).status_code
        == 200
    )
    assert world.secrets == {"OIDC_CLIENT_SECRET_OKTA": "top-secret"}


@pytest.mark.parametrize(
    "claimed",
    [
        "ROOT@CORP.EXAMPLE",  # case
        "root@CORP.example",
    ],
)
def test_email_linking_compares_normalised_addresses(world, claimed):
    world.add_user("u-alice", "alice-local", "role-viewer", email="root@corp.example")
    world.set_provider(link_by_verified_email=True)
    world.idp.claims = {"email": claimed}
    response, _, _ = world.login()
    payload = AuthService.verify_jwt_token(response.cookies["access_token"])
    assert payload["user_id"] == "u-alice"
    with world.db() as s:
        assert s.query(User).count() == 1


@pytest.mark.parametrize(
    "claimed",
    [
        "root@corp.example\n",
        "ro\u200bot@corp.example",
        "root@corp.example\x00",
        "root@corp.example\u202e",
        "ＲＯＯＴ@corp.example",  # fullwidth: a look-alike, not an address
        "\ufb01@corp.example",  # "fi" ligature
        "root@ｃｏｒｐ.example",
        "r\u043e\u043et@corp.example",  # Cyrillic o beside Latin letters
        "a@b@corp.example",
        "root@-corp.example",
    ],
)
def test_an_email_with_control_or_lookalike_characters_is_not_an_email(claimed):
    from core.auth.oidc_accounts import normalize_email

    assert normalize_email(claimed) is None


def test_email_keys_keep_sharp_s_and_compare_domains_as_idna():
    """NFKC+casefold made alice@straße.de the same person as alice@strasse.de."""
    from core.auth.oidc_accounts import normalize_email

    assert normalize_email("Root@Corp.Example") == "root@corp.example"
    assert normalize_email("alice@straße.de") == "alice@xn--strae-oqa.de"
    assert normalize_email("alice@straße.de") != normalize_email("alice@strasse.de")
    assert normalize_email("ALICE@xn--strae-oqa.de") == normalize_email(
        "alice@Straße.de"
    )
    assert normalize_email("straße@corp.example") != normalize_email(
        "strasse@corp.example"
    )
    # NFC: a decomposed "é" is the same address as the precomposed one.
    assert normalize_email("e\u0301lodie@corp.example") == normalize_email(
        "\u00e9lodie@corp.example"
    )


def test_a_sharp_s_domain_does_not_link_to_the_ss_account(world):
    world.add_user("u-alice", "alice", "role-admin", email="alice@strasse.de")
    world.set_provider(link_by_verified_email=True, jit_provisioning=True)
    world.idp.claims = {"email": "alice@straße.de"}
    response, _, _ = world.login()
    payload = AuthService.verify_jwt_token(response.cookies["access_token"])
    assert payload["user_id"] != "u-alice"
    with world.db() as s:
        created = s.query(User).filter(User.user_id != "u-alice").one()
        # Stored as the provider sent it, not folded.
        assert created.email == "alice@straße.de"
        assert created.role_id == "role-viewer"


def test_jit_stores_the_address_as_sent(world):
    world.set_provider()
    world.idp.claims = {"email": "Carol.Smith@Example.COM"}
    world.login()
    with world.db() as s:
        assert s.query(User).one().email == "Carol.Smith@Example.COM"


def test_a_trailing_newline_email_neither_links_nor_provisions(world):
    world.add_user("u-root", "root", "role-viewer", email="root@corp.example")
    world.set_provider(link_by_verified_email=True)
    world.idp.claims = {
        "email": "root@corp.example\n",
        "preferred_username": "x",
    }
    response, _, _ = world.login()
    assert world.sso_error(response) == "account"
    with world.db() as s:
        assert s.query(User).count() == 1
        assert s.get(User, "u-root").login_count == 0


def test_jit_refuses_an_email_that_is_someone_elses_username(world):
    """Sign-in takes a username or an email: they must never collide."""
    world.add_user("u-odd", "Carol@Example.com", "role-viewer", email="c@other.test")
    world.set_provider()
    world.idp.claims = {"email": "carol@example.com"}
    response, _, _ = world.login()
    assert world.sso_error(response) == "account"
    assert "username" in world.audit("sso_failure")[-1]["detail"]
    with world.db() as s:
        assert s.query(User).count() == 1


def test_an_unexpected_failure_log_sanitises_the_provider_id(
    world, caplog, monkeypatch
):
    world.set_provider()
    started = world.start()
    code, state = world.idp.authorize(started.headers["location"])

    async def boom(*a, **k):
        raise RuntimeError("x")

    monkeypatch.setattr(oidc_router, "_take_flow", boom)
    world.client.get(
        "/api/auth/sso/kc%0aINFO%20forged/callback",
        params={"code": code, "state": state},
    )
    messages = [r.getMessage() for r in caplog.records]
    assert any("failed unexpectedly" in m for m in messages)
    assert all("\n" not in m for m in messages)


# --- a deleted provider's secret (round 5 follow-up) ------------------------


def test_a_provider_recreated_under_an_id_with_a_leftover_secret_needs_its_own(
    world,
):
    """An env/.env secret survives deleting the provider; a provider later
    created with that id must not inherit (and send) it."""
    world.add_user("u-admin", "root", "role-admin")
    world.as_user("u-admin")
    world.secrets["OIDC_CLIENT_SECRET_OKTA"] = "from-the-environment"
    body = _provider_body(issuer="https://evil.test")
    del body["client_secret"]
    response = world.client.put("/api/auth/sso/admin/providers/okta", json=body)
    assert response.status_code == 409, response.text
    assert "OIDC_CLIENT_SECRET_OKTA" in response.json()["detail"]
    with world.db() as s:
        assert load_providers(s) == []
    # Bringing its own secret is fine.
    body["client_secret"] = "new"
    assert (
        world.client.put("/api/auth/sso/admin/providers/okta", json=body).status_code
        == 200
    )
    assert world.secrets == {"OIDC_CLIENT_SECRET_OKTA": "new"}


def test_deleting_a_provider_fails_if_its_secret_cannot_be_deleted(world, monkeypatch):
    world.add_user("u-admin", "root", "role-admin")
    world.as_user("u-admin")
    world.client.put("/api/auth/sso/admin/providers/okta", json=_provider_body())
    monkeypatch.setattr(oidc_router, "delete_secret", lambda k: False)
    response = world.client.delete("/api/auth/sso/admin/providers/okta")
    assert response.status_code == 500
    with world.db() as s:
        assert [p.id for p in load_providers(s)] == ["okta"]


def test_clearing_a_secret_that_lives_in_the_environment_is_refused(world, monkeypatch):
    world.add_user("u-admin", "root", "role-admin")
    world.as_user("u-admin")
    world.client.put("/api/auth/sso/admin/providers/okta", json=_provider_body())
    # A store that "deletes" but the value is still readable (process env).
    monkeypatch.setattr(oidc_router, "delete_secret", lambda k: True)
    body = _provider_body(clear_client_secret=True)
    del body["client_secret"]
    response = world.client.put("/api/auth/sso/admin/providers/okta", json=body)
    assert response.status_code == 409
    assert "environment" in response.json()["detail"]
