"""W0.27: password reset flow from upstream (#2199, #2332), security properties.

Request + confirm routes and the operator tool (scripts/reset_password.py):
single use, expiry, a reply that cannot enumerate accounts, rate limits,
SSO-only and service accounts refused, no token in logs or the audit record,
the flow under enforced CSRF, and Referrer-Policy: no-referrer on the page the
link opens.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.responses import PlainTextResponse

from core.auth import password_reset
from core.auth.oidc_accounts import SSO_ONLY_PASSWORD_HASH
from core.platform import email_service
from core.routing import request_unit_of_work
from services.api.middleware.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CSRFMiddleware,
)
from services.api.middleware.rate_limit import limiter
from services.api.middleware.security_headers import SecurityHeadersMiddleware
from services.api.routers import auth

pytestmark = pytest.mark.unit

_spec = importlib.util.spec_from_file_location(
    "reset_password_script_w027",
    Path(__file__).resolve().parents[3] / "scripts" / "reset_password.py",
)
script = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(script)

EMAIL = "ana@example.com"
NEW_PASSWORD = "a-long-new-passphrase-42"


def _user(**over):
    base = dict(
        user_id="u-ana",
        username="ana",
        email=EMAIL,
        full_name="Ana",
        role_id="role-analyst",
        is_active=True,
        password_hash="pbkdf2$x",
        password_history=[],
        service_account=False,
        failed_login_count=0,
        locked_until=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


SSO_ONLY = dict(password_hash=SSO_ONLY_PASSWORD_HASH)
SERVICE = dict(service_account=True, username="medic-gw")


class _Session:
    """query(...).filter(...).first() -> the one user; records add()."""

    def __init__(self, user):
        self.user = user
        self.added = []
        self.flushed = False

    def query(self, *_):
        return self

    def filter(self, *_):
        return self

    def first(self):
        return self.user

    def add(self, row):
        self.added.append(row)

    def flush(self):
        self.flushed = True


class _FakeRedis:
    """SET NX with real semantics, so single use is exercised end to end."""

    def __init__(self):
        self.keys = {}

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.keys:
            return False
        self.keys[key] = value
        return True


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    redis = _FakeRedis()
    monkeypatch.setattr(password_reset, "_redis_client", lambda: redis)
    monkeypatch.setattr(email_service, "_backend", email_service.ConsoleBackend())
    limiter.reset()
    yield redis
    limiter.reset()


def _settings(backend="console", dev_mode=False):
    real = email_service.get_settings()
    return SimpleNamespace(
        vigil_email_backend=backend,
        dev_mode=dev_mode,
        vigil_frontend_url="https://soc.example/autosecops",
        smtp_from=real.smtp_from,
    )


def _app(user, *, csrf=False):
    app = FastAPI()
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(auth.router, prefix="/api/auth")
    app.dependency_overrides[request_unit_of_work] = lambda: _Session(user)
    if csrf:

        @app.get("/reset-password")
        def _page():
            return PlainTextResponse("app shell")

        app.add_middleware(
            CSRFMiddleware,
            enabled=True,
            report_only=False,
            exempt_paths=(),
            cookie_secure=False,
        )
    return app


def _request(client, email=EMAIL, headers=None):
    return client.post(
        "/api/auth/password-reset/request", json={"email": email}, headers=headers
    )


def _confirm(client, token, headers=None):
    return client.post(
        "/api/auth/password-reset/confirm",
        json={"token": token, "new_password": NEW_PASSWORD},
        headers=headers,
    )


@pytest.fixture
def confirm_patches():
    """Stub the password write + session revocation; record the write."""
    applied = []
    with (
        patch.object(auth, "validate_password_strength"),
        patch.object(
            auth, "_apply_new_password", side_effect=lambda u, p: applied.append(u)
        ),
        patch.object(auth, "revoke_all_for_user", AsyncMock()),
    ):
        yield applied


def _token(user=None):
    user = user or _user()
    return password_reset.generate_reset_token(
        user.user_id, user.email, user.password_hash
    )


# --- single use and expiry ----------------------------------------------------


def test_token_works_once(confirm_patches):
    client = TestClient(_app(_user()))
    token = _token()
    assert _confirm(client, token).status_code == 200
    second = _confirm(client, token)
    assert second.status_code == 400
    assert second.json()["detail"] == "Invalid or expired reset token"
    assert len(confirm_patches) == 1


def test_expired_token_is_refused(monkeypatch, confirm_patches):
    token = _token()
    # Every token is older than a negative max_age.
    monkeypatch.setattr(password_reset, "_ttl_seconds", lambda: -1)
    resp = _confirm(TestClient(_app(_user())), token)
    assert resp.status_code == 400
    assert confirm_patches == []


def test_link_ttl_comes_from_settings(monkeypatch):
    monkeypatch.setattr(password_reset, "_ttl_seconds", lambda: 1800)
    sent = {}
    with (
        patch.object(auth, "get_settings", return_value=_settings("smtp")),
        patch.object(auth, "send_email", side_effect=lambda **kw: sent.update(kw)),
    ):
        _request(TestClient(_app(_user())))
    assert "valid for 30 minutes" in sent["body"]
    assert password_reset.ttl_text(3600) == "1 hour"
    assert password_reset.ttl_text(7200) == "2 hours"


def test_password_change_retires_a_pending_link(confirm_patches):
    """W0.13 R6: a link issued before a password change no longer works."""
    user = _user()
    token = _token(user)
    user.password_hash = "pbkdf2$changed-by-change-password"
    resp = _confirm(TestClient(_app(user)), token)
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid or expired reset token"
    assert confirm_patches == []


def test_a_token_without_the_password_binding_is_refused(confirm_patches):
    user = _user()
    legacy = password_reset._get_serializer().dumps(
        {"user_id": user.user_id, "eb": password_reset._email_binding(EMAIL)}
    )
    assert _confirm(TestClient(_app(user)), legacy).status_code == 400
    assert confirm_patches == []


def test_the_payload_does_not_carry_the_password_hash():
    user = _user(password_hash="pbkdf2$verysecrethash")
    payload = password_reset._get_serializer().loads(_token(user))
    assert "verysecrethash" not in json.dumps(payload)


@pytest.mark.parametrize("outage", ["raises", "no_client"])
def test_confirm_fails_closed_without_the_used_token_store(
    outage, monkeypatch, confirm_patches
):
    if outage == "raises":
        broken = AsyncMock()
        broken.set = AsyncMock(side_effect=ConnectionError("redis down"))
        monkeypatch.setattr(password_reset, "_redis_client", lambda: broken)
    else:
        monkeypatch.setattr(password_reset, "_redis_client", lambda: None)
    resp = _confirm(TestClient(_app(_user())), _token())
    assert resp.status_code == 503
    assert resp.json()["detail"] == (
        "Password reset is unavailable right now. Try again later."
    )
    assert confirm_patches == []


def test_links_carry_the_token_in_the_fragment():
    link = password_reset.reset_link("https://soc.example/a/", "TOK")
    assert link == "https://soc.example/a/reset-password#token=TOK"
    sent = {}
    with (
        patch.object(auth, "get_settings", return_value=_settings("smtp")),
        patch.object(auth, "send_email", side_effect=lambda **kw: sent.update(kw)),
    ):
        _request(TestClient(_app(_user())))
    assert "/reset-password#token=" in sent["body"]
    assert "?token=" not in sent["body"]


# --- the reply cannot enumerate accounts ------------------------------------


@pytest.mark.parametrize(
    "backend,dev_mode,delivery",
    [
        ("smtp", False, "email"),
        ("console", True, "server_log"),
        ("console", False, "administrator"),
    ],
)
def test_reply_is_the_same_for_every_account(backend, dev_mode, delivery):
    replies = set()
    for user in (
        _user(),
        None,
        _user(is_active=False),
        _user(**SSO_ONLY),
        _user(**SERVICE),
    ):
        limiter.reset()
        with (
            patch.object(auth, "get_settings", return_value=_settings(backend, dev_mode)),
            patch.object(auth, "send_email"),
        ):
            resp = _request(TestClient(_app(user)))
        assert resp.status_code == 200
        assert resp.json()["delivery"] == delivery
        replies.add(json.dumps(resp.json(), sort_keys=True))
    assert len(replies) == 1


def test_without_mail_the_reply_says_ask_an_administrator():
    with patch.object(auth, "get_settings", return_value=_settings("console")):
        body = _request(TestClient(_app(_user()))).json()
    assert body["delivery"] == "administrator"
    assert "no reset link was sent" in body["message"]
    assert "administrator" in body["message"]
    assert "AutoSecOps" in body["message"] and "Vigil" not in body["message"]


# --- rate limits --------------------------------------------------------------


def test_request_is_rate_limited():
    client = TestClient(_app(_user()))
    with (
        patch.object(auth, "get_settings", return_value=_settings("smtp")),
        patch.object(auth, "send_email") as send,
    ):
        codes = [_request(client).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    assert send.call_count == 3


def test_confirm_is_rate_limited():
    client = TestClient(_app(_user()))
    codes = [_confirm(client, "garbage").status_code for _ in range(6)]
    assert codes == [400] * 5 + [429]


# --- SSO-only and service accounts --------------------------------------------


@pytest.mark.parametrize("kind", [SSO_ONLY, SERVICE], ids=["sso_only", "service"])
def test_request_sends_nothing_to_an_ineligible_account(kind):
    with (
        patch.object(auth, "get_settings", return_value=_settings("smtp")),
        patch.object(auth, "send_email") as send,
        patch.object(auth, "generate_reset_token") as gen,
    ):
        assert _request(TestClient(_app(_user(**kind)))).status_code == 200
    send.assert_not_called()
    gen.assert_not_called()


def test_confirm_refuses_an_sso_only_account_with_a_clear_message(confirm_patches):
    user = _user(**SSO_ONLY)
    resp = _confirm(TestClient(_app(user)), _token(user))
    assert resp.status_code == 400
    assert "single sign-on" in resp.json()["detail"]
    assert "identity provider" in resp.json()["detail"]
    assert confirm_patches == []


def test_confirm_refuses_a_service_account(confirm_patches):
    user = _user(**SERVICE)
    resp = _confirm(TestClient(_app(user)), _token(user))
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Account no longer eligible for reset"
    assert confirm_patches == []


@pytest.mark.parametrize(
    "kind,needle",
    [(SSO_ONLY, "single sign-on"), (SERVICE, "service account"), ({"is_active": False}, "inactive")],
    ids=["sso_only", "service", "inactive"],
)
def test_operator_tool_refuses_and_records_nothing(kind, needle, capsys):
    session = _Session(_user(**kind))
    code, issued = script.issue_link(session, "ana", "http://x", "ops")
    assert code == 1 and issued is None
    assert session.added == []
    out = capsys.readouterr()
    assert needle in out.err
    assert "http" not in out.out


def test_operator_tool_and_routes_agree_on_eligibility():
    assert password_reset.reset_refusal(_user()) is None
    assert password_reset.reset_refusal(None) == password_reset.REFUSED_INACTIVE
    assert (
        password_reset.reset_refusal(_user(**SSO_ONLY))
        == password_reset.REFUSED_SSO_ONLY
    )
    assert (
        password_reset.reset_refusal(_user(**SERVICE))
        == password_reset.REFUSED_SERVICE_ACCOUNT
    )


# --- operator-issued link -----------------------------------------------------


def test_operator_link_is_bound_to_the_email_and_confirms(confirm_patches, monkeypatch):
    """Upstream signed generate_reset_token(user_id): under W1.9's email binding
    that link would be refused at confirm. Ours confirms."""
    monkeypatch.setattr(password_reset, "_ttl_seconds", lambda: 1800)
    monkeypatch.setattr(
        script, "get_settings", lambda: SimpleNamespace(password_reset_ttl_seconds=1800)
    )
    user = _user()
    session = _Session(user)
    code, issued = script.issue_link(
        session, "ana", "https://soc.example/autosecops/", "alice"
    )
    assert code == 0
    _, _, link, ttl = issued
    assert ttl == 1800
    parsed = urlparse(link)
    assert parsed.path == "/autosecops/reset-password"
    assert parsed.query == ""  # fragment only: never sent to the server
    token = parse_qs(parsed.fragment)["token"][0]
    assert password_reset.token_matches_email(token, EMAIL)
    resp = _confirm(TestClient(_app(user)), token)
    assert resp.status_code == 200, resp.text
    assert confirm_patches == [user]


def test_operator_link_audit_record_names_who_whom_when_but_not_the_token(
    monkeypatch, caplog
):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(
        script, "get_settings", lambda: SimpleNamespace(password_reset_ttl_seconds=3600)
    )
    session = _Session(_user())
    code, issued = script.issue_link(session, EMAIL, "http://x", "alice")
    assert code == 0
    token = parse_qs(urlparse(issued[2]).fragment)["token"][0]
    assert session.flushed
    (row,) = session.added
    assert row.entity_type == "user" and row.entity_id == "u-ana"
    assert row.action == script.AUDIT_ACTION and len(row.action) <= 20
    assert row.changed_by == "cli:alice"
    detail = json.loads(row.new_value)
    assert detail["issued_by"] == "alice"
    assert detail["username"] == "ana"
    assert detail["ttl_seconds"] == 3600
    assert detail["issued_at"] and detail["expires_at"] > detail["issued_at"]
    everything = " ".join(
        str(getattr(row, c, ""))
        for c in ("new_value", "change_summary", "changed_by", "field_name")
    )
    assert token not in everything
    assert token not in caplog.text


def test_link_is_printed_only_after_the_audit_record_commits(monkeypatch, capsys):
    """If the record cannot be written, no link is shown."""

    class _Broken(_Session):
        def flush(self):
            raise RuntimeError("db down")

    class _Manager:
        def session_scope(self):
            from contextlib import contextmanager

            @contextmanager
            def scope():
                yield _Broken(_user())

            return scope()

    monkeypatch.setattr(script, "init_database", lambda **_: None)
    monkeypatch.setattr(script, "get_db_manager", lambda: _Manager())
    with pytest.raises(RuntimeError):
        script.main(["ana", "--base-url", "http://x", "--operator", "alice"])
    assert "http" not in capsys.readouterr().out


# --- no token in logs -----------------------------------------------------------


@pytest.mark.parametrize("backend", ["console", "smtp"])
def test_request_logs_no_token(backend, caplog):
    caplog.set_level(logging.DEBUG)
    tokens = []
    real = password_reset.generate_reset_token

    def spy(*a, **kw):
        tokens.append(real(*a, **kw))
        return tokens[-1]

    with (
        patch.object(auth, "get_settings", return_value=_settings(backend)),
        patch.object(email_service, "get_settings", return_value=_settings(backend)),
        patch.object(auth, "generate_reset_token", side_effect=spy),
        patch.object(auth, "send_email"),
    ):
        assert _request(TestClient(_app(_user()))).status_code == 200
    assert tokens
    assert tokens[0] not in caplog.text


def test_confirm_logs_no_token(confirm_patches, caplog):
    caplog.set_level(logging.DEBUG)
    token = _token()
    client = TestClient(_app(_user()))
    _confirm(client, token)
    _confirm(client, token)  # the replay is logged too
    assert token not in caplog.text


# --- CSRF enforced ----------------------------------------------------------------


def test_flow_works_under_enforced_csrf(confirm_patches):
    client = TestClient(_app(_user(), csrf=True))
    with (
        patch.object(auth, "get_settings", return_value=_settings("smtp")),
        patch.object(auth, "send_email"),
    ):
        # A forged cross-site POST (no header) is refused...
        assert _request(client).status_code == 403
        # ...the page load seeds the cookie the SPA echoes back.
        page = client.get("/reset-password")
        csrf = page.cookies.get(CSRF_COOKIE_NAME) or client.cookies.get(
            CSRF_COOKIE_NAME
        )
        assert csrf
        headers = {CSRF_HEADER_NAME: csrf}
        assert _request(client, headers=headers).status_code == 200
    assert _confirm(client, _token(), headers=headers).status_code == 200
    assert _confirm(client, "x", headers={CSRF_HEADER_NAME: "wrong"}).status_code == 403


# --- Referrer-Policy on the reset page -----------------------------------------


def _headers_app(**kw):
    app = FastAPI()

    @app.get("/{path:path}")
    def _any(path: str):
        return PlainTextResponse("ok")

    app.add_middleware(SecurityHeadersMiddleware, **kw)
    return TestClient(app)


@pytest.mark.parametrize(
    "path", ["/reset-password", "/autosecops/reset-password", "/reset-password/"]
)
def test_reset_page_sends_no_referrer(path):
    resp = _headers_app().get(path, params={"token": "t"})
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_reset_page_sends_no_referrer_even_when_the_header_is_turned_off():
    resp = _headers_app(referrer_policy_enabled=False).get("/reset-password")
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_other_pages_keep_the_default_policy():
    for path in ("/login", "/api/auth/password-reset/confirm"):
        resp = _headers_app().get(path)
        assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"


def test_reset_request_message_never_says_vigil():
    for text in auth._RESET_REQUEST_MESSAGES.values():
        assert "Vigil" not in text


def test_redis_used_marker_is_not_the_token(_isolation):
    token = _token()
    asyncio.run(password_reset.verify_reset_token(token))
    assert token not in " ".join(_isolation.keys)
