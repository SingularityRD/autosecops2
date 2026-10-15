"""W0.13 auth/API review: regression tests for the findings fixed on this branch.

R1  PUT /api/users/{id} must not let users.write take over or strip an account
    at or above the editor (now enforced by W1.9's _may_change_identity_of;
    these tests pin that it still holds after the merge).
R2  A service account's email can't be changed through PUT /api/auth/me, and
    it never gets a password-reset email or confirm.
R3  MFA can't be switched off, re-set-up or given new recovery codes with a
    session alone once it is enabled.
R4  The CSRF exemption for /api/ingest/ (and the other header-auth prefixes)
    does not cover a request that carries the browser session cookie.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

from services.api.routers import auth as auth_router  # noqa: E402
from services.api.routers import users  # noqa: E402

pytestmark = pytest.mark.unit

ADMIN_PERMS = {
    "users.read": True,
    "users.write": True,
    "users.delete": True,
    "settings.write": True,
    "medic.admin": True,
}
MANAGER_PERMS = {"users.read": True, "users.write": True, "settings.write": True}
ANALYST_PERMS = {"users.read": True}


# --- R1 ----------------------------------------------------------------------


def _user(user_id, role_id, **kw):
    base = dict(
        user_id=user_id,
        username=user_id,
        email=f"{user_id}@example.com",
        role_id=role_id,
        full_name=user_id,
        is_active=True,
        is_verified=True,
        service_account=False,
    )
    base.update(kw)
    return SimpleNamespace(**base)


ROLES = {
    "role-admin": SimpleNamespace(role_id="role-admin", permissions=ADMIN_PERMS),
    "role-manager": SimpleNamespace(role_id="role-manager", permissions=MANAGER_PERMS),
    "role-analyst": SimpleNamespace(role_id="role-analyst", permissions=ANALYST_PERMS),
}


def _session(target):
    """users rows resolve to ``target``; roles resolve by the filtered id."""
    session = MagicMock()

    def query(model):
        q = MagicMock()

        def filt(clause, *more):
            res = MagicMock()
            if model is users.User:
                # Two clauses is the "email already in use" probe: no clash.
                res.first.return_value = None if more else target
            else:
                res.first.return_value = ROLES.get(clause.right.value)
            return res

        q.filter.side_effect = filt
        return q

    session.query.side_effect = query
    return session


@pytest.fixture
def as_manager():
    manager = _user("mgr", "role-manager")
    with (
        patch.object(users.AuthService, "check_permission", return_value=True),
        patch.object(
            users.AuthService, "get_user_permissions", return_value=MANAGER_PERMS
        ),
        patch.object(users.UserSchema, "dump", return_value={}),
        patch.object(users, "email_owner", return_value=None),
    ):
        yield manager


@pytest.mark.parametrize(
    "change",
    [
        {"email": "mgr-inbox@example.com"},
        {"role_id": "role-analyst"},
        {"is_active": False},
    ],
)
def test_manager_cannot_edit_an_admin(as_manager, change):
    admin = _user("adm", "role-admin")
    with pytest.raises(HTTPException) as exc:
        users._apply_user_update(
            _session(admin), as_manager, "adm", users.UpdateUserRequest(**change)
        )
    assert exc.value.status_code == 403
    assert admin.email == "adm@example.com"
    assert admin.role_id == "role-admin"
    assert admin.is_active is True


def test_manager_can_still_edit_an_analyst(as_manager):
    analyst = _user("ana", "role-analyst")
    _, reason, _, old_email = users._apply_user_update(
        _session(analyst),
        as_manager,
        "ana",
        users.UpdateUserRequest(email="new@example.com"),
    )
    assert analyst.email == "new@example.com"
    assert reason == "Email changed"
    assert old_email == "ana@example.com"


def test_manager_can_edit_themselves(as_manager):
    _, reason, _, _ = users._apply_user_update(
        _session(as_manager), as_manager, "mgr", users.UpdateUserRequest(full_name="M")
    )
    assert as_manager.full_name == "M"
    assert reason is None


# --- R2 ----------------------------------------------------------------------


def _plain_session(user=None):
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = user
    return session


def test_service_account_email_cannot_change_through_me():
    sa = _user("medic-abc", "role-viewer", service_account=True)
    with pytest.raises(HTTPException) as exc:
        auth_router._apply_profile_update(
            _plain_session(None), sa, None, "attacker@example.com"
        )
    assert exc.value.status_code == 403
    assert sa.email == "medic-abc@example.com"


def test_person_can_still_change_own_email_through_me():
    person = _user("ana", "role-analyst")
    with patch.object(auth_router.UserSchema, "dump", return_value={}):
        changed, _ = auth_router._apply_profile_update(
            _plain_session(None), person, None, "ana2@example.com"
        )
    assert changed is True
    assert person.email == "ana2@example.com"


def test_service_account_gets_no_reset_email():
    sa = _user("medic-abc", "role-viewer", service_account=True)
    body = auth_router.PasswordResetRequest(email="medic-abc@example.com")
    with (
        patch.object(auth_router, "send_email") as send,
        patch.object(auth_router, "generate_reset_token") as gen,
    ):
        out = auth_router.password_reset_request.__wrapped__(
            MagicMock(), body, _plain_session(sa)
        )
    send.assert_not_called()
    gen.assert_not_called()
    # W0.27: the reply names the mail setup, never the account (see
    # test_w027_password_reset_security.test_reply_is_the_same_for_every_account).
    assert "reset link" in out["message"]


def test_service_account_reset_confirm_is_refused():
    import asyncio

    sa = _user("medic-abc", "role-viewer", service_account=True)

    async def _verify(_token):
        return "medic-abc"

    body = auth_router.PasswordResetConfirm(token="t", new_password="x" * 40)
    with (
        patch.object(auth_router, "verify_reset_token", _verify),
        patch.object(auth_router, "_apply_new_password") as apply,
    ):
        with pytest.raises(HTTPException) as exc:
            asyncio.run(
                auth_router.password_reset_confirm.__wrapped__(
                    MagicMock(), body, _plain_session(sa)
                )
            )
    assert exc.value.status_code == 400
    apply.assert_not_called()


# --- R3 ----------------------------------------------------------------------


def _mfa_user(enabled=True):
    return SimpleNamespace(
        user_id="u-1",
        username="ada",
        mfa_enabled=enabled,
        mfa_secret="enc",
        mfa_recovery_codes=["h1", "h2"],
    )


def test_setup_refused_while_mfa_is_enabled():
    user = _mfa_user()
    with patch.object(auth_router.AuthService, "setup_mfa") as setup:
        with pytest.raises(HTTPException) as exc:
            auth_router.setup_mfa(user, MagicMock())
    assert exc.value.status_code == 409
    setup.assert_not_called()
    assert user.mfa_enabled is True


def test_disable_needs_a_code_when_enabled():
    user = _mfa_user()
    with pytest.raises(HTTPException) as exc:
        auth_router.disable_mfa.__wrapped__(MagicMock(), user, MagicMock(), None)
    assert exc.value.status_code == 400
    assert user.mfa_enabled is True


def test_disable_refuses_a_wrong_code():
    user = _mfa_user()
    with patch.object(auth_router.AuthService, "verify_mfa_code", return_value=False):
        with pytest.raises(HTTPException) as exc:
            auth_router.disable_mfa.__wrapped__(
                MagicMock(), user, MagicMock(), auth_router.MFACodeRequest(code="1")
            )
    assert exc.value.status_code == 400
    assert user.mfa_enabled is True
    assert user.mfa_secret == "enc"


def test_disable_with_a_current_code_clears_everything():
    user = _mfa_user()
    with patch.object(auth_router.AuthService, "verify_mfa_code", return_value=True):
        auth_router.disable_mfa.__wrapped__(
            MagicMock(), user, MagicMock(), auth_router.MFACodeRequest(code="123456")
        )
    assert user.mfa_enabled is False
    assert user.mfa_secret is None
    assert user.mfa_recovery_codes == []


def test_abandoning_a_pending_setup_needs_no_code():
    user = _mfa_user(enabled=False)
    auth_router.disable_mfa.__wrapped__(MagicMock(), user, MagicMock(), None)
    assert user.mfa_secret is None


def test_regenerating_recovery_codes_needs_a_code():
    user = _mfa_user()
    with patch.object(auth_router.AuthService, "get_mfa_recovery_codes") as regen:
        with pytest.raises(HTTPException) as exc:
            auth_router.regenerate_recovery_codes.__wrapped__(
                MagicMock(), user, MagicMock(), None
            )
    assert exc.value.status_code == 400
    regen.assert_not_called()


# --- R4 ----------------------------------------------------------------------


def _csrf_app():
    from services.api.middleware.csrf import CSRFMiddleware, _parse_exempt_paths

    app = FastAPI()
    app.add_middleware(
        CSRFMiddleware,
        enabled=True,
        report_only=False,
        exempt_paths=_parse_exempt_paths(None, ""),
    )

    @app.post("/api/ingest/ingest-string")
    def ingest():
        return {"ok": True}

    return app


def test_ingest_with_session_cookie_and_no_token_is_refused():
    from core.auth.auth_cookies import ACCESS_COOKIE_NAME

    client = TestClient(_csrf_app())
    client.cookies.set(ACCESS_COOKIE_NAME, "a-session")
    response = client.post("/api/ingest/ingest-string")
    assert response.status_code == 403


def test_ingest_with_session_cookie_and_matching_token_passes():
    from core.auth.auth_cookies import ACCESS_COOKIE_NAME
    from services.api.middleware.csrf import CSRF_COOKIE_NAME, CSRF_HEADER_NAME

    client = TestClient(_csrf_app())
    client.cookies.set(ACCESS_COOKIE_NAME, "a-session")
    client.cookies.set(CSRF_COOKIE_NAME, "tok")
    response = client.post(
        "/api/ingest/ingest-string", headers={CSRF_HEADER_NAME: "tok"}
    )
    assert response.status_code == 200


def test_ingest_with_bearer_and_no_cookie_stays_exempt():
    client = TestClient(_csrf_app())
    response = client.post(
        "/api/ingest/ingest-string", headers={"Authorization": "Bearer x"}
    )
    assert response.status_code == 200


# --- Round 5: merged with W1.9 (password_reset_request keeps both rules) ------


def test_person_reset_uses_the_email_bound_token():
    person = _user("ana", "role-analyst", password_hash="h", sso_subject=None)
    body = auth_router.PasswordResetRequest(email="ana@example.com")
    with (
        patch.object(auth_router, "send_email") as send,
        patch.object(auth_router, "is_sso_only", return_value=False),
        patch.object(auth_router, "generate_reset_token", return_value="t") as gen,
    ):
        auth_router.password_reset_request.__wrapped__(
            MagicMock(), body, _plain_session(person)
        )
    gen.assert_called_once_with("ana", "ana@example.com", "h")
    send.assert_called_once()


def test_sso_only_account_gets_no_reset_email():
    person = _user("ana", "role-analyst")
    body = auth_router.PasswordResetRequest(email="ana@example.com")
    with (
        patch.object(auth_router, "send_email") as send,
        patch.object(auth_router, "is_sso_only", return_value=True),
        patch.object(auth_router, "generate_reset_token") as gen,
    ):
        auth_router.password_reset_request.__wrapped__(
            MagicMock(), body, _plain_session(person)
        )
    send.assert_not_called()
    gen.assert_not_called()


def test_service_account_without_sso_still_gets_no_reset_email():
    sa = _user("medic-abc", "role-viewer", service_account=True)
    body = auth_router.PasswordResetRequest(email="medic-abc@example.com")
    with (
        patch.object(auth_router, "send_email") as send,
        patch.object(auth_router, "is_sso_only", return_value=False),
        patch.object(auth_router, "generate_reset_token") as gen,
    ):
        auth_router.password_reset_request.__wrapped__(
            MagicMock(), body, _plain_session(sa)
        )
    send.assert_not_called()
    gen.assert_not_called()


def test_manager_may_rename_an_admin_under_w19_model(as_manager):
    """W1.9's model wins: only identity changes (email, role, status, delete)
    are guarded; a display-name edit is not a takeover path."""
    admin = _user("adm", "role-admin")
    _, reason, _, old = users._apply_user_update(
        _session(admin), as_manager, "adm", users.UpdateUserRequest(full_name="A")
    )
    assert admin.full_name == "A"
    assert reason is None and old is None


# --- Round 5: R5, CSRF enforced by default in Helm ----------------------------

_REPO = __import__("pathlib").Path(__file__).resolve().parents[3]


def test_helm_enforces_csrf_by_default():
    import yaml

    values = yaml.safe_load(
        (_REPO / "infra" / "helm" / "vigil" / "values.yaml").read_text()
    )
    env = values["config"]
    assert env["VIGIL_CSRF_ENABLED"] == "true"
    assert env["VIGIL_CSRF_REPORT_ONLY"] == "false"


def test_web_client_sends_no_mutating_raw_fetch():
    """Enforcement is only safe because every state-changing call from the
    console carries X-CSRF-Token: axios via its interceptor, fetch only via
    streamFetch. A raw fetch() with a mutating method would be refused."""
    import re

    src = _REPO / "clients" / "web" / "src"
    offenders = []
    for path in list(src.rglob("*.ts")) + list(src.rglob("*.tsx")):
        rel = path.relative_to(src).as_posix()
        if ".test." in rel or rel.startswith("services/generated/"):
            continue
        if rel == "services/api.ts":
            continue  # streamFetch itself
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"(?<![\w.])fetch\(", text):
            window = text[m.end() : m.end() + 400]
            close = window.find("})")
            window = window if close < 0 else window[:close]
            if re.search(r"method:\s*['\"](POST|PUT|PATCH|DELETE)", window, re.I) or (
                "JSON_POST" in window
            ):
                offenders.append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1}")
    assert offenders == [], offenders
