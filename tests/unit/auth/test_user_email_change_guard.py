"""Changing an account's email is a way into it (Round 5, verifier HIGH).

users.write let anyone holding it change an Admin's email to their own
address and then request a password reset: account takeover. Now only an
Admin may change the email of an account at or above the caller's
privileges, the old address is told, and pending reset links die.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.auth import password_reset
from core.storage.models import Base, Role, SystemConfig, User
from services.api.routers import users

PERMS = {
    "role-viewer": {"findings.read": True},
    "role-manager": {"findings.read": True, "users.read": True, "users.write": True},
    "role-admin": {
        "findings.read": True,
        "users.read": True,
        "users.write": True,
        "users.delete": True,
    },
}


@pytest.fixture
def session(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(
        engine, tables=[Role.__table__, User.__table__, SystemConfig.__table__]
    )
    s = sessionmaker(bind=engine)()
    for role_id, perms in PERMS.items():
        s.add(Role(role_id=role_id, name=role_id, description="", permissions=perms))
    for user_id, role_id in (
        ("u-admin", "role-admin"),
        ("u-mgr", "role-manager"),
        ("u-mgr2", "role-manager"),
        ("u-viewer", "role-viewer"),
    ):
        s.add(
            User(
                user_id=user_id,
                username=user_id,
                email=f"{user_id}@corp.example",
                password_hash="x",
                full_name=user_id,
                role_id=role_id,
                is_active=True,
            )
        )
    s.commit()

    def perms_of(user_id, _session=None):
        return dict(PERMS[s.get(User, user_id).role_id])

    monkeypatch.setattr(
        users.AuthService, "get_user_permissions", staticmethod(perms_of)
    )
    monkeypatch.setattr(
        users.AuthService,
        "check_permission",
        staticmethod(lambda uid, perm: perms_of(uid).get(perm, False)),
    )
    monkeypatch.setattr(users.UserSchema, "dump", lambda u: {"email": u.email})
    yield s
    s.close()


def _change_email(session, actor_id, target_id, email):
    return users._apply_user_update(
        session,
        session.get(User, actor_id),
        target_id,
        users.UpdateUserRequest(email=email),
    )


@pytest.mark.parametrize("target", ["u-admin", "u-mgr2"])
def test_a_manager_cannot_change_the_email_of_an_admin_or_a_peer(session, target):
    with pytest.raises(HTTPException) as exc:
        _change_email(session, "u-mgr", target, "attacker@evil.com")
    assert exc.value.status_code == 403
    assert session.get(User, target).email == f"{target}@corp.example"


def test_a_manager_may_change_a_lower_account_and_their_own(session):
    _, reason, _, old = _change_email(session, "u-mgr", "u-viewer", "v2@corp.example")
    assert (reason, old) == ("Email changed", "u-viewer@corp.example")
    _, _, _, old = _change_email(session, "u-mgr", "u-mgr", "me@corp.example")
    assert old == "u-mgr@corp.example"


def test_an_admin_may_change_anyones_email(session):
    _, _, _, old = _change_email(session, "u-admin", "u-mgr", "m@corp.example")
    assert old == "u-mgr@corp.example"


def test_an_email_already_used_in_another_case_is_refused(session):
    with pytest.raises(HTTPException) as exc:
        _change_email(session, "u-admin", "u-viewer", "U-MGR@corp.example")
    assert exc.value.status_code == 400


def test_setting_the_same_email_changes_nothing(session):
    _, reason, _, old = _change_email(
        session, "u-mgr", "u-admin", "u-admin@corp.example"
    )
    assert reason is None and old is None


def test_the_old_address_is_told_of_the_change():
    target = MagicMock(user_id="u-1", username="vic", full_name="Vic")
    sent = []
    with (
        patch.object(
            users,
            "_apply_user_update",
            return_value=(target, "Email changed", {}, "old@corp.example"),
        ),
        patch.object(users, "revoke_all_for_user", new=AsyncMock()),
        patch.object(users, "send_email", lambda **kw: sent.append(kw)),
    ):
        asyncio.run(
            users.update_user(
                "u-1",
                users.UpdateUserRequest(email="new@corp.example"),
                MagicMock(username="root"),
                MagicMock(),
            )
        )
    assert [m["to"] for m in sent] == ["old@corp.example"]
    assert "root" in sent[0]["body"]


def test_a_reset_link_dies_when_the_email_changes(monkeypatch):
    client = AsyncMock()
    client.set = AsyncMock(return_value=True)
    monkeypatch.setattr(password_reset, "_redis_client", lambda: client)
    token = password_reset.generate_reset_token("u-admin", "Root@Corp.example")
    assert asyncio.run(password_reset.verify_reset_token(token)) == "u-admin"
    assert password_reset.token_matches_email(token, "root@corp.example")
    assert not password_reset.token_matches_email(token, "attacker@evil.com")
    # A token minted without the binding (before this fix) is refused.
    legacy = password_reset._get_serializer().dumps({"user_id": "u-admin"})
    assert not password_reset.token_matches_email(legacy, "root@corp.example")


# --- role / active-state changes and look-alike addresses (round 5) ---------


def _update(session, actor_id, target_id, **fields):
    return users._apply_user_update(
        session,
        session.get(User, actor_id),
        target_id,
        users.UpdateUserRequest(**fields),
    )


@pytest.mark.parametrize("fields", [{"role_id": "role-viewer"}, {"is_active": False}])
@pytest.mark.parametrize("target", ["u-admin", "u-mgr2"])
def test_a_manager_cannot_demote_or_deactivate_an_admin_or_a_peer(
    session, target, fields
):
    before = session.get(User, target)
    role, active = before.role_id, before.is_active
    with pytest.raises(HTTPException) as exc:
        _update(session, "u-mgr", target, **fields)
    assert exc.value.status_code == 403
    session.rollback()
    after = session.get(User, target)
    assert (after.role_id, after.is_active) == (role, active)


def test_a_manager_may_still_deactivate_an_account_below_them(session):
    _update(session, "u-mgr", "u-viewer", is_active=False)
    assert session.get(User, "u-viewer").is_active is False


def test_a_manager_cannot_delete_an_admin(session):
    with pytest.raises(HTTPException) as exc:
        users.delete_user("u-admin", session.get(User, "u-mgr"), session)
    assert exc.value.status_code == 403


@pytest.mark.parametrize("fields", [{"role_id": "role-manager"}, {"is_active": False}])
def test_the_last_active_admin_cannot_be_demoted_or_deactivated(session, fields):
    with pytest.raises(HTTPException) as exc:
        _update(session, "u-admin", "u-admin", **fields)
    assert exc.value.status_code == 409
    assert "last active administrator" in exc.value.detail


def test_the_last_admin_cannot_be_deleted(session):
    session.add(
        User(
            user_id="u-admin2",
            username="u-admin2",
            email="u-admin2@corp.example",
            password_hash="x",
            full_name="a2",
            role_id="role-admin",
            is_active=False,
        )
    )
    session.commit()
    with pytest.raises(HTTPException) as exc:
        users.delete_user("u-admin", session.get(User, "u-admin2"), session)
    assert exc.value.status_code == 409


def _break_glass(session, *user_ids):
    from core.auth.login_policy import LOGIN_POLICY_KEY

    session.add(
        SystemConfig(
            key=LOGIN_POLICY_KEY,
            value={
                "local_login_enabled": False,
                "break_glass_user_ids": list(user_ids),
            },
            config_type="auth",
        )
    )
    session.commit()


@pytest.mark.parametrize("fields", [{"role_id": "role-viewer"}, {"is_active": False}])
def test_a_break_glass_account_cannot_be_demoted_or_deactivated(session, fields):
    session.add(
        User(
            user_id="u-admin2",
            username="u-admin2",
            email="u-admin2@corp.example",
            password_hash="x",
            full_name="a2",
            role_id="role-admin",
            is_active=True,
        )
    )
    session.commit()
    _break_glass(session, "u-admin2")
    with pytest.raises(HTTPException) as exc:
        _update(session, "u-admin", "u-admin2", **fields)
    assert exc.value.status_code == 409
    assert "break-glass" in exc.value.detail
    # Other admins are still manageable.
    _update(session, "u-admin2", "u-admin", is_active=False)
    assert session.get(User, "u-admin").is_active is False


@pytest.mark.parametrize(
    "email",
    [
        "U-ADMIN@corp.example",  # case
        "u-admin@CORP.EXAMPLE",
    ],
)
def test_an_email_equal_to_another_after_normalisation_is_refused(session, email):
    with pytest.raises(HTTPException) as exc:
        _change_email(session, "u-mgr", "u-mgr", email)
    assert exc.value.status_code == 400
    assert "in use" in exc.value.detail


@pytest.mark.parametrize(
    "email",
    [
        "ｕ-admin@corp.example",  # fullwidth
        "u-аdmin@corp.example",  # Cyrillic a among Latin letters
    ],
)
def test_a_lookalike_email_is_refused(session, email):
    with pytest.raises(HTTPException) as exc:
        _change_email(session, "u-mgr", "u-mgr", email)
    assert exc.value.status_code == 400
    session.rollback()
    assert session.get(User, "u-mgr").email == "u-mgr@corp.example"


def test_create_refuses_a_colliding_or_lookalike_email(session, monkeypatch):
    monkeypatch.setattr(users, "validate_password_strength", lambda *a, **k: None)
    created = MagicMock()
    monkeypatch.setattr(users.AuthService, "create_user", created)
    for email in ("U-Admin@Corp.Example", "ｕ-admin@corp.example"):
        request = users.CreateUserRequest(
            username="newbie",
            email=email,
            password="x",
            full_name="n",
            role_id="role-viewer",
        )
        with pytest.raises(HTTPException) as exc:
            users.create_user(request, session.get(User, "u-admin"), session)
        assert exc.value.status_code == 400
    # A username that is another account's address is refused too.
    request = users.CreateUserRequest(
        username="U-Admin@corp.example",
        email="fresh@corp.example",
        password="x",
        full_name="n",
        role_id="role-viewer",
    )
    with pytest.raises(HTTPException):
        users.create_user(request, session.get(User, "u-admin"), session)
    created.assert_not_called()
