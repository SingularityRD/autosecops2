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
from core.storage.models import Base, Role, User
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
    Base.metadata.create_all(engine, tables=[Role.__table__, User.__table__])
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
