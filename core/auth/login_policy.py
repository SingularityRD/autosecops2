"""Who may still sign in with a local password once single sign-on is in use.

Stored as one ``system_config`` row, ``auth.login_policy``. Absent means the
default: local sign-in on for everyone, as before single sign-on existed.

When an administrator turns local sign-in off, a password still works for:

* the break-glass accounts named in the policy, so an identity-provider outage
  cannot lock every administrator out;
* service accounts (Medic's gateway), which are machines and cannot do a
  browser redirect to an identity provider.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from core.storage.models import SystemConfig, User

LOGIN_POLICY_KEY = "auth.login_policy"


class LoginPolicy(BaseModel):
    local_login_enabled: bool = True
    break_glass_user_ids: List[str] = Field(default_factory=list)


def get_login_policy(session: Session) -> LoginPolicy:
    row = (
        session.query(SystemConfig).filter(SystemConfig.key == LOGIN_POLICY_KEY).first()
    )
    if row is None or not isinstance(row.value, dict):
        return LoginPolicy()
    # A malformed row must not silently re-open local sign-in or close it for
    # everyone: fall back to what each field says, field by field.
    value = row.value
    enabled = value.get("local_login_enabled", True)
    ids = value.get("break_glass_user_ids", [])
    return LoginPolicy(
        local_login_enabled=enabled is not False,
        break_glass_user_ids=(
            [i for i in ids if isinstance(i, str)] if isinstance(ids, list) else []
        ),
    )


def local_login_allowed(user: User, session: Session) -> bool:
    """Whether ``user`` may authenticate with a password right now."""
    if user.service_account is True:
        return True
    policy = get_login_policy(session)
    if policy.local_login_enabled:
        return True
    return user.user_id in policy.break_glass_user_ids
