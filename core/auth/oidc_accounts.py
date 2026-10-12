"""Single sign-on, AutoSecOps side: provider storage, accounts and roles.

Three kinds of ``system_config`` row, so single sign-on needs no schema change:

* ``auth.oidc.providers`` — every configured provider (no secrets; a client
  secret lives in the secrets manager under ``oidc.client_secret_key``).
* ``auth.oidc.identity.<sha256(iss, sub)>`` — one per linked identity: which
  user an identity provider's subject is. Keyed by the hash so lookup is a
  primary-key read and the key length is fixed.
* ``auth.login_policy`` — see ``core.auth.login_policy``.

An identity is matched on ``iss`` + ``sub`` only. The email claim is never an
identifier: it is used to *link* to an existing account only when an
administrator turned that on for the provider and the provider asserts
``email_verified: true``.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from core.auth.oidc import (
    ADMIN_ROLE_ID,
    VIEWER_ROLE_ID,
    OidcError,
    ProviderConfig,
    digest,
)
from core.storage.models import ConfigAuditLog, Role, SystemConfig, User
from core.storage.unit_of_work import unit_of_work
from core.time import utcnow

logger = logging.getLogger(__name__)

PROVIDERS_KEY = "auth.oidc.providers"
IDENTITY_KEY_PREFIX = "auth.oidc.identity."
AUTH_CONFIG_TYPE = "auth"
IDENTITY_CONFIG_TYPE = "auth_identity"
AUDIT_CONFIG_TYPE = "auth_event"
AUDIT_KEY = "sso.login"

#: ``password_hash`` of an account created by single sign-on. Not a bcrypt
#: hash, so ``AuthService.verify_password`` fails for every password.
SSO_ONLY_PASSWORD_HASH = "!sso-only"

_USERNAME_SAFE = re.compile(r"[^A-Za-z0-9._@-]+")


# ---------------------------------------------------------------------------
# Provider storage
# ---------------------------------------------------------------------------


def load_providers(session: Session) -> List[ProviderConfig]:
    row = session.query(SystemConfig).filter(SystemConfig.key == PROVIDERS_KEY).first()
    if row is None or not isinstance(row.value, dict):
        return []
    providers = []
    for raw in row.value.get("providers") or []:
        try:
            providers.append(ProviderConfig.model_validate(raw))
        except Exception as exc:  # one bad row must not hide the others
            logger.error("Ignoring an invalid stored SSO provider: %s", exc)
    return providers


def get_provider(session: Session, provider_id: str) -> Optional[ProviderConfig]:
    for provider in load_providers(session):
        if provider.id == provider_id:
            return provider
    return None


def save_providers(
    session: Session, providers: List[ProviderConfig], *, changed_by: str, action: str
) -> None:
    """Replace the stored provider list, with an audit row in the same transaction."""
    row = session.query(SystemConfig).filter(SystemConfig.key == PROVIDERS_KEY).first()
    new_value = {"providers": [p.model_dump() for p in providers]}
    old_value = row.value if row is not None else None
    if row is None:
        session.add(
            SystemConfig(
                key=PROVIDERS_KEY,
                value=new_value,
                description="OIDC single sign-on providers",
                config_type=AUTH_CONFIG_TYPE,
                updated_by=changed_by,
            )
        )
    else:
        row.value = new_value
        row.updated_by = changed_by
    session.add(
        ConfigAuditLog(
            config_type=AUTH_CONFIG_TYPE,
            config_key=PROVIDERS_KEY,
            action=action,
            old_value=old_value,
            new_value=new_value,
            changed_by=changed_by,
        )
    )


# ---------------------------------------------------------------------------
# Identity links
# ---------------------------------------------------------------------------


def identity_key(issuer: str, subject: str) -> str:
    return IDENTITY_KEY_PREFIX + digest(f"{issuer}\n{subject}")


def _get_link(session: Session, key: str) -> Optional[SystemConfig]:
    return session.query(SystemConfig).filter(SystemConfig.key == key).first()


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


def _claim_values(claims: Dict[str, Any], claim: str) -> List[str]:
    value = claims.get(claim)
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def map_role(
    provider: ProviderConfig, claims: Dict[str, Any], known_role_ids: set[str]
) -> str:
    """The role the claims earn: the first matching mapping, else the default.

    Never Admin unless the provider allows Admin mappings *and* an explicit
    mapping matched. Never a role that no longer exists; never Admin as a
    default, even if a stored configuration somehow says so.
    """
    for mapping in provider.role_mappings:
        if mapping.value not in _claim_values(claims, mapping.claim):
            continue
        if mapping.role_id not in known_role_ids:
            logger.warning(
                "SSO mapping names unknown role %s; skipped", mapping.role_id
            )
            continue
        if mapping.role_id == ADMIN_ROLE_ID and not provider.allow_admin_mapping:
            logger.warning("SSO mapping to Admin skipped: provider does not allow it")
            continue
        return mapping.role_id
    default = provider.default_role_id
    if default == ADMIN_ROLE_ID or default not in known_role_ids:
        return VIEWER_ROLE_ID
    return default


def known_role_ids(session: Session) -> set[str]:
    return {r for (r,) in session.query(Role.role_id).all()}


# ---------------------------------------------------------------------------
# Resolving the account
# ---------------------------------------------------------------------------


@dataclass
class SsoLogin:
    user: User
    created: bool
    linked: bool
    role_changed: bool


def _email_from_claims(claims: Dict[str, Any]) -> Optional[str]:
    for name in ("email", "preferred_username", "upn"):
        value = claims.get(name)
        if isinstance(value, str) and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
            return value.strip()[:200]
    return None


def _unique_username(session: Session, claims: Dict[str, Any], email: str) -> str:
    raw = claims.get("preferred_username")
    if not isinstance(raw, str) or not raw.strip():
        raw = email
    base = _USERNAME_SAFE.sub("-", raw.strip())[:80].strip("-") or "sso-user"
    candidate = base
    for _ in range(20):
        if not session.query(User.user_id).filter(User.username == candidate).first():
            return candidate
        candidate = f"{base}-{uuid.uuid4().hex[:6]}"
    raise OidcError("account", "could not choose a unique username")


def _find_by_email(session: Session, email: str) -> Optional[User]:
    return session.query(User).filter(func.lower(User.email) == email.lower()).first()


def resolve_user(
    session: Session, provider: ProviderConfig, claims: Dict[str, Any]
) -> SsoLogin:
    """Find, link or create the account for validated ``claims``.

    Every refusal is checked before anything is written, so a refused login
    leaves no partial account or link behind.

    Raises:
        OidcError: ``account`` (no account and none may be made/linked),
            ``machine_account`` (a service account), ``inactive``.
    """
    issuer = claims["iss"]
    subject = claims["sub"]
    key = identity_key(issuer, subject)
    roles = known_role_ids(session)
    now = utcnow()

    link = _get_link(session, key)
    user: Optional[User] = None
    provisioned = False
    if link is not None and isinstance(link.value, dict):
        user = (
            session.query(User)
            .filter(User.user_id == link.value.get("user_id"))
            .first()
        )
        provisioned = bool(link.value.get("provisioned"))
        if user is None:
            # The account was deleted; the link is stale. Treat as first login.
            session.delete(link)
            session.flush()
            link = None

    created = linked = False
    if user is None:
        email = _email_from_claims(claims)
        existing = _find_by_email(session, email) if email else None
        if existing is not None:
            if not provider.link_by_verified_email:
                raise OidcError(
                    "account",
                    "an account with this email exists and linking by email is off",
                )
            if claims.get("email_verified") is not True:
                raise OidcError(
                    "account", "provider did not assert email_verified for linking"
                )
            claimed = claims.get("email")
            if not isinstance(claimed, str) or (
                claimed.strip().lower() != existing.email.lower()
            ):
                # Linking trusts only the verified "email" claim, never
                # preferred_username/upn.
                raise OidcError("account", "verified email claim does not match")
            user = existing
            linked = True
        else:
            if not provider.jit_provisioning:
                raise OidcError("account", "no linked account and JIT is off")
            if not email:
                raise OidcError("account", "ID token carries no usable email")
            provisioned = True
            created = True

    if user is not None:
        if user.service_account is True:
            raise OidcError("machine_account", "service accounts cannot use SSO")
        if not user.is_active:
            raise OidcError("inactive", "account is inactive")

    role_id = map_role(provider, claims, roles)
    role_changed = False
    if created:
        email = _email_from_claims(claims) or ""
        name = claims.get("name")
        user = User(
            user_id=f"user-{uuid.uuid4().hex[:12]}",
            username=_unique_username(session, claims, email),
            email=email,
            password_hash=SSO_ONLY_PASSWORD_HASH,
            full_name=(
                name.strip()[:200] if isinstance(name, str) and name.strip() else email
            ),
            role_id=role_id,
            is_active=True,
            is_verified=claims.get("email_verified") is True,
            mfa_enabled=False,
            login_count=0,
        )
        session.add(user)
        session.flush()
    elif provisioned and user.role_id != role_id:
        # The identity provider is the source of truth for accounts it made;
        # an account linked by email keeps the role an administrator gave it.
        logger.info(
            "SSO role for %s changes %s -> %s", user.username, user.role_id, role_id
        )
        user.role_id = role_id
        role_changed = True

    assert user is not None
    user.last_login = now
    user.login_count = (user.login_count or 0) + 1
    user.failed_login_count = 0

    link_value = {
        "user_id": user.user_id,
        "provider_id": provider.id,
        "issuer": issuer,
        "subject_sha256": digest(subject),
        "provisioned": provisioned,
        "last_login_at": now.isoformat(),
    }
    if link is None:
        link_value["linked_at"] = now.isoformat()
        session.add(
            SystemConfig(
                key=key,
                value=link_value,
                description=f"SSO identity ({provider.id})",
                config_type=IDENTITY_CONFIG_TYPE,
                updated_by="sso",
            )
        )
    else:
        link.value = {**link.value, **link_value}
    session.flush()
    return SsoLogin(
        user=user, created=created, linked=linked, role_changed=role_changed
    )


def is_sso_only(user: User) -> bool:
    return user.password_hash == SSO_ONLY_PASSWORD_HASH


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def audit_success(
    session: Session, provider_id: str, login: SsoLogin, client_ip: Optional[str]
) -> None:
    """Record a completed SSO login in the request's own transaction."""
    session.add(
        ConfigAuditLog(
            config_type=AUDIT_CONFIG_TYPE,
            config_key=AUDIT_KEY,
            action="sso_login",
            old_value=None,
            new_value={
                "provider_id": provider_id,
                "user_id": login.user.user_id,
                "role_id": login.user.role_id,
                "created": login.created,
                "linked": login.linked,
                "role_changed": login.role_changed,
                "client_ip": client_ip,
            },
            changed_by=login.user.username[:100],
        )
    )


def audit_failure(
    provider_id: str, code: str, detail: str, client_ip: Optional[str]
) -> None:
    """Record a refused SSO login in a transaction of its own.

    Its own transaction so the record survives whatever happens to the
    request's. Never raises: failing to audit must not turn a refused login
    into a server error, but it is logged at ERROR.
    """
    try:
        with unit_of_work() as session:
            session.add(
                ConfigAuditLog(
                    config_type=AUDIT_CONFIG_TYPE,
                    config_key=AUDIT_KEY,
                    action="sso_failure",
                    old_value=None,
                    new_value={
                        "provider_id": provider_id[:64],
                        "reason": code,
                        "detail": detail[:500],
                        "client_ip": client_ip,
                    },
                    changed_by="sso",
                )
            )
    except Exception as exc:
        logger.error("Could not audit an SSO failure (%s): %s", code, exc)
