"""
Password reset tokens.

Design:
- Tokens are HMAC-signed with itsdangerous.URLSafeTimedSerializer. The
  secret is reused from JWT_SECRET_KEY so we don't have yet another key
  to rotate; it's fine because the salt (purpose tag) keeps the two
  token spaces separate.
- Tokens are **single-use**: on successful confirm we write the token's
  hash into Redis, and any subsequent confirm with the same token is
  rejected. TTL on that record matches token lifetime so it auto-expires.
- If Redis is unavailable, we fall back to time-based expiry only. A
  cache outage downgrades single-use to "valid once per TTL window" —
  acceptable; the alternative is to reject all reset attempts during
  the outage, which could lock users out.

The token payload is the user_id plus a hash of the address it was mailed
to. We look up the user at confirm time; if the email changed since, the
token is refused, so changing an address invalidates every pending reset.
If the account was deactivated in the meantime, the confirm handler rejects.
"""

import hashlib
import logging
from typing import Any, Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from core.config import get_settings
from core.redis_client import get_async_redis

logger = logging.getLogger(__name__)


RESET_TOKEN_PURPOSE = "vigil-password-reset"

_USED_TOKEN_PREFIX = "password_reset_used:"


def _ttl_seconds() -> int:
    return get_settings().password_reset_ttl_seconds


def _get_serializer() -> URLSafeTimedSerializer:
    # Import lazily so tests can stub JWT_SECRET_KEY via env before auth_service loads.
    from core.auth.auth_service import JWT_SECRET_KEY

    # SHA-256 + HMAC key derivation instead of itsdangerous' default
    # (SHA-1 "django-concat"): FIPS-approved, see docs/fips.md (W3.10).
    return URLSafeTimedSerializer(
        JWT_SECRET_KEY,
        salt=RESET_TOKEN_PURPOSE,
        signer_kwargs={"digest_method": hashlib.sha256, "key_derivation": "hmac"},
    )


def _token_hash(token: str) -> str:
    """Stable hash of a token used as the "used" flag key in Redis. We
    don't store the raw token because writing tokens into the cache, even
    short-lived, expands the blast radius if Redis itself is breached."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _redis_client():
    return get_async_redis("reset single-use check")


def _email_binding(email: Optional[str]) -> str:
    return hashlib.sha256((email or "").strip().lower().encode("utf-8")).hexdigest()[
        :32
    ]


def generate_reset_token(user_id: str, email: Optional[str] = None) -> str:
    """A reset token for ``user_id``, bound to the address it is mailed to.

    The binding (a hash, not the address) makes every pending token stop
    working once the account's email changes; see :func:`token_matches_email`.
    """
    return _get_serializer().dumps({"user_id": user_id, "eb": _email_binding(email)})


def token_matches_email(token: str, email: Optional[str]) -> bool:
    """Whether ``token`` was issued while the account's email was ``email``.

    Call after :func:`verify_reset_token` accepted the token (this does not
    check expiry). A token without a binding is refused.
    """
    try:
        payload = _get_serializer().loads(token)
    except BadSignature:
        return False
    bound = payload.get("eb") if isinstance(payload, dict) else None
    return isinstance(bound, str) and bound == _email_binding(email)


def reset_link(base_url: str, token: str) -> str:
    """Console URL that opens the reset screen for ``token``."""
    return f"{base_url.rstrip('/')}/reset-password?token={token}"


def ttl_text(seconds: Optional[int] = None) -> str:
    """The reset-link lifetime in words ("1 hour", "30 minutes")."""
    seconds = _ttl_seconds() if seconds is None else int(seconds)
    if seconds >= 3600 and seconds % 3600 == 0:
        n, unit = seconds // 3600, "hour"
    elif seconds >= 60:
        n, unit = max(1, seconds // 60), "minute"
    else:
        n, unit = max(1, seconds), "second"
    return f"{n} {unit}{'' if n == 1 else 's'}"


#: Why an account may not get a reset link (``reset_refusal``).
REFUSED_INACTIVE = "inactive"
REFUSED_SSO_ONLY = "sso_only"
REFUSED_SERVICE_ACCOUNT = "service"


def reset_refusal(user: Any) -> Optional[str]:
    """Why ``user`` may not reset a password, or None when it may.

    One rule for the request route, the confirm route and the operator tool
    (``scripts/reset_password.py``):

    * an inactive account is refused;
    * an account single sign-on created (``password_hash == "!sso-only"``) has
      no local password; giving it one would let it outlive its removal at the
      identity provider (W1.9);
    * a service account's password belongs to its gateway alone and is rotated
      with ``python -m core.auth.service_account ensure`` (W0.13).
    """
    from core.auth.oidc_accounts import SSO_ONLY_PASSWORD_HASH

    if user is None or not getattr(user, "is_active", False):
        return REFUSED_INACTIVE
    if getattr(user, "password_hash", None) == SSO_ONLY_PASSWORD_HASH:
        return REFUSED_SSO_ONLY
    from core.auth.auth_service import _is_service_account

    if _is_service_account(user):
        return REFUSED_SERVICE_ACCOUNT
    return None


async def verify_reset_token(token: str) -> Optional[str]:
    """
    Return the user_id the token was issued for, or None if the token is
    invalid, expired, or already used. Marks the token used on success so
    replay within the TTL window is rejected.
    """
    try:
        payload = _get_serializer().loads(token, max_age=_ttl_seconds())
    except SignatureExpired:
        logger.info("Password reset token expired")
        return None
    except BadSignature:
        logger.info("Password reset token has a bad signature")
        return None

    user_id = payload.get("user_id") if isinstance(payload, dict) else None
    if not user_id:
        return None

    client = _redis_client()
    if client is not None:
        try:
            key = f"{_USED_TOKEN_PREFIX}{_token_hash(token)}"
            # SET NX: succeeds only if the key didn't exist. If it did,
            # the token was already consumed.
            set_ok = await client.set(key, "1", ex=_ttl_seconds(), nx=True)
            if not set_ok:
                logger.info("Password reset token replay rejected")
                return None
        except Exception as exc:
            # Fail-open: if Redis is down we lose single-use enforcement
            # but still honour the signed TTL. A compromised reset email
            # during an outage could be replayed within the TTL — a
            # user-facing retry is the mitigation.
            logger.warning(
                "Password reset single-use check failed (%s); allowing by signature only",
                exc,
            )

    return user_id
