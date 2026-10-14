"""Password (and recovery code) hashing: bcrypt or PBKDF2-HMAC-SHA256 (W3.10).

bcrypt is the default and is not a FIPS 140-3 approved algorithm. Under
FIPS_MODE, or with PASSWORD_HASH_SCHEME=pbkdf2_sha256, new hashes are
PBKDF2-HMAC-SHA256 (SP 800-132) computed by OpenSSL through ``hashlib``, so the
FIPS provider does the work when it is active.

Stored format (Django-compatible): ``pbkdf2_sha256$<iterations>$<b64 salt>$<b64 hash>``
with a 16-byte salt and 32-byte output — above the FIPS provider's PBKDF2 lower
bounds (salt >= 128 bits, key >= 112 bits, iterations >= 1000).

Both formats always verify, so switching scheme never locks anyone out:
``needs_rehash`` tells the login path to rewrite a hash in the active scheme
once it has the plaintext. The one exception is FIPS_MODE with
FIPS_LEGACY_BCRYPT_VERIFY=false, which refuses bcrypt for login password hashes.

That flag governs ``users.password_hash`` only. MFA recovery codes and
``password_history`` entries are never rehashed (the plaintext of an unused
recovery code or a past password is never in hand), so their callers pass
``legacy_bcrypt=True``: refusing them would lock users out of their recovery
codes and make old passwords reusable. Both drain on their own: recovery codes
are consumed or regenerated (``POST /auth/mfa/recovery-codes``) in the active
scheme, history entries age out after AUTH_PASSWORD_HISTORY_LIMIT changes.
docs/fips.md has the count queries.

Stored PBKDF2 iteration counts are capped at ``MAX_PBKDF2_ITERATIONS``: a
tampered or corrupt row with ``pbkdf2_sha256$2000000000$...`` must not pin a
worker CPU for hours on one login.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
from typing import Iterable, Optional

import bcrypt

from core.config import get_settings

logger = logging.getLogger(__name__)

BCRYPT = "bcrypt"
PBKDF2_SHA256 = "pbkdf2_sha256"
_PBKDF2_PREFIX = PBKDF2_SHA256 + "$"
_SALT_BYTES = 16
_DK_BYTES = 32
_BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")
# Upper bound for stored and configured PBKDF2 iterations (core/config.py le=).
MAX_PBKDF2_ITERATIONS = 10_000_000


def active_scheme() -> str:
    settings = get_settings()
    if settings.password_hash_scheme:
        return settings.password_hash_scheme
    return PBKDF2_SHA256 if settings.fips_mode else BCRYPT


def _iterations() -> int:
    return get_settings().password_pbkdf2_iterations


def identify(stored: Optional[str]) -> Optional[str]:
    if not stored:
        return None
    if stored.startswith(_PBKDF2_PREFIX):
        return PBKDF2_SHA256
    if stored.startswith(_BCRYPT_PREFIXES):
        return BCRYPT
    return None


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _pbkdf2(plaintext: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", plaintext.encode("utf-8"), salt, iterations, _DK_BYTES
    )


def hash_secret(plaintext: str, scheme: Optional[str] = None) -> str:
    scheme = scheme or active_scheme()
    if scheme == PBKDF2_SHA256:
        iterations = _iterations()
        salt = secrets.token_bytes(_SALT_BYTES)
        digest = _pbkdf2(plaintext, salt, iterations)
        return f"{PBKDF2_SHA256}${iterations}${_b64(salt)}${_b64(digest)}"
    if scheme == BCRYPT:
        if get_settings().fips_mode:
            raise ValueError("bcrypt is not FIPS-approved; refusing under FIPS_MODE")
        return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )
    raise ValueError(f"unknown password hash scheme {scheme!r}")


def _parse_pbkdf2(stored: str) -> tuple[int, bytes, bytes]:
    _, iterations, salt, digest = stored.split("$")
    count = int(iterations)
    if not 1 <= count <= MAX_PBKDF2_ITERATIONS:
        raise ValueError("PBKDF2 iteration count out of range")
    return (
        count,
        base64.b64decode(salt, validate=True),
        base64.b64decode(digest, validate=True),
    )


def verify_secret(
    plaintext: str, stored: Optional[str], *, legacy_bcrypt: bool = False
) -> bool:
    """True if ``plaintext`` matches ``stored``. Never raises on a bad hash.

    ``legacy_bcrypt=True`` verifies bcrypt even under FIPS_MODE with
    FIPS_LEGACY_BCRYPT_VERIFY=false; only for hashes that cannot be migrated
    (recovery codes, password history; see the module docstring).
    """
    scheme = identify(stored)
    try:
        if scheme == PBKDF2_SHA256:
            iterations, salt, expected = _parse_pbkdf2(stored)  # type: ignore[arg-type]
            if not expected:
                return False
            return hmac.compare_digest(_pbkdf2(plaintext, salt, iterations), expected)
        if scheme == BCRYPT:
            settings = get_settings()
            if (
                settings.fips_mode
                and not settings.fips_legacy_bcrypt_verify
                and not legacy_bcrypt
            ):
                logger.warning(
                    "bcrypt hash refused: FIPS_MODE with FIPS_LEGACY_BCRYPT_VERIFY=false"
                )
                return False
            return bcrypt.checkpw(plaintext.encode("utf-8"), stored.encode("utf-8"))  # type: ignore[union-attr]
    except Exception as exc:
        logger.warning(
            "Password hash compare failed (%s): %s", scheme, type(exc).__name__
        )
        return False
    return False


def needs_rehash(stored: Optional[str]) -> bool:
    """True when ``stored`` should be rewritten in the active scheme at next login."""
    scheme = identify(stored)
    if scheme is None:
        return False
    if scheme != active_scheme():
        return True
    if scheme == PBKDF2_SHA256:
        try:
            iterations, _, _ = _parse_pbkdf2(stored)  # type: ignore[arg-type]
        except Exception:
            return False
        return iterations < _iterations()
    return False


def matches_any(
    plaintext: str, hashes: Optional[Iterable[str]], *, legacy_bcrypt: bool = False
) -> bool:
    return any(
        h and verify_secret(plaintext, h, legacy_bcrypt=legacy_bcrypt)
        for h in (hashes or ())
    )
