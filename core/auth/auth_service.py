"""
Authentication Service - User authentication and authorization.

Handles password hashing, JWT generation/validation, MFA, and session management.
"""

import base64
import hashlib
import logging
import secrets
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import jwt
import pyotp
from cryptography.fernet import Fernet
from sqlalchemy import func
from sqlalchemy.orm import Session

from core.auth import passwords
from core.config import get_settings
from core.crypto import data_key
from core.exceptions import default_on_error
from core.secrets import get_secret
from core.storage.models import Role, User
from core.storage.unit_of_work import unit_of_work
from core.time import utcnow

logger = logging.getLogger(__name__)

# Fernet tokens are urlsafe base64 of a version byte + timestamp, so they start
# with "gAAAAA". Lowercase "g" is not base32, so legacy plaintext never matches.
_FERNET_TOKEN_PREFIX = "gAAAAA"
# An MFA secret encrypted under the data key (core.crypto.data_key). A bare
# Fernet token is the legacy form, under a key derived from JWT_SECRET_KEY; the
# start-up rekey (core.crypto.rekey) moves those rows to this one.
MFA_DATA_KEY_PREFIX = "dk:"
_UNDECRYPTABLE_LOG_INTERVAL = 60.0
_last_undecryptable_log = float("-inf")


class MFASecretDecryptionError(Exception):
    """A stored MFA secret is encrypted, but not under a key this process holds."""


def _is_dev_mode() -> bool:
    return get_settings().dev_mode


def _load_jwt_secret() -> str:
    # Resolved at import time. DEV_MODE falls back to a deterministic dev secret
    # so tokens survive restarts; production fails closed when unset.
    value = get_secret("JWT_SECRET_KEY")

    if value:
        return value

    if _is_dev_mode():
        logger.warning(
            "JWT_SECRET_KEY not set; using deterministic DEV_MODE fallback. "
            "Tokens issued in dev are not portable to production."
        )
        return "dev-mode-insecure-jwt-secret-do-not-use-in-production"

    raise RuntimeError(
        "JWT_SECRET_KEY is required when DEV_MODE=false. "
        "Set it in the environment or .env before starting the backend."
    )


# JWT Configuration
JWT_SECRET_KEY = _load_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_ACCESS_EXPIRATION_MINUTES = get_settings().jwt_access_expiration_minutes
JWT_REFRESH_EXPIRATION_DAYS = get_settings().jwt_refresh_expiration_days

# Account lockout configuration
LOCKOUT_THRESHOLD = get_settings().auth_lockout_threshold
LOCKOUT_DURATION_MINUTES = get_settings().auth_lockout_duration_minutes

# Number of prior password hashes to remember and reject on reuse
PASSWORD_HISTORY_LIMIT = get_settings().auth_password_history_limit


def _is_service_account(user: User) -> bool:
    """Only an explicit True exempts from lockout; anything else fails closed."""
    return user.service_account is True


class AccountLockedError(Exception):
    """Raised when authentication is refused because the account is locked."""

    def __init__(self, locked_until: datetime):
        self.locked_until = locked_until
        super().__init__(f"Account locked until {locked_until.isoformat()}")


def password_matches_any(plaintext: str, hashes) -> bool:
    """Return True if `plaintext` matches any stored hash (bcrypt or PBKDF2).

    For the password-history reuse check: legacy bcrypt entries are always
    compared, since they cannot be rehashed and refusing them would let an
    old password back in (core/auth/passwords.py)."""
    return passwords.matches_any(plaintext, hashes, legacy_bcrypt=True)


class AuthService:
    """Service for user authentication and authorization."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password in the active scheme (bcrypt; PBKDF2 under FIPS_MODE)."""
        return passwords.hash_secret(password)

    @staticmethod
    @default_on_error(False)
    def verify_password(password: str, password_hash: str) -> bool:
        """Verify a password against a bcrypt or PBKDF2-HMAC-SHA256 hash.

        A hash in neither format, such as the "!sso-only" placeholder of an
        account single sign-on created, matches nothing: ``passwords.identify``
        returns None and ``verify_secret`` returns False without logging, and
        the login path never rehashes it (needs_rehash is False).
        """
        return passwords.verify_secret(password, password_hash)

    @staticmethod
    def _session_fingerprint(user_agent: Optional[str]) -> str:
        """Short SHA-256 fingerprint binding a token to its user-agent.

        Deliberately excludes the client IP: NAT, VPNs and mobile roaming
        change a client's IP within a token's lifetime (forcing spurious
        re-logins), and behind a reverse proxy every client presents the
        proxy's IP, so it adds no signal. The user-agent is a stable,
        defense-in-depth check on top of the JWT signature.
        """
        return hashlib.sha256((user_agent or "").encode()).hexdigest()[:16]

    @staticmethod
    def generate_jwt_token(
        user: User,
        token_type: str = "access",
        user_agent: Optional[str] = None,
    ) -> str:
        """Generate a JWT token for a user with optional session binding."""
        expiration = (
            timedelta(minutes=JWT_ACCESS_EXPIRATION_MINUTES)
            if token_type == "access"
            else timedelta(days=JWT_REFRESH_EXPIRATION_DAYS)
        )

        now = utcnow()
        payload = {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "role_id": user.role_id,
            "token_type": token_type,
            "jti": uuid.uuid4().hex,
            "exp": now + expiration,
            "iat": now,
        }

        # Bind token to session context when available
        if user_agent:
            payload["sfp"] = AuthService._session_fingerprint(user_agent)

        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        return token

    @staticmethod
    def verify_session_fingerprint(
        payload: Dict[str, Any],
        user_agent: Optional[str] = None,
    ) -> bool:
        """Check that a token's session fingerprint matches the request context.

        Returns True if no fingerprint is bound (backwards compat) or if it matches.
        """
        sfp = payload.get("sfp")
        if not sfp:
            return True
        expected = AuthService._session_fingerprint(user_agent)
        return secrets.compare_digest(sfp, expected)

    @staticmethod
    def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode a JWT token.

        Args:
            token: JWT token string

        Returns:
            Decoded payload or None if invalid
        """
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None

    @staticmethod
    def authenticate_user(
        username_or_email: str, password: str, session: Optional[Session] = None
    ) -> Optional[User]:
        # The unit of work must see any failure, so it sits inside the try —
        # the handlers below swallow the exception and would otherwise let a
        # failed attempt commit.
        try:
            with unit_of_work(session) as session:
                # Try to find user by username or email
                user = (
                    session.query(User)
                    .filter(
                        (User.username == username_or_email)
                        | (User.email == username_or_email)
                    )
                    .first()
                )

                if not user:
                    logger.warning("Login attempt for unknown identifier")
                    return None

                if not user.is_active:
                    logger.warning(
                        "Login attempt for inactive account: %s", user.username
                    )
                    return None

                # Reject while locked. Lockout is authoritative even over a
                # correct password — otherwise an attacker who eventually
                # guesses right would bypass the wait.
                now = utcnow()
                if (
                    user.locked_until
                    and user.locked_until > now
                    and not _is_service_account(user)
                ):
                    logger.warning(
                        "Login rejected, account locked: %s until %s",
                        user.username,
                        user.locked_until.isoformat(),
                    )
                    raise AccountLockedError(user.locked_until)

                # Verify password
                if not AuthService.verify_password(password, user.password_hash):
                    AuthService._record_failed_attempt(user.user_id, now)
                    logger.warning("Invalid password for user: %s", user.username)
                    return None

                # Transparent migration: the plaintext is in hand only now, so
                # this is where a hash in a retired scheme (bcrypt under
                # FIPS_MODE) or with too few iterations is rewritten. Same
                # password, so password_changed_at and history stay as they are.
                if passwords.needs_rehash(user.password_hash):
                    user.password_hash = passwords.hash_secret(password)
                    logger.info(
                        "Password hash for %s rewritten in scheme %s",
                        user.username,
                        passwords.active_scheme(),
                    )

                # Success — reset lockout state and update session tracking
                user.failed_login_count = 0
                user.locked_until = None
                user.last_login = now
                user.login_count += 1

                logger.info(f"User authenticated successfully: {username_or_email}")
                return user

        except AccountLockedError:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None

    @staticmethod
    def _record_failed_attempt(user_id: str, now: datetime) -> None:
        """Persist one failed login attempt in its own transaction.

        Deliberately does not join the caller's transaction: the login endpoint
        answers a failed attempt with 401, which rolls that transaction back. If
        this bookkeeping went with it the counter would never survive, the
        threshold would never trip, and the lockout would silently do nothing.
        """
        with unit_of_work() as session:
            user = session.query(User).filter(User.user_id == user_id).first()
            if not user:
                return
            user.failed_login_count = (user.failed_login_count or 0) + 1
            if _is_service_account(user):
                # Never locked (D2-17): a lock would let anyone who learns the
                # name blind Medic's gateway. Safe only because the password is
                # long, random and held by the gateway alone. Still counted, and
                # logged once at the threshold so brute force stays visible.
                if user.failed_login_count == LOCKOUT_THRESHOLD:
                    logger.warning(
                        "Service account %s reached %d failed logins; "
                        "service accounts are not locked out",
                        user.username,
                        user.failed_login_count,
                    )
                return
            if user.failed_login_count >= LOCKOUT_THRESHOLD:
                user.locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                logger.warning(
                    "Account locked after %d failed attempts: %s",
                    user.failed_login_count,
                    user.username,
                )

    @staticmethod
    @default_on_error(None)
    def setup_mfa(user_id: str, session: Optional[Session] = None) -> Optional[str]:
        with unit_of_work(session) as session:
            user = session.query(User).filter(User.user_id == user_id).first()
            if not user:
                return None

            secret = pyotp.random_base32()
            user.mfa_secret = AuthService._encrypt_mfa_secret(secret)
            user.mfa_enabled = False
            # Clear any stale codes from a prior setup attempt; fresh codes
            # are issued at enable time.
            user.mfa_recovery_codes = []

            logger.info(f"MFA setup initiated for user: {user.username}")
            return secret

    @staticmethod
    @default_on_error(None)
    def enable_mfa(
        user_id: str, code: str, session: Optional[Session] = None
    ) -> Optional[List[str]]:
        """Verify the first TOTP code and enable MFA.

        On the enabling transition, generates one-time recovery codes and
        returns the plaintext (shown once, cannot be retrieved again).

        Returns:
            - list of recovery codes on successful enable
            - [] if the code is valid but MFA was already enabled (no reissue)
            - None if there is no pending secret or the code is invalid
        """
        with unit_of_work(session) as session:
            user = session.query(User).filter(User.user_id == user_id).first()
            if not user or not user.mfa_secret:
                return None

            try:
                valid = AuthService._verify_totp(user.mfa_secret, code)
            except MFASecretDecryptionError:
                return None  # already logged at ERROR with the cause
            if not valid:
                return None

            if user.mfa_enabled:
                # Already enabled — codes were issued at enable time, don't
                # silently reissue. Use the regenerate endpoint to rotate.
                return []

            user.mfa_enabled = True
            codes, user.mfa_recovery_codes = AuthService._generate_recovery_codes()
            logger.info(f"MFA enabled for user: {user.username}")
            return codes

    @staticmethod
    @default_on_error(None)
    def get_mfa_recovery_codes(
        user_id: str, session: Optional[Session] = None
    ) -> Optional[List[str]]:
        """Generate fresh recovery codes for a user (re-setup).

        Returns plaintext codes. Caller must display them once; they cannot
        be retrieved again.
        """
        with unit_of_work(session) as session:
            user = session.query(User).filter(User.user_id == user_id).first()
            if not user or not user.mfa_secret:
                return None

            codes, user.mfa_recovery_codes = AuthService._generate_recovery_codes()
            return codes

    @staticmethod
    @default_on_error(False)
    def verify_mfa_code(
        user_id: str, code: str, session: Optional[Session] = None
    ) -> bool:
        """Verify a TOTP code or a one-time recovery code (login path).

        Enabling MFA is handled by enable_mfa(); this method assumes MFA is
        already enabled and only validates the supplied code.
        """
        with unit_of_work(session) as session:
            user = session.query(User).filter(User.user_id == user_id).first()
            if not user or not user.mfa_secret:
                return False

            # Try TOTP first. An undecryptable secret must not block recovery
            # codes: they are password hashes and do not depend on the key.
            try:
                if AuthService._verify_totp(user.mfa_secret, code):
                    return True
            except MFASecretDecryptionError:
                pass  # already logged at ERROR with the cause

            # Try recovery codes (one-time use)
            recovery_codes = list(user.mfa_recovery_codes or [])
            normalized = code.strip().upper()
            for i, hashed in enumerate(recovery_codes):
                try:
                    # legacy_bcrypt: a code issued before FIPS_MODE cannot be
                    # rehashed; it is consumed here or replaced on regenerate.
                    if passwords.verify_secret(normalized, hashed, legacy_bcrypt=True):
                        recovery_codes.pop(i)
                        user.mfa_recovery_codes = recovery_codes
                        logger.info(
                            "Recovery code used for user: %s (%d remaining)",
                            user.username,
                            len(recovery_codes),
                        )
                        return True
                except Exception:
                    continue

            return False

    @staticmethod
    def _generate_recovery_codes() -> tuple[list[str], list[str]]:
        """Return (plaintext, hashed) lists of 10 one-time recovery codes."""
        codes = [secrets.token_hex(4).upper() for _ in range(10)]
        hashed = [passwords.hash_secret(c) for c in codes]
        return codes, hashed

    @staticmethod
    def _legacy_fernet(jwt_secret: Optional[str] = None) -> Fernet:
        """The pre-data-key cipher: keyed off JWT_SECRET_KEY (SHA-256 -> Fernet key).

        Only decrypts rows written before the data key; nothing is encrypted
        with it any more.
        """
        secret = JWT_SECRET_KEY if jwt_secret is None else jwt_secret
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
        return Fernet(key)

    @staticmethod
    def _encrypt_mfa_secret(secret: str) -> str:
        """Encrypt an MFA secret at rest under the data key, not the JWT key.

        Raises:
            DataKeyUnavailable: no data key (database store without VIGIL_DATA_KEY).
        """
        return MFA_DATA_KEY_PREFIX + data_key.current().encrypt(secret.encode())

    @staticmethod
    def _decrypt_mfa_secret(encrypted: str, jwt_secret: Optional[str] = None) -> str:
        """Decrypt an MFA secret; fall back to plaintext for pre-migration rows.

        ``jwt_secret`` names the JWT key a legacy row was encrypted under; the
        running key by default. A data-key row does not depend on it.

        Raises:
            MFASecretDecryptionError: the value is encrypted under a key this
                process does not hold.
        """
        if encrypted.startswith(MFA_DATA_KEY_PREFIX):
            try:
                ring = data_key.current()
                return ring.decrypt(encrypted[len(MFA_DATA_KEY_PREFIX) :]).decode()
            except (data_key.InvalidToken, data_key.DataKeyUnavailable) as exc:
                AuthService._log_undecryptable_secret(
                    "the current data key (VIGIL_DATA_KEY or master.key)"
                )
                raise MFASecretDecryptionError(
                    "MFA secret cannot be decrypted with the current data key"
                ) from exc
        try:
            return (
                AuthService._legacy_fernet(jwt_secret)
                .decrypt(encrypted.encode())
                .decode()
            )
        except Exception as exc:
            if not encrypted.startswith(_FERNET_TOKEN_PREFIX):
                return encrypted  # legacy plaintext (pre-migration rows)
            AuthService._log_undecryptable_secret("the current JWT_SECRET_KEY")
            raise MFASecretDecryptionError(
                "MFA secret cannot be decrypted with the current JWT_SECRET_KEY"
            ) from exc

    @staticmethod
    def _log_undecryptable_secret(key_name: str) -> None:
        """Log the key mismatch at ERROR, at most once per interval."""
        global _last_undecryptable_log
        now = time.monotonic()
        if now - _last_undecryptable_log < _UNDECRYPTABLE_LOG_INTERVAL:
            return
        _last_undecryptable_log = now
        logger.error(
            "MFA secret cannot be decrypted with %s; the key has changed since "
            "MFA was set up. TOTP codes are rejected until the original key is "
            "restored; recovery codes still work.",
            key_name,
        )

    @staticmethod
    def _verify_totp(encrypted_secret: str, code: str) -> bool:
        """Verify a TOTP code against a stored (encrypted) MFA secret."""
        decrypted = AuthService._decrypt_mfa_secret(encrypted_secret)
        return pyotp.TOTP(decrypted).verify(code, valid_window=1)

    @staticmethod
    def get_mfa_qr_uri(
        user_id: str, session: Optional[Session] = None
    ) -> Optional[str]:
        """
        Get MFA QR code URI for a user.

        Args:
            user_id: User ID
            session: Database session (optional)

        Returns:
            QR code URI or None
        """
        with unit_of_work(session) as session:
            user = session.query(User).filter(User.user_id == user_id).first()
            if not user or not user.mfa_secret:
                return None

            try:
                decrypted_secret = AuthService._decrypt_mfa_secret(user.mfa_secret)
            except MFASecretDecryptionError:
                return None  # already logged at ERROR with the cause
            totp = pyotp.TOTP(decrypted_secret)
            uri = totp.provisioning_uri(name=user.email, issuer_name="AutoSecOps")
            return uri

    @staticmethod
    def check_permission(
        user_id: str, permission: str, session: Optional[Session] = None
    ) -> bool:
        """
        Check if a user has a specific permission.

        Args:
            user_id: User ID
            permission: Permission string (e.g., "cases.write")
            session: Database session (optional)

        Returns:
            True if user has permission
        """
        # DEV MODE: Grant all permissions
        if _is_dev_mode():
            return True

        with unit_of_work(session) as session:
            user = session.query(User).filter(User.user_id == user_id).first()
            if not user or not user.is_active:
                return False

            role = session.query(Role).filter(Role.role_id == user.role_id).first()
            if not role:
                return False

            # Check permission in role's permissions JSONB
            return role.permissions.get(permission, False)

    @staticmethod
    def get_user_permissions(
        user_id: str, session: Optional[Session] = None
    ) -> Dict[str, bool]:
        """
        Get all permissions for a user.

        Args:
            user_id: User ID
            session: Database session (optional)

        Returns:
            Dictionary of permissions
        """
        # DEV MODE: Return all permissions
        if _is_dev_mode():
            return {
                "findings.read": True,
                "findings.write": True,
                "findings.delete": True,
                "cases.read": True,
                "cases.write": True,
                "cases.delete": True,
                "cases.assign": True,
                "integrations.read": True,
                "integrations.write": True,
                "users.read": True,
                "users.write": True,
                "users.delete": True,
                "settings.read": True,
                "settings.write": True,
                "ai_chat.use": True,
                "ai_decisions.approve": True,
                "medic.read": True,
                "medic.admin": True,
            }

        with unit_of_work(session) as session:
            user = session.query(User).filter(User.user_id == user_id).first()
            if not user:
                return {}

            role = session.query(Role).filter(Role.role_id == user.role_id).first()
            if not role:
                return {}

            return role.permissions

    @staticmethod
    @default_on_error(None)
    def create_user(
        username: str,
        email: str,
        password: str,
        full_name: str,
        role_id: str,
        session: Optional[Session] = None,
    ) -> Optional[User]:
        """
        Create a new user.

        Args:
            username: Username
            email: Email address
            password: Plain text password
            full_name: Full name
            role_id: Role ID
            session: Database session (optional)

        Returns:
            Created User object or None
        """
        with unit_of_work(session) as session:
            import uuid

            # Check if username or email already exists
            # Usernames are unique as written in the schema; a new one must
            # also differ from every existing one case-insensitively, so
            # "Carol" and "carol" are never two accounts (W3.2: approvals
            # and the SoD report name people by username).
            existing = (
                session.query(User)
                .filter(
                    (func.lower(User.username) == func.lower(username))
                    | (User.email == email)
                )
                .first()
            )

            if existing:
                logger.warning(f"User already exists: {username} or {email}")
                return None

            # Create user
            user = User(
                user_id=f"user-{uuid.uuid4().hex[:12]}",
                username=username,
                email=email,
                password_hash=AuthService.hash_password(password),
                full_name=full_name,
                role_id=role_id,
                is_active=True,
                is_verified=False,
                mfa_enabled=False,
                login_count=0,
            )

            session.add(user)
            # Flush so the read-back sees server defaults; the unit of work
            # commits.
            session.flush()
            session.refresh(user)

            logger.info(f"User created: {username}")
            return user
