"""The data-encryption key: what TOTP secrets and the database secret store use.

It is not ``JWT_SECRET_KEY``. Rotating the key that signs sessions must end the
sessions and nothing else; before this key existed the TOTP secrets were
encrypted under a key derived from the JWT secret, so rotating it locked every
MFA user out (PY-35).

Where the key comes from, in order:

1. ``VIGIL_DATA_KEY``: one or more keys, comma-separated, of at least 32
   characters each. The first encrypts; every one decrypts, which is how a key is
   rotated without downtime (see the admin guide, "Sır döndürme"). Each entry is
   stretched with HKDF-SHA256 into a Fernet key, so any high-entropy string
   works (``openssl rand -base64 32``).
2. The State Directory's ``master.key`` (the key of ``secrets.enc``), created on
   first use, unless the database secret store is in use. There the State
   Directory is per pod (Helm: ``emptyDir``, two replicas), so a key in it would
   differ per replica and be lost on restart; the key must come from the
   environment (the chart's Secret).
3. ``DEV_MODE`` with the database store and no key: a fixed development key,
   with a warning, as ``JWT_SECRET_KEY`` has.

With ``VIGIL_DATA_KEY`` set outside the database store, an existing ``master.key``
is kept as a decrypt-only key, so switching a Compose install to the variable
does not lock anyone out: the start-up rekey moves every row to the new key.

Fernet is AES-128-CBC with HMAC-SHA256 and HKDF is SP 800-56C; both are
FIPS-approved, so ``FIPS_MODE`` needs nothing different here.
"""

from __future__ import annotations

import base64
import logging
import os
import threading
from dataclasses import dataclass
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

ENV_NAME = "VIGIL_DATA_KEY"
MIN_KEY_LENGTH = 32
_HKDF_INFO = b"autosecops data-encryption key v1"
_DEV_KEY = "dev-mode-insecure-data-key-do-not-use-in-production"

__all__ = [
    "ENV_NAME",
    "DataKeyUnavailable",
    "InvalidToken",
    "KeyRing",
    "current",
    "database_mode",
]


class DataKeyUnavailable(RuntimeError):
    """No usable data key: the variable is missing where it is required, or malformed."""


@dataclass(frozen=True)
class KeyRing:
    """The keys in use, primary first. Encrypts with the primary, decrypts with any."""

    fernets: tuple[Fernet, ...]
    # "env", "master.key" or "dev": what an operator is told by the status command.
    source: str

    @property
    def primary(self) -> Fernet:
        return self.fernets[0]

    def _multi(self) -> MultiFernet:
        return MultiFernet(list(self.fernets))

    def encrypt(self, plaintext: bytes) -> str:
        return self.primary.encrypt(plaintext).decode("ascii")

    def decrypt(self, token: str) -> bytes:
        """Raises :class:`InvalidToken` when no key in the ring opens it."""
        return self._multi().decrypt(token.encode("ascii"))

    def is_current(self, token: str) -> bool:
        """Whether the primary key alone opens ``token`` (nothing to re-encrypt)."""
        try:
            self.primary.decrypt(token.encode("ascii"))
            return True
        except InvalidToken:
            return False

    def rotate(self, token: str) -> str:
        """Re-encrypt under the primary. Raises :class:`InvalidToken` like decrypt."""
        return self._multi().rotate(token.encode("ascii")).decode("ascii")


def database_mode() -> bool:
    """Whether this process writes secrets to the database store (Helm)."""
    # os.environ, not Settings: read by the secrets manager before Settings exists.
    backend = os.environ.get("SECRETS_BACKEND", "")  # noqa: ENV001 - bootstrap
    return backend.strip().lower() == "database"


def derive(material: str) -> Fernet:
    """The Fernet key an operator-supplied string stands for (HKDF-SHA256)."""
    if len(material) < MIN_KEY_LENGTH:
        raise DataKeyUnavailable(
            f"{ENV_NAME}: every key must be at least {MIN_KEY_LENGTH} characters"
        )
    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(
        material.encode("utf-8")
    )
    return Fernet(base64.urlsafe_b64encode(raw))


_dev_warned = False
_derived_lock = threading.Lock()
_derived: dict[str, tuple[Fernet, ...]] = {}


def _from_env(raw: str) -> tuple[Fernet, ...]:
    # Cached by the variable's value: HKDF on every TOTP check is wasted work,
    # and a changed value (a test, a reinit) is a different entry.
    with _derived_lock:
        found = _derived.get(raw)
        if found is None:
            parts = [p.strip() for p in raw.split(",") if p.strip()]
            if not parts:
                raise DataKeyUnavailable(f"{ENV_NAME} is set but holds no key")
            found = tuple(derive(p) for p in parts)
            _derived[raw] = found
        return found


def _state_dir_key(create: bool) -> Optional[Fernet]:
    from core.secrets_manager import EncryptedFileBackend

    backend = EncryptedFileBackend()
    if create:
        return Fernet(backend._load_or_create_master_key())
    key = backend._read_master_key()
    return Fernet(key) if key else None


def current(*, allow_state_dir: bool = True) -> KeyRing:
    """The key ring this process uses now.

    ``allow_state_dir=False`` refuses the ``master.key`` fallback: the database
    store never takes a key that lives in one pod.

    Raises:
        DataKeyUnavailable: no key where one is required, or a malformed one.
    """
    raw = os.environ.get(ENV_NAME, "")  # noqa: ENV001 - key bootstrap, not a Setting
    shared = database_mode() or not allow_state_dir
    if raw.strip():
        fernets = _from_env(raw)
        if not shared:
            legacy = _state_dir_key(create=False)
            if legacy is not None:
                fernets = fernets + (legacy,)
        return KeyRing(fernets, "env")
    if not shared:
        return KeyRing((_state_dir_key(create=True),), "master.key")
    from core.config import get_settings

    if get_settings().dev_mode:
        global _dev_warned
        if not _dev_warned:
            _dev_warned = True
            logger.warning(
                "%s not set; using the deterministic DEV_MODE data key. Data "
                "encrypted in dev is not portable to production.",
                ENV_NAME,
            )
        return KeyRing((derive(_DEV_KEY),), "dev")
    raise DataKeyUnavailable(
        f"{ENV_NAME} is required with SECRETS_BACKEND=database: set "
        "secrets.dataEncryptionKey (or the same key in secrets.existingSecret). "
        "Generate one with: openssl rand -base64 32"
    )


def check_at_startup() -> Optional[KeyRing]:
    """Fail start-up on a missing or malformed key where one is required.

    Only where the variable is set or the database store is in use: a Compose
    install without the variable uses ``master.key`` and needs nothing checked.
    """
    raw = os.environ.get(ENV_NAME, "")  # noqa: ENV001 - key bootstrap, not a Setting
    if raw.strip() or database_mode():
        return current()
    return None
