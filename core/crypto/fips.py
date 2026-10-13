"""Is the OpenSSL 3 FIPS provider actually in force for this process?

Python reaches OpenSSL twice: ``hashlib``/``hmac``/``ssl`` through the
interpreter's own libssl, and ``cryptography`` (Fernet, JWT keys, signatures)
through whichever OpenSSL its wheel was built against. A pip wheel of
``cryptography`` bundles its own OpenSSL without a FIPS provider, so a host
with a FIPS system OpenSSL can still be running non-FIPS crypto. FIPS_MODE is
only honoured when both report FIPS, which is why both are probed here.

``/proc/sys/crypto/fips_enabled`` is reported for the operator but not
required: a FIPS container on a non-FIPS kernel is a supported layout (the
OpenSSL config, not the kernel flag, decides what the provider allows).
"""

from __future__ import annotations

import ssl
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

_KERNEL_FLAG = Path("/proc/sys/crypto/fips_enabled")


@dataclass(frozen=True)
class FipsStatus:
    # OpenSSL behind hashlib (the interpreter's libssl).
    hashlib_openssl: str
    hashlib_fips: bool
    # OpenSSL behind the `cryptography` package.
    cryptography_openssl: str
    cryptography_fips: bool
    # Informational only.
    kernel_fips: Optional[bool]

    @property
    def active(self) -> bool:
        return fips_refusal_reason(self) is None

    def as_dict(self) -> dict:
        return {**asdict(self), "active": self.active}


def _hashlib_fips() -> bool:
    try:
        import _hashlib  # CPython's OpenSSL binding

        return bool(_hashlib.get_fips_mode())
    except (ImportError, AttributeError, ValueError):
        return False


def _cryptography_fips() -> tuple[str, bool]:
    try:
        from cryptography.hazmat.bindings._rust import openssl as rust_openssl

        return rust_openssl.openssl_version_text(), bool(rust_openssl.is_fips_enabled())
    except (ImportError, AttributeError):
        pass
    try:  # older cryptography releases
        from cryptography.hazmat.backends.openssl.backend import backend

        return backend.openssl_version_text(), bool(
            getattr(backend, "_fips_enabled", False)
        )
    except Exception:
        return "unavailable", False


def _kernel_fips() -> Optional[bool]:
    try:
        return _KERNEL_FLAG.read_text().strip() == "1"
    except OSError:
        return None


def fips_status() -> FipsStatus:
    crypto_version, crypto_fips = _cryptography_fips()
    return FipsStatus(
        hashlib_openssl=ssl.OPENSSL_VERSION,
        hashlib_fips=_hashlib_fips(),
        cryptography_openssl=crypto_version,
        cryptography_fips=crypto_fips,
        kernel_fips=_kernel_fips(),
    )


def fips_refusal_reason(status: Optional[FipsStatus] = None) -> Optional[str]:
    """None when FIPS is in force; otherwise why startup must be refused."""
    status = status or fips_status()
    if ssl.OPENSSL_VERSION_INFO[0] < 3:
        return f"{status.hashlib_openssl} is not OpenSSL 3; the FIPS provider needs OpenSSL 3"
    missing = []
    if not status.hashlib_fips:
        missing.append(f"hashlib ({status.hashlib_openssl})")
    if not status.cryptography_fips:
        missing.append(f"cryptography ({status.cryptography_openssl})")
    if missing:
        return (
            "the OpenSSL 3 FIPS provider is not active for "
            + " and ".join(missing)
            + "; see docs/fips.md"
        )
    return None


def fips_mode_enabled() -> bool:
    from core.config import get_settings

    return get_settings().fips_mode
