"""Detached signatures for audit checkpoints: Ed25519 or ECDSA P-256 (W3.10).

Ed25519 is the default. Validated OpenSSL 3 FIPS providers (3.0.x, 3.1.x) do not
offer EdDSA, so ``checkpoint_algorithm()`` picks ECDSA over P-256 and SHA-256
(FIPS 186-5, DER-encoded and base64'd) under FIPS_MODE.

NOT WIRED YET: ``core/audit/checkpoint.py``, ``core/audit/verify.py`` and the
evidence-pack code still sign with Ed25519 directly and do not call this
module, so FIPS_MODE does not change their signatures (known gap, docs/fips.md
"Bilinen boşluklar"). tests/unit/crypto/test_fips_docs_consistency.py keeps the
operator docs honest about that until they are wired. Every signature records the
algorithm next to it (``ALG_*``), so a verifier never has to guess and keys of
either kind can coexist across a migration.

ECDSA signatures are malleable and randomized: (r, s) and (r, n - s) both
verify, and signing the same message twice gives different bytes. Never use a
signature as an identifier, dedupe key or cache key; identify a checkpoint by
the digest of what it signs.
"""

from __future__ import annotations

import base64
from typing import Literal, Optional, Union

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

Algorithm = Literal["ed25519", "ecdsa-p256"]
ALG_ED25519: Algorithm = "ed25519"
ALG_ECDSA_P256: Algorithm = "ecdsa-p256"
ALGORITHMS = (ALG_ED25519, ALG_ECDSA_P256)

PrivateKey = Union["Ed25519PrivateKey", ec.EllipticCurvePrivateKey]  # noqa: F821
PublicKey = Union["Ed25519PublicKey", ec.EllipticCurvePublicKey]  # noqa: F821


class SigningKeyError(ValueError):
    """A key that is not usable for the requested algorithm."""


def checkpoint_algorithm(fips_mode: Optional[bool] = None) -> Algorithm:
    """ECDSA P-256 under FIPS_MODE, Ed25519 otherwise. No production caller yet."""
    if fips_mode is None:
        from core.config import get_settings

        fips_mode = get_settings().fips_mode
    return ALG_ECDSA_P256 if fips_mode else ALG_ED25519


def _ed25519():
    # Imported on use: under a FIPS-only OpenSSL the Ed25519 classes exist but
    # every operation raises, and this keeps the ECDSA path free of it.
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return ed25519


def generate_private_key(alg: Algorithm) -> PrivateKey:
    if alg == ALG_ECDSA_P256:
        return ec.generate_private_key(ec.SECP256R1())
    if alg == ALG_ED25519:
        return _ed25519().Ed25519PrivateKey.generate()
    raise SigningKeyError(f"unknown signature algorithm {alg!r}")


def algorithm_of(key: Union[PrivateKey, PublicKey]) -> Algorithm:
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        if not isinstance(key.curve, ec.SECP256R1):
            raise SigningKeyError(f"ECDSA key on {key.curve.name}, expected secp256r1")
        return ALG_ECDSA_P256
    ed = _ed25519()
    if isinstance(key, (ed.Ed25519PrivateKey, ed.Ed25519PublicKey)):
        return ALG_ED25519
    raise SigningKeyError(f"unsupported key type {type(key).__name__}")


def private_key_pem(key: PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def public_key_pem(key: Union[PrivateKey, PublicKey]) -> str:
    public = key.public_key() if hasattr(key, "private_bytes") else key
    return public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_private_key(pem: str, alg: Optional[Algorithm] = None) -> PrivateKey:
    try:
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    except (ValueError, TypeError) as exc:
        raise SigningKeyError("not a PEM private key") from exc
    actual = algorithm_of(key)
    if alg is not None and actual != alg:
        raise SigningKeyError(f"key is {actual}, expected {alg}")
    return key  # type: ignore[return-value]


def load_public_key(pem: str, alg: Optional[Algorithm] = None) -> PublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise SigningKeyError("not a PEM public key") from exc
    actual = algorithm_of(key)
    if alg is not None and actual != alg:
        raise SigningKeyError(f"key is {actual}, expected {alg}")
    return key  # type: ignore[return-value]


def sign(key: PrivateKey, message: bytes) -> tuple[Algorithm, str]:
    """(algorithm, base64 signature) over ``message``."""
    alg = algorithm_of(key)
    if alg == ALG_ECDSA_P256:
        raw = key.sign(message, ec.ECDSA(hashes.SHA256()))  # type: ignore[call-arg]
    else:
        raw = key.sign(message)  # type: ignore[call-arg]
    return alg, base64.b64encode(raw).decode("ascii")


def verify(public: PublicKey, alg: str, message: bytes, signature: str) -> bool:
    """True only if ``signature`` is a valid ``alg`` signature by ``public``."""
    try:
        if algorithm_of(public) != alg:
            return False
        raw = base64.b64decode(signature, validate=True)
        if alg == ALG_ECDSA_P256:
            public.verify(raw, message, ec.ECDSA(hashes.SHA256()))  # type: ignore[call-arg]
        else:
            public.verify(raw, message)  # type: ignore[call-arg]
        return True
    except (InvalidSignature, SigningKeyError, UnsupportedAlgorithm, ValueError):
        # UnsupportedAlgorithm: e.g. Ed25519 under a FIPS-only OpenSSL.
        return False
