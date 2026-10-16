"""The two signing keys an install provisions (W0.36): audit checkpoints and evidence packs.

``AUDIT_CHECKPOINT_SIGNING_KEY`` signs the daemon's audit checkpoints (W1.10);
``EVIDENCE_PACK_SIGNING_KEY`` signs case evidence packs (W3.7). Both are Ed25519
seeds held as secrets. W3.10's FIPS mode does not change that: these signatures
stay Ed25519 under ``FIPS_MODE`` (a documented gap), so nothing here picks an
algorithm.

Installation creates them when absent: Compose runs ``provision`` as a one-shot
service before the backend and daemon start (the encrypted secrets store on the
shared State Directory volume); Helm mints them into a Kubernetes Secret
(``signingKeys`` in values), which the air-gap installer inherits.

    python -m core.audit.signing_keys provision [--warn-only]
        # create the missing keys in the secrets store; never overwrites one
    python -m core.audit.signing_keys status [--json]
    python -m core.audit.signing_keys export [--format env|json|pem] [--purpose P]
        # the public keys, for whoever verifies offline

No path through this module prints, logs or returns a private key.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization

# The key handling is checkpoint.py's (W3.10 keeps it Ed25519): this module
# only moves keys between it and the secrets store.
from core.audit.checkpoint import SIGNING_KEY_SECRET as CHECKPOINT_SECRET
from core.audit.checkpoint import (
    generate_key,
    key_id,
    load_private_key,
    load_public_key,
    public_hex,
)
from core.compliance.evidence_bundle import SIGNING_KEY_SECRET as EVIDENCE_SECRET
from core.secrets import get_secret, get_secrets_manager, set_secret

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SigningKeySpec:
    purpose: str
    secret: str
    public_env: str
    used_by: str


AUDIT_CHECKPOINTS = SigningKeySpec(
    purpose="audit_checkpoints",
    secret=CHECKPOINT_SECRET,
    public_env="AUDIT_CHECKPOINT_PUBLIC_KEY",
    used_by="daemon (audit checkpoint job)",
)
EVIDENCE_PACKS = SigningKeySpec(
    purpose="evidence_packs",
    secret=EVIDENCE_SECRET,
    public_env="EVIDENCE_PACK_PUBLIC_KEY",
    used_by="backend (case evidence pack)",
)
KEYS = (AUDIT_CHECKPOINTS, EVIDENCE_PACKS)
ALGORITHM = "ed25519"


@dataclass(frozen=True)
class KeyStatus:
    """What may be said about one key: never the private part."""

    spec: SigningKeySpec
    configured: bool
    usable: bool
    key_id: Optional[str] = None
    public_key: Optional[str] = None  # raw, hex
    error: Optional[str] = None
    generated: bool = False

    def public_pem(self) -> Optional[str]:
        if self.public_key is None:
            return None
        key = load_public_key(self.public_key)
        return key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "purpose": self.spec.purpose,
            "secret": self.spec.secret,
            "algorithm": ALGORITHM,
            "configured": self.configured,
            "usable": self.usable,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "public_key_pem": self.public_pem(),
            "error": self.error,
            "generated": self.generated,
        }


def _private(spec: SigningKeySpec) -> Any:
    value = get_secret(spec.secret)
    if not value or not value.strip():
        return None
    return load_private_key(value)


def key_status(spec: SigningKeySpec) -> KeyStatus:
    """The key as this process sees it (secrets store, then environment)."""
    try:
        private = _private(spec)
    except (ValueError, TypeError):
        return KeyStatus(
            spec, configured=True, usable=False, error="not an Ed25519 private key"
        )
    except Exception as e:  # noqa: BLE001 - an unreadable store is "not usable"
        return KeyStatus(
            spec,
            configured=False,
            usable=False,
            error=f"unreadable: {type(e).__name__}",
        )
    if private is None:
        return KeyStatus(spec, configured=False, usable=False)
    public = private.public_key()
    return KeyStatus(
        spec,
        configured=True,
        usable=True,
        key_id=key_id(public),
        public_key=public_hex(public),
    )


def status() -> List[KeyStatus]:
    return [key_status(spec) for spec in KEYS]


class ProvisionError(RuntimeError):
    """A missing key could not be stored durably."""


def provision() -> List[KeyStatus]:
    """Create each missing key in the secrets store. An existing key is kept.

    A key that is set but unreadable is reported, not replaced: replacing it
    would orphan whatever it signed. Raises ``ProvisionError`` when the store
    cannot hold a new key (the write backend is the process environment, or
    the write or its read-back fails).
    """
    backend = get_secrets_manager().write_backend_name
    results: List[KeyStatus] = []
    for spec in KEYS:
        current = key_status(spec)
        if current.configured or current.error:
            results.append(current)
            continue
        if backend == "env":
            raise ProvisionError(
                "SECRETS_BACKEND=env keeps a secret for this process only; "
                f"cannot provision {spec.secret}"
            )
        seed, _public = generate_key()
        if not set_secret(spec.secret, seed):
            raise ProvisionError(f"the secrets store did not accept {spec.secret}")
        stored = key_status(spec)
        if not stored.usable:
            raise ProvisionError(f"{spec.secret} did not read back from the store")
        logger.info(
            "Generated %s (key id %s) in the secrets store",
            spec.secret,
            stored.key_id,
        )
        results.append(
            KeyStatus(
                spec,
                configured=True,
                usable=True,
                key_id=stored.key_id,
                public_key=stored.public_key,
                generated=True,
            )
        )
    return results


# --- health ------------------------------------------------------------------

WARN_CHECKPOINTS = "audit_checkpoint_signing_not_configured"
WARN_EVIDENCE = "evidence_pack_signing_key_missing"
_HEALTH_TTL_SECONDS = 60.0
_health_cache: Dict[str, Any] = {}


def _recent_checkpoint(interval: int) -> bool:
    """Whether some process (the daemon) signed a checkpoint lately.

    On Helm the backend does not hold the checkpoint key; a checkpoint written
    within two intervals (at least two hours) is the evidence that the daemon
    does.
    """
    from datetime import timedelta

    from sqlalchemy import text

    from core.storage.connection import get_db_manager
    from core.time import utcnow

    since = utcnow() - timedelta(seconds=max(2 * interval, 7200))
    try:
        with get_db_manager().engine.connect() as conn:
            if (
                conn.execute(text("SELECT to_regclass('audit_checkpoints')")).scalar()
                is None
            ):
                return False
            return bool(
                conn.execute(
                    text(
                        "SELECT 1 FROM audit_checkpoints WHERE created_at >= :s LIMIT 1"
                    ),
                    {"s": since},
                ).scalar()
            )
    except Exception:  # noqa: BLE001 - health must not raise
        logger.debug("Could not read audit_checkpoints for the signing health")
        return False


def signing_health(*, use_cache: bool = True) -> Dict[str, Any]:
    """Booleans and warning codes for the public health route; no key material.

    ``audit_checkpoints`` is true when the job is on and either this process
    holds a usable checkpoint key or a checkpoint was signed recently;
    ``evidence_packs`` when this process holds a usable evidence-pack key (the
    backend signs packs itself). Cached for a minute: probes call this often.
    """
    import time

    from core.config import get_settings

    now = time.monotonic()
    if use_cache and _health_cache and now - _health_cache["at"] < _HEALTH_TTL_SECONDS:
        return _health_cache["value"]
    interval = int(get_settings().audit_checkpoint_interval_seconds or 0)
    checkpoints = interval > 0 and (
        key_status(AUDIT_CHECKPOINTS).usable or _recent_checkpoint(interval)
    )
    evidence = key_status(EVIDENCE_PACKS).usable
    warnings: List[str] = []
    if not checkpoints:
        warnings.append(WARN_CHECKPOINTS)
    if not evidence:
        warnings.append(WARN_EVIDENCE)
    value = {
        "audit_checkpoints": bool(checkpoints),
        "evidence_packs": bool(evidence),
        "warnings": warnings,
    }
    _health_cache.update(at=now, value=value)
    return value


def _print_status(rows: List[KeyStatus]) -> None:
    for row in rows:
        if row.usable:
            state = "generated" if row.generated else "present"
            print(
                f"{row.spec.secret}: {state}  key id {row.key_id}  "
                f"public key {row.public_key}"
            )
        elif row.configured:
            print(f"{row.spec.secret}: SET BUT UNUSABLE ({row.error})")
        else:
            print(
                f"{row.spec.secret}: missing" + (f" ({row.error})" if row.error else "")
            )


def export_text(rows: List[KeyStatus], fmt: str) -> str:
    """The public keys this process holds, as env lines, JSON or PEM blocks."""
    usable = [r for r in rows if r.usable]
    if fmt == "json":
        return (
            json.dumps(
                {
                    "algorithm": ALGORITHM,
                    "keys": [
                        {
                            "purpose": r.spec.purpose,
                            "key_id": r.key_id,
                            "public_key": r.public_key,
                            "public_key_pem": r.public_pem(),
                        }
                        for r in usable
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    if fmt == "pem":
        return "".join(
            f"# {r.spec.purpose} (key id {r.key_id})\n{r.public_pem()}" for r in usable
        )
    return "".join(f"{r.spec.public_env}={r.public_key}\n" for r in usable)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m core.audit.signing_keys",
        description="Provision and export the AutoSecOps signing keys "
        "(audit checkpoints, evidence packs).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    prov = sub.add_parser(
        "provision", help="create the missing keys in the secrets store"
    )
    prov.add_argument(
        "--warn-only",
        action="store_true",
        help="exit 0 when a key cannot be stored (the backend health then warns)",
    )
    st = sub.add_parser("status", help="which keys are present (no private parts)")
    st.add_argument("--json", action="store_true")
    ex = sub.add_parser("export", help="print the public keys for offline verifiers")
    ex.add_argument("--format", choices=("env", "json", "pem"), default="env")
    ex.add_argument(
        "--purpose",
        choices=[spec.purpose for spec in KEYS],
        help="only this key (one PEM block, e.g. for --public-key @file)",
    )
    args = parser.parse_args(argv)

    if args.command == "provision":
        try:
            rows = provision()
        except ProvisionError as e:
            print(f"signing keys: {e}", file=sys.stderr)
            return 0 if args.warn_only else 1
        _print_status(rows)
        bad = [r for r in rows if not r.usable]
        if bad:
            print(
                "signing keys: fix or remove the unusable secret(s) above; "
                "they are never overwritten",
                file=sys.stderr,
            )
            return 0 if args.warn_only else 1
        return 0
    rows = status()
    if args.command == "export" and args.purpose:
        rows = [r for r in rows if r.spec.purpose == args.purpose]
    if args.command == "status":
        if args.json:
            print(json.dumps([r.to_dict() for r in rows], indent=2, sort_keys=True))
        else:
            _print_status(rows)
        return 0 if all(r.usable for r in rows) else 1
    text = export_text(rows, args.format)
    sys.stdout.write(text)
    missing = [r.spec.secret for r in rows if not r.usable]
    if missing:
        print(
            "signing keys: not held by this process: " + ", ".join(missing),
            file=sys.stderr,
        )
    return 0 if text else 1


if __name__ == "__main__":
    raise SystemExit(main())
