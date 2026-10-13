"""The signed, self-verifying evidence pack of one case (W3.7).

A ZIP holding:

``data/case.json``                    the case row
``data/findings.json``                its linked findings (canaries dropped when W1.5 is installed)
``data/case_evidence.json``           its ``case_evidence`` rows
``data/case_audit.json``              its ``case_audit_logs`` rows
``data/actions.json``                 its response actions: approvals, execution,
                                      full before/after state, verification, reversal
``data/ledger.json``                  the agent ledger of its runs, with the hash chain
``data/ai_provenance.json``           AI verdicts on its findings, AI decision logs, runs
``data/regulatory_clock_events.json`` DORA / NIS2 start instants (W3.8), chained
``data/audit_chain.json``             W1.10 chain rows of its audit/approval rows (when installed)
``data/citable_index.json``           the items W3.8 drafts cite, and their digest
``data/verification.json``            the checks, as computed at export
``verify_bundle.py``                  the offline verifier (stdlib only)
``README.txt``                        how to verify
``manifest.json``                     sha256 and size of every file above
``manifest.sig``                      base64 Ed25519 signature of manifest.json's bytes

The signing key is the ``EVIDENCE_PACK_SIGNING_KEY`` secret (an Ed25519 seed
as 64 hex chars or base64, or a PEM private key). Without it each pack is
signed with a fresh key and says so (``key_source: ephemeral``): the pack is
still internally consistent, but only a pinned key proves who made it.
``python -m core.compliance.evidence_bundle keygen`` prints a new seed and its
public key.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import logging
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.compliance import verify_bundle
from core.compliance.evidence import CaseRecord, jsonable, row_dict
from core.secrets import get_secret

logger = logging.getLogger(__name__)

SIGNING_KEY_SECRET = "EVIDENCE_PACK_SIGNING_KEY"


class SigningKeyError(ValueError):
    """EVIDENCE_PACK_SIGNING_KEY is set but is not an Ed25519 private key."""


def parse_private_key(value: str) -> Ed25519PrivateKey:
    value = value.strip()
    if value.startswith("-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(value.encode("utf-8"), None)
        except (ValueError, TypeError):
            raise SigningKeyError("PEM is not a readable private key") from None
        if not isinstance(key, Ed25519PrivateKey):
            raise SigningKeyError("PEM key is not Ed25519")
        return key
    raw: Optional[bytes] = None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raw = None
    if raw is None or len(raw) != 32:
        raise SigningKeyError("an Ed25519 seed is 32 bytes as hex or base64")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_signing_key() -> Tuple[Ed25519PrivateKey, str]:
    """The configured key and ``configured``, or a fresh one and ``ephemeral``."""
    value = get_secret(SIGNING_KEY_SECRET)
    if value and value.strip():
        return parse_private_key(value), "configured"
    logger.warning(
        "%s is not set: signing this evidence pack with a one-off key",
        SIGNING_KEY_SECRET,
    )
    return Ed25519PrivateKey.generate(), "ephemeral"


def public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _dump(obj: Any) -> bytes:
    return (
        json.dumps(jsonable(obj), sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


README = """AutoSecOps evidence pack
========================

Case: {case_id}
Exported: {created_at} by {created_by}
Signer key id: {key_id} ({key_source})

Verify offline (Python 3.8+, no network, no database):

    python verify_bundle.py {name}
    python verify_bundle.py {name} --public-key <the signer's public key>

or, on an AutoSecOps host:

    scripts/autosecops verify-bundle {name} --public-key <key>

Exit 0 means every file matches the signed manifest and every chain in the
pack recomputes. Exit 1 means the pack was altered or a chain in it is broken.
The verify_bundle.py inside the pack is a convenience: for an independent check
run your own copy and pin the signer's public key ({public_key}).

data/ holds the case, its findings, evidence, case audit log, response actions
(with before/after state and verification), the agent ledger of its runs
(payload_text is the exact text each event_hash covers), AI verdict
provenance, regulatory clock events and the citable index regulatory drafts
cite (their pack_digest is citable_digest in manifest.json).
"""


@dataclass(frozen=True)
class Bundle:
    data: bytes
    filename: str
    manifest_sha256: str
    key_id: str
    key_source: str
    manifest: Dict[str, Any]


def _verification(record: CaseRecord) -> Dict[str, Any]:
    """The same checks the offline verifier runs, computed now, plus action states."""
    ledger = []
    for run in record.ledger:
        why = verify_bundle.check_ledger_run(run["events"])
        ledger.append(
            {
                "run_id": run["run_id"],
                "status": run["status"],
                "events": len(run["events"]),
                "ok": why is None,
                "break": why,
            }
        )
    clock_why = verify_bundle.check_clock_chain(
        record.case_id, [_clock_dict(e, record.case_id) for e in record.clock_events]
    )
    chain_why = (
        verify_bundle.check_audit_rows(record.audit_chain)
        if record.audit_chain is not None
        else None
    )
    actions = [a for a in record.actions if "action_id" in a]
    return {
        "ledger": ledger,
        "clock_chain": {
            "status": record.clock_status,
            "events": len(record.clock_events),
            "ok": clock_why is None,
            "break": clock_why,
        },
        "audit_chain": (
            {"status": "absent"}
            if record.audit_chain is None
            else {
                "status": "included",
                "rows": len(record.audit_chain),
                "ok": chain_why is None,
                "break": chain_why,
            }
        ),
        "actions": [
            {
                "action_id": a["action_id"],
                "status": a.get("status"),
                "verify_status": a.get("verify_status"),
                "verified_at": a.get("verified_at"),
                "reversed_at": a.get("reversed_at"),
            }
            for a in actions
        ],
        "notes": list(record.notes),
    }


def _clock_dict(event: Any, case_id: str) -> Dict[str, Any]:
    out = event.to_dict()
    out["case_id"] = case_id
    return out


def build_bundle(
    record: CaseRecord,
    actor: str,
    now: datetime,
    key: Ed25519PrivateKey,
    key_source: str,
) -> Bundle:
    """The pack as ZIP bytes, signed with ``key``."""
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)
    case_id = record.case_id
    citable = record.citable()
    citable_items = [i.to_dict() for i in citable.items]
    public = public_bytes(key)
    kid = verify_bundle.key_id(public)
    created_at = now.isoformat()

    data: Dict[str, bytes] = {
        "data/case.json": _dump(row_dict(record.case)),
        "data/findings.json": _dump(
            {
                "findings": [row_dict(f) for f in record.findings],
                "excluded_canaries": record.excluded_canaries,
                "canary_exclusion": record.canary_exclusion,
            }
        ),
        "data/case_evidence.json": _dump(
            {"evidence": [row_dict(e) for e in record.evidence]}
        ),
        "data/case_audit.json": _dump({"audit": [row_dict(a) for a in record.audits]}),
        "data/actions.json": _dump({"actions": record.actions}),
        "data/ledger.json": _dump({"runs": record.ledger}),
        "data/ai_provenance.json": _dump(record.ai),
        "data/regulatory_clock_events.json": _dump(
            {
                "status": record.clock_status,
                "events": [_clock_dict(e, case_id) for e in record.clock_events],
            }
        ),
        "data/citable_index.json": _dump(
            {"digest": citable.digest, "items": citable_items}
        ),
    }
    if record.audit_chain is not None:
        data["data/audit_chain.json"] = _dump({"rows": record.audit_chain})
    data["data/verification.json"] = _dump(_verification(record))
    data["verify_bundle.py"] = Path(verify_bundle.__file__).read_bytes()
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    filename = f"evidence-pack-{_safe(case_id)}-{stamp}.zip"
    data["README.txt"] = README.format(
        case_id=case_id,
        created_at=created_at,
        created_by=actor,
        key_id=kid,
        key_source=key_source,
        name=filename,
        public_key=public.hex(),
    ).encode("utf-8")

    events = sum(len(r["events"]) for r in record.ledger)
    manifest = {
        "format": verify_bundle.FORMAT,
        "version": verify_bundle.VERSION,
        "product": "AutoSecOps",
        "case_id": case_id,
        "created_at": created_at,
        "created_by": actor,
        "citable_digest": citable.digest,
        "counts": {
            "findings": len(record.findings),
            "case_evidence": len(record.evidence),
            "case_audit": len(record.audits),
            "actions": len([a for a in record.actions if "action_id" in a]),
            "ledger_runs": len(record.ledger),
            "ledger_events": events,
            "clock_events": len(record.clock_events),
            "audit_chain_rows": len(record.audit_chain or []),
        },
        "sources": {
            "audit_chain": "absent" if record.audit_chain is None else "included",
            "canary_exclusion": record.canary_exclusion,
            "regulatory_clocks": record.clock_status,
        },
        "excluded": {"canary_findings": record.excluded_canaries},
        "signer": {
            "algorithm": "ed25519",
            "key_id": kid,
            "public_key": base64.b64encode(public).decode("ascii"),
            "key_source": key_source,
        },
        "files": [
            {
                "path": name,
                "sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body),
            }
            for name, body in sorted(data.items())
        ],
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    signature = base64.b64encode(key.sign(manifest_bytes)) + b"\n"

    buffer = io.BytesIO()
    stamp_tuple = now.timetuple()[:6]
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in [
            *sorted(data.items()),
            (verify_bundle.MANIFEST, manifest_bytes),
            (verify_bundle.SIGNATURE, signature),
        ]:
            info = zipfile.ZipInfo(name, date_time=stamp_tuple)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, body)
    return Bundle(
        data=buffer.getvalue(),
        filename=filename,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        key_id=kid,
        key_source=key_source,
        manifest=manifest,
    )


def _safe(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in value)[:80]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="autosecops evidence-keygen")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("keygen", help="print a new Ed25519 signing seed and its public key")
    args = parser.parse_args(argv)
    if args.command == "keygen":
        key = Ed25519PrivateKey.generate()
        seed = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public = public_bytes(key)
        print(f"{SIGNING_KEY_SECRET}={seed.hex()}")
        print(f"public key (hex):    {public.hex()}")
        print(f"public key (base64): {base64.b64encode(public).decode('ascii')}")
        print(f"key id:              {verify_bundle.key_id(public)}")
        print(
            "Store the seed as a secret; give the public key to whoever verifies packs."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__: List[str] = [
    "Bundle",
    "SigningKeyError",
    "build_bundle",
    "load_signing_key",
    "parse_private_key",
]
