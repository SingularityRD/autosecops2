#!/usr/bin/env python3
"""Verify an AutoSecOps evidence pack offline: ``autosecops verify-bundle PACK``.

A pack is a ZIP (or the directory it was extracted to) holding
``manifest.json``, ``manifest.sig`` and the files the manifest lists. This
program needs no network, no database and nothing from AutoSecOps: only the
Python standard library. It uses the ``cryptography`` package for Ed25519 when
installed and a pure-Python RFC 8032 verifier otherwise, so every copy of this
file (the pack carries one) can run on its own.

Checks, each reported on its own line:

signature        manifest.sig is an Ed25519 signature of manifest.json's exact
                 bytes by the key the manifest names; with ``--public-key`` that
                 key must also be the one you trust. Without it the key is only
                 the pack's own claim, which is reported as a warning.
files            every listed file is present with the listed sha256 and size,
                 nothing unlisted is present, and no name appears twice.
ledger           each agent run's events chain: the first prev_hash is empty,
                 each next prev_hash is the previous event_hash, and each
                 event_hash is sha256(prev_hash || payload_text).
clock_chain      the regulatory clock events chain (W3.8's formula).
audit_chain      each audit_chain row's event_hash is
                 sha256(prev_hash || canonical) (only when the pack has them).
citable_index    the digest the regulatory drafts cite is the sha256 of the
                 listed items.

Exit status: 0 the pack verifies; 1 it does not (tampered, or a chain in it is
broken); 2 it cannot be read, or bad usage.

The copy inside a pack is a convenience. A recipient who wants to rule out a
doctored verifier runs their own copy and pins the signer's public key.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import sys
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

FORMAT = "autosecops.evidence-pack"
VERSION = 1
MANIFEST = "manifest.json"
SIGNATURE = "manifest.sig"

# -- Ed25519 verification (RFC 8032 section 5.1.7) ----------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _add(p: tuple, q: tuple) -> tuple:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s: int, p: tuple) -> tuple:
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _same(p: tuple, q: tuple) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (
        p[1] * q[2] - q[1] * p[2]
    ) % _P == 0


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)  # type: ignore[operator]


def _decompress(raw: bytes) -> Optional[tuple]:
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def ed25519_verify_pure(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 verification in pure Python (slow, dependency-free)."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decompress(public_key)
    if a is None:
        return False
    r_raw = signature[:32]
    r = _decompress(r_raw)
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(r_raw + public_key + message).digest(), "little")
    return _same(_mul(s, _G), _add(r, _mul(h % _L, a)))


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        return ed25519_verify_pure(public_key, message, signature)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def key_id(public_key: bytes) -> str:
    """First 16 hex chars of sha256(raw public key)."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def parse_public_key(value: str) -> bytes:
    """32 raw bytes from hex, base64 or a PEM SubjectPublicKeyInfo."""
    value = value.strip()
    if value.startswith("-----BEGIN"):
        body = "".join(
            line for line in value.splitlines() if not line.startswith("-----")
        )
        der = base64.b64decode(body)
        # SubjectPublicKeyInfo for Ed25519 is a fixed 12-byte prefix + 32 bytes.
        if len(der) != 44 or der[:12] != bytes.fromhex("302a300506032b6570032100"):
            raise ValueError("PEM is not an Ed25519 public key")
        return der[12:]
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        try:
            raw = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("public key is not hex, base64 or PEM") from None
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return raw


# -- the chains ------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def chain_hash(prev_hash: str, text: str) -> str:
    """sha256(prev_hash || text), hex: the agent ledger's and audit_chain's formula."""
    return sha256_hex((prev_hash + text).encode("utf-8"))


def check_ledger_run(events: Sequence[Mapping[str, Any]]) -> Optional[str]:
    """None when the run's events chain from the start; else what broke."""
    prev = ""
    last_seq = None
    for event in events:
        seq = event.get("seq")
        if last_seq is not None and (not isinstance(seq, int) or seq <= last_seq):
            return f"seq {seq}: out of order"
        if event.get("prev_hash") != prev:
            return f"seq {seq}: prev_hash does not follow the previous event"
        text = event.get("payload_text")
        if not isinstance(text, str):
            return f"seq {seq}: payload_text missing"
        try:
            json.loads(text)
        except ValueError:
            return f"seq {seq}: payload_text is not JSON"
        if chain_hash(prev, text) != event.get("event_hash"):
            return f"seq {seq}: payload does not match event_hash"
        prev = str(event.get("event_hash"))
        last_seq = seq
    return None


def clock_event_hash(event: Mapping[str, Any], case_id: str, prev_hash: str) -> str:
    """W3.8's row hash (core/compliance/regulatory_service.event_hash)."""
    body = json.dumps(
        {
            "case_id": case_id,
            "seq": event.get("seq"),
            "regime": event.get("regime"),
            "instant": event.get("instant"),
            "value": event.get("value"),
            "previous_value": event.get("previous_value"),
            "actor": event.get("actor"),
            "reason": event.get("reason"),
            "recorded_at": event.get("recorded_at"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256_hex((prev_hash + body).encode("utf-8"))


def check_clock_chain(case_id: str, events: Sequence[Mapping[str, Any]]) -> Optional[str]:
    prev = ""
    for expected, event in enumerate(events, start=1):
        seq = event.get("seq")
        if seq != expected:
            return f"seq {seq}: expected {expected}, a row is missing"
        if event.get("prev_hash") != prev:
            return f"seq {seq}: prev_hash does not follow the previous row"
        if clock_event_hash(event, case_id, prev) != event.get("row_hash"):
            return f"seq {seq}: row does not match row_hash"
        prev = str(event.get("row_hash"))
    return None


def check_audit_rows(rows: Sequence[Mapping[str, Any]]) -> Optional[str]:
    for row in rows:
        canonical = row.get("canonical")
        prev = row.get("prev_hash")
        if not isinstance(canonical, str) or not isinstance(prev, str):
            return f"seq {row.get('seq')}: canonical text missing"
        if chain_hash(prev, canonical) != row.get("event_hash"):
            return f"seq {row.get('seq')}: row does not match event_hash"
    return None


def citable_digest(items: List[Mapping[str, Any]]) -> str:
    body = json.dumps(items, sort_keys=True, separators=(",", ":"))
    return sha256_hex(body.encode("utf-8"))


# -- reading a pack -----------------------------------------------------------------


class PackUnreadable(Exception):
    """The pack cannot be opened or has no manifest (exit 2)."""


def read_pack(path: str) -> Dict[str, bytes]:
    """Every file of the pack by its path. Duplicate ZIP names are refused."""
    files: Dict[str, bytes] = {}
    if os.path.isdir(path):
        root = os.path.abspath(path)
        for base, _dirs, names in os.walk(root):
            for name in names:
                full = os.path.join(base, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                with open(full, "rb") as handle:
                    files[rel] = handle.read()
        return files
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if info.filename in files:
                    raise PackUnreadable(f"{info.filename} appears twice in the archive")
                files[info.filename] = archive.read(info)
    except (OSError, zipfile.BadZipFile) as exc:
        raise PackUnreadable(f"cannot read {path}: {exc}") from None
    return files


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    warning: bool = False


def _json_file(files: Mapping[str, bytes], name: str) -> Any:
    return json.loads(files[name].decode("utf-8"))


def verify_files(
    files: Mapping[str, bytes], trusted_key: Optional[bytes] = None
) -> List[Check]:
    """Every check over an already-read pack. Raises PackUnreadable."""
    if MANIFEST not in files or SIGNATURE not in files:
        raise PackUnreadable("manifest.json or manifest.sig is missing")
    raw_manifest = files[MANIFEST]
    try:
        manifest = json.loads(raw_manifest.decode("utf-8"))
    except ValueError:
        raise PackUnreadable("manifest.json is not JSON") from None
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise PackUnreadable("not an AutoSecOps evidence pack")
    if manifest.get("version") != VERSION:
        raise PackUnreadable(f"unsupported pack version {manifest.get('version')!r}")

    checks: List[Check] = []

    # signature
    signer = manifest.get("signer") or {}
    try:
        public = base64.b64decode(str(signer.get("public_key", "")), validate=True)
        signature = base64.b64decode(files[SIGNATURE].strip(), validate=True)
    except (binascii.Error, ValueError):
        public, signature = b"", b""
    if signer.get("algorithm") != "ed25519" or not ed25519_verify(
        public, raw_manifest, signature
    ):
        checks.append(Check("signature", False, "manifest signature is not valid"))
    elif trusted_key is not None and trusted_key != public:
        checks.append(
            Check(
                "signature",
                False,
                f"signed by key {key_id(public)}, not the pinned key {key_id(trusted_key)}",
            )
        )
    elif trusted_key is not None:
        checks.append(Check("signature", True, f"valid, pinned key {key_id(public)}"))
    else:
        source = signer.get("key_source", "unknown")
        checks.append(
            Check(
                "signature",
                True,
                f"valid for the pack's own key {key_id(public)} ({source}); "
                "pass --public-key to pin the signer",
                warning=True,
            )
        )
    if signer.get("key_id") and signer.get("key_id") != key_id(public):
        checks.append(Check("signature", False, "manifest key_id does not match its key"))

    # files
    listed = manifest.get("files")
    problems: List[str] = []
    if not isinstance(listed, list):
        listed = []
        problems.append("manifest lists no files")
    names = set()
    for entry in listed:
        name = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or name.startswith("/") or ".." in name.split("/"):
            problems.append(f"bad path {name!r}")
            continue
        if name in names or name in (MANIFEST, SIGNATURE):
            problems.append(f"{name} listed twice")
            continue
        names.add(name)
        data = files.get(name)
        if data is None:
            problems.append(f"{name} is missing")
        elif sha256_hex(data) != entry.get("sha256") or len(data) != entry.get("bytes"):
            problems.append(f"{name} does not match its sha256")
    for name in sorted(set(files) - names - {MANIFEST, SIGNATURE}):
        problems.append(f"{name} is not in the manifest")
    checks.append(
        Check("files", not problems, "; ".join(problems) or f"{len(names)} files match")
    )
    if problems:
        # Contents of a pack whose files do not match are not worth reading.
        return checks

    case_id = str(manifest.get("case_id"))
    checks.extend(_content_checks(files, case_id, manifest))
    return checks


def _content_checks(
    files: Mapping[str, bytes], case_id: str, manifest: Mapping[str, Any]
) -> List[Check]:
    out: List[Check] = []
    try:
        ledger = _json_file(files, "data/ledger.json")
        breaks = []
        events = 0
        for run in ledger.get("runs", []):
            events += len(run.get("events", []))
            why = check_ledger_run(run.get("events", []))
            if why:
                breaks.append(f"run {run.get('run_id')} {why}")
        out.append(
            Check(
                "ledger",
                not breaks,
                "; ".join(breaks)
                or f"{len(ledger.get('runs', []))} run(s), {events} event(s) chain",
            )
        )

        clocks = _json_file(files, "data/regulatory_clock_events.json")
        why = check_clock_chain(case_id, clocks.get("events", []))
        out.append(
            Check(
                "clock_chain",
                why is None,
                why or f"{len(clocks.get('events', []))} event(s) chain",
            )
        )

        if "data/audit_chain.json" in files:
            chain = _json_file(files, "data/audit_chain.json")
            rows = chain.get("rows") or []
            why = check_audit_rows(rows)
            out.append(Check("audit_chain", why is None, why or f"{len(rows)} row(s) match"))

        index = _json_file(files, "data/citable_index.json")
        digest = citable_digest(index.get("items", []))
        ok = digest == index.get("digest") == manifest.get("citable_digest")
        out.append(
            Check(
                "citable_index",
                ok,
                f"digest {digest}" if ok else "items do not match the digest drafts cite",
            )
        )
    except (KeyError, ValueError, AttributeError, TypeError) as exc:
        out.append(Check("contents", False, f"unreadable content: {type(exc).__name__}: {exc}"))
    return out


def verify_pack(path: str, trusted_key: Optional[bytes] = None) -> List[Check]:
    return verify_files(read_pack(path), trusted_key)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="autosecops verify-bundle",
        description="Verify an AutoSecOps evidence pack offline.",
    )
    parser.add_argument("pack", help="the pack (.zip) or the directory it was extracted to")
    parser.add_argument(
        "--public-key",
        help="the signer's Ed25519 public key you trust (hex, base64, PEM, or @file)",
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)

    trusted = None
    if args.public_key:
        value = args.public_key
        try:
            if value.startswith("@"):
                with open(value[1:], encoding="utf-8") as handle:
                    value = handle.read()
            trusted = parse_public_key(value)
        except (OSError, ValueError) as exc:
            print(f"error: --public-key: {exc}", file=sys.stderr)
            return 2
    try:
        checks = verify_pack(args.pack, trusted)
    except PackUnreadable as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2
    ok = all(c.ok for c in checks)
    if args.json:
        print(
            json.dumps(
                {
                    "ok": ok,
                    "checks": [
                        {"name": c.name, "ok": c.ok, "detail": c.detail, "warning": c.warning}
                        for c in checks
                    ],
                },
                indent=2,
            )
        )
    else:
        for c in checks:
            mark = "ok  " if c.ok else "FAIL"
            if c.ok and c.warning:
                mark = "warn"
            print(f"{mark}  {c.name:<14} {c.detail}")
        print("RESULT: VERIFIED" if ok else "RESULT: REJECTED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
