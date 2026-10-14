"""Round 7 verifier findings (WP w3.6): checkpoints survive every format,
broader key-based masking, and a per-event scrub budget."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.audit.checkpoint import canonical_json
from core.compliance.audit_export import (
    BODY_PART_ACTION,
    REDACTED,
    AuditEvent,
    HttpDestination,
    HttpTransport,
    Redactor,
    SyslogDestination,
    SyslogTransport,
    encode_rfc5424,
    format_cef,
)

from .conftest import HttpReceiver, SyslogReceiver, UdpReceiver
from .test_audit_export_formats import _parse_cef

pytestmark = pytest.mark.unit

TS = datetime(2026, 10, 12, 8, 30, tzinfo=timezone.utc)
_BOM = b"\xef\xbb\xbf"


# -- (a) checkpoints are never cut --------------------------------------------


def _checkpoint(n_runs: int = 3) -> tuple[AuditEvent, str]:
    """A checkpoint signed with a throwaway key made for this test."""
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    body = canonical_json(
        {
            "v": 1,
            "issued_at": "2026-10-12T08:30:00.000Z",
            "key_id": "test-key",
            "prev": "0" * 64,
            "audit_chain": {"head": {"seq": 41, "hash": "a" * 64}},
            "agent_events": {
                "heads": {
                    f"run-{i:05d}": {"seq": i, "hash": f"{i:064x}"}
                    for i in range(n_runs)
                }
            },
        }
    )
    body_hash = hashlib.sha256(body.encode()).hexdigest()
    sig = base64.b64encode(key.sign(body.encode())).decode()
    ev = AuditEvent(
        id="audit_checkpoints:9",
        source="audit_checkpoints",
        category="integrity",
        action="audit.checkpoint",
        outcome="success",
        severity=3,
        timestamp=TS,
        message="audit chain checkpoint 9 signed by key test-key",
        target_type="audit_checkpoint",
        target_id="9",
        hash=body_hash,
        details={
            "key_id": "test-key",
            "public_key": pub,
            "body": body,
            "body_hash": body_hash,
            "prev_body_hash": "0" * 64,
            "signature": sig,
            "tsa_token": None,
            "audit_chain_head": {"seq": 41, "hash": "a" * 64},
            "schema_change": None,
        },
    )
    return Redactor().event(ev), body


def _verifies(pub_hex: str, sig: str, body: str) -> bool:
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
        base64.b64decode(sig), body.encode()
    )
    return True


def _check_cef(line: str, body: str, ev: AuditEvent) -> None:
    _, ext = _parse_cef(line)
    assert ext["cs6Label"] == "checkpointSignature"
    assert ext["cs6"] == ev.details["signature"]
    assert ext["flexString1"] == ev.details["public_key"]
    assert ext["rawEvent"] == body
    assert ext["cs5"] == hashlib.sha256(body.encode()).hexdigest()
    assert ext["cn1"] == "41" and ext["flexString2"] == "a" * 64
    details = json.loads(ext["cs4"])  # complete and valid JSON
    assert details["prev_body_hash"] == "0" * 64 and "_truncated" not in details
    assert _verifies(ext["flexString1"], ext["cs6"], ext["rawEvent"])


def test_cef_checkpoint_is_complete_beyond_the_details_limit():
    ev, body = _checkpoint(200)
    assert len(body) > 16_384
    line = format_cef(ev, "soc")
    assert "...[truncated]" not in line
    _check_cef(line, body, ev)


def test_cef_details_over_the_limit_stay_valid_json_with_a_flag():
    ev = AuditEvent(
        id="config:1",
        source="config",
        category="configuration",
        action="config.update",
        outcome="success",
        severity=5,
        timestamp=TS,
        message="m",
        details={"a": "x" * 100, "b": "y" * 5000, "c": 3},
    )
    _, ext = _parse_cef(format_cef(ev, "h"))
    details = json.loads(ext["cs4"])
    assert len(ext["cs4"]) <= 1024
    assert details["a"] == "x" * 100 and details["c"] == 3 and "b" not in details
    full = json.dumps(ev.details, sort_keys=True, separators=(",", ":"))
    assert details["_truncated"] == {"original_chars": len(full), "omitted_keys": 1}


async def test_cef_over_http_checkpoint_signature_verifies():
    ev, body = _checkpoint(300)
    rx = HttpReceiver().start()
    tx = HttpTransport(
        HttpDestination(
            type="http",
            name="hec",
            url=f"http://127.0.0.1:{rx.port}/cef",
            allow_plaintext=True,
            format="cef",
            timeout_s=5,
        ),
        lambda _n: None,
        "soc",
    )
    try:
        await tx.send([ev])
    finally:
        await tx.close()
        rx.stop()
    (req,) = rx.requests
    _check_cef(req["body"].decode().rstrip("\n"), body, ev)


def _msg(raw: bytes) -> bytes:
    return raw.split(_BOM, 1)[1]


def _reassemble(msgs: list[bytes], fmt: str) -> tuple[dict, str]:
    """The primary event's details and the body rebuilt from its parts."""
    docs = []
    for raw in msgs:
        if fmt == "cef":
            _, ext = _parse_cef(_msg(raw).decode())
            docs.append(
                {"action": ext["act"], "details": json.loads(ext["cs4"]), "ext": ext}
            )
        else:
            docs.append(json.loads(_msg(raw)))
    primary, parts = docs[0], docs[1:]
    assert primary["action"] == "audit.checkpoint"
    flag = primary["details"]["_truncated"]
    assert flag["fields"] == ["body"] and flag["body_parts"] == len(parts) > 1
    assert all(p["action"] == BODY_PART_ACTION for p in parts)
    assert [p["details"]["part"] for p in parts] == list(range(1, len(parts) + 1))
    body = "".join(p["details"]["body_chunk"] for p in parts)
    assert len(body) == flag["body_chars"]
    return primary, body


@pytest.mark.parametrize("fmt", ["rfc5424", "cef"])
def test_syslog_checkpoint_too_big_for_one_message_is_split_not_cut(fmt):
    ev, body = _checkpoint(400)
    msgs = encode_rfc5424(ev, host="soc", body=fmt, max_bytes=4096, procid=1)
    assert all(len(m) <= 4096 for m in msgs)
    sd = msgs[0].split(b" ", 6)[6]
    assert f'signature="{ev.details["signature"]}"'.encode() in sd
    assert f'publicKey="{ev.details["public_key"]}"'.encode() in sd
    primary, rebuilt = _reassemble(msgs, fmt)
    assert rebuilt == body
    assert hashlib.sha256(rebuilt.encode()).hexdigest() == ev.details["body_hash"]
    d = primary["details"]
    assert _verifies(d["public_key"], d["signature"], rebuilt)


@pytest.mark.parametrize("fmt", ["rfc5424", "cef"])
def test_syslog_checkpoint_that_fits_is_one_complete_message(fmt):
    ev, body = _checkpoint(3)
    (msg,) = encode_rfc5424(ev, host="soc", body=fmt, procid=1)
    if fmt == "cef":
        _check_cef(_msg(msg).decode(), body, ev)
    else:
        doc = json.loads(_msg(msg))
        d = doc["details"]
        assert d["body"] == body and _verifies(d["public_key"], d["signature"], body)


async def test_syslog_json_tcp_delivers_every_part():
    ev, body = _checkpoint(400)
    rx = await SyslogReceiver().start()
    tx = SyslogTransport(
        SyslogDestination(
            type="syslog",
            name="siem",
            host="127.0.0.1",
            port=rx.port,
            protocol="tcp",
            max_message_bytes=4096,
            timeout_s=5,
        ),
        lambda _n: None,
        "soc",
    )
    expected = len(encode_rfc5424(ev, host="soc", max_bytes=4096))
    try:
        await tx.send([ev])
        await rx.wait_for(expected)
    finally:
        await tx.close()
        await rx.stop()
    primary, rebuilt = _reassemble(rx.messages, "rfc5424")
    d = primary["details"]
    assert rebuilt == body and _verifies(d["public_key"], d["signature"], rebuilt)


async def test_syslog_cef_udp_delivers_every_part():
    import asyncio

    ev, body = _checkpoint(400)
    rx = await UdpReceiver().start()
    tx = SyslogTransport(
        SyslogDestination(
            type="syslog",
            name="siem",
            host="127.0.0.1",
            port=rx.port,
            protocol="udp",
            format="cef",
            max_message_bytes=4096,
            timeout_s=5,
        ),
        lambda _n: None,
        "soc",
    )
    expected = len(encode_rfc5424(ev, host="soc", body="cef", max_bytes=4096))
    try:
        await tx.send([ev])
        for _ in range(100):
            if len(rx.messages) >= expected:
                break
            await asyncio.sleep(0.02)
    finally:
        rx.stop()
    primary, rebuilt = _reassemble(rx.messages, "cef")
    ext = primary["ext"]
    assert _verifies(ext["flexString1"], ext["cs6"], rebuilt)
