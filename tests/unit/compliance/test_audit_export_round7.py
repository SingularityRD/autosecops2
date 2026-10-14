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


# -- (b) key-based masking gaps -------------------------------------------------

FAKE = "fake-placeholder-Value-123"


@pytest.mark.parametrize(
    "key",
    [
        "foo_key",
        "fooKey",
        "foo-key",
        "FOO_KEY",
        "primaryKey",
        "secondary_key",
        "storage_account_key",
        "wrapping_key",
        "api_keys",
        "kek",
        "dek",
        "wrapped-dek",
        "tenantKek",
        "wallet_seed",
        "totpSeed",
        "backup_code",
        "recovery-code",
        "recoveryCode",
        "xsrf",
        "XSRF-TOKEN",
        "security_answer",
        "securityAnswer",
    ],
)
def test_credential_like_keys_are_masked(key):
    out = Redactor().value("", {key: FAKE, "note": "kept"})
    assert out[key] == REDACTED and out["note"] == "kept"
    text = Redactor().text(f"changed {key}={FAKE} ok")
    assert FAKE not in text, text


@pytest.mark.parametrize(
    "key",
    [
        "config_key",
        "partition_key",
        "sortKey",
        "idempotency-key",
        "public_key",
        "publicKey",
        "issue_key",
        "cache_key",
        "key_id",
        "primary_key_id",
        "random_seed",
    ],
)
def test_id_like_keys_on_the_allow_list_pass(key):
    out = Redactor().value("", {key: "SEC-4821"})
    assert out[key] == "SEC-4821"


@pytest.mark.parametrize(
    "key",
    [
        "account_number",
        "accountNumber",
        "bank-account",
        "routing_number",
        "iban",
        "vkn",
        "vergi_no",
        "vergiNo",
        "tckn",
        "nin",
        "aadhaar",
        "cpf",
        "nhs_number",
        "nhsNumber",
        "gender",
        "health",
        "health_data",
        "religion",
        "ethnicity",
        "sexual_orientation",
        "sexualOrientation",
        "political",
        "political-party",
        "biometric",
        "biometric_template",
    ],
)
def test_personal_and_special_category_keys_are_masked(key):
    out = Redactor().value("", {key: "plain value 7"})
    assert out[key] == REDACTED
    text = Redactor().text(f'saved {key}=plainvalue7 and "{key}": "other"')
    assert "plainvalue7" not in text and '"other"' not in text, text
    assert "[REDACTED-PII]" in text


@pytest.mark.parametrize(
    "key", ["health_check", "health_status", "gender_count", "biometric_enabled"]
)
def test_about_personal_data_is_not_personal_data(key):
    assert Redactor().value("", {key: "ok"})[key] == "ok"


@pytest.mark.parametrize(
    "url",
    [
        "jdbc:postgresql://db:5432/app?user=svc&password=" + FAKE,
        "jdbc:sqlserver://db:1433;databaseName=x;user=sa;password=" + FAKE,
        "jdbc:oracle:thin:scott/" + FAKE + "@db:1521/orcl",
        "jdbc:mysql://svc:" + FAKE + "@db:3306/app",
        "postgres://svc:" + FAKE + "@db/app",
        "redis://:" + FAKE + "@cache:6379/0",
        "amqp://svc:" + FAKE + "@mq:5672/",
    ],
)
def test_url_values_lose_embedded_credentials(url):
    for key in ("jdbc_url", "jdbcUrl", "callback-url", "endpoint"):
        out = Redactor().value("", {key: url})[key]
        assert FAKE not in out, out
        assert out.startswith(url.split(":", 1)[0])  # the rest of the URL stays


# -- (c) per-event scrub budget ---------------------------------------------------


def _big_event(details: dict) -> AuditEvent:
    return AuditEvent(
        id="config:big",
        source="config",
        category="configuration",
        action="config.update",
        outcome="success",
        severity=5,
        timestamp=TS,
        message="bulk import",
        details=details,
    )


_CHUNK = ("token:abc Ab1 x@y.co 4111 " * 80)[:1640]


def test_a_16_mb_event_is_scrubbed_in_a_few_seconds_and_flagged():
    details = {"rows": [{f"f{j}": _CHUNK for j in range(100)} for _ in range(100)]}
    assert len(json.dumps(details)) > 16_000_000
    t0 = time.perf_counter()
    out = Redactor().event(_big_event(details))
    elapsed = time.perf_counter() - t0
    assert elapsed < 10, elapsed  # was ~45 s before the budget
    assert out.details["_redaction_budget_exceeded"] is True
    rows = out.details["rows"]
    # The tail is masked, not passed through.
    assert rows[-1] == "[REDACTED-BUDGET]" or set(rows[-1].values()) == {
        "[REDACTED-BUDGET]"
    }
    assert out.message == "bulk import"  # scrubbed before details


def test_json_in_string_parses_are_bounded_and_fail_closed():
    inner = json.dumps({"password": FAKE, "n": 1})
    details = {f"j{i}": inner for i in range(80)}
    r = Redactor(event_json_parses=10)
    out = r.event(_big_event(details))
    assert FAKE not in json.dumps(out.details)
    assert out.details["_redaction_budget_exceeded"] is True
    assert out.details["j79"] == "[REDACTED-BUDGET]"
    assert r.budget_exceeded == 1


def test_node_budget_masks_the_remainder():
    details = {"items": [{"v": f"value {i}"} for i in range(90)]}
    out = Redactor(event_nodes=50).event(_big_event(details))
    flat = json.dumps(out.details)
    assert "value 89" not in flat and "[REDACTED-BUDGET]" in flat
    assert out.details["_redaction_budget_exceeded"] is True


def test_small_events_are_not_flagged():
    out = Redactor().event(_big_event({"a": "b", "nested": {"c": [1, 2, "d"]}}))
    assert "_redaction_budget_exceeded" not in out.details
    assert out.details == {"a": "b", "nested": {"c": [1, 2, "d"]}}


def test_checkpoints_are_outside_the_budget():
    ev, body = _checkpoint(400)
    raw = AuditEvent(**{**ev.__dict__})
    out = Redactor(event_chars=100, event_nodes=5).event(raw)
    assert out.details["body"] == body
    assert out.details["signature"] == ev.details["signature"]
