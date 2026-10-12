"""CEF / RFC 5424 encoding and redaction of exported audit events (WP w3.6)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import pytest

from core.compliance.audit_export import (
    REDACTED,
    SD_ID,
    AuditEvent,
    Redactor,
    cef_escape_ext,
    cef_escape_header,
    format_cef,
    format_rfc5424,
    frame_octet_count,
    sd_escape,
)

pytestmark = pytest.mark.unit

TS = datetime(2026, 10, 12, 8, 30, 15, 123000, tzinfo=timezone.utc)


def _event(**kw) -> AuditEvent:
    base = dict(
        id="config:42",
        source="config",
        category="configuration",
        action="config.update",
        outcome="success",
        severity=5,
        timestamp=TS,
        message="system config x update",
        actor="alice",
        target_type="system",
        target_id="x",
    )
    base.update(kw)
    return AuditEvent(**base)


# -- CEF ------------------------------------------------------------------


def test_cef_header_escapes_pipe_and_backslash_and_flattens_newlines():
    assert cef_escape_header(r"a|b\c") == r"a\|b\\c"
    assert cef_escape_header("line1\r\nline2\nline3") == "line1 line2 line3"
    # '=' is legal in a header
    assert cef_escape_header("k=v") == "k=v"


def test_cef_extension_escapes_equals_backslash_and_encodes_newlines():
    assert cef_escape_ext(r"a=b\c") == r"a\=b\\c"
    assert cef_escape_ext("x\ny\rz") == r"x\ny\rz"
    # '|' is legal in an extension value
    assert cef_escape_ext("a|b") == "a|b"


def _parse_cef(line: str) -> tuple[list[str], dict]:
    """A strict CEF reader: split the header on unescaped '|', then the
    extension on unescaped '=' preceded by a key."""
    header, i, cur, esc = [], 0, "", False
    while len(header) < 7:
        ch = line[i]
        i += 1
        if esc:
            cur += ch
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == "|":
            header.append(cur)
            cur = ""
        else:
            cur += ch
    ext_raw = line[i:]
    keys = list(re.finditer(r"(?:^| )([A-Za-z0-9]+)=", ext_raw))
    # Drop matches whose '=' is escaped (preceded by an odd number of '\').
    ext = {}
    starts = []
    for m in keys:
        eq = m.end() - 1
        bs = 0
        j = eq - 1
        while j >= 0 and ext_raw[j] == "\\":
            bs += 1
            j -= 1
        if bs % 2 == 0:
            starts.append(m)
    for n, m in enumerate(starts):
        end = starts[n + 1].start() if n + 1 < len(starts) else len(ext_raw)
        raw = ext_raw[m.end() : end]
        val = re.sub(r"\\(.)", lambda g: {"n": "\n", "r": "\r"}.get(g[1], g[1]), raw)
        ext[m.group(1)] = val
    return header, ext


def test_cef_round_trips_hostile_values():
    nasty = "pwn|ed = yes \\ back\nslash dvchost=evil"
    line = format_cef(_event(message=nasty, actor="bob=admin", target_id="a|b"), "h1")
    assert "\n" not in line
    header, ext = _parse_cef(line)
    assert header[0] == "CEF:0"
    assert header[1] == "AutoSecOps"
    assert header[4] == "config:config.update"
    assert header[5] == nasty.replace("\n", " ")
    assert header[6] == "5"
    assert ext["msg"] == nasty
    assert ext["suser"] == "bob=admin"
    assert ext["cs2"] == "a|b"
    assert ext["dvchost"] == "h1"  # the injected dvchost stayed inside msg
    assert ext["externalId"] == "config:42"
    assert ext["rt"] == str(int(TS.timestamp() * 1000))


def test_cef_omits_absent_fields_and_their_labels():
    line = format_cef(_event(actor=None, target_type=None, target_id=None), "h")
    _, ext = _parse_cef(line)
    assert "suser" not in ext and "cs1" not in ext and "cs1Label" not in ext
    assert ext["cs3Label"] == "source" and ext["cs3"] == "config"


def test_cef_src_only_carries_a_valid_ip():
    _, ext = _parse_cef(format_cef(_event(src_ip="10.0.0.5"), "h"))
    assert ext["src"] == "10.0.0.5"
    _, ext = _parse_cef(format_cef(_event(src_ip="not-an-ip src=1.2.3.4"), "h"))
    assert "src" not in ext


def test_cef_severity_is_clamped():
    assert format_cef(_event(severity=99), "h").split("|")[6] == "10"
    assert format_cef(_event(severity=-3), "h").split("|")[6] == "0"


# -- RFC 5424 -------------------------------------------------------------


_RFC5424 = re.compile(
    rb"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (\[.*?[^\\]\]) \xef\xbb\xbf(.*)$",
    re.S,
)


def test_rfc5424_header_sd_and_json_body():
    msg = format_rfc5424(
        _event(actor='ev"il]\\', src_ip="192.0.2.7"), host="soc-1", procid=7
    )
    m = _RFC5424.match(msg)
    assert m, msg
    pri, ts, host, app, procid, msgid, sd, body = m.groups()
    assert int(pri) == 13 * 8 + 5  # facility log audit, severity notice
    assert ts == b"2026-10-12T08:30:15.123Z"
    assert (host, app, procid, msgid) == (
        b"soc-1",
        b"autosecops",
        b"7",
        b"configuration",
    )
    assert sd.startswith(b"[" + SD_ID.encode())
    assert b'actor="ev\\"il\\]\\\\"' in sd
    assert b'srcIp="192.0.2.7"' in sd
    doc = json.loads(body)
    assert doc["schema"] == "autosecops.audit.v1"
    assert doc["id"] == "config:42"
    assert doc["actor"]["name"] == 'ev"il]\\'


def test_rfc5424_header_tokens_are_printable_ascii():
    msg = format_rfc5424(_event(category="a b\tc"), host="h ost\n", procid=1)
    m = _RFC5424.match(msg)
    assert m
    assert m.group(3) == b"host"
    assert m.group(6) == b"abc"


def test_rfc5424_cef_body():
    msg = format_rfc5424(_event(), host="h", body="cef", procid=1)
    assert msg.split(b"\xef\xbb\xbf", 1)[1].startswith(b"CEF:0|AutoSecOps|")


def test_rfc5424_truncates_details_first_then_hard_cut():
    big = _event(details={"blob": "x" * 5000})
    msg = format_rfc5424(big, host="h", max_bytes=2048, procid=1)
    assert len(msg) <= 2048
    body = json.loads(msg.split(b"\xef\xbb\xbf", 1)[1])
    assert body["details"] == {"_truncated": True}
    huge = _event(message="é" * 3000)
    cut = format_rfc5424(huge, host="h", max_bytes=1000, procid=1)
    assert len(cut) <= 1000
    cut.decode("utf-8")  # never split inside a character


def test_sd_escape():
    assert sd_escape('a"b]c\\') == 'a\\"b\\]c\\\\'


def test_octet_counting_frame():
    assert frame_octet_count(b"hello") == b"5 hello"
    assert frame_octet_count("é".encode()) == b"2 \xc3\xa9"


# -- Redaction ------------------------------------------------------------


JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


def test_redactor_scrubs_secret_keys_values_and_pii():
    r = Redactor()
    ev = _event(
        message=f"login by alice@example.com with {JWT} and sk-ant-api03-SECRETSECRET",
        actor="alice@example.com",
        user_agent=f"curl Bearer {JWT}",
        details={
            "password": "hunter2",
            "new_value": {"api_key": "abc", "nested": {"client_secret": "s"}},
            "mfa_code": "123456",
            "email": "bob@example.com",
            "dsn": "postgres://u:pw@db/x",
            "note": "conn postgresql://admin:hunter2@db:5432/vigil ok",
            "aws": "AKIAABCDEFGHIJKLMNOP",
            "prev_hash": "a" * 64,
            "safe": "nothing to see",
            "count": 3,
        },
    )
    out = r.event(ev)
    dumped = json.dumps(out.to_dict("h"))
    for leaked in (
        "hunter2",
        JWT,
        "SECRETSECRET",
        "alice@example.com",
        "bob@example.com",
        "AKIAABCDEFGHIJKLMNOP",
        "123456",
        "pw@db",
    ):
        assert leaked not in dumped, leaked
    assert out.details["password"] == REDACTED
    assert out.details["new_value"]["api_key"] == REDACTED
    assert out.details["new_value"]["nested"]["client_secret"] == REDACTED
    assert out.details["prev_hash"] == "a" * 64  # ledger hash survives
    assert out.details["safe"] == "nothing to see"
    assert out.details["count"] == 3
    assert r.count >= 8


def test_redactor_pii_off_keeps_emails_but_not_secrets():
    r = Redactor(redact_pii=False)
    out = r.event(
        _event(message=f"alice@example.com {JWT}", details={"email": "e@x.io"})
    )
    assert "alice@example.com" in out.message
    assert JWT not in out.message
    assert out.details["email"] == "e@x.io"


def test_redactor_bounds_depth_size_and_length():
    r = Redactor(max_string=10, max_depth=3, max_items=3)
    deep = {"a": {"b": {"c": {"d": 1}}}}
    out = r.value("", {"deep": deep, "list": [1, 2, 3, 4], "s": "x" * 50})
    assert out["deep"]["a"]["b"] == "[truncated]"
    assert out["list"] == [1, 2, 3, "[truncated]"]
    assert out["s"].endswith("...[truncated]") and len(out["s"]) < 30
