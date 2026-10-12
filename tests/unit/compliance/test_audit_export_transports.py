"""Syslog (TLS/TCP/UDP) and HTTPS transports against local receivers (WP w3.6)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from core.compliance.audit_export import (
    AuditEvent,
    AuditExportConfig,
    DeliveryError,
    HttpDestination,
    HttpTransport,
    SyslogDestination,
    SyslogTransport,
    secret_name,
)

from .conftest import HttpReceiver, SyslogReceiver, UdpReceiver

pytestmark = pytest.mark.unit


def _ev(n: int = 1, **kw) -> AuditEvent:
    base = dict(
        id=f"test:{n}",
        source="config",
        category="configuration",
        action="config.update",
        outcome="success",
        severity=5,
        timestamp=datetime(2026, 10, 12, tzinfo=timezone.utc),
        message=f"event {n}",
    )
    base.update(kw)
    return AuditEvent(**base)


def _no_secrets(_name):
    return None


def _syslog(port, **kw) -> SyslogDestination:
    return SyslogDestination(
        type="syslog", name="siem", host="127.0.0.1", port=port, timeout_s=5, **kw
    )


# -- syslog over TLS ------------------------------------------------------


async def test_tls_syslog_delivers_with_custom_ca(pki):
    rx = await SyslogReceiver(pki.server_context()).start()
    tx = SyslogTransport(_syslog(rx.port, ca_pem=pki.ca_pem), _no_secrets, "soc")
    try:
        await tx.send([_ev(1), _ev(2, message="line\nbreak")])
        await rx.wait_for(2)
    finally:
        await tx.close()
        await rx.stop()
    assert all(m.startswith(b"<") and b"autosecops@32473" in m for m in rx.messages)
    bodies = [json.loads(m.split(b"\xef\xbb\xbf", 1)[1]) for m in rx.messages]
    assert [b["id"] for b in bodies] == ["test:1", "test:2"]
    assert bodies[1]["message"] == "line\nbreak"


async def test_tls_syslog_rejects_untrusted_server(pki, other_pki):
    """Verification is on by default: a certificate from a CA we were not
    told to trust (or the system store) is a delivery failure, not a send."""
    rx = await SyslogReceiver(pki.server_context()).start()
    try:
        default = SyslogTransport(_syslog(rx.port), _no_secrets, "soc")
        with pytest.raises(DeliveryError) as exc:
            await default.send([_ev()])
        assert exc.value.reason == "tls_handshake_failed"
        await default.close()

        wrong_ca = SyslogTransport(
            _syslog(rx.port, ca_pem=other_pki.ca_pem), _no_secrets, "soc"
        )
        with pytest.raises(DeliveryError):
            await wrong_ca.send([_ev()])
        await wrong_ca.close()
        assert rx.messages == []
    finally:
        await rx.stop()


def test_tls_is_the_default_protocol_and_verify_is_on():
    dest = SyslogDestination(type="syslog", name="s", host="siem.example")
    assert dest.protocol == "tls" and dest.tls_verify is True and dest.port == 6514
    http = HttpDestination(type="http", name="h", url="https://siem.example/in")
    assert http.tls_verify is True


async def test_tls_verify_off_is_explicit_and_works(pki):
    rx = await SyslogReceiver(pki.server_context()).start()
    tx = SyslogTransport(_syslog(rx.port, tls_verify=False), _no_secrets, "soc")
    try:
        await tx.send([_ev()])
        await rx.wait_for(1)
    finally:
        await tx.close()
        await rx.stop()


async def test_tcp_syslog_reconnects_after_receiver_restart():
    rx = await SyslogReceiver().start()
    port = rx.port
    tx = SyslogTransport(_syslog(port, protocol="tcp"), _no_secrets, "soc")
    try:
        await tx.send([_ev(1)])
        await rx.wait_for(1)
        await rx.stop()
        with pytest.raises(DeliveryError):
            for _ in range(5):  # the closed link is noticed within a few sends
                await tx.send([_ev(2)])
        rx2 = await SyslogReceiver().start(port)
        try:
            await tx.send([_ev(3)])
            await rx2.wait_for(1)
            assert b"test:3" in rx2.messages[0]
        finally:
            await rx2.stop()
    finally:
        await tx.close()


async def test_connect_refused_is_a_delivery_error():
    rx = await SyslogReceiver().start()
    port = rx.port
    await rx.stop()
    tx = SyslogTransport(_syslog(port, protocol="tcp"), _no_secrets, "soc")
    with pytest.raises(DeliveryError) as exc:
        await tx.send([_ev()])
    assert exc.value.reason == "connect_failed"
    await tx.close()


async def test_udp_syslog_one_datagram_per_event():
    rx = await UdpReceiver().start()
    tx = SyslogTransport(
        _syslog(rx.port, protocol="udp", format="cef"), _no_secrets, "h"
    )
    try:
        await tx.send([_ev(1), _ev(2)])
        import asyncio

        for _ in range(50):
            if len(rx.messages) == 2:
                break
            await asyncio.sleep(0.02)
    finally:
        rx.stop()
    assert len(rx.messages) == 2
    assert b"CEF:0|AutoSecOps|" in rx.messages[0]
    assert not rx.messages[0][:6].isdigit()  # UDP is not octet-counted


# -- HTTP -----------------------------------------------------------------


def _http(url, **kw) -> HttpDestination:
    return HttpDestination(type="http", name="hec", url=url, timeout_s=5, **kw)


async def test_https_json_with_token_and_custom_ca(pki):
    rx = HttpReceiver(pki.server_context()).start()
    secrets = {secret_name("hec", "TOKEN"): "tok-123"}
    tx = HttpTransport(
        _http(f"https://127.0.0.1:{rx.port}/ingest", ca_pem=pki.ca_pem),
        secrets.get,
        "soc",
    )
    try:
        await tx.send([_ev(1), _ev(2)])
    finally:
        await tx.close()
        rx.stop()
    (req,) = rx.requests
    assert req["path"] == "/ingest"
    assert req["headers"]["Authorization"] == "Bearer tok-123"
    assert req["headers"]["Content-Type"] == "application/json"
    assert [e["id"] for e in json.loads(req["body"])] == ["test:1", "test:2"]


async def test_https_rejects_untrusted_server(pki):
    rx = HttpReceiver(pki.server_context()).start()
    tx = HttpTransport(_http(f"https://127.0.0.1:{rx.port}/"), _no_secrets, "soc")
    try:
        with pytest.raises(DeliveryError) as exc:
            await tx.send([_ev()])
        assert exc.value.reason == "tls_handshake_failed"
    finally:
        await tx.close()
        rx.stop()
    assert rx.requests == []


async def test_http_cef_lines_and_custom_auth_header():
    rx = HttpReceiver().start()
    secrets = {secret_name("hec", "TOKEN"): "abc"}
    tx = HttpTransport(
        _http(
            f"http://127.0.0.1:{rx.port}/cef",
            allow_plaintext=True,
            format="cef",
            auth_header="X-Api-Key",
            auth_scheme="",
        ),
        secrets.get,
        "soc",
    )
    try:
        await tx.send([_ev(1), _ev(2)])
    finally:
        await tx.close()
        rx.stop()
    (req,) = rx.requests
    assert req["headers"]["X-Api-Key"] == "abc"
    lines = req["body"].decode().strip().split("\n")
    assert len(lines) == 2 and all(line.startswith("CEF:0|") for line in lines)


async def test_http_status_codes_map_to_retry_or_split():
    rx = HttpReceiver(statuses=[503, 413]).start()
    tx = HttpTransport(
        _http(f"http://127.0.0.1:{rx.port}/", allow_plaintext=True), _no_secrets, "s"
    )
    try:
        with pytest.raises(DeliveryError) as exc:
            await tx.send([_ev()])
        assert exc.value.reason == "http_503"
        with pytest.raises(DeliveryError) as exc:
            await tx.send([_ev()])
        assert exc.value.reason == "batch_too_large"
        await tx.send([_ev()])
    finally:
        await tx.close()
        rx.stop()
    assert len(rx.requests) == 1


# -- config validation ----------------------------------------------------


@pytest.mark.parametrize(
    "dest",
    [
        {"type": "http", "name": "a", "url": "http://siem.example/"},  # plaintext
        {"type": "http", "name": "a", "url": "https://u:p@siem.example/"},
        {"type": "http", "name": "a", "url": "https://169.254.169.254/latest"},
        {"type": "http", "name": "a", "url": "ftp://siem.example/"},
        {"type": "syslog", "name": "a", "host": "metadata.google.internal"},
        {"type": "syslog", "name": "a", "host": "0.0.0.0"},
        {"type": "syslog", "name": "A B", "host": "siem.example"},
        {"type": "syslog", "name": "a", "host": "siem.example", "ca_pem": "nope"},
        {"type": "syslog", "name": "a", "host": "h", "token": "x"},  # no extra keys
    ],
)
def test_bad_destinations_are_refused(dest):
    with pytest.raises(ValidationError):
        AuditExportConfig.model_validate({"destinations": [dest]})


def test_enabled_needs_a_destination_and_names_are_unique():
    with pytest.raises(ValidationError):
        AuditExportConfig.model_validate({"enabled": True})
    d = {"type": "syslog", "name": "a", "host": "siem.example"}
    with pytest.raises(ValidationError):
        AuditExportConfig.model_validate({"destinations": [d, d]})


def test_secret_names_derive_from_the_destination():
    assert secret_name("splunk-hec", "TOKEN") == "AUDIT_EXPORT_SPLUNK_HEC_TOKEN"
    assert secret_name("qr", "CLIENT_KEY") == "AUDIT_EXPORT_QR_CLIENT_KEY"
