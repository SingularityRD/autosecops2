"""Outbound webhooks without a database: signing, retry policy, SSRF, sending.

The sending tests go over a real socket to a local receiver; the SSRF tests fake
DNS (``socket.getaddrinfo``) so a public-looking name can answer with an
internal address.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest

from core.integrations import outbound_webhooks as hooks
from core.platform import url_safety
from core.platform.url_safety import (
    UnresolvableHostError,
    UrlSafetyError,
    parse_networks,
    resolve_allowed_addresses,
)
from tests.unit.integrations._webhook_receiver import start_receiver

pytestmark = pytest.mark.unit

SECRET = "whsec_test_secret_value_0123456789"
LOOPBACK = parse_networks("127.0.0.1/32")


@pytest.fixture
def receiver():
    r = start_receiver()
    yield r
    r.close()


def _fake_dns(monkeypatch, answers):
    """Make getaddrinfo answer ``answers[host]`` and count the lookups."""
    calls = []

    def getaddrinfo(host, port, *args, **kwargs):
        calls.append(host)
        if host not in answers:
            raise socket.gaierror("no such host")
        out = []
        for addr in answers[host]:
            family = socket.AF_INET6 if ":" in addr else socket.AF_INET
            out.append((family, socket.SOCK_STREAM, 6, "", (addr, port or 0)))
        return out

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", getaddrinfo)
    return calls


# --- signing -------------------------------------------------------------------


def test_signature_round_trips_and_binds_body_secret_and_time():
    body = b'{"id":"e1"}'
    header = hooks.signature_header(SECRET, body, 1_700_000_000)

    assert header.startswith("t=1700000000,v1=")
    assert hooks.verify_signature(SECRET, header, body, now=1_700_000_010)
    # tampered body, wrong secret, missing header
    assert not hooks.verify_signature(SECRET, header, body + b" ", now=1_700_000_010)
    assert not hooks.verify_signature("other" * 8, header, body, now=1_700_000_010)
    assert not hooks.verify_signature(SECRET, None, body, now=1_700_000_010)
    assert not hooks.verify_signature(SECRET, "garbage", body, now=1_700_000_010)


def test_signature_outside_the_tolerance_window_is_a_replay():
    body = b"{}"
    header = hooks.signature_header(SECRET, body, 1_700_000_000)

    assert hooks.verify_signature(SECRET, header, body, now=1_700_000_300)
    assert not hooks.verify_signature(SECRET, header, body, now=1_700_000_301)
    assert not hooks.verify_signature(SECRET, header, body, now=1_699_999_699)


def test_signature_is_over_timestamp_and_body_so_the_timestamp_cannot_be_moved():
    body = b"{}"
    header = hooks.signature_header(SECRET, body, 1_700_000_000)
    moved = header.replace("t=1700000000", "t=1700000500")

    assert not hooks.verify_signature(SECRET, moved, body, now=1_700_000_500)


def test_any_of_several_v1_signatures_may_match_for_secret_rotation():
    body = b"{}"
    good = hooks.compute_signature(SECRET, body, 1_700_000_000)
    header = f"t=1700000000,v1={'0' * 64},v1={good}"

    assert hooks.verify_signature(SECRET, header, body, now=1_700_000_000)


def test_body_encoding_is_deterministic():
    a = hooks.encode_body({"b": 1, "a": {"y": 2, "x": 1}})
    b = hooks.encode_body({"a": {"x": 1, "y": 2}, "b": 1})
    assert a == b == b'{"a":{"x":1,"y":2},"b":1}'


# --- retry policy --------------------------------------------------------------


def test_backoff_doubles_from_thirty_seconds_and_caps_at_an_hour():
    assert [hooks.backoff_seconds(n) for n in range(1, 9)] == [
        30,
        60,
        120,
        240,
        480,
        960,
        1920,
        3600,
    ]
    assert hooks.backoff_seconds(50) == 3600


@pytest.mark.parametrize(
    "status,outcome",
    [
        (200, "delivered"),
        (204, "delivered"),
        (500, "retry"),
        (503, "retry"),
        (408, "retry"),
        (429, "retry"),
        (400, "failed"),
        (401, "failed"),
        (404, "failed"),
        (410, "failed"),
        (301, "failed"),
        (302, "failed"),
    ],
)
def test_status_classification(status, outcome):
    assert hooks.classify_status(status).outcome == outcome


# --- url and SSRF checks ---------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://example.com/hook",
        "file:///etc/passwd",
        "gopher://example.com/",
        "http:///nohost",
        "https://user:pass@example.com/hook",
        "https://example.com/hook#frag",
        "https://example.com:99999/hook",
        "https://example.com/" + "a" * 3000,
    ],
)
def test_bad_urls_are_refused(url):
    with pytest.raises(hooks.WebhookError):
        hooks.validate_url(url)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.5.4",
        "192.168.0.10",
        "169.254.169.254",
        "169.254.10.10",
        "0.0.0.0",
        "::1",
        "fd00::5",
        "fe80::1",
        "::ffff:10.0.0.1",
        "fd00:ec2::254",
    ],
)
def test_internal_answers_are_refused(monkeypatch, address):
    _fake_dns(monkeypatch, {"hooks.example.com": [address]})

    with pytest.raises(UrlSafetyError):
        resolve_allowed_addresses("hooks.example.com", 443)


def test_one_internal_address_in_the_answer_refuses_the_host(monkeypatch):
    _fake_dns(monkeypatch, {"hooks.example.com": ["93.184.216.34", "10.0.0.7"]})

    with pytest.raises(UrlSafetyError):
        resolve_allowed_addresses("hooks.example.com", 443)


def test_public_answers_pass(monkeypatch):
    _fake_dns(monkeypatch, {"hooks.example.com": ["93.184.216.34"]})

    assert resolve_allowed_addresses("hooks.example.com", 443) == ["93.184.216.34"]


def test_an_admin_allowed_network_opens_a_private_range(monkeypatch):
    _fake_dns(monkeypatch, {"hooks.corp": ["10.20.1.5"]})
    allowed = parse_networks("10.20.0.0/16")

    assert resolve_allowed_addresses("hooks.corp", 443, allowed_networks=allowed) == [
        "10.20.1.5"
    ]
    _fake_dns(monkeypatch, {"hooks.corp": ["10.21.1.5"]})
    with pytest.raises(UrlSafetyError):
        resolve_allowed_addresses("hooks.corp", 443, allowed_networks=allowed)


def test_the_metadata_address_stays_refused_even_inside_an_allowed_network(
    monkeypatch,
):
    _fake_dns(monkeypatch, {"meta.example": ["169.254.169.254"]})

    with pytest.raises(UrlSafetyError, match="metadata"):
        resolve_allowed_addresses(
            "meta.example", 80, allowed_networks=parse_networks("169.254.0.0/16")
        )


def test_unresolvable_is_its_own_transient_error(monkeypatch):
    _fake_dns(monkeypatch, {})

    with pytest.raises(UnresolvableHostError):
        resolve_allowed_addresses("nowhere.example", 443)


def test_parse_networks_rejects_garbage():
    assert parse_networks("") == ()
    assert parse_networks(" 10.0.0.0/8 , ::1/128 ") == (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    )
    with pytest.raises(ValueError):
        parse_networks("10.0.0.0/8,not-a-network")


def test_malformed_allowed_cidrs_setting_allows_nothing(monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_CIDRS", "10.0.0.0/8,oops")
    assert hooks.configured_networks() == ()


@pytest.mark.asyncio
async def test_pinned_resolver_answers_only_for_its_host():
    resolver = hooks.PinnedResolver("hooks.example.com", ["93.184.216.34"])

    answer = await resolver.resolve("hooks.example.com", 443)
    assert [a["host"] for a in answer] == ["93.184.216.34"]
    with pytest.raises(OSError):
        await resolver.resolve("elsewhere.example", 443)


# --- sending over a real socket ----------------------------------------------------


def _send_kwargs(**over):
    kwargs = dict(
        secret=SECRET,
        event_type="case.sla_warning",
        event_id="sla:c1:response:90",
        delivery_id="42",
        payload={"id": "sla:c1:response:90", "type": "case.sla_warning", "data": {}},
    )
    kwargs.update(over)
    return kwargs


@pytest.mark.asyncio
async def test_loopback_receiver_is_refused_without_an_allowed_network(receiver):
    result = await hooks.send_signed(
        receiver.url(), allowed_networks=(), **_send_kwargs()
    )

    assert result.outcome == "failed"
    assert "target refused" in result.error
    assert receiver.requests == []


@pytest.mark.asyncio
async def test_signed_delivery_reaches_an_allowed_receiver(receiver):
    result = await hooks.send_signed(
        receiver.url(), allowed_networks=LOOPBACK, **_send_kwargs()
    )

    assert result.delivered and result.status_code == 200
    [request] = receiver.requests
    assert request.headers["X-AutoSecOps-Event"] == "case.sla_warning"
    assert request.headers["X-AutoSecOps-Event-Id"] == "sla:c1:response:90"
    assert request.headers["X-AutoSecOps-Delivery"] == "42"
    assert request.headers["User-Agent"] == hooks.USER_AGENT
    assert request.body == hooks.encode_body(_send_kwargs()["payload"])
    assert hooks.verify_signature(
        SECRET, request.headers["X-AutoSecOps-Signature"], request.body
    )


@pytest.mark.asyncio
async def test_connection_is_pinned_to_the_checked_address(monkeypatch, receiver):
    """A name is resolved once, checked, and the socket goes to that address.

    The receiver sees the original Host header, and DNS is asked exactly once:
    a rebinding answer on a second lookup has nowhere to go.
    """
    calls = _fake_dns(monkeypatch, {"hooks.allowed.test": ["127.0.0.1"]})

    result = await hooks.send_signed(
        receiver.url(host="hooks.allowed.test"),
        allowed_networks=LOOPBACK,
        **_send_kwargs(),
    )

    assert result.delivered
    assert calls == ["hooks.allowed.test"]
    assert receiver.requests[0].headers["Host"] == f"hooks.allowed.test:{receiver.port}"


@pytest.mark.asyncio
async def test_rebinding_to_an_internal_address_is_refused(monkeypatch, receiver):
    _fake_dns(monkeypatch, {"rebind.example.com": ["127.0.0.1"]})

    result = await hooks.send_signed(
        receiver.url(host="rebind.example.com"), allowed_networks=(), **_send_kwargs()
    )

    assert result.outcome == "failed"
    assert receiver.requests == []


@pytest.mark.asyncio
async def test_redirects_are_not_followed(receiver):
    other = start_receiver()
    try:
        receiver.statuses = [302]
        receiver.headers_out = {"Location": other.url()}
        result = await hooks.send_signed(
            receiver.url(), allowed_networks=LOOPBACK, **_send_kwargs()
        )
    finally:
        other.close()

    assert result.outcome == "failed" and result.status_code == 302
    assert other.requests == []


@pytest.mark.asyncio
async def test_server_errors_and_refused_connections_are_retried(receiver):
    receiver.statuses = [503]
    busy = await hooks.send_signed(
        receiver.url(), allowed_networks=LOOPBACK, **_send_kwargs()
    )
    port = receiver.port
    receiver.close()
    down = await hooks.send_signed(
        f"http://127.0.0.1:{port}/hook", allowed_networks=LOOPBACK, **_send_kwargs()
    )

    assert busy.outcome == "retry" and busy.status_code == 503
    assert down.outcome == "retry" and down.error.startswith("connection failed")


@pytest.mark.asyncio
async def test_unresolvable_host_is_retried_not_failed(monkeypatch):
    _fake_dns(monkeypatch, {})

    result = await hooks.send_signed(
        "https://gone.example.com/hook", allowed_networks=(), **_send_kwargs()
    )

    assert result.outcome == "retry"


@pytest.mark.asyncio
async def test_sender_refuses_to_send_unsigned(receiver, monkeypatch):
    monkeypatch.setattr(hooks, "get_secret", lambda key: None)
    sender = hooks.WebhookSender(allowed_networks=LOOPBACK)

    result = await sender.attempt(
        {
            "id": 1,
            "url": receiver.url(),
            "secret_ref": "WEBHOOK_SECRET_X",
            "endpoint_enabled": True,
            "event_type": "case.sla_warning",
            "event_id": "e",
            "payload": {},
        }
    )

    assert result.outcome == "failed" and result.error == "signing secret missing"
    assert receiver.requests == []


@pytest.mark.asyncio
async def test_sender_does_not_send_to_a_disabled_endpoint(receiver):
    sender = hooks.WebhookSender(allowed_networks=LOOPBACK)

    result = await sender.attempt({"id": 1, "endpoint_enabled": False})

    assert result.outcome == "failed" and result.error == "endpoint disabled"
    assert receiver.requests == []


def test_event_types_are_validated():
    assert hooks.validate_event_types(["case.stale_case", "case.sla_warning"]) == [
        "case.sla_warning",
        "case.stale_case",
    ]
    with pytest.raises(hooks.WebhookError, match="case.typo"):
        hooks.validate_event_types(["case.typo"])


def test_public_endpoint_hides_the_secret_reference():
    out = hooks.public_endpoint({"id": "x", "secret_ref": "WEBHOOK_SECRET_X"})
    assert out == {"id": "x", "has_secret": True}
