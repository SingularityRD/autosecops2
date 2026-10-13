"""W4.3: SSRF regression matrix across every url_safety entry point.

The product funnels operator-supplied URLs through
``core.platform.url_safety`` at two live egress surfaces:

* **LLM provider discovery** (``core/llm/providers/discovery.py``) —
  ``validate_provider_url`` gates the Anthropic/OpenAI/Ollama ``base_url``;
* **outbound webhooks** (``core/integrations/outbound_webhooks.py``) —
  ``resolve_allowed_addresses`` / ``resolve_target`` gates every delivery, and
  the request is then pinned to the checked addresses.

This file drives *both* with one SSRF payload corpus — the standard playbook:
cloud-metadata IPs, decimal/hex/octal/mixed IPv4 encodings, IPv4-mapped IPv6,
loopback/private/link-local literals, a DNS-rebinding answer (public + private
in one resolution), and dangerous schemes. Each must be refused. It then pins
the two protections the address check cannot provide on its own: redirects are
not followed, and a rebinding second answer cannot move the connection.

Outbound URL inputs that do **not** go through ``url_safety`` are listed in
``UNGUARDED_OUTBOUND`` below (findings F-3 in
docs/security/w4.3-redteam-findings.md). Where such a surface has a weaker
check of its own (stored LLM ``base_url`` shape check, the Bifrost stock-host
comparison), that check is driven here too, and the gap it leaves -- the
metadata address passes -- is pinned so a real fix is noticed.

Resolution is stubbed (``_FakeGetaddrinfo``) so the suite is deterministic and
makes no network call; numeric-literal IPs are left to resolve locally (pure
parsing, no DNS).
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from core.platform import url_safety as us  # noqa: E402
from core.platform.url_safety import (  # noqa: E402
    UrlSafetyError,
    resolve_allowed_addresses,
    validate_provider_url,
)

pytestmark = pytest.mark.unit


# Hostnames the stubbed resolver answers for. Numeric IP literals are NOT listed
# here — they are parsed locally by getaddrinfo without a lookup, which is the
# real behaviour we want to exercise.
_STUB_DNS = {
    "metadata.attacker.test": ["169.254.169.254"],
    "loopback.attacker.test": ["127.0.0.1"],
    "internal.attacker.test": ["10.1.2.3"],
    "linklocal.attacker.test": ["169.254.0.17"],
    # DNS rebinding: one answer carries a public AND an internal address.
    "rebind.attacker.test": ["93.184.216.34", "10.0.0.5"],
    # A legitimate public host, to prove the guard is not a blanket deny.
    "public.ok.test": ["93.184.216.34"],
}


class _FakeGetaddrinfo:
    """socket.getaddrinfo stand-in: table for known hosts, real parse for literals."""

    def __init__(self, real):
        self._real = real

    def __call__(self, host, port, *args, **kwargs):
        if host in _STUB_DNS:
            fam = socket.AF_INET
            return [
                (fam, socket.SOCK_STREAM, 0, "", (addr, port or 0))
                for addr in _STUB_DNS[host]
            ]
        # Numeric literals (decimal/hex/octal/mapped) resolve locally.
        return self._real(host, port, *args, **kwargs)


@pytest.fixture(autouse=True)
def _stub_resolver(monkeypatch):
    monkeypatch.setattr(us.socket, "getaddrinfo", _FakeGetaddrinfo(socket.getaddrinfo))


# Payload -> short reason. Every one must be refused by both entry points.
BLOCKED = {
    # cloud metadata, several encodings
    "http://169.254.169.254/latest/meta-data/": "metadata literal",
    "http://metadata.attacker.test/": "metadata via DNS",
    "http://[::ffff:169.254.169.254]/": "metadata IPv4-mapped IPv6",
    "http://[::ffff:a9fe:a9fe]/": "metadata IPv4-mapped IPv6 hex",
    "http://2852039166/": "metadata as decimal (169.254.169.254)",
    # loopback / private / link-local, literal and via DNS
    "http://127.0.0.1:11434/": "loopback literal",
    "http://loopback.attacker.test/": "loopback via DNS",
    "http://2130706433/": "loopback as decimal",
    "http://0x7f000001/": "loopback as hex",
    "http://017700000001/": "loopback as octal",
    "http://[::1]/": "loopback IPv6",
    "http://10.1.2.3/": "private literal",
    "http://internal.attacker.test/": "private via DNS",
    "http://192.168.0.1/": "private literal",
    "http://172.16.9.9/": "private literal",
    "http://169.254.0.17/": "link-local literal",
    "http://linklocal.attacker.test/": "link-local via DNS",
    "http://0.0.0.0/": "unspecified",
    # DNS rebinding: a public + internal multi-answer must be refused whole.
    "http://rebind.attacker.test/": "DNS rebinding (public+private answer)",
    # dangerous schemes / malformed
    "file:///etc/passwd": "file scheme",
    "gopher://attacker.test/": "gopher scheme",
    "ftp://attacker.test/": "ftp scheme",
    "http://user:pass@public.ok.test/": "embedded credentials",
    "http://public.ok.test/#frag": "fragment",
}


def _provider_entry(url: str) -> None:
    # allow_loopback=True is the self-hosted-provider path; metadata and the
    # non-loopback blocks must still hold, so we assert the strongest config.
    validate_provider_url(url, allow_custom=True, allow_loopback=False)


def _webhook_entry(url: str) -> None:
    from urllib.parse import urlsplit

    from core.integrations.outbound_webhooks import validate_url

    parts = urlsplit(validate_url(url))
    port = parts.port or (443 if parts.scheme == "https" else 80)
    resolve_allowed_addresses(parts.hostname, port, allowed_networks=())


ENTRY_POINTS = {
    "provider_discovery": _provider_entry,
    "outbound_webhook": _webhook_entry,
}


@pytest.mark.parametrize("entry", ENTRY_POINTS, ids=list(ENTRY_POINTS))
@pytest.mark.parametrize("url", list(BLOCKED), ids=[BLOCKED[u] for u in BLOCKED])
def test_ssrf_payload_refused(entry, url):
    from core.integrations.outbound_webhooks import WebhookError

    fn = ENTRY_POINTS[entry]
    # UrlSafetyError: refused address/scheme. WebhookError: the webhook path's
    # own scheme/credential/fragment check, which fires before DNS. Either is a
    # refusal; the point is that no usable SSRF address is ever returned.
    with pytest.raises((UrlSafetyError, WebhookError)):
        fn(url)


@pytest.mark.parametrize("entry", ENTRY_POINTS, ids=list(ENTRY_POINTS))
def test_public_host_allowed(entry):
    """The guard is not a blanket deny: a plain public host passes both."""
    ENTRY_POINTS[entry]("https://public.ok.test/v1")


def test_metadata_blocked_even_with_allow_loopback():
    """A self-hosted provider may use loopback, but never the metadata IP."""
    validate_provider_url("http://127.0.0.1:11434", allow_loopback=True)  # ok
    for bad in (
        "http://169.254.169.254/latest/meta-data",
        "http://[::ffff:169.254.169.254]/",
        "http://metadata.attacker.test/",
    ):
        with pytest.raises(UrlSafetyError):
            validate_provider_url(bad, allow_custom=True, allow_loopback=True)


def test_rebinding_refused_whole_answer():
    """resolve_allowed_addresses refuses a host the moment one answer is internal,
    so the later-used address set can never include the private one."""
    with pytest.raises(UrlSafetyError):
        resolve_allowed_addresses("rebind.attacker.test", 443, allowed_networks=())


# --- redirects are not followed at either surface ----------------------------


def test_webhook_treats_redirects_as_permanent_failure():
    from core.integrations.outbound_webhooks import FAILED, classify_status

    for code in (301, 302, 303, 307, 308):
        res = classify_status(code)
        assert res.outcome == FAILED
        assert "redirect" in (res.error or "").lower()


def test_webhook_sender_disables_redirects_and_proxy_env():
    """The one request the webhook path makes pins redirects/proxy off."""
    src = (REPO / "core" / "integrations" / "outbound_webhooks.py").read_text()
    assert "allow_redirects=False" in src
    assert "trust_env=False" in src
    assert "PinnedResolver" in src


def test_provider_discovery_disables_redirects():
    """Every httpx client in discovery is built with follow_redirects=False, so a
    30x from a validated public host can't bounce the request to an internal one."""
    src = (REPO / "core" / "llm" / "providers" / "discovery.py").read_text()
    assert "follow_redirects=False" in src
    assert "follow_redirects=True" not in src
    # No client is constructed without the flag.
    import re

    clients = re.findall(r"httpx\.AsyncClient\(([^)]*)\)", src, re.S)
    assert clients, "expected httpx.AsyncClient usage in discovery.py"
    for args in clients:
        assert "follow_redirects=False" in args, args


# --- surfaces outside url_safety (round-5 coverage) --------------------------

# (file, outbound input, what guards it today). Each is a finding (F-3): the
# URL reaches httpx/requests with no address check. The test below fails when a
# file starts using url_safety, so the entry moves into ENTRY_POINTS above.
UNGUARDED_OUTBOUND = {
    "services/api/routers/jira_export.py": (
        "stored Jira url; POST /api/cases/{id}/export/jira (cases.read) posts to "
        "it with follow_redirects=True"
    ),
    "core/integrations/splunk/client.py": "stored Splunk server_url",
    "core/integrations/elastic/client.py": "stored Elasticsearch/Kibana url",
    "core/integrations/opensearch/client.py": "stored OpenSearch/Dashboards url",
    "core/integrations/crowdstrike/client.py": "stored CrowdStrike base_url",
    "core/integrations/vstrike/client.py": "stored/env VStrike base_url",
    "core/integrations/palo_alto/client.py": "stored PAN-OS hostname (base_url_for)",
    "services/api/routers/llm_providers.py": (
        "stored LLM base_url: shape check only (scheme/userinfo/fragment); the "
        "address is checked at discovery time, not when Bifrost uses it"
    ),
    "core/llm/bifrost/admin.py": (
        "custom OpenAI-compatible base_url pushed to Bifrost network_config; only "
        "compared against the stock OpenAI hosts, ollama sync skips the IP gate"
    ),
}


@pytest.mark.parametrize("path", sorted(UNGUARDED_OUTBOUND))
def test_unguarded_outbound_inventory_is_current(path):
    src = (REPO / path).read_text()
    assert "validate_provider_url" not in src and "resolve_allowed_addresses" not in src, (
        f"{path} now calls url_safety: move it from UNGUARDED_OUTBOUND into "
        "ENTRY_POINTS and drive it with the payload corpus"
    )


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "ftp://internal.attacker.test/",
        "javascript:alert(1)",
        "http://user:pw@public.ok.test/",
        "http://public.ok.test/#frag",
        "http:///nohost",
    ],
)
def test_stored_llm_base_url_shape_check_rejects(url):
    from fastapi import HTTPException

    from services.api.routers.llm_providers import _validate_provider_base_url_shape

    with pytest.raises(HTTPException) as exc:
        _validate_provider_base_url_shape(url)
    assert exc.value.status_code == 400


def test_stored_llm_base_url_shape_check_does_not_block_metadata():
    """Pins finding F-3: the save-time check is shape-only by design (self-hosted
    Ollama on RFC1918 is legitimate), so the metadata address is stored. When a
    fix makes this raise, flip the assertion and drop the entry from
    UNGUARDED_OUTBOUND."""
    from services.api.routers.llm_providers import _validate_provider_base_url_shape

    _validate_provider_base_url_shape("http://169.254.169.254/latest")


def test_bifrost_never_overrides_the_stock_openai_host():
    from core.llm.bifrost.admin import _STOCK_OPENAI_HOSTS, _custom_openai_base_url

    assert _STOCK_OPENAI_HOSTS
    for host in _STOCK_OPENAI_HOSTS:
        assert _custom_openai_base_url(f"https://{host}/v1") is None
    assert _custom_openai_base_url("https://llm.corp.test/v1") == "https://llm.corp.test"


def test_bifrost_custom_base_url_has_no_address_check():
    """Pins finding F-3: a stored custom base_url pointing at the metadata
    address is handed to Bifrost unchanged."""
    from core.llm.bifrost.admin import _custom_openai_base_url

    assert _custom_openai_base_url("http://169.254.169.254/v1") == "http://169.254.169.254"
