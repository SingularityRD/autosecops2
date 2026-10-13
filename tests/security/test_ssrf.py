"""Regression tests for FIN-005 — SSRF via LLM provider discovery.

Covers the ``core.platform.url_safety.validate_provider_url`` gate that all
provider-discovery / provider-test paths now run through.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))

from core.platform.url_safety import (  # noqa: E402
    DEFAULT_ALLOWED_PROVIDER_HOSTS,
    UrlSafetyError,
    validate_provider_url,
)

pytestmark = pytest.mark.unit


# Every entry must raise UrlSafetyError. Sourced from the disclosure
# plus the standard SSRF playbook.
BLOCKED_URLS = [
    "http://127.0.0.1:11434",
    "http://localhost:11434",
    "http://[::1]:11434",
    "http://0.0.0.0/admin",
    "http://169.254.169.254/latest/meta-data?x=",
    "http://10.0.0.1/admin?x=",
    "http://172.16.0.1/admin?x=",
    "http://192.168.1.1/admin?x=",
    "http://fd00::1/admin",  # private IPv6
    "http://100.64.0.1/admin",  # carrier-grade NAT (not is_private)
    "http://100.100.100.200/latest/meta-data",  # Alibaba Cloud metadata
    "http://198.18.0.1/",  # benchmarking range
    "http://[fd00:ec2::254]/latest/meta-data",  # AWS IMDS over IPv6
    "file:///etc/passwd",
    "gopher://attacker/",
    "ftp://attacker/",
    "http://user:pass@api.openai.com/v1",  # userinfo banned
    "http://api.openai.com/v1#frag",  # fragment banned
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_blocked_url_rejected(url):
    with pytest.raises(UrlSafetyError):
        validate_provider_url(url, allow_custom=True)


def test_allowlisted_host_passes():
    safe = validate_provider_url("https://api.openai.com/v1", allow_custom=False)
    assert safe.is_allowlisted_host
    assert safe.sanitized == "https://api.openai.com/v1"


def test_query_string_stripped():
    """The disclosure showed ``base_url=http://x/foo?proof=`` letting an
    attacker control the path of the final request once the handler
    appended ``/models``. Verify the validator strips the query
    string."""
    safe = validate_provider_url(
        "https://api.openai.com/internal/status?proof=", allow_custom=False
    )
    assert "?" not in safe.sanitized
    assert "proof" not in safe.sanitized
    assert safe.sanitized == "https://api.openai.com/internal/status"


def test_non_allowlisted_requires_allow_custom():
    with pytest.raises(UrlSafetyError):
        validate_provider_url("https://attacker.example/", allow_custom=False)


def test_default_allowed_hosts_includes_openai_anthropic():
    assert "api.openai.com" in DEFAULT_ALLOWED_PROVIDER_HOSTS
    assert "api.anthropic.com" in DEFAULT_ALLOWED_PROVIDER_HOSTS


# An IPv4-mapped IPv6 literal connects as real IPv4 on Linux, so it must
# not slip the metadata block by classifying as a plain private address.
IPV4_MAPPED_METADATA = [
    "http://[::ffff:169.254.169.254]/latest/meta-data",
    "http://[::ffff:a9fe:a9fe]/latest/meta-data",
]


@pytest.mark.parametrize("url", IPV4_MAPPED_METADATA)
def test_ipv4_mapped_metadata_blocked_even_with_loopback(url):
    with pytest.raises(UrlSafetyError):
        validate_provider_url(url, allow_custom=True, allow_loopback=True)


def test_allow_loopback_permits_localhost_but_not_metadata():
    safe = validate_provider_url("http://127.0.0.1:11434", allow_loopback=True)
    assert safe.sanitized == "http://127.0.0.1:11434"
    with pytest.raises(UrlSafetyError):
        validate_provider_url(
            "http://169.254.169.254/latest/meta-data", allow_loopback=True
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://100.100.100.200/latest/meta-data",
        "http://[fd00:ec2::254]/latest/meta-data",
        "http://169.254.170.2/v2/credentials",
    ],
)
def test_metadata_addresses_blocked_even_with_loopback(url):
    with pytest.raises(UrlSafetyError, match="metadata"):
        validate_provider_url(url, allow_loopback=True)


# W3.6 made carrier-grade NAT (100.64.0.0/10) "non-global" and refused. An
# on-prem LLM gateway reached over Tailscale lives there: the operator opts it
# in with LLM_PROVIDER_ALLOWED_CIDRS, and metadata addresses stay refused.
def test_allowed_networks_admit_a_tailscale_gateway_but_not_metadata():
    from core.platform.url_safety import parse_networks

    nets = parse_networks("100.64.0.0/10")
    with pytest.raises(UrlSafetyError):
        validate_provider_url("http://100.101.102.103:8080/v1", allow_custom=True)
    safe = validate_provider_url(
        "http://100.101.102.103:8080/v1", allow_custom=True, allowed_networks=nets
    )
    assert safe.host == "100.101.102.103"
    with pytest.raises(UrlSafetyError):
        validate_provider_url(
            "http://100.100.100.200/latest/meta-data",
            allow_custom=True,
            allowed_networks=nets,
        )


def test_llm_provider_allowed_cidrs_setting_reaches_discovery(monkeypatch):
    from core.config import get_settings
    from core.llm.providers import discovery

    monkeypatch.setenv("LLM_PROVIDER_ALLOWED_CIDRS", "100.64.0.0/10")
    get_settings.cache_clear()
    try:
        nets = discovery.provider_allowed_networks()
        assert [str(n) for n in nets] == ["100.64.0.0/10"]
        monkeypatch.setenv("LLM_PROVIDER_ALLOWED_CIDRS", "100.64.0.0/10,oops")
        get_settings.cache_clear()
        assert discovery.provider_allowed_networks() == ()
    finally:
        get_settings.cache_clear()
