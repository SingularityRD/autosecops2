"""url_safety.refuse_metadata_target: an integration's own server (W0.44).

Private addresses are fine (on-prem firewalls, SIEMs); cloud metadata,
link-local and scoped addresses are not, by literal or by what a name
resolves to.
"""

from __future__ import annotations

import socket

import pytest

from core.platform import url_safety
from core.platform.url_safety import UrlSafetyError, refuse_metadata_target

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "target",
    [
        "10.0.0.5",
        "https://192.168.1.1",
        "https://fw01.corp.example:8443/api",
        "203.0.113.10",
        "https://[2001:db8::1]",
    ],
)
def test_private_and_public_servers_pass(monkeypatch, target):
    real = socket.getaddrinfo

    def fake(host, *a, **k):
        if host == "fw01.corp.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 0))]
        return real(host, *a, **k)

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", fake)
    refuse_metadata_target(target)


@pytest.mark.parametrize(
    "target",
    [
        "169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "100.100.100.200",
        "168.63.129.16",
        "https://[fd00:ec2::254]",
        "https://[::ffff:169.254.169.254]",
        "169.254.1.1",
        "https://[fe80::1]",
    ],
)
def test_metadata_and_link_local_are_refused(target):
    with pytest.raises(UrlSafetyError):
        refuse_metadata_target(target)


def test_a_name_that_resolves_to_metadata_is_refused(monkeypatch):
    monkeypatch.setattr(
        url_safety.socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0)),
        ],
    )
    with pytest.raises(UrlSafetyError, match="cloud metadata"):
        refuse_metadata_target("https://splunk.corp.example")


def test_an_unresolvable_name_is_left_to_the_client(monkeypatch):
    def fail(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", fail)
    refuse_metadata_target("https://nowhere.invalid")


def test_no_host_is_refused():
    with pytest.raises(UrlSafetyError):
        refuse_metadata_target("https://")
