"""check_credentials reads the saved URL and credentials, read-only, per integration."""

from __future__ import annotations

import pytest

from core.integrations import credential_check

pytestmark = pytest.mark.unit


def _resolved(monkeypatch, **fields):
    monkeypatch.setattr(credential_check, "resolve", lambda descriptor: fields)


async def test_integration_without_a_check_is_left_to_the_mcp_probe():
    assert await credential_check.check_credentials("virustotal") is None


async def test_splunk_without_a_password_says_what_is_missing(monkeypatch):
    _resolved(monkeypatch, server_url="https://s:8089", username="u", password=None)

    assert await credential_check.check_credentials("splunk") == (
        False,
        "Missing password",
    )


async def test_splunk_reports_what_the_login_said(monkeypatch):
    _resolved(
        monkeypatch,
        server_url="https://s:8089",
        username="u",
        password="wrong",
        verify_ssl=True,
        ca_cert_path=None,
    )
    seen = {}

    def test_connection(self):
        seen["url"], seen["password"] = self.server_url, self.password
        return False, "Authentication failed"

    monkeypatch.setattr(
        "core.integrations.splunk.client.SplunkService.test_connection",
        test_connection,
    )

    assert await credential_check.check_credentials("splunk") == (
        False,
        "Authentication failed",
    )
    assert seen == {"url": "https://s:8089", "password": "wrong"}


async def test_elastic_without_a_url_says_so(monkeypatch):
    _resolved(monkeypatch, elasticsearch_url=None)

    assert await credential_check.check_credentials("elastic-siem") == (
        False,
        "Missing elasticsearch_url",
    )


async def test_elastic_unreachable_url_fails_with_the_connection_error(monkeypatch):
    # nothing listens on port 1: a real refused connection, no mock of the client
    _resolved(
        monkeypatch,
        elasticsearch_url="http://127.0.0.1:1",
        api_key="not-a-key",
        verify_ssl=None,
    )

    ok, message = await credential_check.check_credentials("elastic-siem")

    assert ok is False
    assert message


async def test_a_check_that_blows_up_is_a_failure_that_names_no_value(monkeypatch):
    async def boom():
        raise RuntimeError("http://user:hunter2@host")

    monkeypatch.setitem(credential_check._CHECKS, "splunk", boom)

    assert await credential_check.check_credentials("splunk") == (
        False,
        "Could not check the connection (RuntimeError)",
    )


# ----------------------------------------------- response executors (W0.37)

_ENTRA_SECRET = "entra-secret-not-real"
_PAN_KEY = "pan-key-not-real"


@pytest.fixture()
def nothing_stored(monkeypatch):
    monkeypatch.setattr(credential_check, "_stored", lambda integration_id: {})


@pytest.fixture()
def offline(monkeypatch):
    """No route to Entra ID: the token request raises as it does with no network."""
    import httpx

    def refuse(*args, **kwargs):
        raise httpx.ConnectError("[Errno -3] Temporary failure in name resolution")

    monkeypatch.setattr("core.integrations._base.aad_token.httpx.post", refuse)


@pytest.mark.parametrize(
    "integration_id", ["microsoft-defender", "azure-ad", "palo-alto", "fortigate"]
)
async def test_every_executor_has_a_check(integration_id):
    assert integration_id in credential_check._CHECKS


@pytest.mark.parametrize("integration_id", ["microsoft-defender", "azure-ad"])
async def test_entra_backed_executor_without_a_secret_says_what_is_missing(
    monkeypatch, nothing_stored, integration_id
):
    _resolved(monkeypatch, tenant_id="t", client_id="c", client_secret=None)

    assert await credential_check.check_credentials(integration_id) == (
        False,
        "Missing client_secret",
    )


@pytest.mark.parametrize("integration_id", ["microsoft-defender", "azure-ad"])
async def test_entra_backed_executor_offline_fails_cleanly(
    monkeypatch, nothing_stored, offline, integration_id
):
    _resolved(monkeypatch, tenant_id="t", client_id="c", client_secret=_ENTRA_SECRET)

    ok, message = await credential_check.check_credentials(integration_id)

    assert ok is False
    assert "ConnectError" in message and "could not be reached" in message
    assert _ENTRA_SECRET not in message


async def test_defender_reads_one_machine_and_nothing_else(monkeypatch, nothing_stored):
    _resolved(monkeypatch, tenant_id="t", client_id="c", client_secret=_ENTRA_SECRET)
    calls = []

    def request(self, method, path, *, params=None, json=None):
        calls.append((method, path, dict(params or {}), json))
        return {"value": []}

    monkeypatch.setattr(
        "core.integrations.microsoft_defender.client.MDEClient.request", request
    )

    ok, message = await credential_check.check_credentials("microsoft-defender")

    assert ok is True, message
    assert calls == [("GET", "machines", {"$top": 1}, None)]


async def test_defender_refuses_a_stored_api_base_that_is_not_microsoft(monkeypatch):
    _resolved(monkeypatch, tenant_id="t", client_id="c", client_secret=_ENTRA_SECRET)
    monkeypatch.setattr(
        credential_check, "_stored", lambda i: {"api_base": "https://evil.test/api"}
    )

    ok, message = await credential_check.check_credentials("microsoft-defender")

    assert ok is False
    assert message.startswith("api_base must be an official Microsoft")


async def test_entra_reads_one_user_and_reports_a_refusal(monkeypatch, nothing_stored):
    from core.integrations.azure_ad.client import GraphError

    _resolved(monkeypatch, tenant_id="t", client_id="c", client_secret=_ENTRA_SECRET)
    calls = []

    def request(self, method, path, *, params=None, json=None, headers=None):
        calls.append((method, path, dict(params or {})))
        raise GraphError(
            "Graph GET /users returned HTTP 403 (Authorization_RequestDenied)"
        )

    monkeypatch.setattr(
        "core.integrations.azure_ad.client.GraphClient.request", request
    )

    ok, message = await credential_check.check_credentials("azure-ad")

    assert ok is False
    assert "403" in message
    assert calls == [("GET", "/users", {"$top": 1, "$select": "id"})]


async def test_palo_alto_offline_fails_cleanly_without_the_key(
    monkeypatch, nothing_stored
):
    # nothing listens on port 1: a real refused connection
    _resolved(
        monkeypatch,
        hostname="https://127.0.0.1:1",
        api_key=_PAN_KEY,
        verify_ssl=False,
        ca_cert_path=None,
    )

    ok, message = await credential_check.check_credentials("palo-alto")

    assert ok is False
    assert "transport error" in message
    assert _PAN_KEY not in message


async def test_palo_alto_runs_one_operational_read(monkeypatch, nothing_stored):
    import xml.etree.ElementTree as ET

    _resolved(
        monkeypatch,
        hostname="fw.example.test",
        api_key=_PAN_KEY,
        verify_ssl=True,
        ca_cert_path=None,
    )
    calls = []

    def call(self, method, fields, **kwargs):
        calls.append((method, dict(fields)))
        return ET.fromstring(
            '<response status="success"><result><system><model>PA-440</model>'
            "<sw-version>11.1.2</sw-version></system></result></response>"
        )

    monkeypatch.setattr("core.integrations.palo_alto.client.PanConnection.call", call)

    ok, message = await credential_check.check_credentials("palo-alto")

    assert (ok, message) == (True, "API key accepted (PA-440 PAN-OS 11.1.2)")
    assert calls == [
        ("GET", {"type": "op", "cmd": "<show><system><info></info></system></show>"})
    ]


async def test_fortigate_runs_one_status_read(monkeypatch, nothing_stored):
    _resolved(
        monkeypatch,
        hostname="fgt.example.test",
        api_token="fgt-token-1",
        vdom=None,
        verify_ssl=True,
        ca_cert_path=None,
    )
    calls = []

    def call(self, method, path, body=None, **kwargs):
        calls.append((method, path, self.vdom))
        return {"status": "success", "serial": "FGT60F", "version": "v7.4.3"}

    monkeypatch.setattr("core.integrations.fortinet.client.FortiConnection.call", call)

    ok, message = await credential_check.check_credentials("fortigate")

    assert (ok, message) == (True, "API token accepted (FGT60F v7.4.3)")
    assert calls == [("GET", "monitor/system/status", "root")]


async def test_fortigate_without_a_token_says_what_is_missing(
    monkeypatch, nothing_stored
):
    _resolved(monkeypatch, hostname="fgt.example.test", api_token=None)
    ok, message = await credential_check.check_credentials("fortigate")
    assert ok is False and "api_token" in message


# --- W0.44: the target may be private, never cloud metadata; messages scrubbed --


@pytest.mark.parametrize(
    "address",
    [
        "http://169.254.169.254:8089",
        "https://169.254.170.2",
        "https://[fd00:ec2::254]",
        "169.254.10.10",  # link-local, where metadata services live
        "https://[::ffff:169.254.169.254]",
    ],
)
async def test_a_metadata_or_link_local_target_is_refused_before_any_call(
    monkeypatch, address
):
    _resolved(
        monkeypatch,
        server_url=address,
        hostname=address,
        username="u",
        password="p",
        api_key="k",
        api_token="t",
    )

    def boom(*a, **k):
        raise AssertionError("no call may be made")

    monkeypatch.setattr(
        "core.integrations.splunk.client.SplunkService.test_connection", boom
    )
    for integration in ("splunk", "palo-alto", "fortigate"):
        ok, message = await credential_check.check_credentials(integration)
        assert ok is False
        assert message.startswith("Refused:"), message


async def test_a_private_target_is_still_checked(monkeypatch):
    _resolved(
        monkeypatch,
        server_url="https://10.20.30.40:8089",
        username="u",
        password="p",
        verify_ssl=True,
        ca_cert_path=None,
    )
    monkeypatch.setattr(
        "core.integrations.splunk.client.SplunkService.test_connection",
        lambda self: (True, "Connected to Splunk 9.2"),
    )
    assert await credential_check.check_credentials("splunk") == (
        True,
        "Connected to Splunk 9.2",
    )


async def test_a_vendor_message_is_scrubbed_and_bounded(monkeypatch):
    _resolved(
        monkeypatch,
        server_url="https://s:8089",
        username="u",
        password="p",
        verify_ssl=True,
        ca_cert_path=None,
    )
    echoed = (
        "HTTP 401: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig "
        + "x" * 1000
    )
    monkeypatch.setattr(
        "core.integrations.splunk.client.SplunkService.test_connection",
        lambda self: (False, echoed),
    )
    ok, message = await credential_check.check_credentials("splunk")
    assert ok is False
    assert "eyJhbGci" not in message
    assert len(message) <= credential_check.MESSAGE_MAX
