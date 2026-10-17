"""One read-only check that a saved integration's URL and credentials work.

The MCP probe behind "Test" only shows that a server answered. A Splunk or
Elastic server starts and lists its tools whatever it is pointed at, so a wrong
password or an unreachable URL still read as Good. This logs in and reads the
server's own info endpoint with the saved settings, and nothing else: no search,
no write to the external system.

The response executors (Microsoft Defender for Endpoint, Entra ID, PAN-OS)
are checked the same way, with the call each executor itself needs to read
before it acts (W0.37): Defender lists one machine, Entra ID reads one user,
PAN-OS reads ``show system info``. None of them changes anything. Each is tried
once, without the executor's retries, so an unreachable tenant or firewall
fails in seconds with the transport error's class name.

Only integrations with a client that can answer are listed. For any other id
``check_credentials`` returns ``None``, and the test stays what the MCP probe
said.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from core.integrations._base.config import missing, resolve
from core.integrations.azure_ad.descriptor import AZURE_AD
from core.integrations.elastic.descriptor import ELASTIC
from core.integrations.microsoft_defender.descriptor import MICROSOFT_DEFENDER
from core.integrations.palo_alto.descriptor import PALO_ALTO
from core.integrations.splunk.descriptor import SPLUNK

logger = logging.getLogger(__name__)

# (success, one line safe to show: never a secret)
Outcome = Tuple[bool, str]


def _absent(names: Tuple[str, ...]) -> Outcome:
    return False, f"Missing {', '.join(names)}"


async def _splunk() -> Outcome:
    from core.integrations.splunk.client import SplunkService

    config = resolve(SPLUNK)
    absent = missing(config, "server_url", "username", "password")
    if absent:
        return _absent(absent)
    service = SplunkService(
        server_url=config["server_url"],
        username=config["username"],
        password=config["password"],
        verify_ssl=config["verify_ssl"],
        ca_cert_path=config.get("ca_cert_path"),
    )
    try:
        # sync client: login, then GET /services/server/info
        return await asyncio.to_thread(service.test_connection)
    finally:
        if service._session is not None:
            service._session.close()


async def _elastic() -> Outcome:
    from core.integrations.elastic.client import ElasticService

    config = resolve(ELASTIC)
    if missing(config, "elasticsearch_url"):
        return _absent(("elasticsearch_url",))
    verify = True if config.get("verify_ssl") is None else config["verify_ssl"]
    service = ElasticService(
        elasticsearch_url=config["elasticsearch_url"],
        kibana_url=config.get("kibana_url"),
        api_key=config.get("api_key"),
        username=config.get("username"),
        password=config.get("password"),
        verify_ssl=verify,
        ca_cert_path=config.get("ca_cert_path"),
    )
    try:
        # GET / on Elasticsearch (and /api/status on Kibana when one is set)
        return await service.test_connection()
    finally:
        await service.close()


# A response executor's check gives up after this long on any one call.
EXECUTOR_CHECK_TIMEOUT = 15.0


def _stored(integration_id: str) -> Dict[str, Any]:
    """Saved settings outside the descriptor (Defender's ``api_base``, ``vsys``)."""
    from core.config import load_integrations_config

    return dict(load_integrations_config()["integrations"].get(integration_id) or {})


def _defender_check() -> Outcome:
    import httpx

    from core.integrations._base.aad_token import TokenError
    from core.integrations.microsoft_defender.client import (
        API_BASE,
        MDEApiError,
        MDEClient,
        acquire_token,
    )

    config = resolve(MICROSOFT_DEFENDER)
    absent = missing(config, "tenant_id", "client_id", "client_secret")
    if absent:
        return _absent(absent)
    api_base = str(_stored(MICROSOFT_DEFENDER.id).get("api_base") or API_BASE)
    try:
        with httpx.Client(timeout=EXECUTOR_CHECK_TIMEOUT) as http:
            client = MDEClient(
                lambda: acquire_token(config),
                api_base=api_base,
                http=http,
                max_retries=0,
            )
            # read-only: Machine.Read.All, which isolate_host needs to find the host
            client.request("GET", "machines", params={"$top": 1})
    except (TokenError, MDEApiError, ValueError) as exc:
        return False, str(exc)
    return True, "Token issued; machines readable"


def _entra_check() -> Outcome:
    from core.integrations.azure_ad.client import (
        GraphClient,
        GraphError,
        TokenError,
        get_graph_token,
    )

    config = resolve(AZURE_AD)
    absent = missing(config, "tenant_id", "client_id", "client_secret")
    if absent:
        return _absent(absent)
    client = GraphClient(
        lambda: get_graph_token(config), timeout=EXECUTOR_CHECK_TIMEOUT, max_retries=0
    )
    try:
        # read-only: User.Read.All, which disable_user needs to look the user up
        client.get_json("/users", params={"$top": 1, "$select": "id"})
    except (TokenError, GraphError) as exc:
        return False, str(exc)
    return True, "Token issued; users readable"


def _palo_alto_check() -> Outcome:
    from core.integrations.palo_alto.client import (
        PanApiError,
        PanConfigError,
        PanConnection,
    )

    config = resolve(PALO_ALTO)
    absent = missing(config, "hostname", "api_key")
    if absent:
        return _absent(absent)
    stored = _stored(PALO_ALTO.id)
    try:
        connection = PanConnection.from_config(
            {**config, "vsys": stored.get("vsys"), "timeout": EXECUTOR_CHECK_TIMEOUT}
        )
        # read-only operational command
        root = connection.call(
            "GET", {"type": "op", "cmd": "<show><system><info></info></system></show>"}
        )
    except (PanApiError, PanConfigError) as exc:
        return False, str(exc)
    model = root.findtext(".//model") or "firewall"
    version = root.findtext(".//sw-version")
    return True, f"API key accepted ({model}{f' PAN-OS {version}' if version else ''})"


async def _defender() -> Outcome:
    return await asyncio.to_thread(_defender_check)


async def _entra() -> Outcome:
    return await asyncio.to_thread(_entra_check)


async def _palo_alto() -> Outcome:
    return await asyncio.to_thread(_palo_alto_check)


_CHECKS: Dict[str, Callable[[], Awaitable[Outcome]]] = {
    SPLUNK.id: _splunk,
    ELASTIC.id: _elastic,
    MICROSOFT_DEFENDER.id: _defender,
    AZURE_AD.id: _entra,
    PALO_ALTO.id: _palo_alto,
}


# The operator-set address each check calls (W0.44): it may be private, but
# never a cloud metadata or link-local address, where a token or the reply
# would leak credentials. Defender's api_base is optional (default public).
_TARGETS: Dict[str, Callable[[], Optional[str]]] = {
    SPLUNK.id: lambda: resolve(SPLUNK).get("server_url"),
    ELASTIC.id: lambda: resolve(ELASTIC).get("elasticsearch_url"),
    MICROSOFT_DEFENDER.id: lambda: _stored(MICROSOFT_DEFENDER.id).get("api_base"),
    PALO_ALTO.id: lambda: resolve(PALO_ALTO).get("hostname"),
}

# A message shown in the console is at most this long.
MESSAGE_MAX = 300


def _safe(message: str) -> str:
    """A vendor's error text may echo a request or a token: scrub it (W0.44)."""
    from core.compliance.audit_export import redact_text

    return redact_text(str(message))[:MESSAGE_MAX]


def _refused_target(integration_id: str) -> Optional[str]:
    from core.platform.url_safety import UrlSafetyError, refuse_metadata_target

    target = _TARGETS.get(integration_id)
    address = target() if target else None
    if not address:
        return None
    try:
        refuse_metadata_target(str(address))
    except UrlSafetyError as exc:
        return f"Refused: {exc}"
    return None


async def check_credentials(integration_id: str) -> Optional[Outcome]:
    """``(ok, message)`` for the saved settings, or ``None`` when no check exists."""
    check = _CHECKS.get(integration_id)
    if check is None:
        return None
    try:
        refused = await asyncio.to_thread(_refused_target, integration_id)
        if refused:
            return False, refused
        ok, message = await check()
        return ok, _safe(message)
    except Exception as exc:  # noqa: BLE001
        # The class name only: a client error can carry the URL it was given.
        logger.warning(
            "Credential check for %s failed to run (%s)",
            integration_id,
            type(exc).__name__,
        )
        return False, f"Could not check the connection ({type(exc).__name__})"
