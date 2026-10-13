"""Microsoft Defender for Endpoint API client, shared by the MCP tool server
and the response executor.

One place that knows how to get a token, which host to call, how to retry and
how to turn an MDE error body into something safe to log. The token and the
client secret never appear in a log record, an exception message or ``repr``.

Synchronous on purpose: ``core.response`` executors are synchronous, and the
MCP tool server already made blocking httpx calls from its handlers.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from typing import Any, Optional

import httpx

from core.integrations._base.aad_token import fetch_client_credentials_token

logger = logging.getLogger(__name__)

API_BASE = "https://api.securitycenter.microsoft.com/api"
TOKEN_SCOPE = "https://api.securitycenter.microsoft.com/.default"
LABEL = "Microsoft Defender"

DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=5.0)
# Entra ID access tokens live 60-90 minutes; refresh well before that, and
# immediately on a 401.
TOKEN_REUSE_SECONDS = 45 * 60
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_BACKOFF_SECONDS = 30.0

ISOLATION_TYPES = ("Full", "Selective")

# The only API bases the client will send a bearer token to: the global MDE
# endpoint and its documented commercial regional ones
# (learn.microsoft.com/defender-endpoint/api/exposed-apis-list), all of which
# accept a token for TOKEN_SCOPE. An operator-supplied base is matched against
# this list, never trusted, so integration config cannot redirect the token to
# a host it controls. Sovereign clouds need a different token scope and are not
# supported.
ALLOWED_API_BASES = frozenset(
    {
        API_BASE,
        "https://api-us.securitycenter.microsoft.com/api",
        "https://api-eu.securitycenter.microsoft.com/api",
        "https://api-uk.securitycenter.microsoft.com/api",
        "https://api-au.securitycenter.microsoft.com/api",
        "https://api.security.microsoft.com/api",
        "https://us.api.security.microsoft.com/api",
        "https://eu.api.security.microsoft.com/api",
        "https://uk.api.security.microsoft.com/api",
        "https://au.api.security.microsoft.com/api",
    }
)


def check_api_base(api_base: str) -> str:
    """``api_base`` normalised, or ``ValueError`` if it is not an MDE endpoint."""
    normalised = str(api_base or "").strip().rstrip("/")
    if normalised.lower() not in ALLOWED_API_BASES:
        raise ValueError(
            "api_base must be an official Microsoft Defender for Endpoint API "
            f"endpoint, one of: {', '.join(sorted(ALLOWED_API_BASES))}"
        )
    return normalised.lower()


class MDEApiError(Exception):
    """An MDE API call failed. ``str()`` carries no credential and is safe to log.

    ``status`` is the HTTP status, or None for a transport failure; ``code`` is
    MDE's ``error.code`` when the body had one (``ActiveRequestAlreadyExists``).
    """

    def __init__(
        self, message: str, *, status: Optional[int] = None, code: Optional[str] = None
    ):
        super().__init__(message)
        self.status = status
        self.code = code

    @property
    def retryable(self) -> bool:
        return self.status is None or self.status in RETRY_STATUSES


def acquire_token(config: Mapping[str, Any]) -> Optional[str]:
    """An MDE access token, or None when credentials are not configured.

    Raises ``TokenError`` when they are configured but the exchange fails.
    """
    tenant = config.get("tenant_id")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    if not all([tenant, client_id, client_secret]):
        return None
    return fetch_client_credentials_token(
        LABEL, str(tenant), str(client_id), str(client_secret), TOKEN_SCOPE
    )


def isolate_payload(comment: str, isolation_type: str = "Full") -> dict[str, str]:
    """The body of ``POST /machines/{id}/isolate``."""
    if isolation_type not in ISOLATION_TYPES:
        raise ValueError(f"isolation type must be one of {ISOLATION_TYPES}")
    return {"Comment": comment, "IsolationType": isolation_type}


def odata_quote(value: str) -> str:
    """An OData string literal: single quotes doubled."""
    return "'" + value.replace("'", "''") + "'"


def _error_detail(resp: httpx.Response) -> tuple[Optional[str], str]:
    """MDE's ``error.code`` and a short message from an error response."""
    try:
        body = resp.json()
    except ValueError:
        return None, ""
    err = body.get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return None, ""
    code = err.get("code")
    message = str(err.get("message") or "")[:200]
    return (str(code) if code else None), message


def _retry_after(resp: Optional[httpx.Response]) -> Optional[float]:
    if resp is None:
        return None
    raw = resp.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None


class MDEClient:
    """Calls to ``api.securitycenter.microsoft.com`` with retry and backoff.

    ``token_provider`` returns a bearer token or None (not configured); it may
    raise ``TokenError``. The token is cached for ``TOKEN_REUSE_SECONDS`` and
    dropped on a 401, after which the call is tried once more.

    429, 5xx and transport errors are retried up to ``max_retries`` times with
    exponential backoff (``backoff_base * 2**attempt``, capped), honouring a
    ``Retry-After`` header when MDE sends one.
    """

    def __init__(
        self,
        token_provider: Callable[[], Optional[str]],
        *,
        api_base: str = API_BASE,
        http: Optional[httpx.Client] = None,
        max_retries: int = 3,
        backoff_base: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._token_provider = token_provider
        self._api_base = check_api_base(api_base)
        self._http = http if http is not None else httpx.Client(timeout=DEFAULT_TIMEOUT)
        self._owns_http = http is None
        self.max_retries = max(0, int(max_retries))
        self.backoff_base = max(0.0, float(backoff_base))
        self._sleep = sleep
        self._clock = clock
        self._token: Optional[str] = None
        self._token_at = 0.0

    def __repr__(self) -> str:
        return f"MDEClient(api_base={self._api_base!r})"

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> "MDEClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ auth

    def _bearer(self) -> str:
        now = self._clock()
        if self._token is None or now - self._token_at > TOKEN_REUSE_SECONDS:
            token = self._token_provider()
            if not token:
                raise MDEApiError(f"{LABEL} is not configured")
            self._token, self._token_at = token, now
        return self._token

    def _drop_token(self) -> None:
        self._token = None

    # --------------------------------------------------------------- request

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        """The decoded JSON body (None for an empty one), or ``MDEApiError``."""
        url = f"{self._api_base}/{path.lstrip('/')}"
        refreshed = False
        attempt = 0
        while True:
            headers = {
                "Authorization": f"Bearer {self._bearer()}",
                "Content-Type": "application/json",
            }
            resp: Optional[httpx.Response] = None
            try:
                resp = self._http.request(
                    method,
                    url,
                    headers=headers,
                    params=dict(params) if params else None,
                    json=dict(json) if json is not None else None,
                    timeout=DEFAULT_TIMEOUT,
                )
            except httpx.HTTPError as exc:
                error = MDEApiError(
                    f"{LABEL} {method} {path} failed ({type(exc).__name__})"
                )
            else:
                if resp.status_code == 401 and not refreshed:
                    refreshed = True
                    self._drop_token()
                    continue
                if resp.status_code < 400:
                    if not resp.content:
                        return None
                    try:
                        return resp.json()
                    except ValueError as exc:
                        raise MDEApiError(
                            f"{LABEL} {method} {path} returned a non-JSON body",
                            status=resp.status_code,
                        ) from exc
                code, message = _error_detail(resp)
                text = f"{LABEL} {method} {path} returned HTTP {resp.status_code}"
                if code:
                    text += f" ({code})"
                if message:
                    text += f": {message}"
                error = MDEApiError(text, status=resp.status_code, code=code)

            if not error.retryable or attempt >= self.max_retries:
                logger.warning("%s", error)
                raise error
            delay = _retry_after(resp)
            if delay is None:
                delay = self.backoff_base * (2**attempt)
            delay = min(delay, MAX_BACKOFF_SECONDS)
            logger.info(
                "%s; retry %d/%d in %.1fs", error, attempt + 1, self.max_retries, delay
            )
            self._sleep(delay)
            attempt += 1

    # ------------------------------------------------------------ endpoints

    def list_alerts(self, top: int = 20) -> list[dict[str, Any]]:
        body = self.request("GET", "alerts", params={"$top": top}) or {}
        return list(body.get("value", []))

    def get_machine(self, machine_id: str) -> dict[str, Any]:
        return self.request("GET", f"machines/{machine_id}") or {}

    def find_machines(
        self, odata_filter: str, top: int = 50
    ) -> tuple[list[dict[str, Any]], bool]:
        """One page of machines matching ``odata_filter``, and whether there are more.

        ``more`` is True when MDE sent an ``@odata.nextLink`` or filled the
        page: the caller has not seen every match and must not treat the page
        as complete. The nextLink is never followed (it is a URL from the
        response; following it would send the token wherever it points).
        """
        body = (
            self.request(
                "GET", "machines", params={"$filter": odata_filter, "$top": top}
            )
            or {}
        )
        values = list(body.get("value", []))
        more = bool(body.get("@odata.nextLink")) or len(values) >= top
        return values, more

    def isolate(
        self, machine_id: str, comment: str, isolation_type: str = "Full"
    ) -> dict[str, Any]:
        return (
            self.request(
                "POST",
                f"machines/{machine_id}/isolate",
                json=isolate_payload(comment, isolation_type),
            )
            or {}
        )

    def unisolate(self, machine_id: str, comment: str) -> dict[str, Any]:
        return (
            self.request(
                "POST", f"machines/{machine_id}/unisolate", json={"Comment": comment}
            )
            or {}
        )

    def get_machine_action(self, action_id: str) -> dict[str, Any]:
        return self.request("GET", f"machineactions/{action_id}") or {}

    def list_isolation_actions(
        self, machine_id: str, top: int = 50
    ) -> list[dict[str, Any]]:
        """Isolate / Unisolate machine actions for one machine, any status,
        newest first, so the ``top`` returned always include the latest."""
        odata = (
            f"machineId eq {odata_quote(machine_id)} and "
            "(type eq 'Isolate' or type eq 'Unisolate')"
        )
        body = (
            self.request(
                "GET",
                "machineactions",
                params={
                    "$filter": odata,
                    "$orderby": "creationDateTimeUtc desc",
                    "$top": top,
                },
            )
            or {}
        )
        return list(body.get("value", []))


__all__ = [
    "ALLOWED_API_BASES",
    "API_BASE",
    "ISOLATION_TYPES",
    "MDEApiError",
    "MDEClient",
    "acquire_token",
    "check_api_base",
    "isolate_payload",
    "odata_quote",
]
