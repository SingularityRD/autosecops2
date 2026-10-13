"""Microsoft Graph client shared by the Entra ID MCP tool and executor.

The token exchange lives in ``core.integrations._base.aad_token``; this module
adds what both ``tool.py`` and ``executor.py`` need on top of it: the Graph
base URL and scope, a bounded retry on throttling and server errors, and an
error type whose text is safe to show.

The access token is held only in memory and only ever placed in the
``Authorization`` header. Nothing here logs headers, and ``GraphError`` carries
the status, Graph's error code and message, never the request.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from typing import Any, Optional
from urllib.parse import quote

import httpx

from core.integrations._base.aad_token import TokenError, fetch_client_credentials_token

logger = logging.getLogger(__name__)

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
LABEL = "Azure AD"

# Retried: throttling and the transient server errors Graph documents.
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
# A client-credentials token lives ~60-90 min; refresh well before that.
TOKEN_TTL_SECONDS = 45 * 60

__all__ = [
    "GRAPH_BASE",
    "GRAPH_SCOPE",
    "GraphClient",
    "GraphError",
    "TokenError",
    "get_graph_token",
    "user_path",
]


def get_graph_token(config: Mapping[str, Any]) -> Optional[str]:
    """A Graph access token, or None when credentials are not configured.

    Raises ``TokenError`` when they are configured but the exchange fails.
    """
    tenant = config.get("tenant_id")
    client_id = config.get("client_id")
    client_secret = config.get("client_secret")
    if not all([tenant, client_id, client_secret]):
        return None
    return fetch_client_credentials_token(
        LABEL, tenant, client_id, client_secret, GRAPH_SCOPE
    )


def user_path(user: str) -> str:
    """``/users/{user}`` with the identifier percent-encoded.

    A guest UPN carries ``#EXT#``; unencoded, the ``#`` would end the path.
    """
    return f"/users/{quote(user, safe='@')}"


class GraphError(Exception):
    """A Graph call that did not succeed. ``str()`` is safe to show and log."""

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        code: Optional[str] = None,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.retry_after = retry_after

    @property
    def transient(self) -> bool:
        """Throttled, a server error, or no answer at all: worth trying later."""
        return self.status is None or self.status in RETRY_STATUSES


def _error_from(resp: httpx.Response, method: str, path: str) -> GraphError:
    code = message = None
    try:
        body = resp.json()
    except ValueError:
        body = None
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        code = body["error"].get("code")
        message = body["error"].get("message")
    detail = f": {code}" if code else ""
    if message:
        detail += f" ({str(message)[:200]})"
    return GraphError(
        f"Graph {method} {path} returned HTTP {resp.status_code}{detail}",
        status=resp.status_code,
        code=code,
        retry_after=_retry_after(resp),
    )


def _retry_after(resp: httpx.Response) -> Optional[float]:
    value = resp.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None  # HTTP-date form; fall back to exponential backoff


class GraphClient:
    """Synchronous Graph v1.0 calls with token caching and bounded retries.

    ``token_provider`` returns a fresh access token (or raises ``TokenError``).
    The token is cached for ``TOKEN_TTL_SECONDS`` and fetched again once after
    a 401. 429 and 5xx responses, and transport failures, are retried up to
    ``max_retries`` times, waiting ``Retry-After`` when Graph sends it (capped
    at ``max_backoff``) and ``backoff_base * 2**attempt`` otherwise.
    """

    def __init__(
        self,
        token_provider: Callable[[], Optional[str]],
        *,
        timeout: float = 30.0,
        max_retries: int = 3,
        backoff_base: float = 1.0,
        max_backoff: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._token_provider = token_provider
        self._token: Optional[str] = None
        self._token_at = 0.0
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))
        self.backoff_base = backoff_base
        self.max_backoff = max_backoff
        self._sleep = sleep
        self._clock = clock

    def __repr__(self) -> str:  # never show the cached token
        return f"GraphClient(timeout={self.timeout}, max_retries={self.max_retries})"

    # ------------------------------------------------------------------ auth

    def _bearer(self, *, refresh: bool = False) -> str:
        now = self._clock()
        if refresh or not self._token or now - self._token_at > TOKEN_TTL_SECONDS:
            token = self._token_provider()
            if not token:
                raise TokenError(f"{LABEL} not configured")
            self._token, self._token_at = token, now
        return self._token

    # ----------------------------------------------------------------- calls

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json: Any = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> httpx.Response:
        """One Graph call, retried as described above; a 2xx response or GraphError."""
        url = path if path.startswith("https://") else f"{GRAPH_BASE}{path}"
        refreshed = False
        attempt = 0
        while True:
            hdrs = {
                "Authorization": f"Bearer {self._bearer()}",
                "Content-Type": "application/json",
                **(headers or {}),
            }
            try:
                resp = httpx.request(
                    method,
                    url,
                    params=params,
                    json=json,
                    headers=hdrs,
                    timeout=self.timeout,
                )
            except httpx.HTTPError as exc:
                err = GraphError(f"Graph {method} {path} failed ({type(exc).__name__})")
                if attempt >= self.max_retries:
                    raise err from exc
                self._backoff(attempt, None, method, path, type(exc).__name__)
                attempt += 1
                continue

            if resp.status_code < 300:
                return resp
            if resp.status_code == 401 and not refreshed:
                # An expired or revoked token; fetch one more, once.
                refreshed = True
                self._bearer(refresh=True)
                continue
            err = _error_from(resp, method, path)
            if resp.status_code in RETRY_STATUSES and attempt < self.max_retries:
                self._backoff(
                    attempt, err.retry_after, method, path, f"HTTP {resp.status_code}"
                )
                attempt += 1
                continue
            logger.warning("%s", err)
            raise err

    def _backoff(
        self,
        attempt: int,
        retry_after: Optional[float],
        method: str,
        path: str,
        why: str,
    ) -> None:
        delay = (
            retry_after if retry_after is not None else self.backoff_base * (2**attempt)
        )
        delay = min(delay, self.max_backoff)
        logger.info(
            "Graph %s %s: %s, retry %d/%d in %.1fs",
            method,
            path,
            why,
            attempt + 1,
            self.max_retries,
            delay,
        )
        self._sleep(delay)

    # --------------------------------------------------------------- helpers

    def get_json(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> dict[str, Any]:
        body = self.request("GET", path, params=params, headers=headers).json()
        if not isinstance(body, dict):
            raise GraphError(f"Graph GET {path} returned a non-object body")
        return body

    def get_all(
        self,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        max_pages: int = 20,
    ) -> list[dict[str, Any]]:
        """Every item of a collection, following ``@odata.nextLink``."""
        items: list[dict[str, Any]] = []
        body = self.get_json(path, params=params, headers=headers)
        for _ in range(max_pages):
            items.extend(v for v in body.get("value", []) if isinstance(v, dict))
            next_link = body.get("@odata.nextLink")
            if not next_link:
                return items
            if not str(next_link).startswith(GRAPH_BASE):
                raise GraphError(
                    "Graph returned a nextLink outside graph.microsoft.com"
                )
            body = self.get_json(next_link, headers=headers)
        raise GraphError(f"Graph GET {path}: more than {max_pages} pages")

    def set_account_enabled(self, user: str, enabled: bool) -> None:
        """``PATCH /users/{user}`` with ``accountEnabled``. Graph answers 204."""
        self.request("PATCH", user_path(user), json={"accountEnabled": enabled})

    def revoke_sign_in_sessions(self, user: str) -> bool:
        """``POST /users/{user}/revokeSignInSessions``; Graph's ``value``."""
        resp = self.request("POST", f"{user_path(user)}/revokeSignInSessions")
        try:
            body = resp.json()
        except ValueError:
            return True  # a 2xx without a body still means accepted
        return bool(body.get("value", True)) if isinstance(body, dict) else True
