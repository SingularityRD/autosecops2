"""FortiOS REST API connection for the FortiGate executor (W0.57).

The API token travels in the ``Authorization: Bearer`` header, never in the
query string (a URL ends up in proxy logs and exception text). Everything this
module puts into an exception or a log line goes through ``redact`` first.

FortiOS answers JSON: ``{"http_status": 200, "status": "success", ...}`` on
success, an HTTP error with ``"error": <negative code>`` otherwise. Two codes
matter to the executor and are surfaced as ``FortiApiError.code``: -5 (the
entry already exists) and -3 (the entry was not found; HTTP 404).
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

import httpx

from core.integrations._base.tls import tls_verify

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
DEFAULT_VDOM = "root"
_FALSE_STRINGS = {"false", "0", "no", "off"}
# Retried: transport failures, rate limiting and a gateway that is not up.
# FortiOS reports most refusals (a duplicate entry among them) as HTTP 500, so
# a plain 500 is the device's answer and is not retried.
_RETRYABLE = {429, 502, 503, 504}

ENTRY_EXISTS = -5
ENTRY_NOT_FOUND = -3


class FortiConfigError(ValueError):
    """The integration config cannot reach a FortiGate (missing host or token)."""


class FortiApiError(Exception):
    """A FortiOS API call failed. The message is already redacted."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        code: Optional[int] = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
        self.retryable = retryable

    @property
    def not_found(self) -> bool:
        return self.status_code == 404 or self.code == ENTRY_NOT_FOUND

    @property
    def exists(self) -> bool:
        return self.code == ENTRY_EXISTS


def base_url_for(hostname: str) -> str:
    host = str(hostname).strip().rstrip("/")
    return host if host.startswith(("http://", "https://")) else f"https://{host}"


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() not in _FALSE_STRINGS
    return bool(value)


def path_name(name: str) -> str:
    """``name`` as one URL path segment (FortiOS names may hold ':' or '/')."""
    return quote(str(name), safe="")


@dataclass(frozen=True)
class FortiConnection:
    """Where the FortiGate is and how to talk to it. The token is never in repr."""

    base_url: str
    api_token: str = field(repr=False)
    vdom: str = DEFAULT_VDOM
    verify_ssl: bool = True
    ca_cert_path: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> "FortiConnection":
        hostname = config.get("hostname")
        token = config.get("api_token")
        if not hostname or not token:
            raise FortiConfigError(
                "FortiGate not configured (hostname and api_token required)"
            )
        timeout = config.get("timeout")
        return cls(
            base_url=base_url_for(str(hostname)),
            api_token=str(token),
            vdom=str(config.get("vdom") or DEFAULT_VDOM),
            verify_ssl=_as_bool(config.get("verify_ssl"), True),
            ca_cert_path=config.get("ca_cert_path") or None,
            timeout=float(timeout) if timeout else DEFAULT_TIMEOUT,
        )

    @property
    def host(self) -> str:
        return httpx.URL(self.base_url).host

    def redact(self, text: Any) -> str:
        out = str(text)
        if self.api_token:
            for form in {self.api_token, quote(self.api_token, safe="")}:
                out = out.replace(form, "***")
        return out

    def _send(
        self, method: str, path: str, body: Optional[Mapping[str, Any]]
    ) -> httpx.Response:
        return httpx.request(
            method,
            f"{self.base_url}/api/v2/{path.lstrip('/')}",
            params={"vdom": self.vdom},
            json=dict(body) if body is not None else None,
            headers={"Authorization": f"Bearer {self.api_token}"},
            verify=tls_verify(self.verify_ssl, self.ca_cert_path),
            timeout=self.timeout,
        )

    def call(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        *,
        attempts: int = 1,
        backoff_seconds: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> dict[str, Any]:
        """One API call; the parsed JSON body of a success, else ``FortiApiError``."""
        attempts = max(1, int(attempts))
        for attempt in range(1, attempts + 1):
            try:
                err = None
                response = self._send(method.upper(), path, body)
            except httpx.TransportError as exc:
                err = FortiApiError(
                    f"transport error: {type(exc).__name__}: {self.redact(exc)}",
                    retryable=True,
                )
            except OSError as exc:  # an unusable ca_cert_path, from tls_verify
                raise FortiApiError(self.redact(exc)) from None
            if err is None:
                payload = _json(response)
                code = response.status_code
                if code == 200 and payload.get("status", "success") == "success":
                    return payload
                err = FortiApiError(
                    f"HTTP {code}: {self.redact(_error_text(payload, response))}",
                    status_code=code,
                    code=_int(payload.get("error")),
                    retryable=code in _RETRYABLE,
                )
            if not err.retryable or attempt == attempts:
                raise err
            delay = backoff_seconds * (2 ** (attempt - 1))
            logger.warning(
                "fortigate API attempt %d/%d failed (%s); retrying in %.2fs",
                attempt,
                attempts,
                err.message,
                delay,
            )
            sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover


def _json(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _error_text(payload: Mapping[str, Any], response: httpx.Response) -> str:
    parts = [
        str(payload[k])
        for k in ("cli_error", "error", "status")
        if payload.get(k) not in (None, "")
    ]
    if parts:
        return "; ".join(parts)[:300]
    return (response.text or "no body").strip()[:200]


__all__ = [
    "ENTRY_EXISTS",
    "ENTRY_NOT_FOUND",
    "FortiApiError",
    "FortiConfigError",
    "FortiConnection",
    "base_url_for",
    "path_name",
]
