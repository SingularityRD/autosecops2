"""PAN-OS XML API connection shared by the MCP tool and the response executor.

One place builds the base URL from the configured hostname, applies the
integration's TLS policy, and sends the API key. The key travels in the
``X-PAN-KEY`` header, never in the query string: a URL ends up in proxy logs,
httpx exception text and tracebacks, a header does not. Everything this module
puts into an exception or a log line goes through ``redact`` first.

XML responses are parsed with the standard library; a response carrying a DTD
or entity declaration is refused rather than parsed (PAN-OS never sends one).
"""

from __future__ import annotations

import logging
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote, quote_plus

import httpx

from core.integrations._base.tls import tls_verify

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
_FALSE_STRINGS = {"false", "0", "no", "off"}


class PanConfigError(ValueError):
    """The integration config cannot reach a firewall (missing host or key)."""


class PanApiError(Exception):
    """A PAN-OS API call failed.

    ``retryable`` is True for transport failures, 429 and 5xx: the request may
    succeed if sent again. An HTTP 4xx or a ``status="error"`` response is the
    firewall's answer and is not retried. The message is already redacted.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.retryable = retryable


def base_url_for(hostname: str) -> str:
    """The Settings form collects a hostname; PAN-OS is reached over HTTPS."""
    host = str(hostname).strip().rstrip("/")
    return host if host.startswith(("http://", "https://")) else f"https://{host}"


def _as_bool(value: Any, default: bool) -> bool:
    # resolve() returns every declared field, so an unset verify_ssl is
    # present-but-None and a .get(k, True) default would never fire.
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip().lower() not in _FALSE_STRINGS
    return bool(value)


@dataclass(frozen=True)
class PanConnection:
    """Where the firewall is and how to talk to it. ``api_key`` is never in repr."""

    base_url: str
    api_key: str = field(repr=False)
    verify_ssl: bool = True
    ca_cert_path: Optional[str] = None
    timeout: float = DEFAULT_TIMEOUT
    vsys: Optional[str] = None

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> "PanConnection":
        hostname = config.get("hostname")
        api_key = config.get("api_key")
        if not hostname or not api_key:
            raise PanConfigError(
                "Palo Alto not configured (hostname and api_key required)"
            )
        timeout = config.get("timeout")
        return cls(
            base_url=base_url_for(str(hostname)),
            api_key=str(api_key),
            verify_ssl=_as_bool(config.get("verify_ssl"), True),
            ca_cert_path=config.get("ca_cert_path") or None,
            timeout=float(timeout) if timeout else DEFAULT_TIMEOUT,
            vsys=config.get("vsys") or None,
        )

    @property
    def api_url(self) -> str:
        return f"{self.base_url}/api/"

    @property
    def host(self) -> str:
        return httpx.URL(self.base_url).host

    def redact(self, text: Any) -> str:
        """``text`` with the API key (raw or URL-encoded) blanked out."""
        out = str(text)
        if self.api_key:
            for form in {
                self.api_key,
                quote(self.api_key, safe=""),
                quote_plus(self.api_key),
            }:
                out = out.replace(form, "***")
        return out

    def _headers(self) -> dict[str, str]:
        return {"X-PAN-KEY": self.api_key}

    def _verify(self):
        return tls_verify(self.verify_ssl, self.ca_cert_path)

    def get(self, params: Mapping[str, Any]) -> httpx.Response:
        """One GET to ``/api/``; the key is added as a header."""
        return httpx.get(
            self.api_url,
            params=dict(params),
            headers=self._headers(),
            verify=self._verify(),
            timeout=self.timeout,
        )

    def post(self, data: Mapping[str, Any]) -> httpx.Response:
        """One form-encoded POST to ``/api/``; the key is added as a header."""
        return httpx.post(
            self.api_url,
            data=dict(data),
            headers=self._headers(),
            verify=self._verify(),
            timeout=self.timeout,
        )

    def call(
        self,
        method: str,
        fields: Mapping[str, Any],
        *,
        attempts: int = 1,
        backoff_seconds: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> ET.Element:
        """Send a request and return the parsed ``<response status="success">``.

        Retries a retryable failure up to ``attempts`` times in all, sleeping
        ``backoff_seconds * 2**n`` between tries. Raises ``PanApiError``.
        """
        attempts = max(1, int(attempts))
        send = self.get if method.upper() == "GET" else self.post
        for attempt in range(1, attempts + 1):
            try:
                err = None
                response = send(fields)
            except httpx.TransportError as exc:
                err = PanApiError(
                    f"transport error: {type(exc).__name__}: {self.redact(exc)}",
                    retryable=True,
                )
            except OSError as exc:  # an unusable ca_cert_path, from tls_verify
                raise PanApiError(self.redact(exc)) from None
            if err is None:
                code = response.status_code
                if code == 200:
                    return parse_response(response.text, self.redact)
                retryable = code == 429 or code >= 500
                err = PanApiError(
                    f"HTTP {code}: {_error_text(response.text, self.redact)}",
                    status_code=code,
                    retryable=retryable,
                )
            if not err.retryable or attempt == attempts:
                raise err
            delay = backoff_seconds * (2 ** (attempt - 1))
            logger.warning(
                "palo-alto API attempt %d/%d failed (%s); retrying in %.2fs",
                attempt,
                attempts,
                err.message,
                delay,
            )
            sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover


def _safe_fromstring(text: str) -> ET.Element:
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise PanApiError("refusing an XML response with a DTD or entity declaration")
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        raise PanApiError("unparseable XML response") from None


def _messages(root: ET.Element) -> str:
    """Every human-readable message in a PAN-OS error response."""
    parts: list[str] = []
    for el in root.iter():
        msg = el.get("message")
        if msg:
            parts.append(msg.strip())
        if (
            el.text
            and el.text.strip()
            and el.tag in ("msg", "line", "member", "result")
        ):
            parts.append(el.text.strip())
    seen: list[str] = []
    for p in parts:
        if p not in seen:
            seen.append(p)
    return "; ".join(seen)[:500]


def _error_text(text: str, redact: Callable[[Any], str]) -> str:
    try:
        root = _safe_fromstring(text)
    except PanApiError:
        return redact(text.strip()[:200]) or "no body"
    return redact(_messages(root)) or "no message"


def parse_response(text: str, redact: Callable[[Any], str] = str) -> ET.Element:
    """The root ``<response>`` of a successful call; ``PanApiError`` otherwise."""
    root = _safe_fromstring(text)
    status = root.get("status")
    if root.tag != "response" or status != "success":
        code = root.get("code")
        detail = redact(_messages(root)) or "no message"
        raise PanApiError(
            f"PAN-OS returned status={status!r}"
            + (f" code={code}" if code else "")
            + f": {detail}"
        )
    return root


__all__ = [
    "PanApiError",
    "PanConfigError",
    "PanConnection",
    "base_url_for",
    "parse_response",
]
