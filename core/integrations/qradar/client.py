"""IBM QRadar REST API client (W0.41): offenses, read only.

Auth is an authorized service token in the ``SEC`` header. ``Version`` is
sent only when ``api_version`` is set; without it QRadar answers with its
newest API version. Paging is the ``Range: items=a-b`` header. Redirects are
not followed.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from core.integrations._base.tls import tls_verify

logger = logging.getLogger(__name__)

OFFENSES = "/api/siem/offenses"
# An offense's id or a filter value is put into a QRadar filter expression;
# only these characters are let through from configuration.
_FILTER_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ .,=<>!'()-"
)


class QRadarError(RuntimeError):
    pass


def check_filter(expression: Optional[str]) -> Optional[str]:
    """An operator's extra offense filter (e.g. ``status = 'OPEN'``), checked."""
    if not expression:
        return None
    expression = expression.strip()
    if len(expression) > 500 or not set(expression) <= _FILTER_CHARS:
        raise QRadarError(
            "offense_filter may hold letters, digits, spaces and _ .,=<>!'()- only"
        )
    return expression


class QRadarClient:
    def __init__(
        self,
        console_url: str,
        api_token: str,
        *,
        api_version: Optional[str] = None,
        verify_ssl: bool = True,
        ca_cert_path: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        if not console_url:
            raise QRadarError("console_url is required")
        if not console_url.startswith(("https://", "http://")):
            raise QRadarError("console_url must be an http(s) URL")
        if not api_token:
            raise QRadarError("api_token is required")
        self.console_url = console_url.rstrip("/")
        self._headers = {"SEC": api_token, "Accept": "application/json"}
        if api_version:
            self._headers["Version"] = str(api_version).strip()
        self._verify = tls_verify(verify_ssl, ca_cert_path or None)
        self._timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.console_url,
                headers=self._headers,
                verify=self._verify,
                timeout=self._timeout,
                follow_redirects=False,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(
        self, path: str, params: Dict[str, Any], first: int = 0, count: int = 50
    ) -> Any:
        headers = {"Range": f"items={first}-{first + max(count, 1) - 1}"}
        resp = await self._http().get(path, params=params, headers=headers)
        if resp.status_code >= 300:
            # The body may carry the request back; only the status and QRadar's
            # own message code are kept.
            code = ""
            try:
                code = str(resp.json().get("code", ""))
            except Exception:
                pass
            raise QRadarError(
                f"QRadar {path} answered {resp.status_code}"
                + (f" (code {code})" if code else "")
            )
        return resp.json()

    async def offenses_after(
        self, after_id: int, limit: int, extra_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Offenses with an id above ``after_id``, oldest (lowest id) first."""
        expression = f"id > {int(after_id)}"
        extra = check_filter(extra_filter)
        if extra:
            expression = f"{expression} and ({extra})"
        data = await self._get(
            OFFENSES, {"filter": expression, "sort": "+id"}, count=limit
        )
        if not isinstance(data, list):
            raise QRadarError("QRadar offenses answer is not a list")
        return [o for o in data if isinstance(o, dict)]

    async def newest_offense_id(self) -> int:
        """The highest offense id, 0 when there is none."""
        data = await self._get(OFFENSES, {"fields": "id", "sort": "-id"}, count=1)
        if isinstance(data, list) and data and isinstance(data[0], dict):
            return int(data[0].get("id") or 0)
        return 0

    async def recent_offenses(
        self, limit: int = 50, extra_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """The newest offenses, newest first (the MCP tool)."""
        params: Dict[str, Any] = {"sort": "-id"}
        extra = check_filter(extra_filter)
        if extra:
            params["filter"] = extra
        data = await self._get(OFFENSES, params, count=limit)
        return (
            [o for o in data if isinstance(o, dict)] if isinstance(data, list) else []
        )

    async def offense(self, offense_id: int) -> Dict[str, Any]:
        data = await self._get(f"{OFFENSES}/{int(offense_id)}", {}, count=1)
        if not isinstance(data, dict):
            raise QRadarError("QRadar offense answer is not an object")
        return data

    async def system_about(self) -> Dict[str, Any]:
        """``/api/system/about``: version, for a connection test."""
        data = await self._get("/api/system/about", {}, count=1)
        return data if isinstance(data, dict) else {}
