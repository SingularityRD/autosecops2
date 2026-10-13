"""Cloudflare REST calls for the response actions.

Shared by the MCP tool server (``tool.py``) and the approved-action executor
(``executor.py``), so the Cloudflare API surface is written once. No MCP
imports here: the executor runs inside the API and daemon processes.

Each helper returns a plain dict with ``success`` and never raises for an HTTP
error status; transport errors (timeouts, DNS) do raise, and the caller turns
them into a failed result.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx

CF_API_BASE = "https://api.cloudflare.com/client/v4"
DEFAULT_TIMEOUT = 30


def _headers(api_token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }


def _json(resp: httpx.Response) -> Dict[str, Any]:
    if not resp.content:
        return {}
    try:
        data = resp.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _waf_block_ip(
    api_token: str,
    account_id: Optional[str],
    ip: Optional[str],
    reason: str,
    mode: str = "block",
) -> Dict[str, Any]:
    if not ip:
        return {"error": "ip required"}
    if not account_id:
        return {"error": "account_id required for WAF IP Access Rules"}
    payload = {
        "mode": mode,
        "configuration": {"target": "ip", "value": ip},
        "notes": reason[:1024],
    }
    resp = httpx.post(
        f"{CF_API_BASE}/accounts/{account_id}/firewall/access_rules/rules",
        headers=_headers(api_token),
        json=payload,
        timeout=DEFAULT_TIMEOUT,
    )
    data = resp.json() if resp.content else {}
    success = resp.status_code in (200, 201) and data.get("success", False)
    return {
        "success": success,
        "status_code": resp.status_code,
        "rule_id": (data.get("result") or {}).get("id"),
        "ip": ip,
        "mode": mode,
        "errors": data.get("errors"),
    }


def _waf_unblock_ip(
    api_token: str, account_id: Optional[str], rule_id: Optional[str]
) -> Dict[str, Any]:
    if not rule_id:
        return {"error": "rule_id required"}
    if not account_id:
        return {"error": "account_id required"}
    resp = httpx.delete(
        f"{CF_API_BASE}/accounts/{account_id}/firewall/access_rules/rules/{rule_id}",
        headers=_headers(api_token),
        timeout=DEFAULT_TIMEOUT,
    )
    data = resp.json() if resp.content else {}
    return {
        "success": resp.status_code in (200, 204) and data.get("success", True),
        "status_code": resp.status_code,
        "rule_id": rule_id,
        "errors": data.get("errors"),
    }


def _gateway_block_domain(
    api_token: str,
    account_id: Optional[str],
    domain: Optional[str],
    reason: str,
    rule_name: Optional[str],
) -> Dict[str, Any]:
    if not domain:
        return {"error": "domain required"}
    if not account_id:
        return {"error": "account_id required for Zero Trust Gateway rules"}
    payload = {
        "name": rule_name or f"vigil-block-{domain}",
        "description": reason[:512],
        "action": "block",
        "filters": ["dns", "http"],
        "traffic": f'any(dns.domains[*] in {{"{domain}"}}) or http.host == "{domain}"',
        "enabled": True,
    }
    resp = httpx.post(
        f"{CF_API_BASE}/accounts/{account_id}/gateway/rules",
        headers=_headers(api_token),
        json=payload,
        timeout=DEFAULT_TIMEOUT,
    )
    data = resp.json() if resp.content else {}
    success = resp.status_code in (200, 201) and data.get("success", False)
    return {
        "success": success,
        "status_code": resp.status_code,
        "rule_id": (data.get("result") or {}).get("id"),
        "domain": domain,
        "errors": data.get("errors"),
    }


def _access_revoke_session(
    api_token: str,
    account_id: Optional[str],
    email: Optional[str],
    reason: str,
) -> Dict[str, Any]:
    if not email:
        return {"error": "email required"}
    if not account_id:
        return {"error": "account_id required for Access session revoke"}
    resp = httpx.post(
        f"{CF_API_BASE}/accounts/{account_id}/access/organizations/revoke_user",
        headers=_headers(api_token),
        json={"email": email},
        timeout=DEFAULT_TIMEOUT,
    )
    data = resp.json() if resp.content else {}
    return {
        "success": resp.status_code in (200, 201) and data.get("success", False),
        "status_code": resp.status_code,
        "email": email,
        "reason": reason,
        "errors": data.get("errors"),
    }


def _gateway_unblock_domain(
    api_token: str, account_id: Optional[str], rule_id: Optional[str]
) -> Dict[str, Any]:
    if not rule_id:
        return {"error": "rule_id required"}
    if not account_id:
        return {"error": "account_id required"}
    resp = httpx.delete(
        f"{CF_API_BASE}/accounts/{account_id}/gateway/rules/{rule_id}",
        headers=_headers(api_token),
        timeout=DEFAULT_TIMEOUT,
    )
    data = _json(resp)
    return {
        "success": resp.status_code in (200, 204) and data.get("success", True),
        "status_code": resp.status_code,
        "rule_id": rule_id,
        "errors": data.get("errors"),
    }


def _get_rule(
    api_token: str, account_id: Optional[str], path: str, rule_id: str
) -> Dict[str, Any]:
    """Whether a rule exists: ``{"found": bool}``, or ``{"error": ...}`` when unknown."""
    if not account_id or not rule_id:
        return {"error": "account_id and rule_id required"}
    resp = httpx.get(
        f"{CF_API_BASE}/accounts/{account_id}/{path}/{rule_id}",
        headers=_headers(api_token),
        timeout=DEFAULT_TIMEOUT,
    )
    if resp.status_code == 404:
        return {"found": False, "status_code": 404}
    data = _json(resp)
    if resp.status_code == 200 and data.get("success", False):
        return {"found": True, "status_code": 200, "rule": data.get("result") or {}}
    return {"error": f"HTTP {resp.status_code}", "status_code": resp.status_code}


def _waf_get_rule(
    api_token: str, account_id: Optional[str], rule_id: str
) -> Dict[str, Any]:
    return _get_rule(api_token, account_id, "firewall/access_rules/rules", rule_id)


def _gateway_get_rule(
    api_token: str, account_id: Optional[str], rule_id: str
) -> Dict[str, Any]:
    return _get_rule(api_token, account_id, "gateway/rules", rule_id)
