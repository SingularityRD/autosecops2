"""The Okta MCP entry hands its server the variables it reads (W0.28).

The okta-mcp-server reads ``OKTA_CLIENT_ORGURL`` (a full URL) and
``OKTA_API_TOKEN``. Settings stores the bare domain as ``OKTA_DOMAIN``; the old
entry passed ``OKTA_DOMAIN`` through unchanged, so every call answered "Okta
configuration required" (upstream 596850b6).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.integrations.mcp.service import MCPService

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]


def _okta(tmp_path, monkeypatch):
    shutil.copy(REPO / "mcp-config.json", tmp_path / "mcp-config.json")
    monkeypatch.setenv("OKTA_DOMAIN", "acme.okta.com")
    monkeypatch.setenv("OKTA_API_TOKEN", "test-token")
    monkeypatch.delenv("OKTA_CLIENT_ORGURL", raising=False)
    service = MCPService(
        project_root=tmp_path,
        integration_bridge=SimpleNamespace(derive_remote_mcp_env=lambda: {}),
        detection_rules=SimpleNamespace(get_mcp_env_vars=lambda: {}),
    )
    return service.servers["okta"]


def _passed(server) -> dict:
    """What the child sees: its env, plus any ``-e KEY=VALUE`` docker args."""
    seen = {k: v for k, v in server.env.items() if k.startswith("OKTA_")}
    for arg in server.args:
        key, sep, value = arg.partition("=")
        if sep and key.startswith("OKTA_"):
            seen[key] = value
    return seen


def test_okta_gets_the_org_url_built_from_the_stored_domain(tmp_path, monkeypatch):
    server = _okta(tmp_path, monkeypatch)
    passed = _passed(server)
    assert passed["OKTA_CLIENT_ORGURL"] == "https://acme.okta.com"
    assert passed["OKTA_API_TOKEN"] == "test-token"


def test_okta_still_waits_for_the_domain_and_token(tmp_path, monkeypatch):
    server = _okta(tmp_path, monkeypatch)
    assert server.required_env_vars == ["OKTA_API_TOKEN", "OKTA_DOMAIN"]
