"""Connecting a response executor from Settings (W0.37, gaps SA-01 / KS-18).

Saving the executor's integration stores its credential in the secret store and
takes effect in the API process at once (the registry is invalidated); Test
reports whether its actions are available now; and no response hands a
credential back to the browser.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.deps import provide_executors, provide_integration_bridge, provide_mcp_client
from core.integrations.integration_bridge_service import IntegrationBridgeService
from core.response.executors.wiring import EXECUTOR_SOURCES, LiveExecutorRegistry
from services.api.routers.config import router as config_router

pytestmark = pytest.mark.unit

SECRETS = {
    "microsoft-defender": ("client_secret", "MICROSOFT_DEFENDER_CLIENT_SECRET"),
    "azure-ad": ("client_secret", "AZURE_AD_CLIENT_SECRET"),
    "palo-alto": ("api_key", "PALO_ALTO_API_KEY"),
}
FORMS = {
    "microsoft-defender": {"tenant_id": "t", "client_id": "c"},
    "azure-ad": {"tenant_id": "t", "client_id": "c"},
    "palo-alto": {"hostname": "fw.example.test", "verify_ssl": True},
}
VALUE = "credential-value-not-real"


class _Rows:
    """integration_configs as the API sees it."""

    def __init__(self) -> None:
        self.rows: Dict[str, Dict[str, Any]] = {}
        self.tests: List[dict] = []

    def get_integration_config(self, integration_id):
        row = self.rows.get(integration_id)
        return {"config": row["config"]} if row else None

    def set_integration_config(self, integration_id, config, enabled=True, **kw):
        self.rows[integration_id] = {"config": dict(config), "enabled": enabled}
        return True

    def record_integration_test(self, integration_id, **kw):
        self.tests.append({"integration_id": integration_id, **kw})
        return True

    def loaded(self) -> dict:
        return {
            "configured": True,
            "enabled_integrations": [i for i, r in self.rows.items() if r["enabled"]],
            "integrations": {i: r["config"] for i, r in self.rows.items()},
        }


class _Mcp:
    class _Service:
        def reload_server_configs(self):
            pass

        def is_server_enabled(self, name):
            return True

    def __init__(self):
        self.mcp_service = self._Service()
        self.persistent_sessions = {}

    async def connect_to_server(self, name, persistent=True, skip_enabled_check=False):
        return True

    def get_last_error(self, name):
        return None

    def get_missing_credentials(self, name):
        return None


@pytest.fixture()
def world(authenticate_app, monkeypatch):
    """An API app whose config rows, secret store and executors are in memory."""
    rows = _Rows()
    secrets: Dict[str, str] = {}

    def config_for(integration_id):
        """What resolved_integration_config gives: the row plus its secret."""
        config = dict(rows.rows.get(integration_id, {}).get("config", {}))
        field, env = SECRETS[integration_id]
        if env in secrets:
            config[field] = secrets[env]
        return config

    registry = LiveExecutorRegistry(
        EXECUTOR_SOURCES,
        enabled=lambda i: rows.rows.get(i, {}).get("enabled", False),
        config_for=config_for,
        # an hour: anything seen sooner than that came from invalidate()
        reload_seconds=3600,
    )
    app = FastAPI()
    app.include_router(config_router, prefix="/api/config")
    app.state.executors = registry
    authenticate_app(app)
    bridge = IntegrationBridgeService()
    bridge.load_integration_config = rows.loaded
    app.dependency_overrides[provide_integration_bridge] = lambda: bridge
    app.dependency_overrides[provide_mcp_client] = lambda: _Mcp()

    def set_secret(key, value):
        secrets[key] = value
        return True

    monkeypatch.setattr("services.api.routers.config.set_secret", set_secret)
    monkeypatch.setattr(
        "services.api.routers.config.get_secret", lambda key, default=None: secrets.get(key)
    )
    monkeypatch.setattr(
        "services.api.routers.config.get_config_service", lambda *a, **k: rows
    )
    monkeypatch.setattr(
        "services.api.routers.config.load_integrations_config",
        lambda *a, **k: rows.loaded(),
    )
    monkeypatch.setattr("services.api.routers.config._mirror_to_file", lambda *a: None)
    return TestClient(app), rows, secrets, registry


def _save(client, integration_id, *, enabled=True, secret=VALUE):
    field, _ = SECRETS[integration_id]
    return client.post(
        "/api/config/integrations",
        json={
            "enabled_integrations": [integration_id] if enabled else [],
            "integrations": {integration_id: {**FORMS[integration_id], field: secret}},
        },
    )


@pytest.mark.parametrize("integration_id", sorted(SECRETS))
def test_saving_an_executor_stores_the_secret_and_enables_it_at_once(
    world, integration_id
):
    client, rows, secrets, registry = world
    assert registry.action_types_for(integration_id) == frozenset()

    assert _save(client, integration_id).status_code == 200

    field, env = SECRETS[integration_id]
    assert secrets[env] == VALUE
    assert field not in rows.rows[integration_id]["config"]
    # no restart, and no wait for reload_seconds: the save invalidated the registry
    assert registry.action_types_for(integration_id)


@pytest.mark.parametrize("integration_id", sorted(SECRETS))
def test_disabling_in_settings_takes_the_executor_away_at_once(world, integration_id):
    client, _, _, registry = world
    _save(client, integration_id)
    assert registry.action_types_for(integration_id)

    assert _save(client, integration_id, enabled=False, secret="").status_code == 200
    assert registry.action_types_for(integration_id) == frozenset()


def test_test_reports_the_executor_live_and_never_echoes_the_secret(world):
    client, _, _, _ = world
    _save(client, "palo-alto")

    async def refused(integration_id):
        return False, "HTTP 403: Invalid credentials."

    with patch("services.api.routers.config.check_credentials", refused):
        body = client.post("/api/config/integrations/palo-alto/test").json()

    assert body["executor"] == {"available": True, "action_types": ["block_ip", "unblock_ip"]}
    assert body["success"] is False
    assert body["credentials"] == {"success": False, "message": "HTTP 403: Invalid credentials."}
    assert VALUE not in json.dumps(body)


def test_test_says_a_disabled_executor_is_not_available(world):
    client, _, _, _ = world
    _save(client, "azure-ad", enabled=False)

    async def accepted(integration_id):
        return True, "Token issued; users readable"

    with patch("services.api.routers.config.check_credentials", accepted):
        body = client.post("/api/config/integrations/azure-ad/test").json()

    assert body["executor"] == {"available": False, "action_types": []}


def test_a_connector_with_no_executor_has_no_executor_field(world):
    client, rows, _, _ = world
    rows.rows["virustotal"] = {"config": {}, "enabled": True}

    async def none(integration_id):
        return None

    with patch("services.api.routers.config.check_credentials", none):
        body = client.post("/api/config/integrations/virustotal/test").json()

    assert "executor" not in body


def test_get_never_returns_an_executor_credential(world):
    client, rows, _, _ = world
    for integration_id in SECRETS:
        _save(client, integration_id)
        # a row written before the secret store held the value in plaintext
        field, _ = SECRETS[integration_id]
        rows.rows[integration_id]["config"][field] = VALUE

    body = client.get("/api/config/integrations").json()

    assert VALUE not in json.dumps(body)
    for integration_id, (field, _) in SECRETS.items():
        assert field not in body["integrations"][integration_id]
        assert body["secrets_set"][integration_id] == {field: True}


def test_provide_executors_is_none_without_a_registry():
    class _Req:
        class app:  # noqa: N801
            class state:  # noqa: N801
                pass

    assert provide_executors(_Req()) is None
