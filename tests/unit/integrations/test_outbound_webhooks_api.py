"""``/api/webhook-endpoints``: admin-only CRUD, test send and delivery history."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from core.config import get_settings
from core.integrations import outbound_webhooks as hooks
from core.storage.connection import get_db_manager
from core.storage.models import User
from services.api import main as backend_main
from services.api.middleware import auth as auth_module
from tests.unit.integrations._webhook_receiver import start_receiver

pytestmark = pytest.mark.unit

ENDPOINT = "9c1c2d3e-0000-4000-8000-0000000000aa"
ROUTES = [
    ("GET", "/api/webhook-endpoints", None),
    ("POST", "/api/webhook-endpoints", {"name": "x", "url": "https://example.com"}),
    ("GET", f"/api/webhook-endpoints/{ENDPOINT}", None),
    ("PATCH", f"/api/webhook-endpoints/{ENDPOINT}", {"enabled": False}),
    ("DELETE", f"/api/webhook-endpoints/{ENDPOINT}", None),
    ("POST", f"/api/webhook-endpoints/{ENDPOINT}/test", None),
    ("GET", f"/api/webhook-endpoints/{ENDPOINT}/deliveries", None),
    ("POST", f"/api/webhook-endpoints/{ENDPOINT}/deliveries/1/retry", None),
]


def _user() -> User:
    return User(
        user_id="u-1",
        username="ada_admin",
        email="ada@test.local",
        password_hash="",
        role_id="role-admin",
        is_active=True,
        mfa_enabled=False,
    )


@pytest.fixture
def client_as(monkeypatch):
    """A TestClient signed in as a user holding exactly ``granted``."""
    clients = []

    def make(granted: set):
        monkeypatch.setattr(
            "core.auth.auth_service.AuthService.check_permission",
            lambda user_id, perm, session=None: perm in granted,
        )
        app = backend_main.app
        user = _user()
        app.dependency_overrides[auth_module.get_current_active_user] = lambda: user
        app.dependency_overrides[auth_module.get_current_user] = lambda: user
        client = TestClient(app)
        clients.append(client)
        return client

    yield make
    backend_main.app.dependency_overrides.pop(auth_module.get_current_active_user, None)
    backend_main.app.dependency_overrides.pop(auth_module.get_current_user, None)


@pytest.mark.parametrize("method,path,body", ROUTES)
def test_every_route_needs_settings_write(client_as, method, path, body):
    # An analyst-like role: may read settings and change integrations, not
    # settings. Webhooks are egress targets with secrets: admin only.
    client = client_as({"settings.read", "integrations.read", "integrations.write"})

    response = client.request(method, path, json=body)

    assert response.status_code == 403, response.text
    assert "settings.write" in response.json()["detail"]


def test_the_old_csrf_exempt_paths_are_gone(client_as):
    """Management must not live under the CSRF-exempt /api/webhooks/ prefix."""
    client = client_as({"settings.write"})

    for method, path in (("GET", "/api/webhooks/"), ("POST", "/api/webhooks/")):
        assert client.request(method, path, json={}).status_code in (404, 405)


# --- with a database ------------------------------------------------------------

SQL = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "47_webhooks_alert_routes.sql"
)


@pytest.fixture
def db_env(monkeypatch):
    with get_db_manager().engine.begin() as conn:
        conn.execute(text(SQL.read_text(encoding="utf-8")))
        conn.execute(
            text("TRUNCATE webhook_deliveries, alert_routes, webhook_endpoints")
        )
    store: dict = {}
    monkeypatch.setattr(
        hooks, "set_secret", lambda k, v: store.__setitem__(k, v) or True
    )
    monkeypatch.setattr(hooks, "get_secret", lambda k, default=None: store.get(k))
    monkeypatch.setattr(hooks, "delete_secret", lambda k: bool(store.pop(k, 1)))
    monkeypatch.setenv("WEBHOOK_ALLOWED_CIDRS", "127.0.0.1/32")
    get_settings.cache_clear()
    receiver = start_receiver()
    yield store, receiver
    receiver.close()


@pytest.mark.external_service
@pytest.mark.database
def test_crud_test_send_and_deliveries(client_as, db_env):
    store, receiver = db_env
    client = client_as({"settings.write"})

    created = client.post(
        "/api/webhook-endpoints",
        json={
            "name": "siem",
            "url": receiver.url(),
            "event_types": ["case.sla_warning"],
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    secret = body["secret"]
    assert secret.startswith("whsec_") and body["has_secret"] is True
    assert body["created_by"] == "ada_admin"
    assert "secret_ref" not in body
    endpoint_id = body["id"]
    assert list(store.values()) == [secret]

    listed = client.get("/api/webhook-endpoints").json()
    assert [e["name"] for e in listed["endpoints"]] == ["siem"]
    assert "secret" not in listed["endpoints"][0]
    assert listed["event_types"] == ["case.sla_warning", "case.stale_case"]

    assert (
        client.post(
            "/api/webhook-endpoints", json={"name": "siem", "url": receiver.url()}
        ).status_code
        == 409
    )
    bad_type = client.post(
        "/api/webhook-endpoints",
        json={"name": "x", "url": receiver.url(), "event_types": ["case.nope"]},
    )
    assert bad_type.status_code == 422

    sent = client.post(f"/api/webhook-endpoints/{endpoint_id}/test").json()
    assert sent == {
        "delivered": True,
        "outcome": "delivered",
        "status_code": 200,
        "error": None,
    }
    [request] = receiver.requests
    assert request.headers["X-AutoSecOps-Event"] == "webhook.test"
    assert hooks.verify_signature(
        secret, request.headers["X-AutoSecOps-Signature"], request.body
    )

    patched = client.patch(
        f"/api/webhook-endpoints/{endpoint_id}",
        json={"enabled": False, "event_types": []},
    )
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False and patched.json()["event_types"] == []

    hooks.update_endpoint(endpoint_id, enabled=True)
    hooks.enqueue_event("case.stale_case", "stale:c:1", {})
    deliveries = client.get(f"/api/webhook-endpoints/{endpoint_id}/deliveries").json()
    [d] = deliveries["deliveries"]
    assert d["status"] == "pending" and d["event_id"] == "stale:c:1"
    assert (
        client.post(
            f"/api/webhook-endpoints/{endpoint_id}/deliveries/{d['id']}/retry"
        ).status_code
        == 404  # only failed/dead deliveries can be requeued
    )

    assert client.delete(f"/api/webhook-endpoints/{endpoint_id}").json() == {
        "deleted": True
    }
    assert store == {}
    assert client.get(f"/api/webhook-endpoints/{endpoint_id}").status_code == 404


@pytest.mark.external_service
@pytest.mark.database
def test_internal_targets_are_refused_with_a_422(client_as, db_env, monkeypatch):
    monkeypatch.setenv("WEBHOOK_ALLOWED_CIDRS", "")
    get_settings.cache_clear()
    client = client_as({"settings.write"})

    for url in (
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1:9/hook",
        "http://10.0.0.1/hook",
        "file:///etc/passwd",
    ):
        response = client.post(
            "/api/webhook-endpoints", json={"name": "bad", "url": url}
        )
        assert response.status_code == 422, (url, response.text)
    assert client.get("/api/webhook-endpoints").json()["endpoints"] == []
