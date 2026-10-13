"""/api/autonomy (W3.1): RBAC, people only, evidence, and refusals to statuses."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

from core.autonomy import AutonomyController  # noqa: E402
from core.autonomy.autonomy_router import provide_autonomy  # noqa: E402
from core.autonomy.tiers import AUTONOMOUS, TierEntry  # noqa: E402
from core.storage.models import User  # noqa: E402
from services.api import main as backend_main  # noqa: E402
from services.api.middleware import auth as auth_module  # noqa: E402
from tests.unit.response._autonomy import MemoryTierStore, bounds  # noqa: E402

pytestmark = pytest.mark.unit

PATH = "/api/autonomy/tiers/phishing/waf_block"
PROMOTE = {
    "tier": "autonomous",
    "reason": "Scorecard met",
    "evidence_url": "https://console.example/scorecard",
    "min_confidence": 0.9,
    "max_ttl_seconds": 3600,
}


@pytest.fixture
def client(monkeypatch):
    user = User(
        user_id="u-1",
        username="alice",
        email="a@test.local",
        password_hash="",
        role_id="role-admin",
        is_active=True,
        mfa_enabled=False,
        service_account=False,
    )
    granted = {"value": True}
    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.check_permission",
        lambda user_id, perm, session=None: granted["value"],
    )
    store = MemoryTierStore()
    controller = AutonomyController(store=store, bound_reader=bounds(True))
    app = backend_main.app
    app.dependency_overrides[auth_module.get_current_active_user] = lambda: user
    app.dependency_overrides[auth_module.get_current_user] = lambda: user
    app.dependency_overrides[provide_autonomy] = lambda: controller
    try:
        yield TestClient(app), controller, store, granted, user
    finally:
        for dep in (
            auth_module.get_current_active_user,
            auth_module.get_current_user,
            provide_autonomy,
        ):
            app.dependency_overrides.pop(dep, None)


def test_the_matrix_defaults_to_approve(client):
    http, *_ = client
    body = http.get("/api/autonomy/tiers").json()
    assert body["default_tier"] == "approve"
    assert {e["tier"] for e in body["entries"]} == {"approve"}
    assert body["fn_bound_min_reviews"] == 299


def test_a_person_promotes_with_evidence_and_it_is_audited(client):
    http, _, store, _, _ = client
    response = http.put(PATH, json=PROMOTE)
    assert response.status_code == 200, response.text
    assert response.json()["tier"] == AUTONOMOUS
    assert response.json()["eligible"] is True
    audit = http.get("/api/autonomy/audit").json()["entries"]
    assert audit[0]["action"] == "promote"
    assert audit[0]["changed_by"] == "alice"


def test_a_service_account_cannot_change_a_tier(client):
    http, _, store, _, user = client
    user.service_account = True
    assert http.put(PATH, json=PROMOTE).status_code == 403
    assert store.rows == {}


def test_without_settings_write_it_is_refused(client):
    http, _, store, granted, _ = client
    granted["value"] = False
    assert http.put(PATH, json=PROMOTE).status_code == 403
    assert http.post("/api/autonomy/check").status_code == 403
    assert store.rows == {}


def test_an_irreversible_class_is_422(client):
    http, _, store, _, _ = client
    response = http.put("/api/autonomy/tiers/identity/access_revoke", json=PROMOTE)
    assert response.status_code == 422
    assert store.rows == {}


def test_no_evidence_is_422(client):
    http, *_ = client
    body = {k: v for k, v in PROMOTE.items() if k != "evidence_url"}
    assert http.put(PATH, json=body).status_code == 422


def test_a_bound_that_does_not_hold_is_409(client):
    http, controller, store, _, _ = client
    controller.bound_reader = bounds(False)
    assert http.put(PATH, json=PROMOTE).status_code == 409
    assert store.rows == {}


def test_check_demotes_and_reports(client):
    http, controller, store, _, _ = client
    store.rows[("phishing", "waf_block")] = TierEntry(
        "phishing", "waf_block", AUTONOMOUS, 0.5, 3600, explicit=True
    )
    controller.bound_reader = bounds(False)
    body = http.post("/api/autonomy/check").json()
    assert body["demoted"][0]["to"] == "approve"
    assert store.rows[("phishing", "waf_block")].tier == "approve"


def test_no_agent_or_mcp_tool_can_set_a_tier():
    """Only the HTTP route (a signed-in person) reaches set_tier."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    for rel in ("core/agents", "tools", "core/chat", "core/workflows"):
        for path in (root / rel).rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert "set_tier" not in text, path
            assert "autonomy_tiers" not in text, path
