"""POST /api/response/actions/{id}/revert (W2.4): RBAC, a reason, and outcomes."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

from core.deps import provide_response  # noqa: E402
from core.storage.models import User  # noqa: E402
from services.api import main as backend_main  # noqa: E402
from services.api.middleware import auth as auth_module  # noqa: E402

pytestmark = pytest.mark.unit

PATH = "/api/response/actions/action-1/revert"


class _Response:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls = []

    def reverse_action(self, action_id, *, actor, reason):
        self.calls.append((action_id, actor, reason))
        return self.outcome


@pytest.fixture
def client(monkeypatch):
    user = User(
        user_id="u-1",
        username="alice",
        email="a@test.local",
        password_hash="",
        role_id="role-analyst",
        is_active=True,
        mfa_enabled=False,
    )
    granted = {"value": True}
    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.check_permission",
        lambda user_id, perm, session=None: granted["value"],
    )
    app = backend_main.app
    app.dependency_overrides[auth_module.get_current_active_user] = lambda: user
    app.dependency_overrides[auth_module.get_current_user] = lambda: user
    fake = _Response({"outcome": "reversed"})
    app.dependency_overrides[provide_response] = lambda: fake
    try:
        yield TestClient(app), fake, granted
    finally:
        for dep in (
            auth_module.get_current_active_user,
            auth_module.get_current_user,
            provide_response,
        ):
            app.dependency_overrides.pop(dep, None)


def test_a_revert_names_the_session_user_and_the_reason(client):
    http, fake, _ = client
    fake.outcome = {
        "outcome": "reversed",
        "reverse_action_id": "action-1-rev",
        "verify_status": "verified",
        "reversed_at": "2026-10-12T00:00:00",
        "message": "rule removed",
    }
    response = http.post(PATH, json={"reason": "false positive"})
    assert response.status_code == 200, response.text
    assert response.json()["reverse_action_id"] == "action-1-rev"
    assert fake.calls == [("action-1", "alice", "false positive")]


@pytest.mark.parametrize("body", [{}, {"reason": ""}, {"reason": "   "}])
def test_a_reason_is_required(client, body):
    http, fake, _ = client
    assert http.post(PATH, json=body).status_code == 422
    assert fake.calls == []


def test_without_the_permission_it_is_refused(client):
    http, fake, granted = client
    granted["value"] = False
    assert http.post(PATH, json={"reason": "x"}).status_code == 403
    assert fake.calls == []


@pytest.mark.parametrize(
    "outcome,status",
    [
        ({"outcome": "not_found"}, 404),
        ({"outcome": "conflict", "message": "waf_block is irreversible"}, 409),
        ({"outcome": "failed", "reverse_action_id": "r"}, 502),
    ],
)
def test_outcomes_map_to_statuses(client, outcome, status):
    http, fake, _ = client
    fake.outcome = outcome
    assert http.post(PATH, json={"reason": "x"}).status_code == status
