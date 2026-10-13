"""POST /api/workflows/runs/{id}/resume under the two-person rule (W2.4 verifier #6).

The first approver approving again raised ``SecondApproverConflict`` out of the
route, a 500; it is a 409. A first approval of two does not resume the run.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

from core.deps import (  # noqa: E402
    provide_approvals,
    provide_workflow_runs,
    provide_workflows,
)
from core.response.approval_service import (  # noqa: E402
    PendingAction,
    SecondApproverConflict,
)
from core.storage.models import User  # noqa: E402
from services.api import main as backend_main  # noqa: E402
from services.api.middleware import auth as auth_module  # noqa: E402

pytestmark = pytest.mark.unit

PATH = "/api/workflows/runs/run-1/resume"


def _pending(status="pending"):
    return PendingAction(
        action_id="action-1",
        action_type="disable_user",
        title="t",
        description="d",
        target="bob@example.com",
        confidence=0.9,
        reason="r",
        evidence=[],
        created_at="",
        created_by="workflow",
        requires_approval=True,
        status=status,
        approved_by="alice",
        workflow_run_id="run-1",
    )


class _Runs:
    def get_run(self, run_id):
        return {"run_id": run_id, "status": "paused"}


class _Approvals:
    def __init__(self, outcome):
        self.outcome = outcome
        self.approved: list[tuple[str, str]] = []

    def list_actions(self, **_):
        return [_pending()]

    def approve_action(self, action_id, approved_by="analyst"):
        self.approved.append((action_id, approved_by))
        if isinstance(self.outcome, Exception):
            raise self.outcome
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
    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.check_permission",
        lambda user_id, perm, session=None: True,
    )
    resumed: list[str] = []

    async def _resume(run_id, action_id, decided_by):
        resumed.append(run_id)
        return {"success": True, "status": "resuming", "run_id": run_id}

    monkeypatch.setattr("core.workflows.run_resume.resume_run", _resume)
    approvals = _Approvals(None)
    app = backend_main.app
    overrides = {
        auth_module.get_current_active_user: lambda: user,
        auth_module.get_current_user: lambda: user,
        provide_workflow_runs: lambda: _Runs(),
        provide_approvals: lambda: approvals,
        provide_workflows: lambda: object(),
    }
    app.dependency_overrides.update(overrides)
    try:
        yield TestClient(app), approvals, resumed
    finally:
        for dep in overrides:
            app.dependency_overrides.pop(dep, None)


def test_the_first_approver_approving_again_is_a_409(client):
    http, approvals, resumed = client
    approvals.outcome = SecondApproverConflict("alice already approved action-1")
    response = http.post(PATH, json={})
    assert response.status_code == 409, response.text
    assert "different person" in response.json()["detail"]
    assert resumed == []


def test_a_first_of_two_approvals_does_not_resume_the_run(client):
    http, approvals, resumed = client
    approvals.outcome = _pending("pending")
    response = http.post(PATH, json={})
    assert response.status_code == 200, response.text
    assert response.json()["awaiting"] == "second_approver"
    assert resumed == []


def test_the_deciding_approval_resumes_the_run(client):
    http, approvals, resumed = client
    approvals.outcome = _pending("approved")
    response = http.post(PATH, json={})
    assert response.status_code == 200, response.text
    assert resumed == ["run-1"]
