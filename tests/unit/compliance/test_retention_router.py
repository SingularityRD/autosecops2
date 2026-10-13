"""Retention admin API: permissions, dry-run default, error mapping (W3.5).

The service layer is stubbed; its SQL is covered by test_retention_purge.py.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.compliance import retention, retention_router
from core.routing import request_unit_of_work

pytestmark = pytest.mark.unit

PREFIX = retention_router.ROUTER_META.prefix


@pytest.fixture()
def app(authenticate_app):
    app = FastAPI()
    authenticate_app(app)
    app.include_router(retention_router.router, prefix=PREFIX)
    app.dependency_overrides[request_unit_of_work] = lambda: None
    return app


@pytest.fixture()
def client(app):
    return TestClient(app, raise_server_exceptions=False)


def _deny(monkeypatch, permission):
    def _check(user_id, perm, session=None):
        return perm != permission

    monkeypatch.setattr("core.auth.auth_service.AuthService.check_permission", _check)


WRITES = [
    ("PUT", "/policies/findings", {"retain_days": 30}),
    ("DELETE", "/policies/findings", None),
    ("PUT", "/legal-holds/cases/c-1", {"reason": "dava"}),
    ("DELETE", "/legal-holds/cases/c-1", None),
    ("POST", "/purge", {}),
    ("GET", "/agent-ledger/archive?before=2026-01-01T00:00:00", None),
]
READS = ["/classes", "/policies", "/legal-holds", "/reports"]


@pytest.mark.parametrize("method,path,body", WRITES)
def test_writes_need_settings_write(client, monkeypatch, method, path, body):
    _deny(monkeypatch, "settings.write")
    response = client.request(method, PREFIX + path, json=body)
    assert response.status_code == 403, response.text


@pytest.mark.parametrize("path", READS)
def test_reads_need_settings_read(client, monkeypatch, path):
    _deny(monkeypatch, "settings.read")
    assert client.get(PREFIX + path).status_code == 403


def test_classes_list_every_class_and_mark_the_ledger_chained(client):
    classes = {
        c["data_class"]: c for c in client.get(PREFIX + "/classes").json()["classes"]
    }
    assert set(classes) == set(retention.DATA_CLASSES)
    assert classes["agent_ledger"]["chained"] is True
    assert classes["agent_ledger"]["methods"] == []


def test_purge_is_a_dry_run_unless_asked(client, monkeypatch):
    seen = {}

    def _run(**kwargs):
        seen.update(kwargs)
        return {"dry_run": kwargs["dry_run"]}

    monkeypatch.setattr(retention, "run_purge", _run)
    assert client.post(PREFIX + "/purge", json={}).json() == {"dry_run": True}
    assert seen["actor"] == "test-admin"

    client.post(PREFIX + "/purge", json={"dry_run": False})
    assert seen["dry_run"] is False


def test_purge_maps_busy_and_bad_requests(client, monkeypatch):
    def _busy(**kwargs):
        raise retention.RetentionBusy("x")

    monkeypatch.setattr(retention, "run_purge", _busy)
    assert client.post(PREFIX + "/purge", json={}).status_code == 409

    def _bad(**kwargs):
        raise retention.RetentionError("unknown data class: nope")

    monkeypatch.setattr(retention, "run_purge", _bad)
    response = client.post(PREFIX + "/purge", json={"data_classes": ["nope"]})
    assert response.status_code == 400


def test_purge_rejects_batch_sizes_out_of_range(client):
    response = client.post(PREFIX + "/purge", json={"batch_size": 0})
    assert response.status_code == 422
    response = client.post(
        PREFIX + "/purge", json={"max_batches": retention.MAX_BATCHES + 1}
    )
    assert response.status_code == 422


def test_policy_errors_are_400_and_the_actor_is_the_user(client, monkeypatch):
    seen = {}

    def _set(session, data_class, **kwargs):
        seen.update(kwargs, data_class=data_class)
        if data_class == "agent_ledger":
            raise retention.RetentionError("hash-chained")
        return {"data_class": data_class}

    monkeypatch.setattr(retention, "set_policy", _set)
    ok = client.put(PREFIX + "/policies/findings", json={"retain_days": 30})
    assert ok.status_code == 200 and seen["actor"] == "test-admin"
    bad = client.put(
        PREFIX + "/policies/agent_ledger", json={"retain_days": 30, "method": "delete"}
    )
    assert bad.status_code == 400
    assert (
        client.put(PREFIX + "/policies/findings", json={"retain_days": 0}).status_code
        == 422
    )


def test_legal_hold_on_a_missing_case_is_404(client, monkeypatch):
    def _missing(session, case_id, **kwargs):
        raise LookupError(case_id)

    monkeypatch.setattr(retention, "set_legal_hold", _missing)
    response = client.put(PREFIX + "/legal-holds/cases/c-x", json={"reason": "dava"})
    assert response.status_code == 404


def test_report_as_markdown(client, monkeypatch):
    monkeypatch.setattr(
        retention,
        "build_destruction_report",
        lambda session, since, until: {"since": since, "until": until},
    )
    monkeypatch.setattr(retention, "render_markdown", lambda report: "# tutanak\n")
    response = client.get(PREFIX + "/reports?format=markdown")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.text == "# tutanak\n"

    bad = client.get(
        PREFIX + "/reports?since=2026-02-01T00:00:00&until=2026-01-01T00:00:00"
    )
    assert bad.status_code == 400


def test_purge_with_an_empty_class_list_is_400_not_all(client, monkeypatch):
    # The real run_purge: it refuses before touching the database.
    response = client.post(
        PREFIX + "/purge", json={"data_classes": [], "dry_run": False}
    )
    assert response.status_code == 400
    assert "at least one" in response.json()["detail"]


def test_every_retention_audit_action_fits_the_column():
    # config_audit_log.action is VARCHAR(20).
    assert all(len(a) <= 20 for a in retention.AUDIT_ACTIONS)
    assert retention.LEDGER_ARCHIVE_ACTION in retention.AUDIT_ACTIONS
