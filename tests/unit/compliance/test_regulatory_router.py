"""Regulatory clock API: RBAC, actor from the login, audit, drafts (W3.8).

The SQL store is swapped for the in-memory one; its SQL is covered by
tests/unit/storage/test_regulatory_clocks_db.py.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.compliance import regulatory_config_router, regulatory_router
from core.compliance.regulatory_drafts import build_evidence_pack
from core.compliance.regulatory_service import MemoryClockStore
from core.routing import request_unit_of_work

pytestmark = pytest.mark.unit

CASES = regulatory_router.ROUTER_META.prefix
CONFIG = regulatory_config_router.ROUTER_META.prefix


@pytest.fixture()
def store(monkeypatch):
    store = MemoryClockStore(cases={"c-1"})
    monkeypatch.setattr(regulatory_router, "_store", lambda session: store)
    monkeypatch.setattr(
        regulatory_config_router, "SqlClockStore", lambda session: store
    )
    monkeypatch.setattr(
        regulatory_router,
        "_evidence_pack",
        lambda session, case_id, events: build_evidence_pack(
            {"case_id": case_id, "title": "Outage"},
            findings=[{"finding_id": "f-1", "title": "Beacon"}],
            clock_events=events,
        ),
    )
    return store


@pytest.fixture()
def client(authenticate_app, store):
    app = FastAPI()
    authenticate_app(app)
    app.include_router(regulatory_router.router, prefix=CASES)
    app.include_router(regulatory_config_router.router, prefix=CONFIG)
    app.dependency_overrides[request_unit_of_work] = lambda: None
    return TestClient(app, raise_server_exceptions=False)


def _deny(monkeypatch, permission):
    def _check(user_id, perm, session=None):
        return perm != permission

    monkeypatch.setattr("core.auth.auth_service.AuthService.check_permission", _check)


AWARE = {"regime": "nis2", "instant": "aware_at", "value": "2026-03-02T08:00:00+00:00"}

ROUTES = [
    ("GET", f"{CASES}/c-1/regulatory/clocks", None, "cases.read"),
    ("GET", f"{CASES}/c-1/regulatory/events", None, "cases.read"),
    ("GET", f"{CASES}/c-1/regulatory/drafts", None, "cases.read"),
    ("POST", f"{CASES}/c-1/regulatory/events", AWARE, "cases.write"),
    (
        "POST",
        f"{CASES}/c-1/regulatory/drafts",
        {"regime": "dora", "kind": "initial"},
        "cases.write",
    ),
    ("GET", f"{CONFIG}/config", None, "settings.read"),
    ("PUT", f"{CONFIG}/config", {"timezone": "Europe/Berlin"}, "settings.write"),
]


@pytest.mark.parametrize("method,path,body,permission", ROUTES)
def test_each_route_needs_its_permission(
    client, store, monkeypatch, method, path, body, permission
):
    _deny(monkeypatch, permission)
    response = client.request(method, path, json=body)
    assert response.status_code == 403, response.text
    assert permission in response.json()["detail"]
    assert store.rows == [] and store.audits == [] and store.config_rows == {}


@pytest.mark.parametrize("method,path,body,permission", ROUTES)
def test_each_route_works_with_its_permission(
    client, monkeypatch, method, path, body, permission
):
    _deny(monkeypatch, "something.else")
    assert client.request(method, path, json=body).status_code == 200


def test_a_viewer_reads_but_cannot_record(client, store, monkeypatch):
    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.check_permission",
        lambda user_id, perm, session=None: perm == "cases.read",
    )
    assert client.get(f"{CASES}/c-1/regulatory/clocks").status_code == 200
    assert client.post(f"{CASES}/c-1/regulatory/events", json=AWARE).status_code == 403
    assert store.rows == []


def test_recording_uses_the_login_as_actor_and_returns_clocks(client, store):
    response = client.post(
        f"{CASES}/c-1/regulatory/events", json={**AWARE, "actor": "someone-else"}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["changed"] is True
    assert body["event"]["actor"] == "test-admin"
    assert store.audits[-1]["changed_by"] == "test-admin"
    early = next(
        c for c in body["status"]["clocks"] if c["key"] == "nis2.early_warning"
    )
    assert early["due_at"] == "2026-03-03T08:00:00+00:00"
    assert early["bound_to"] == "aware_at"
    assert set(early) >= {"due_at", "remaining_seconds", "overdue", "state"}


def test_a_change_without_reason_is_422_and_records_nothing(client, store):
    client.post(f"{CASES}/c-1/regulatory/events", json=AWARE)
    moved = {**AWARE, "value": "2026-03-02T06:00:00+00:00"}
    response = client.post(f"{CASES}/c-1/regulatory/events", json=moved)
    assert response.status_code == 422
    assert "reason" in response.json()["detail"]
    assert len(store.rows) == 1
    ok = client.post(
        f"{CASES}/c-1/regulatory/events", json={**moved, "reason": "earlier alert"}
    )
    assert ok.status_code == 200
    events = client.get(f"{CASES}/c-1/regulatory/events").json()
    assert [e["seq"] for e in events["events"]] == [1, 2]
    assert events["events"][1]["previous_value"] == "2026-03-02T08:00:00+00:00"
    assert events["chain"]["ok"] is True


@pytest.mark.parametrize(
    "body",
    [
        {**AWARE, "value": "2026-03-02T08:00:00"},  # no offset
        {**AWARE, "instant": "classification_at"},  # not a NIS2 instant
        {**AWARE, "regime": "gdpr"},
        {**AWARE, "value": "2999-01-01T00:00:00+00:00"},
    ],
)
def test_bad_instants_are_422(client, store, body):
    assert client.post(f"{CASES}/c-1/regulatory/events", json=body).status_code == 422
    assert store.rows == []


def test_unknown_case_is_404(client):
    assert client.get(f"{CASES}/nope/regulatory/clocks").status_code == 404
    assert client.post(f"{CASES}/nope/regulatory/events", json=AWARE).status_code == 404
    assert (
        client.post(
            f"{CASES}/nope/regulatory/drafts",
            json={"regime": "dora", "kind": "initial"},
        ).status_code
        == 404
    )


def test_a_draft_is_stored_audited_and_cites_the_pack(client, store):
    client.post(f"{CASES}/c-1/regulatory/events", json=AWARE)
    response = client.post(
        f"{CASES}/c-1/regulatory/drafts",
        json={"regime": "nis2", "kind": "early_warning"},
    )
    assert response.status_code == 200, response.text
    draft = response.json()
    assert draft["generator"] == "template"
    assert set(draft["cited_ids"]) <= {"case:c-1", "finding:f-1", "clock:1"}
    assert "finding:f-1" in draft["cited_ids"]
    assert draft["created_by"] == "test-admin"
    assert store.audits[-1]["field_name"] == "regulatory.draft.nis2.early_warning"
    listed = client.get(f"{CASES}/c-1/regulatory/drafts").json()["drafts"]
    assert [d["draft_id"] for d in listed] == [draft["draft_id"]]


def test_a_kind_from_the_other_regime_is_422(client):
    response = client.post(
        f"{CASES}/c-1/regulatory/drafts",
        json={"regime": "dora", "kind": "early_warning"},
    )
    assert response.status_code == 422


def test_config_round_trip_and_refusal(client, store):
    put = client.put(
        f"{CONFIG}/config",
        json={
            "timezone": "Europe/Berlin",
            "durations": {"dora.initial_after_classification": {"hours": 2}},
        },
    )
    assert put.status_code == 200, put.text
    assert put.json()["durations"]["dora.initial_after_classification"] == {
        "hours": 2,
        "months": 0,
    }
    assert store.config_audits[-1]["changed_by"] == "test-admin"
    got = client.get(f"{CONFIG}/config").json()
    assert got["timezone"] == "Europe/Berlin"
    assert got["defaults"]["dora.initial_after_classification"] == {
        "hours": 4,
        "months": 0,
    }
    bad = client.put(
        f"{CONFIG}/config",
        json={"timezone": "Europe/Berlin", "durations": {"x": {"hours": 1}}},
    )
    assert bad.status_code == 422
    assert client.get(f"{CONFIG}/config").json()["timezone"] == "Europe/Berlin"
