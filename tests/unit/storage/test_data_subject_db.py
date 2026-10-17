"""Data-subject requests against a real Postgres (W0.48).

Everything runs in one transaction that is rolled back: a person's data is
planted in a finding, a case, a comment and a user, then found and exported
through the API, and every lookup is on the request's audit trail.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.compliance import data_subject, data_subject_router
from core.routing import request_unit_of_work
from core.storage.connection import get_db_manager
from core.storage.models import ConfigAuditLog

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

PREFIX = data_subject_router.ROUTER_META.prefix
WHO = "zeynep.kaya@w048-musteri.example"


@pytest.fixture()
def session():
    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            with Session(bind=conn, join_transaction_mode="create_savepoint") as s:
                s.execute(
                    text(
                        "INSERT INTO findings (finding_id, data_source, title, description,"
                        " entity_context, timestamp, severity, status, created_at, updated_at)"
                        " VALUES ('w048-f1', 'test', 'Phish', 'clicked by user',"
                        " CAST(:ctx AS jsonb), now(), 'high', 'new', now(), now()),"
                        " ('w048-f2', 'test', 'Other', 'nothing here', '{}'::jsonb, now(),"
                        " 'low', 'new', now(), now())"
                    ),
                    {"ctx": '{"usernames": ["%s"]}' % WHO.upper()},
                )
                s.execute(
                    text(
                        "INSERT INTO cases (case_id, title, description, status, priority,"
                        " timeline, created_at, updated_at) VALUES ('w048-c1', 'Phish',"
                        " :d, 'open', 'high', '[]'::jsonb, now(), now())"
                    ),
                    {"d": f"Reported by {WHO}"},
                )
                s.execute(
                    text(
                        "INSERT INTO case_comments (case_id, author, content, is_edited,"
                        " is_deleted, created_at, updated_at) VALUES ('w048-c1', 'ayse',"
                        " :c, false, false, now(), now())"
                    ),
                    {"c": f"called {WHO} back"},
                )
                yield s
        finally:
            tx.rollback()


@pytest.fixture()
def client(authenticate_app, session):
    app = FastAPI()
    authenticate_app(app)
    app.include_router(data_subject_router.router, prefix=PREFIX)
    app.dependency_overrides[request_unit_of_work] = lambda: session
    return TestClient(app, raise_server_exceptions=False)


def _register(client, **over):
    body = {"identifier": WHO, "kind": "access", "reference": "KVKK-2026-17", **over}
    response = client.post(f"{PREFIX}/requests", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def test_a_request_is_due_in_30_days_and_does_not_store_the_identifier(client, session):
    received = (datetime.utcnow() - timedelta(days=45)).replace(microsecond=0)
    request = _register(client, received_at=received.isoformat())
    assert request["due_at"] == (received + timedelta(days=30)).isoformat()
    assert request["identifier_hint"] == "z***@w048-musteri.example"
    assert request["state"] == "open"
    rows = (
        session.query(ConfigAuditLog)
        .filter(ConfigAuditLog.config_key == request["request_id"])
        .all()
    )
    assert len(rows) == 1
    assert WHO not in repr(rows[0].new_value) and WHO not in (
        rows[0].change_reason or ""
    )
    listed = client.get(f"{PREFIX}/requests").json()["requests"]
    mine = next(r for r in listed if r["request_id"] == request["request_id"])
    assert mine["overdue"] is True  # received 45 days ago
    fresh = _register(client)
    assert fresh["overdue"] is False and fresh["days_left"] in (29, 30)


def test_search_finds_every_place_case_insensitively_and_is_recorded(client, session):
    request = _register(client)
    url = f"{PREFIX}/requests/{request['request_id']}/search"
    results = client.post(url, json={"identifier": WHO}).json()["results"]
    assert "w048-f1" in results["findings"]["items"]
    assert "w048-f2" not in results["findings"]["items"]
    assert "w048-c1" in results["cases"]["items"]
    assert results["case_comments"]["count"] >= 1
    actions = [
        r.action
        for r in session.query(ConfigAuditLog)
        .filter(ConfigAuditLog.config_key == request["request_id"])
        .order_by(ConfigAuditLog.id)
    ]
    assert actions == ["create", "search"]


def test_export_returns_the_records(client):
    request = _register(client)
    url = f"{PREFIX}/requests/{request['request_id']}/export"
    body = client.post(url, json={"identifier": WHO}).json()
    finding = next(
        i for i in body["results"]["findings"]["items"] if i["finding_id"] == "w048-f1"
    )
    assert finding["title"] == "Phish"
    assert "review each" in body["note"]


def test_a_lookup_needs_the_identifier_of_its_request(client):
    request = _register(client)
    url = f"{PREFIX}/requests/{request['request_id']}/search"
    assert (
        client.post(url, json={"identifier": "someone@else.example"}).status_code == 422
    )
    assert (
        client.post(
            f"{PREFIX}/requests/dsr-nope/search", json={"identifier": WHO}
        ).status_code
        == 404
    )


def test_wildcards_in_the_identifier_are_literal(client):
    request = _register(client, identifier="%%%_")
    url = f"{PREFIX}/requests/{request['request_id']}/search"
    results = client.post(url, json={"identifier": "%%%_"}).json()["results"]
    assert "w048-f1" not in results["findings"]["items"]


def test_a_closed_request_allows_no_lookup(client):
    request = _register(client)
    rid = request["request_id"]
    closed = client.post(
        f"{PREFIX}/requests/{rid}/close", json={"outcome": "sent by e-mail"}
    )
    assert closed.status_code == 200 and closed.json()["state"] == "closed"
    assert (
        client.post(
            f"{PREFIX}/requests/{rid}/search", json={"identifier": WHO}
        ).status_code
        == 409
    )
    assert (
        client.post(f"{PREFIX}/requests/{rid}/close", json={"outcome": "x"}).status_code
        == 409
    )


def test_every_route_needs_settings_write(client, monkeypatch):
    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.check_permission",
        lambda user_id, perm, session=None: perm != "settings.write",
    )
    assert client.get(f"{PREFIX}/requests").status_code == 403
    assert (
        client.post(
            f"{PREFIX}/requests", json={"identifier": WHO, "kind": "access"}
        ).status_code
        == 403
    )


def test_masking():
    assert data_subject.masked("ali@corp.example") == "a***@corp.example"
    assert data_subject.masked("10.1.2.3") == "1***"
    assert data_subject.identifier_hash(
        " Ali@Corp.Example "
    ) == data_subject.identifier_hash("ali@corp.example")
