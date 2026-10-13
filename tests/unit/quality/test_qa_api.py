"""/api/qa end to end against a real Postgres: draw, queue, review, scorecard."""

from __future__ import annotations

import os
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from core.time import utcnow
from tests.unit.quality._factory import PREFIX, add_decisions

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]


class _User:
    is_active = True
    username = "ana_analyst"
    user_id = "u-ana"


@pytest.fixture
def client(qa_db, monkeypatch):
    from services.api.main import app
    from services.api.middleware import auth as auth_module

    granted = {"perms": None}  # None: everything

    def check(user_id, perm, session=None):
        return granted["perms"] is None or perm in granted["perms"]

    monkeypatch.setattr("core.auth.auth_service.AuthService.check_permission", check)
    app.dependency_overrides[auth_module.get_current_active_user] = lambda: _User()
    app.dependency_overrides[auth_module.get_current_user] = lambda: _User()
    try:
        c = TestClient(app)
        c.granted = granted
        yield c
    finally:
        app.dependency_overrides.pop(auth_module.get_current_active_user, None)
        app.dependency_overrides.pop(auth_module.get_current_user, None)


def _seed():
    at = utcnow() - timedelta(hours=2)
    add_decisions(
        [
            {"id": f"ph-{i}", "verdict": "benign", "category": "phishing"}
            for i in range(6)
        ]
        + [{"id": "mal", "verdict": "malicious", "category": "phishing"}],
        at=at,
    )


def test_draw_review_and_scorecard(client):
    _seed()
    r = client.post(
        "/api/qa/samples/draw", json={"days": 1, "per_category": 4, "seed": 3}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["categories"]["phishing"] == {
        "population": 6,
        "drawn": 4,
        "inclusion_probability": pytest.approx(4 / 6),
    }
    assert body["risk_weighted"] == {"population": 0, "drawn": 0}

    queue = client.get("/api/qa/samples", params={"status": "pending"}).json()
    assert queue["count"] == 4
    s = queue["samples"][0]
    assert s["subject_id"].startswith(PREFIX)
    assert s["category"] == "phishing"
    assert s["ai_verdict"] == "benign"
    assert s["sampling_kind"] == "simple_random"
    assert s["reasoning"] == "looked fine"

    ok = client.post(f"/api/qa/samples/{s['id']}/review", json={"agrees": True})
    assert ok.status_code == 200, ok.text
    assert ok.json()["reviewer"] == "ana_analyst"
    assert ok.json()["review_verdict"] == "benign"

    again = client.post(f"/api/qa/samples/{s['id']}/review", json={"agrees": True})
    assert again.status_code == 409

    second = queue["samples"][1]["id"]
    bad = client.post(f"/api/qa/samples/{second}/review", json={"agrees": False})
    assert bad.status_code == 422
    miss = client.post(
        f"/api/qa/samples/{second}/review",
        json={"agrees": False, "review_verdict": "malicious", "notes": "C2"},
    )
    assert miss.status_code == 200, miss.text

    assert (
        client.post(
            "/api/qa/samples/999999999/review", json={"agrees": True}
        ).status_code
        == 404
    )

    filtered = client.get(
        "/api/qa/samples", params={"status": "reviewed", "category": "phishing"}
    ).json()
    assert filtered["count"] == 2

    card = client.get("/api/qa/scorecard").json()
    assert card["target"] == 0.01 and card["confidence"] == 0.95
    phishing = next(c for c in card["categories"] if c["category"] == "phishing")
    assert phishing["reviewed"] == 2
    assert phishing["misses"] == 1
    assert phishing["pending"] == 2
    assert phishing["status"] == "not_met"
    assert 0.5 < phishing["fn_upper_bound"] < 1


def test_bad_query_values_are_refused(client):
    assert client.get("/api/qa/samples", params={"status": "nope"}).status_code == 422
    assert client.get("/api/qa/samples", params={"category": "nope"}).status_code == 422
    assert client.get("/api/qa/scorecard", params={"target": 2}).status_code == 422
    assert client.post("/api/qa/samples/draw", json={"days": 0}).status_code == 422


@pytest.mark.parametrize(
    "method,path,body,needs",
    [
        ("POST", "/api/qa/samples/draw", {}, "ai_decisions.approve"),
        ("POST", "/api/qa/samples/1/review", {"agrees": True}, "findings.write"),
    ],
)
def test_writes_need_their_permission(client, method, path, body, needs):
    client.granted["perms"] = {"findings.read"}
    r = client.request(method, path, json=body)
    assert r.status_code == 403
    assert needs in r.text


def test_an_analyst_can_review_but_not_draw(client):
    _seed()
    client.post("/api/qa/samples/draw", json={"days": 1, "per_category": 1, "seed": 1})
    sid = client.get("/api/qa/samples").json()["samples"][0]["id"]

    client.granted["perms"] = {"findings.read", "findings.write"}
    assert client.post("/api/qa/samples/draw", json={}).status_code == 403
    assert (
        client.post(f"/api/qa/samples/{sid}/review", json={"agrees": True}).status_code
        == 200
    )
    # Reads stay open to any signed-in user.
    client.granted["perms"] = set()
    assert client.get("/api/qa/scorecard").status_code == 200
    assert client.get("/api/qa/samples").status_code == 200
