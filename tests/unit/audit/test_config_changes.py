"""W0.35 (G5): settings-change audit rows are redacted, and the rule-source
routes write one per change as the signed-in user."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from core.audit.config_changes import REDACTED, redact
from services.api.routers import detection_rules as rules_api

pytestmark = pytest.mark.unit


def test_redact_hides_credentials_and_keeps_the_rest():
    value = {
        "api_key": "sk-abcdefghijklmnop",
        "client_secret": "x",
        "password": "hunter2",
        "token": "t",
        "max_tokens": 4096,
        "has_api_key": True,
        "headers": [{"Authorization": "Bearer abcdefghijkl"}],
        "url": "https://user:pw@git.example.com/rules.git",
        "note": "uses sk-proj-0123456789abcdef as fallback",
        "empty_secret": "",
        "model": "gpt-4o",
    }
    out = redact(value)
    assert out["api_key"] == out["client_secret"] == out["password"] == REDACTED
    assert out["token"] == REDACTED
    assert out["max_tokens"] == 4096 and out["has_api_key"] is True
    assert out["headers"] == [{"Authorization": REDACTED}]
    assert out["url"] == f"https://{REDACTED}@git.example.com/rules.git"
    assert out["note"] == f"uses {REDACTED} as fallback"
    assert out["empty_secret"] == "" and out["model"] == "gpt-4o"
    assert value["api_key"].startswith("sk-")  # a copy; the input is untouched


class _Rules:
    def __init__(self):
        self.sources = {"s-1": {"id": "s-1", "name": "sigma", "rule_count": 10}}

    def add_source(self, **kw):
        return {"id": "s-2", **kw}

    def get_source(self, source_id):
        return self.sources.get(source_id)

    def remove_source(self, source_id, delete_files=False):
        return self.sources.pop(source_id, None) is not None


@pytest.fixture
def audited(monkeypatch):
    rows: list[dict] = []
    monkeypatch.setattr(
        rules_api, "record_change_now", lambda **row: rows.append(row) or True
    )
    return rows


MGR = SimpleNamespace(user_id="u-mgr", username="mgr")


def test_adding_and_removing_a_rule_source_is_audited(audited):
    service = _Rules()
    request = rules_api.AddSourceRequest(
        name="corp", source_type="git", format="sigma", url="https://g.example/r.git"
    )
    asyncio.run(rules_api.add_source(request, current_user=MGR, service=service))
    asyncio.run(
        rules_api.remove_source(
            "s-1", delete_files=True, current_user=MGR, service=service
        )
    )
    assert [(r["config_key"], r["action"], r["actor"]) for r in audited] == [
        ("s-2", "create", "mgr"),
        ("s-1", "delete", "mgr"),
    ]
    assert audited[0]["config_type"] == "detection_rules"
    assert audited[0]["new"]["url"] == "https://g.example/r.git"
    assert audited[1]["old"]["rule_count"] == 10


def test_a_missing_rule_source_is_not_audited(audited):
    with pytest.raises(Exception):
        asyncio.run(
            rules_api.remove_source(
                "nope", delete_files=False, current_user=MGR, service=_Rules()
            )
        )
    assert audited == []
