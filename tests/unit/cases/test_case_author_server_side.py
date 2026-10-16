"""SA-13 (W0.35): who wrote a comment or collected evidence is the signed-in user.

The client used to send a hard-coded ``'SOC Analyst'`` and the server stored
whatever it was given. Now the name a client sends is accepted (older clients
keep working) and ignored.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from core.api.v1 import cases_router as v1
from services.api.routers import cases as cases_api

pytestmark = pytest.mark.unit

ANA = SimpleNamespace(user_id="u-ana", username="ana")


class _Recorder:
    calls: list = []

    def __init__(self, *a, **k):
        pass

    def add_comment(self, case_id, author, content, parent_comment_id=None):
        self.calls.append(("comment", case_id, author, content))
        return SimpleNamespace(
            comment_id=1,
            case_id=case_id,
            author=author,
            content=content,
            parent_comment_id=parent_comment_id,
            mentions=[],
            is_edited=False,
            created_at=None,
            updated_at=None,
        )

    def add_evidence(self, **kw):
        self.calls.append(("evidence", kw["case_id"], kw["collected_by"], kw["name"]))
        return None  # the route answers 500; the call is what is under test

    def add_chain_of_custody_entry(self, evidence_id, action, user, notes):
        self.calls.append(("custody", evidence_id, user, action))
        return True


@pytest.fixture(autouse=True)
def recorder(monkeypatch):
    _Recorder.calls = []
    monkeypatch.setattr(cases_api, "CaseCollaborationService", _Recorder)
    monkeypatch.setattr(cases_api, "CaseEvidenceService", _Recorder)
    monkeypatch.setattr(v1, "CaseEvidenceService", _Recorder)
    return _Recorder.calls


def test_a_comment_is_authored_by_the_signed_in_user(recorder):
    data = cases_api.CommentAdd(author="SOC Analyst", content="looked at it")
    out = asyncio.run(cases_api.add_comment("c-1", data, current_user=ANA))
    assert recorder == [("comment", "c-1", "ana", "looked at it")]
    assert out["author"] == "ana"


def test_a_comment_needs_no_author_from_the_client(recorder):
    data = cases_api.CommentAdd(content="no name sent")
    asyncio.run(cases_api.add_comment("c-1", data, current_user=ANA))
    assert recorder[0][2] == "ana"


def test_evidence_is_collected_by_the_signed_in_user(recorder):
    data = v1.EvidenceAdd(
        evidence_type="file", name="pcap", collected_by="Someone Else"
    )
    with pytest.raises(Exception):
        v1.add_evidence("c-1", data, current_user=ANA)
    assert recorder == [("evidence", "c-1", "ana", "pcap")]


def test_a_custody_entry_is_made_by_the_signed_in_user(recorder):
    data = cases_api.ChainOfCustodyAdd(action="transferred", user="mallory")
    asyncio.run(cases_api.add_custody_entry("c-1", 7, data, current_user=ANA))
    assert recorder == [("custody", 7, "ana", "transferred")]


def test_a_user_without_a_username_is_named_by_id(recorder):
    data = cases_api.CommentAdd(content="x")
    asyncio.run(
        cases_api.add_comment(
            "c-1", data, current_user=SimpleNamespace(user_id="u-9", username="")
        )
    )
    assert recorder[0][2] == "u-9"
