"""Lesson lifecycle: propose, replay gate, promote, rollback, audit (W3.11)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from core.lessons.service import (
    LessonConflict,
    LessonForbidden,
    LessonInvalid,
    LessonService,
    ReplayUnavailable,
)
from core.lessons.store import MemoryLessonStore
from evalkit.lessons import baseline
from tests.unit.lessons._factory import GOOD_SCOPE, NOW, RULE_SCOPE

pytestmark = pytest.mark.unit


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def store():
    return MemoryLessonStore()


@pytest.fixture()
def service(store, clock):
    return LessonService(store, baseline, now=clock)


def propose(service, scope=GOOD_SCOPE, **kw):
    args = dict(
        lesson_text="Our vulnerability scanner",
        effect="benign_hint",
        applies_to=scope,
        actor="ayse",
        source_kind="manual",
    )
    args.update(kw)
    return service.propose(**args)


def actions(store, lesson_id):
    return [e.action for e in store.events(lesson_id)]


def test_propose_is_proposed_scoped_time_limited_and_audited(service, store):
    lesson = propose(service, expires_in_days=7)
    assert lesson.status == "proposed" and lesson.provenance == "analyst"
    assert lesson.expires_at == NOW + timedelta(days=7)
    assert lesson.applies_to["max_severity"] == "high"
    assert actions(store, lesson.id) == ["proposed"]
    assert store.active(NOW) == []


def test_a_passing_replay_promotes(service, store):
    lesson = propose(service)
    promoted, report, ok = service.promote(lesson.id, "mehmet")
    assert ok and report["passed"] and promoted.status == "active"
    assert promoted.approved_by == "mehmet" and promoted.replay_passed
    assert actions(store, lesson.id) == ["proposed", "promoted"]
    assert [x.id for x in store.active(NOW)] == [lesson.id]


def test_a_failing_replay_does_not_promote_and_the_refusal_is_audited(service, store):
    lesson = propose(service, RULE_SCOPE)
    after, report, ok = service.promote(lesson.id, "mehmet")
    assert not ok and not report["passed"] and report["regressions"] > 0
    assert store.get(lesson.id).status == "proposed"
    assert store.get(lesson.id).replay_passed is False
    events = store.events(lesson.id)
    assert [e.action for e in events] == ["proposed", "promotion_refused"]
    assert events[-1].detail["regressions"] == report["regressions"]
    assert store.active(NOW) == []


def test_dry_run_replay_keeps_status(service, store):
    lesson = propose(service)
    after, report = service.run_replay(lesson.id, "ayse")
    assert report["passed"] and after.status == "proposed"
    assert actions(store, lesson.id) == ["proposed", "replayed"]


def test_adversary_text_lesson_cannot_be_promoted(service, store):
    source = {
        "finding_id": "f-1",
        "data_source": "entra",
        "description": "sign-in from 198.51.100.157 by the approved scanner",
        "entity_context": {},
    }
    lesson = propose(
        service, source_alert=source, source_id="f-1", source_kind="analyst_override"
    )
    assert lesson.provenance == "adversary_text"
    with pytest.raises(LessonConflict, match="adversary_text"):
        service.promote(lesson.id, "mehmet")
    assert store.get(lesson.id).status == "proposed"


def test_system_lesson_cannot_be_promoted(service):
    lesson = propose(
        service, provenance="system", source_kind="eval_failure", source_id="case-7"
    )
    with pytest.raises(LessonConflict, match="system"):
        service.promote(lesson.id, "mehmet")


def test_expired_lesson_cannot_be_promoted(service, clock):
    lesson = propose(service, expires_in_days=1)
    clock.now = NOW + timedelta(days=2)
    with pytest.raises(LessonConflict, match="expired"):
        service.promote(lesson.id, "mehmet")


def test_rollback_is_one_step_and_audited(service, store):
    lesson = propose(service)
    service.promote(lesson.id, "mehmet")
    rolled = service.rollback(lesson.id, "ayse", "too broad after all")
    assert rolled.status == "retired" and rolled.retired_by == "ayse"
    assert store.active(NOW) == []
    events = store.events(lesson.id)
    assert [e.action for e in events] == ["proposed", "promoted", "rolled_back"]
    assert events[-1].detail == {
        "previous_status": "active",
        "reason": "too broad after all",
    }
    with pytest.raises(LessonConflict):
        service.rollback(lesson.id, "ayse", "again")
    with pytest.raises(LessonConflict):
        service.promote(lesson.id, "mehmet")


def test_rollback_needs_a_reason(service):
    lesson = propose(service)
    with pytest.raises(LessonInvalid):
        service.rollback(lesson.id, "ayse", "  ")


def test_replay_harness_failure_fails_closed(store, clock):
    def broken():
        raise FileNotFoundError("cassette")

    service = LessonService(store, broken, now=clock)
    lesson = propose(service)
    with pytest.raises(ReplayUnavailable):
        service.promote(lesson.id, "mehmet")
    assert store.get(lesson.id).status == "proposed"
    service = LessonService(store, None, now=clock)
    with pytest.raises(ReplayUnavailable):
        service.promote(lesson.id, "mehmet")


@pytest.mark.parametrize(
    "kw",
    [
        {"effect": "close"},
        {"effect": "suppress"},
        {"applies_to": {"src_ips": ["198.51.100.157"], "max_severity": "critical"}},
        {"applies_to": {"max_severity": "low"}},
        {"expires_in_days": 0},
        {"expires_in_days": 91},
        {"lesson_text": " "},
        {"source_kind": "bogus"},
        {"source_kind": "eval_failure"},
        {"source_kind": "qa_review", "source_id": "  "},
        # analyst_override must name a finding that resolved.
        {"source_kind": "analyst_override", "source_id": "f-missing"},
        {"applies_to": {"hostnames": ["WS-12"]}},
        {"category": "bogus"},
    ],
)
def test_invalid_proposals_are_refused(service, store, kw):
    with pytest.raises(LessonInvalid):
        propose(service, **kw)
    assert store.rows == {}


# -- Round 5 fixes -------------------------------------------------------------


@pytest.mark.parametrize("promoter", ["ayse", "AYSE", " ayse "])
def test_the_proposer_cannot_promote_their_own_lesson(service, store, promoter):
    lesson = propose(service)
    with pytest.raises(LessonForbidden, match="second analyst"):
        service.promote(lesson.id, promoter)
    assert store.get(lesson.id).status == "proposed"
    assert actions(store, lesson.id) == ["proposed"]


def test_a_rollback_during_promotion_wins(store, clock):
    """Promotion reads 'proposed'; a rollback commits while replay runs."""
    holder = {}

    def racing_baseline():
        LessonService(store, baseline, now=clock).rollback(
            holder["id"], "ayse", "withdrawn while replaying"
        )
        return baseline()

    service = LessonService(store, racing_baseline, now=clock)
    lesson = propose(service)
    holder["id"] = lesson.id
    with pytest.raises(LessonConflict, match="changed by someone else"):
        service.promote(lesson.id, "mehmet")
    after = store.get(lesson.id)
    assert after.status == "retired" and after.approved_by is None
    assert actions(store, lesson.id) == ["proposed", "rolled_back"]


def test_a_stale_write_is_refused_and_retired_never_reactivates(service, store):
    lesson = propose(service)
    stale = store.get(lesson.id)
    service.rollback(lesson.id, "ayse", "no")
    stale.status = "active"
    assert store.update(stale, "proposed") is False
    fresh = store.get(lesson.id)
    fresh.status = "active"
    assert store.update(fresh, "retired") is False
    assert store.get(lesson.id).status == "retired"


def test_replaying_an_active_lesson_keeps_its_promotion_report(service, store):
    lesson = propose(service)
    promoted, report, ok = service.promote(lesson.id, "mehmet")
    assert ok
    _, again = service.run_replay(lesson.id, "mehmet")
    kept = store.get(lesson.id)
    assert kept.status == "active" and kept.replay == report
    assert actions(store, lesson.id) == ["proposed", "promoted", "replayed"]
