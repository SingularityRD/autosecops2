"""``55_lessons_promotion.sql`` and the SQL lesson store in a real Postgres (W3.11).

48 and 55 are applied twice (both must be rerunnable) inside a transaction that
is rolled back. The constraints refuse an active lesson without a passing
replay, with untrusted provenance or naming critical, and the audit table
refuses UPDATE and DELETE.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from core.lessons.model import LessonEvent
from core.lessons.service import LessonService
from core.lessons.store import SqlLessonStore
from core.storage.connection import get_db_manager

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

INIT = Path(__file__).resolve().parents[3] / "infra" / "database" / "init"
FILES = ("48_autonomy_lessons_suppression_retention.sql", "55_lessons_promotion.sql")
NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
SCOPE = {"data_source": "entra", "src_ips": ["198.51.100.157"], "max_severity": "high"}


@pytest.fixture()
def session():
    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            for _ in range(2):
                for name in FILES:
                    conn.execute(text((INIT / name).read_text(encoding="utf-8")))
            with Session(bind=conn, join_transaction_mode="create_savepoint") as s:
                yield s
        finally:
            tx.rollback()


def _refused(session, sql, params, exc=IntegrityError):
    sp = session.connection().begin_nested()
    with pytest.raises(exc):
        session.connection().execute(text(sql), params)
    sp.rollback()


def _service(session, passed=True):
    def baseline():
        from core.lessons.replay import ReplayCase

        alert = {
            "data_source": "entra",
            "severity": "high",
            "entity_context": {"src_ips": ["198.51.100.157"]},
        }
        # A benign alert called malicious: the lesson fixes it. A malicious one: it regresses.
        expected = "benign" if passed else "malicious"
        return [
            ReplayCase("c-1", "test", alert, expected=expected, actual="malicious")
        ], {"harness": "test"}

    return LessonService(SqlLessonStore(session), baseline, now=lambda: NOW)


def test_round_trip_promote_and_rollback(session):
    service = _service(session)
    lesson = service.propose(
        lesson_text="scanner", effect="benign_hint", applies_to=SCOPE, actor="ayse"
    )
    got = service.get(lesson.id)
    assert got.applies_to == SCOPE and got.provenance == "analyst"
    assert got.expires_at == NOW + timedelta(days=30)
    _, report, ok = service.promote(lesson.id, "mehmet")
    assert ok and report["passed"]
    store = SqlLessonStore(session)
    active = store.active(NOW)
    assert [x.id for x in active] == [lesson.id]
    assert active[0].replay["improvements"] == 1
    assert store.active(NOW + timedelta(days=31)) == []
    service.rollback(lesson.id, "ayse", "moved")
    assert store.active(NOW) == []
    assert [e.action for e in store.events(lesson.id)] == [
        "proposed",
        "promoted",
        "rolled_back",
    ]
    assert [x.id for x in store.list("retired")] == [lesson.id]
    assert store.get("not-a-uuid") is None


def test_failed_replay_is_recorded_and_stays_proposed(session):
    service = _service(session, passed=False)
    lesson = service.propose(
        lesson_text="scanner", effect="benign_hint", applies_to=SCOPE, actor="ayse"
    )
    _, _, ok = service.promote(lesson.id, "mehmet")
    assert not ok
    assert service.get(lesson.id).status == "proposed"
    assert [e.action for e in service.events(lesson.id)] == [
        "proposed",
        "promotion_refused",
    ]


INSERT = (
    "INSERT INTO lessons (source_kind, lesson, applies_to, status, created_by, approved_by, "
    "effect, expires_at, provenance, replay_passed) VALUES ('manual', 'x', CAST(:scope AS JSONB), "
    "'active', 'a', 'b', :effect, :expires, :provenance, :passed)"
)
OK = {
    "scope": '{"src_ips": ["1.2.3.4"], "max_severity": "low"}',
    "effect": "benign_hint",
    "expires": NOW,
    "provenance": "analyst",
    "passed": True,
}


def test_constraints_gate_active(session):
    session.connection().execute(text(INSERT), OK)
    for bad in (
        {"passed": False},
        {"provenance": "adversary_text"},
        {"provenance": "system"},
        {"expires": None},
        {"effect": None},
        {"effect": "close"},
        {"scope": '{"src_ips": ["1.2.3.4"], "max_severity": "critical"}'},
    ):
        _refused(session, INSERT, {**OK, **bad})


def test_provenance_defaults_to_system(session):
    lesson_id = (
        session.connection()
        .execute(
            text(
                "INSERT INTO lessons (source_kind, lesson, created_by) VALUES ('manual', 'x', 'bot') RETURNING id"
            )
        )
        .scalar_one()
    )
    assert (
        session.connection()
        .execute(
            text("SELECT provenance FROM lessons WHERE id = :id"), {"id": lesson_id}
        )
        .scalar_one()
        == "system"
    )


def test_events_are_append_only(session):
    service = _service(session)
    lesson = service.propose(
        lesson_text="scanner", effect="benign_hint", applies_to=SCOPE, actor="ayse"
    )
    SqlLessonStore(session).add_event(
        LessonEvent(lesson_id=lesson.id, action="replayed", actor="x", at=NOW)
    )
    _refused(session, "UPDATE lesson_events SET actor = 'mallory'", {}, DBAPIError)
    _refused(session, "DELETE FROM lesson_events", {}, DBAPIError)
    _refused(
        session,
        "INSERT INTO lesson_events (lesson_id, action, actor) VALUES (CAST(:id AS UUID), 'deleted', 'x')",
        {"id": lesson.id},
    )
