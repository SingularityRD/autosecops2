"""``55_lessons_promotion.sql`` and the SQL lesson store in a real Postgres (W3.11).

48 and 55 are applied twice (both must be rerunnable) inside a transaction that
is rolled back. The constraints refuse an active lesson without a passing
replay, with untrusted provenance or naming critical, and the audit table
refuses UPDATE and DELETE.
"""

import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from core.lessons.model import LessonEvent
from core.lessons.service import LessonConflict, LessonService
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
        lesson_text="scanner",
        effect="benign_hint",
        applies_to=SCOPE,
        actor="ayse",
        source_kind="manual",
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
        lesson_text="scanner",
        effect="benign_hint",
        applies_to=SCOPE,
        actor="ayse",
        source_kind="manual",
    )
    _, _, ok = service.promote(lesson.id, "mehmet")
    assert not ok
    assert service.get(lesson.id).status == "proposed"
    assert [e.action for e in service.events(lesson.id)] == [
        "proposed",
        "promotion_refused",
    ]


INSERT = (
    "INSERT INTO lessons (source_kind, source_id, lesson, applies_to, status, created_by, "
    "created_at, approved_by, effect, expires_at, provenance, replay_passed, replay) "
    "VALUES (:kind, :source_id, 'x', CAST(:scope AS JSONB), :status, :created_by, :created, "
    ":approved_by, :effect, :expires, :provenance, :passed, CAST(:replay AS JSONB))"
)
OK = {
    "kind": "manual",
    "source_id": None,
    "status": "active",
    "scope": '{"data_source": "entra", "src_ips": ["1.2.3.4"], "max_severity": "low"}',
    "created_by": "a",
    "created": NOW,
    "approved_by": "b",
    "effect": "benign_hint",
    "expires": NOW + timedelta(days=90),
    "provenance": "analyst",
    "passed": True,
    "replay": '{"passed": true}',
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
        {"scope": '{"data_source": "entra", "max_severity": "critical"}'},
        # Round 5: case-insensitive critical (also on proposed rows).
        {"scope": '{"data_source": "entra", "max_severity": "Critical"}'},
        {
            "status": "proposed",
            "scope": '{"data_source": "e", "max_severity": " CRITICAL"}',
        },
        # Round 5: the replay report itself must be kept.
        {"replay": None},
        # Round 5: expiry at most 90 days after creation.
        {"expires": NOW + timedelta(days=90, seconds=1)},
        # Round 5: two-person rule, any letter case.
        {"approved_by": "a"},
        {"approved_by": " A "},
        {"approved_by": None},
        # Round 5: host/user/IP-only scope (no data_source/rule_name/mitre).
        {
            "scope": '{"hostnames": ["WS-12"], "src_ips": ["1.2.3.4"], "max_severity": "low"}'
        },
        # Round 5: non-manual lessons name their source.
        {"kind": "analyst_override", "status": "proposed"},
        {"kind": "eval_failure", "source_id": " ", "status": "proposed"},
    ):
        _refused(session, INSERT, {**OK, **bad})
    session.connection().execute(
        text(INSERT), {**OK, "kind": "analyst_override", "source_id": "f-1"}
    )


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
        lesson_text="scanner",
        effect="benign_hint",
        applies_to=SCOPE,
        actor="ayse",
        source_kind="manual",
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


# -- Round 5 fixes -------------------------------------------------------------


def _insert(session, **kw):
    return (
        session.connection()
        .execute(text(INSERT + " RETURNING id"), {**OK, **kw})
        .scalar_one()
    )


def test_lesson_events_cannot_be_truncated(session):
    _refused(session, "TRUNCATE lesson_events", {}, DBAPIError)


def test_a_retired_lesson_is_final(session):
    lesson_id = _insert(session)
    upd = "UPDATE lessons SET status = :s WHERE id = :id"
    _refused(session, upd, {"s": "proposed", "id": lesson_id}, DBAPIError)
    session.connection().execute(text(upd), {"s": "retired", "id": lesson_id})
    for status in ("active", "proposed", "retired"):
        _refused(session, upd, {"s": status, "id": lesson_id}, DBAPIError)


def test_an_active_lessons_definition_is_frozen(session):
    lesson_id = _insert(session)
    for sql in (
        "UPDATE lessons SET applies_to = applies_to - 'src_ips' WHERE id = :id",
        "UPDATE lessons SET effect = 'escalate' WHERE id = :id",
        "UPDATE lessons SET expires_at = expires_at - interval '1 day' WHERE id = :id",
        "UPDATE lessons SET created_by = 'z' WHERE id = :id",
    ):
        _refused(session, sql, {"id": lesson_id}, DBAPIError)


@pytest.fixture()
def scratch_schema():
    """Committed tables in a throwaway schema, for two real sessions.

    The other tests run in one rolled-back transaction; a race needs two
    connections that see each other's commits. ``DROP SCHEMA ... CASCADE``
    removes the append-only audit table without a DELETE or TRUNCATE.
    """
    engine = get_db_manager().engine
    schema = f"w311_race_{uuid.uuid4().hex[:10]}"
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        conn.execute(text(f'SET LOCAL search_path TO "{schema}", public'))
        for name in FILES:
            conn.execute(text((INIT / name).read_text(encoding="utf-8")))

    def connect():
        conn = engine.connect()
        conn.execute(text(f'SET search_path TO "{schema}", public'))
        conn.commit()
        return conn

    opened = []

    def session():
        conn = connect()
        opened.append(conn)
        return Session(bind=conn)

    try:
        yield session
    finally:
        for conn in opened:
            conn.rollback()
            conn.execute(text("RESET search_path"))
            conn.commit()
            conn.close()
        with engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))


def _proposed(session):
    lesson = _service(session).propose(
        lesson_text="scanner",
        effect="benign_hint",
        applies_to=SCOPE,
        actor="ayse",
        source_kind="manual",
    )
    session.commit()
    return lesson.id


def test_a_rollback_committed_after_a_stale_read_is_not_undone(scratch_schema):
    """Without a row lock: the conditional UPDATE refuses the stale promotion."""
    a, b = scratch_schema(), scratch_schema()
    lesson_id = _proposed(a)
    stale = SqlLessonStore(a).get(lesson_id)  # A read 'proposed' (no lock)
    a.commit()
    _service(b).rollback(lesson_id, "ayse", "withdrawn")
    b.commit()
    stale.status, stale.approved_by = "active", "mehmet"
    stale.replay, stale.replay_passed = {"passed": True}, True
    assert SqlLessonStore(a).update(stale, "proposed") is False
    a.commit()
    after = SqlLessonStore(b).get(lesson_id)
    assert after.status == "retired" and after.approved_by is None


def test_promote_holds_the_row_and_a_concurrent_rollback_waits(scratch_schema):
    """A promotes (row locked through replay); B's rollback waits, then retires."""
    a, b = scratch_schema(), scratch_schema()
    lesson_id = _proposed(a)
    started, outcome = threading.Event(), {}

    def rollback_in_b():
        b.execute(text("SET lock_timeout = '20s'"))
        started.set()
        try:
            outcome["lesson"] = _service(b).rollback(lesson_id, "ayse", "withdrawn")
            b.commit()
        except Exception as exc:  # noqa: BLE001 — reported by the assertion below
            outcome["error"] = exc
            b.rollback()

    service = _service(a)
    real_baseline = service.baseline

    def baseline_that_lets_b_try():
        worker.start()
        started.wait(10)
        # B is now blocked on A's row lock; prove it before A commits.
        worker.join(1.0)
        outcome["blocked"] = worker.is_alive()
        return real_baseline()

    worker = threading.Thread(target=rollback_in_b)
    service.baseline = baseline_that_lets_b_try
    _, _, ok = service.promote(lesson_id, "mehmet")
    assert ok
    a.commit()
    worker.join(30)
    assert outcome.get("blocked") is True
    assert "error" not in outcome, outcome.get("error")
    final = SqlLessonStore(a).get(lesson_id)
    a.commit()
    assert final.status == "retired" and final.retire_reason == "withdrawn"
    assert [e.action for e in SqlLessonStore(a).events(lesson_id)] == [
        "proposed",
        "promoted",
        "rolled_back",
    ]
    # Retired is final: a promotion attempt now conflicts and the trigger
    # refuses even a raw write.
    with pytest.raises(LessonConflict):
        _service(a).promote(lesson_id, "mehmet")
    a.rollback()
    with pytest.raises(DBAPIError):
        a.execute(
            text("UPDATE lessons SET status = 'active' WHERE id = CAST(:id AS UUID)"),
            {"id": lesson_id},
        )
    a.rollback()
