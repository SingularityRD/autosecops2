"""The SLA monitor raises each threshold once; the stale detector once a day.

It used to write a fresh warning for every crossed threshold on every one-minute
pass, so a breached case gained three notifications a minute forever. Canary
cases raise nothing.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import text

from core.cases.case_automation_service import CaseAutomationService, highest_crossed
from core.cases.case_notification_service import BROADCAST_USER_ID, sla_event_key
from core.storage.connection import get_db_session
from core.storage.models import Case, CaseNotification, CaseSLA, Finding, SLAPolicy
from core.time import utcnow

pytestmark = pytest.mark.unit

PREFIX = "w18sla-"


def test_highest_crossed_threshold():
    assert highest_crossed(10) is None
    assert highest_crossed(75) == 75
    assert highest_crossed(89.9) == 75
    assert highest_crossed(95) == 90
    assert highest_crossed(250) == 100


@pytest.fixture
def db():
    session = get_db_session()

    def clean():
        session.query(CaseNotification).delete()
        session.query(CaseSLA).filter(CaseSLA.case_id.like(PREFIX + "%")).delete(
            synchronize_session=False
        )
        session.execute(
            text("DELETE FROM case_findings WHERE case_id LIKE :p"), {"p": PREFIX + "%"}
        )
        session.query(Case).filter(Case.case_id.like(PREFIX + "%")).delete(
            synchronize_session=False
        )
        session.query(Finding).filter(Finding.finding_id.like(PREFIX + "%")).delete(
            synchronize_session=False
        )
        session.query(SLAPolicy).filter(SLAPolicy.policy_id == PREFIX + "p").delete()
        session.commit()

    clean()
    session.add(
        SLAPolicy(
            policy_id=PREFIX + "p",
            name=PREFIX + "policy",
            priority_level="high",
            response_time_hours=1,
            resolution_time_hours=8,
        )
    )
    session.commit()
    try:
        yield session
    finally:
        session.rollback()
        clean()
        session.close()


def _case_with_sla(session, case_id, *, canary=False, updated_days_ago=0):
    now = utcnow()
    case = Case(
        case_id=PREFIX + case_id,
        title=case_id,
        status="open",
        priority="high",
        assignee="alice",
        created_at=now - timedelta(days=updated_days_ago),
        updated_at=now - timedelta(days=updated_days_ago),
    )
    finding = Finding(
        finding_id=PREFIX + "f-" + case_id,
        data_source="test",
        entity_context={"canary": True} if canary else {},
    )
    case.findings.append(finding)
    session.add_all([finding, case])
    session.flush()
    session.add(
        CaseSLA(
            case_id=case.case_id,
            sla_policy_id=PREFIX + "p",
            response_due=now + timedelta(hours=1),
            resolution_due=now + timedelta(hours=8),
        )
    )
    session.commit()
    return case


def _service(percents: dict) -> CaseAutomationService:
    svc = CaseAutomationService()
    svc.sla_service.get_sla_status = lambda case_id, session=None: percents
    return svc


def _broadcast_keys(session):
    session.expire_all()
    rows = (
        session.query(CaseNotification)
        .filter(CaseNotification.user_id == BROADCAST_USER_ID)
        .all()
    )
    return sorted(r.notification_metadata["event_key"] for r in rows)


@pytest.mark.external_service
@pytest.mark.database
def test_each_threshold_is_raised_once(db):
    case = _case_with_sla(db, "c1")
    percents = {"response_percent_elapsed": 80, "resolution_percent_elapsed": 10}
    svc = _service(percents)

    assert svc.check_sla_deadlines() == 1
    assert svc.check_sla_deadlines() == 0  # the next minute: nothing new
    assert _broadcast_keys(db) == [sla_event_key(case.case_id, "response", 75)]

    percents["response_percent_elapsed"] = 120
    assert svc.check_sla_deadlines() == 1
    assert svc.check_sla_deadlines() == 0
    assert _broadcast_keys(db) == sorted(
        [
            sla_event_key(case.case_id, "response", 75),
            sla_event_key(case.case_id, "response", 100),
        ]
    )
    db.expire_all()
    sla = db.query(CaseSLA).filter(CaseSLA.case_id == case.case_id).one()
    assert sla.breached is True and sla.breach_time is not None
    # One broadcast + one assignee row per raised threshold.
    assert db.query(CaseNotification).count() == 4


@pytest.mark.external_service
@pytest.mark.database
def test_an_unassigned_unwatched_case_still_raises_its_event(db):
    case = _case_with_sla(db, "c2")
    case.assignee = None
    db.commit()
    svc = _service({"response_percent_elapsed": 95, "resolution_percent_elapsed": 0})

    assert svc.check_sla_deadlines() == 1
    assert svc.check_sla_deadlines() == 0
    assert _broadcast_keys(db) == [sla_event_key(case.case_id, "response", 90)]


@pytest.mark.external_service
@pytest.mark.database
def test_canary_cases_raise_no_sla_warning(db):
    _case_with_sla(db, "c3", canary=True)
    svc = _service({"response_percent_elapsed": 150, "resolution_percent_elapsed": 150})

    assert svc.check_sla_deadlines() == 0
    assert db.query(CaseNotification).count() == 0


@pytest.mark.external_service
@pytest.mark.database
def test_stale_cases_are_raised_once_a_day_and_canaries_never(db):
    stale = _case_with_sla(db, "c4", updated_days_ago=10)
    _case_with_sla(db, "c5", updated_days_ago=10, canary=True)
    _case_with_sla(db, "c6", updated_days_ago=1)
    svc = CaseAutomationService()

    assert svc.detect_stale_cases() == 1
    assert svc.detect_stale_cases() == 0
    keys = _broadcast_keys(db)
    assert keys == [f"stale:{stale.case_id}:{utcnow().date().isoformat()}"]


@pytest.mark.external_service
@pytest.mark.database
def test_two_passes_racing_past_the_check_raise_the_event_once(db):
    """Both passes read "not raised yet"; the unique index lets one insert win.

    The losing pass keeps its transaction: the breach it marks in the same
    pass is still committed.
    """
    case = _case_with_sla(db, "race")
    svc = _service({"response_percent_elapsed": 120, "resolution_percent_elapsed": 10})
    # Both passes see "not raised yet", as two monitors would when they read
    # before either commits.
    svc.notification_service.event_already_raised = lambda key, session: False

    assert svc.check_sla_deadlines() == 1
    assert svc.check_sla_deadlines() == 0
    assert _broadcast_keys(db) == [sla_event_key(case.case_id, "response", 100)]
    # One broadcast and one assignee row: the loser wrote no per-person copies.
    assert db.query(CaseNotification).count() == 2
    sla = db.query(CaseSLA).filter(CaseSLA.case_id == case.case_id).one()
    assert sla.breached is True


@pytest.mark.external_service
@pytest.mark.database
def test_concurrent_broadcast_inserts_conflict_on_the_event_key(db):
    """Two sessions in flight at once: the second insert waits, then conflicts."""
    import threading

    from core.cases.case_notification_service import CaseNotificationService

    case = _case_with_sla(db, "race2")
    service = CaseNotificationService()
    first = get_db_session()
    second = get_db_session()
    try:
        assert service.notify_sla_warning(case.case_id, 90, "response", first)
        results = []

        def run():
            results.append(
                service.notify_sla_warning(case.case_id, 90, "response", second)
            )
            second.commit()

        worker = threading.Thread(target=run)
        worker.start()
        worker.join(timeout=1)
        assert worker.is_alive()  # blocked on the first session's uncommitted row
        first.commit()
        worker.join(timeout=30)
        assert results == [False]
    finally:
        first.close()
        second.close()
    assert _broadcast_keys(db) == [sla_event_key(case.case_id, "response", 90)]
