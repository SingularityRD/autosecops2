"""The dispatcher sends pending case notifications and marks them sent.

DB-backed: the batch is claimed with ``FOR UPDATE SKIP LOCKED`` and broadcast
rows are found by a JSONB key, neither of which a fake session would check.
Email, Slack and the webhook queue are injected fakes, except in the last test,
which queues into the real ``webhook_deliveries`` table.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from core.cases.case_notification_service import (
    BROADCAST_USER_ID,
    CaseNotificationService,
    sla_event_key,
)
from core.cases.notification_dispatcher import CaseNotificationDispatcher, is_canary
from core.config import get_settings
from core.storage.connection import get_db_manager, get_db_session
from core.storage.models import Case, CaseNotification, Finding, Role, User
from core.time import utcnow

pytestmark = pytest.mark.unit

PREFIX = "w18-"


# --- is_canary (no database) ---------------------------------------------------


def test_is_canary_reads_the_entity_context_flag():
    assert is_canary({"entity_context": {"canary": True}})
    assert is_canary({"entity_context": {"canary": "marker-123"}})
    assert not is_canary({"entity_context": {"canary": False}})
    assert not is_canary({"entity_context": {}})
    assert not is_canary({"entity_context": None})
    assert not is_canary({})
    assert not is_canary(None)


def test_a_case_is_a_canary_when_any_of_its_findings_is():
    real = {"entity_context": {"hostnames": ["h"]}}
    canary = {"entity_context": {"canary": True}}

    assert is_canary({"findings": [real, canary]})
    assert not is_canary({"findings": [real]})
    assert not is_canary({"findings": ["f-1", "f-2"]})  # ids only: unknown, not canary


# --- with a database ----------------------------------------------------------


class Recorder:
    def __init__(self):
        self.slack = []
        self.email = []
        self.webhooks = []
        self.teams = []

    def post_slack(self, text, channel=None):
        self.slack.append(text)
        return True, "sent"

    def send_email(self, to, subject, body):
        self.email.append((to, subject, body))
        return True, "sent"

    def post_teams(self, title, text, facts=None):
        self.teams.append((title, text, facts))
        return True, "sent"

    def enqueue(self, event_type, event_id, data, session=None):
        self.webhooks.append((event_type, event_id, data))
        return 1

    def dispatcher(self):
        return CaseNotificationDispatcher(
            post_slack=self.post_slack,
            send_email=self.send_email,
            enqueue_webhook=self.enqueue,
            post_teams=self.post_teams,
        )


@pytest.fixture
def db(monkeypatch):
    session = get_db_session()

    def clean():
        session.query(CaseNotification).delete()
        session.execute(
            text("DELETE FROM case_findings WHERE case_id LIKE :p"), {"p": PREFIX + "%"}
        )
        session.query(Case).filter(Case.case_id.like(PREFIX + "%")).delete(
            synchronize_session=False
        )
        session.query(Finding).filter(Finding.finding_id.like(PREFIX + "%")).delete(
            synchronize_session=False
        )
        session.query(User).filter(User.user_id.like(PREFIX + "%")).delete(
            synchronize_session=False
        )
        session.commit()

    clean()
    if session.query(Role).filter(Role.role_id == PREFIX + "role").first() is None:
        session.add(
            Role(role_id=PREFIX + "role", name=PREFIX + "role", description="t")
        )
    session.add(
        User(
            user_id=PREFIX + "u1",
            username="alice",
            email="alice@example.test",
            password_hash="x",
            full_name="Alice",
            role_id=PREFIX + "role",
        )
    )
    session.commit()
    try:
        yield session
    finally:
        session.rollback()
        clean()
        session.close()


def _case(session, case_id, *, canary=False, assignee="alice"):
    case = Case(
        case_id=PREFIX + case_id,
        title=f"case {case_id}",
        status="open",
        priority="high",
        assignee=assignee,
    )
    finding = Finding(
        finding_id=PREFIX + "f-" + case_id,
        data_source="test",
        entity_context={"canary": True} if canary else {"hostnames": ["h1"]},
    )
    case.findings.append(finding)
    session.add_all([finding, case])
    session.commit()
    return case


def _rows(session):
    session.expire_all()
    return (
        session.query(CaseNotification).order_by(CaseNotification.notification_id).all()
    )


@pytest.mark.external_service
@pytest.mark.database
def test_sla_warning_reaches_webhooks_slack_and_marks_every_row_sent(db, monkeypatch):
    monkeypatch.setenv("CASE_NOTIFY_SLACK_ENABLED", "true")
    get_settings.cache_clear()
    case = _case(db, "c1")
    CaseNotificationService().notify_sla_warning(case.case_id, 90, "response")
    rec = Recorder()

    counts = rec.dispatcher().dispatch_pending()

    assert counts == {"sent": 2}  # broadcast row + assignee row
    key = sla_event_key(case.case_id, "response", 90)
    [(event_type, event_id, data)] = rec.webhooks
    assert (event_type, event_id) == ("case.sla_warning", key)
    assert data["case"]["case_id"] == case.case_id
    assert data["details"] == {"threshold_percent": 90, "sla_type": "response"}
    assert len(rec.slack) == 1 and "SLA Warning" in rec.slack[0]
    assert rec.email == []  # ui channel, priority not opted into email
    rows = _rows(db)
    assert all(r.is_sent and r.sent_at for r in rows)
    broadcast = next(r for r in rows if r.user_id == BROADCAST_USER_ID)
    assert broadcast.notification_metadata["dispatch"]["channels"]["slack"] == "sent"

    # A second pass has nothing to do.
    assert rec.dispatcher().dispatch_pending() == {}
    assert len(rec.webhooks) == 1


@pytest.mark.external_service
@pytest.mark.database
def test_slack_broadcast_is_off_by_default(db):
    case = _case(db, "c2")
    CaseNotificationService().notify_sla_warning(case.case_id, 75, "resolution")
    rec = Recorder()

    rec.dispatcher().dispatch_pending()

    assert rec.slack == []
    assert len(rec.webhooks) == 1


@pytest.mark.external_service
@pytest.mark.database
def test_personal_rows_go_by_email_by_channel_or_priority(db, monkeypatch):
    monkeypatch.setenv("CASE_NOTIFY_EMAIL_PRIORITIES", "urgent")
    get_settings.cache_clear()
    case = _case(db, "c3")
    svc = CaseNotificationService()
    svc.create_notification(
        user_id="alice",
        notification_type="comment_mention",
        title="Mentioned",
        message="bob mentioned you",
        case_id=case.case_id,
        delivery_channel="email",
    )
    svc.create_notification(
        user_id=PREFIX + "u1",  # by id as well as by username
        notification_type="escalation",
        title="Urgent thing",
        message="look now",
        priority="urgent",
    )
    svc.create_notification(
        user_id="alice",
        notification_type="comment_mention",
        title="Quiet",
        message="ui only",
    )
    svc.create_notification(
        user_id="nobody",
        notification_type="comment_mention",
        title="Lost",
        message="no such user",
        delivery_channel="email",
    )
    rec = Recorder()

    assert rec.dispatcher().dispatch_pending() == {"sent": 4}

    assert [(to, subject) for to, subject, _ in rec.email] == [
        ("alice@example.test", "[AutoSecOps] Mentioned"),
        ("alice@example.test", "[AutoSecOps] Urgent thing"),
    ]
    assert case.case_id in rec.email[0][2]
    assert rec.webhooks == [] and rec.slack == []  # personal rows are not broadcast
    lost = _rows(db)[-1]
    assert lost.notification_metadata["dispatch"]["channels"]["email"] == (
        "no email address"
    )


@pytest.mark.external_service
@pytest.mark.database
def test_slack_channel_rows_post_to_slack(db):
    CaseNotificationService().create_notification(
        user_id="alice",
        notification_type="escalation",
        title="Ping",
        message="hello",
        delivery_channel="slack",
    )
    rec = Recorder()

    rec.dispatcher().dispatch_pending()

    assert rec.slack == ["*Ping* (for alice)\nhello"]


@pytest.mark.external_service
@pytest.mark.database
def test_canary_cases_never_leave_the_system(db, monkeypatch):
    monkeypatch.setenv("CASE_NOTIFY_SLACK_ENABLED", "true")
    monkeypatch.setenv("CASE_NOTIFY_EMAIL_PRIORITIES", "urgent,high,normal")
    get_settings.cache_clear()
    case = _case(db, "c4", canary=True)
    CaseNotificationService().notify_sla_warning(case.case_id, 100, "resolution")
    rec = Recorder()

    counts = rec.dispatcher().dispatch_pending()

    assert counts == {"canary": 2}
    assert rec.webhooks == [] and rec.slack == [] and rec.email == []
    assert all(r.is_sent for r in _rows(db))


@pytest.mark.external_service
@pytest.mark.database
def test_an_old_backlog_is_marked_sent_without_sending(db):
    case = _case(db, "c5")
    CaseNotificationService().notify_sla_warning(case.case_id, 90, "response")
    for row in db.query(CaseNotification).all():
        row.created_at = utcnow() - timedelta(days=3)
    db.commit()
    rec = Recorder()

    assert rec.dispatcher().dispatch_pending() == {"expired": 2}
    assert rec.webhooks == []


@pytest.mark.external_service
@pytest.mark.database
def test_a_failed_send_is_recorded_not_retried_forever(db):
    CaseNotificationService().create_notification(
        user_id="alice",
        notification_type="comment_mention",
        title="t",
        message="m",
        delivery_channel="email",
    )
    rec = Recorder()
    rec.send_email = lambda **kw: (False, "email failed: SMTPException")

    rec.dispatcher().dispatch_pending()

    [row] = _rows(db)
    assert row.is_sent
    assert row.notification_metadata["dispatch"]["channels"]["email"] == (
        "email failed: SMTPException"
    )


@pytest.mark.external_service
@pytest.mark.database
def test_a_broadcast_lands_in_the_real_webhook_queue_once(db):
    sql = (
        Path(__file__).resolve().parents[3]
        / "infra/database/init/47_webhooks_alert_routes.sql"
    )
    with get_db_manager().engine.begin() as conn:
        conn.execute(text(sql.read_text(encoding="utf-8")))
        conn.execute(
            text("TRUNCATE webhook_deliveries, alert_routes, webhook_endpoints")
        )
        conn.execute(
            text(
                "INSERT INTO webhook_endpoints (name, url, secret_ref, event_types) "
                "VALUES ('siem', 'https://siem.example/hook', 'REF', '{case.sla_warning}'), "
                "('stale-only', 'https://other.example/hook', 'REF2', '{case.stale_case}')"
            )
        )
    case = _case(db, "c6")
    svc = CaseNotificationService()
    svc.notify_sla_warning(case.case_id, 90, "response")
    CaseNotificationDispatcher().dispatch_pending()
    # The same event raised again (say, two daemons) is one delivery.
    svc.notify_sla_warning(case.case_id, 90, "response")
    CaseNotificationDispatcher().dispatch_pending()

    with get_db_manager().engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT d.event_type, d.event_id, d.payload, e.name "
                "FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.endpoint_id"
            )
        ).fetchall()
    assert [(r.event_type, r.event_id, r.name) for r in rows] == [
        ("case.sla_warning", sla_event_key(case.case_id, "response", 90), "siem")
    ]
    assert rows[0].payload["data"]["case"]["case_id"] == case.case_id
    assert rows[0].payload["type"] == "case.sla_warning"


# --- W0.46: a mail list and a Teams channel for broadcast events ------------------


@pytest.mark.external_service
@pytest.mark.database
def test_a_broadcast_goes_to_the_mail_list_for_its_priorities(db, monkeypatch):
    monkeypatch.setenv("CASE_NOTIFY_EMAIL_TO", "soc@corp.test, , ciso@corp.test")
    get_settings.cache_clear()
    try:
        case = _case(db, "m1")
        CaseNotificationService().notify_sla_warning(case.case_id, 90, "response")
        rec = Recorder()
        rec.dispatcher().dispatch_pending()
    finally:
        get_settings.cache_clear()
    listed = [to for to, _, _ in rec.email]
    assert listed == ["soc@corp.test", "ciso@corp.test"]
    assert all("SLA Warning" in subject for _, subject, _ in rec.email)
    assert all(case.case_id in body for _, _, body in rec.email)
    broadcast = next(r for r in _rows(db) if r.user_id == BROADCAST_USER_ID)
    assert (
        broadcast.notification_metadata["dispatch"]["channels"]["email_list"]
        == "sent 2/2"
    )


@pytest.mark.external_service
@pytest.mark.database
def test_a_lower_priority_broadcast_skips_the_mail_list(db, monkeypatch):
    monkeypatch.setenv("CASE_NOTIFY_EMAIL_TO", "soc@corp.test")
    monkeypatch.setenv("CASE_NOTIFY_EMAIL_TO_PRIORITIES", "urgent")
    get_settings.cache_clear()
    try:
        case = _case(db, "m2")
        CaseNotificationService().notify_sla_warning(case.case_id, 75, "response")
        rec = Recorder()
        rec.dispatcher().dispatch_pending()
    finally:
        get_settings.cache_clear()
    assert [to for to, _, _ in rec.email if to == "soc@corp.test"] == []


@pytest.mark.external_service
@pytest.mark.database
def test_teams_gets_one_card_per_broadcast_when_on(db, monkeypatch):
    monkeypatch.setenv("CASE_NOTIFY_TEAMS_ENABLED", "true")
    get_settings.cache_clear()
    try:
        case = _case(db, "t1")
        CaseNotificationService().notify_sla_warning(case.case_id, 90, "response")
        rec = Recorder()
        rec.dispatcher().dispatch_pending()
    finally:
        get_settings.cache_clear()
    [(title, _text, facts)] = rec.teams
    assert "SLA Warning" in title
    assert facts["Case"] == case.case_id and facts["Assignee"] == "alice"


@pytest.mark.external_service
@pytest.mark.database
def test_teams_and_the_mail_list_are_off_by_default(db):
    case = _case(db, "t2")
    CaseNotificationService().notify_sla_warning(case.case_id, 90, "response")
    rec = Recorder()
    rec.dispatcher().dispatch_pending()
    assert rec.teams == []
    broadcast = next(r for r in _rows(db) if r.user_id == BROADCAST_USER_ID)
    channels = broadcast.notification_metadata["dispatch"]["channels"]
    assert "teams" not in channels and "email_list" not in channels


@pytest.mark.external_service
@pytest.mark.database
def test_a_canary_never_reaches_teams_or_the_mail_list(db, monkeypatch):
    monkeypatch.setenv("CASE_NOTIFY_TEAMS_ENABLED", "true")
    monkeypatch.setenv("CASE_NOTIFY_EMAIL_TO", "soc@corp.test")
    get_settings.cache_clear()
    try:
        case = _case(db, "t3", canary=True)
        CaseNotificationService().notify_sla_warning(case.case_id, 90, "response")
        rec = Recorder()
        rec.dispatcher().dispatch_pending()
    finally:
        get_settings.cache_clear()
    assert rec.teams == [] and rec.email == []


def test_the_teams_card_is_an_adaptive_card():
    from core.cases.notification_dispatcher import teams_card

    card = teams_card("SLA Warning", "90% used", {"Case": "c-1", "Assignee": ""})
    content = card["attachments"][0]["content"]
    assert card["type"] == "message"
    assert (
        card["attachments"][0]["contentType"]
        == "application/vnd.microsoft.card.adaptive"
    )
    assert content["type"] == "AdaptiveCard"
    assert content["body"][0]["text"] == "SLA Warning"
    assert content["body"][2]["facts"] == [{"title": "Case", "value": "c-1"}]


@pytest.mark.parametrize(
    "url,detail",
    [
        ("", "teams not configured"),
        ("http://prod.westus.logic.azure.com/workflows/x", "teams url must be https"),
        ("https://169.254.169.254/x", "teams url refused"),
    ],
)
def test_post_teams_refuses_before_any_call(monkeypatch, url, detail):
    from core.cases import notification_dispatcher as nd

    monkeypatch.setattr("core.secrets.get_secret", lambda name: url)

    def boom(*a, **k):
        raise AssertionError("no request may be made")

    monkeypatch.setattr(nd.httpx, "post", boom)
    ok, got = nd.post_teams_message("t", "x")
    assert ok is False and got.startswith(detail)


def test_post_teams_reports_the_status_without_the_url(monkeypatch):
    import httpx as real_httpx

    from core.cases import notification_dispatcher as nd

    url = "https://prod-00.westeurope.logic.azure.com/workflows/abc?sig=SECRETSIG"
    monkeypatch.setattr("core.secrets.get_secret", lambda name: url)
    monkeypatch.setattr(
        "core.platform.url_safety.refuse_metadata_target", lambda u: None
    )
    seen = {}

    def post(u, json, timeout, follow_redirects):
        seen.update(url=u, json=json, follow_redirects=follow_redirects)
        return real_httpx.Response(400)

    monkeypatch.setattr(nd.httpx, "post", post)
    ok, detail = nd.post_teams_message("t", "x", {"Case": "c"})
    assert (ok, detail) == (False, "teams answered HTTP 400")
    assert "SECRETSIG" not in detail
    assert seen["follow_redirects"] is False
    assert seen["json"]["type"] == "message"
