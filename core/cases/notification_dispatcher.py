"""Send pending case notifications to the channels they are owed.

``CaseNotificationService`` writes ``case_notifications`` rows with
``is_sent=False``; this module is what sends them. Each pass takes a batch of
unsent rows (``FOR UPDATE SKIP LOCKED``), delivers each one, and marks it sent
with what happened recorded under ``notification_metadata["dispatch"]``.

Two kinds of row (see ``BROADCAST_USER_ID`` in case_notification_service):

- **Broadcast** rows are the case event itself, one per event. They are queued
  to every subscribed outbound webhook endpoint (``case.<notification_type>``,
  event id = the row's ``event_key``, so a re-raised event is not delivered
  twice) and, when ``CASE_NOTIFY_SLACK_ENABLED`` is on, posted once to the
  Slack integration's default channel.
- **Personal** rows go to their recipient: by email when the row's channel is
  ``email`` or its priority is in ``CASE_NOTIFY_EMAIL_PRIORITIES``; to Slack
  when the channel is ``slack``. ``ui`` rows need no sending: being stored is
  their delivery.

Email and Slack are tried once per row; a failure is recorded on the row and
not retried (webhooks have their own retrying queue). Rows for a canary case
(see ``is_canary``) and rows older than ``MAX_AGE`` are marked sent without
leaving the system, so a test event never pages anyone and enabling the
dispatcher on an old install does not replay its backlog.

Runs in the daemon only (``CaseAutomationService.run``).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, Callable, Dict, Optional, Tuple

import httpx
from sqlalchemy import or_
from sqlalchemy.orm import Session

from core.cases.case_notification_service import BROADCAST_CHANNEL, BROADCAST_USER_ID
from core.config import get_settings
from core.integrations import outbound_webhooks
from core.storage.models import Case, CaseNotification, User
from core.storage.unit_of_work import unit_of_work
from core.time import utcnow

logger = logging.getLogger(__name__)

MAX_AGE = timedelta(hours=24)
SLACK_POST_URL = "https://slack.com/api/chat.postMessage"
SLACK_TIMEOUT_SECONDS = 10


def is_canary(entity: Any) -> bool:
    """Whether ``entity`` (a finding or case, ORM object or dict) is a canary.

    A canary is a synthetic known-answer event pushed through the live pipeline
    (``canary_injections``); nothing it produces may reach a person or an
    external system. A finding is a canary when ``entity_context["canary"]`` is
    truthy; a case is one when any of its findings is.
    """
    if entity is None:
        return False
    if isinstance(entity, dict):
        context = entity.get("entity_context")
        findings = entity.get("findings")
    else:
        context = getattr(entity, "entity_context", None)
        findings = getattr(entity, "findings", None)
    if isinstance(context, dict) and context.get("canary"):
        return True
    if isinstance(findings, (list, tuple)):
        return any(is_canary(f) for f in findings if not isinstance(f, str))
    return False


def post_slack_message(text: str, channel: Optional[str] = None) -> Tuple[bool, str]:
    """Post ``text`` with the Slack integration's bot token. Returns (ok, detail)."""
    from core.integrations._base.config import resolve
    from core.integrations.slack.descriptor import SLACK

    config = resolve(SLACK)
    token = config.get("bot_token")
    target = channel or config.get("default_channel")
    if not token or not target:
        return False, "slack not configured"
    try:
        response = httpx.post(
            SLACK_POST_URL,
            headers={"Authorization": f"Bearer {token}"},
            json={"channel": target, "text": text},
            timeout=SLACK_TIMEOUT_SECONDS,
        )
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        return False, f"slack request failed: {type(exc).__name__}"
    if data.get("ok"):
        return True, "sent"
    return False, f"slack error: {data.get('error', 'unknown')}"


def send_email_message(to: str, subject: str, body: str) -> Tuple[bool, str]:
    from core.platform.email_service import get_email_backend

    try:
        get_email_backend().send(to=to, subject=subject, body=body)
    except Exception as exc:  # noqa: BLE001 - any backend failure is recorded
        return False, f"email failed: {type(exc).__name__}"
    return True, "sent"


def _priorities(raw: str) -> frozenset:
    return frozenset(p.strip().lower() for p in (raw or "").split(",") if p.strip())


class CaseNotificationDispatcher:
    """One pass over unsent notifications. Synchronous; call it off the loop."""

    def __init__(
        self,
        *,
        post_slack: Callable[..., Tuple[bool, str]] = post_slack_message,
        send_email: Callable[..., Tuple[bool, str]] = send_email_message,
        enqueue_webhook: Callable[..., int] = outbound_webhooks.enqueue_event,
    ):
        self._post_slack = post_slack
        self._send_email = send_email
        self._enqueue_webhook = enqueue_webhook

    def dispatch_pending(self, limit: int = 50) -> Dict[str, int]:
        settings = get_settings()
        email_priorities = _priorities(settings.case_notify_email_priorities)
        slack_broadcast = bool(settings.case_notify_slack_enabled)
        now = utcnow()
        counts: Dict[str, int] = {}
        with unit_of_work() as session:
            rows = (
                session.query(CaseNotification)
                .filter(CaseNotification.is_sent.is_(False))
                .order_by(CaseNotification.notification_id)
                .limit(limit)
                .with_for_update(skip_locked=True)
                .all()
            )
            for row in rows:
                try:
                    with session.begin_nested():
                        outcome = self._dispatch_one(
                            session, row, now, email_priorities, slack_broadcast
                        )
                except Exception:
                    # A row that cannot be sent (e.g. no webhook tables yet) is
                    # left unsent for the next pass rather than lost.
                    logger.exception(
                        "Dispatching notification %s failed", row.notification_id
                    )
                    counts["error"] = counts.get("error", 0) + 1
                    continue
                row.is_sent = True
                row.sent_at = now
                row.notification_metadata = {
                    **(row.notification_metadata or {}),
                    "dispatch": outcome,
                }
                key = outcome.get("skipped") or "sent"
                counts[key] = counts.get(key, 0) + 1
        return counts

    def _dispatch_one(
        self,
        session: Session,
        row: CaseNotification,
        now,
        email_priorities: frozenset,
        slack_broadcast: bool,
    ) -> Dict[str, Any]:
        if row.created_at is not None and now - row.created_at > MAX_AGE:
            return {"skipped": "expired"}
        case = None
        if row.case_id:
            case = session.query(Case).filter(Case.case_id == row.case_id).first()
            if is_canary(case):
                return {"skipped": "canary"}

        channels: Dict[str, str] = {}
        if (
            row.user_id == BROADCAST_USER_ID
            or row.delivery_channel == BROADCAST_CHANNEL
        ):
            meta = row.notification_metadata or {}
            event_id = meta.get("event_key") or f"notification:{row.notification_id}"
            queued = self._enqueue_webhook(
                f"case.{row.notification_type}",
                event_id,
                self._event_data(row, case),
                session=session,
            )
            channels["webhook"] = f"queued {queued}"
            if slack_broadcast:
                ok, detail = self._post_slack(f"*{row.title}*\n{row.message}")
                channels["slack"] = detail
            return {"channels": channels}

        channel = (row.delivery_channel or "ui").lower()
        if channel == "email" or (row.priority or "").lower() in email_priorities:
            channels["email"] = self._email(session, row)
        if channel == "slack":
            ok, detail = self._post_slack(
                f"*{row.title}* (for {row.user_id})\n{row.message}"
            )
            channels["slack"] = detail
        elif channel not in ("ui", "email"):
            channels[channel] = "unsupported channel"
        return {"channels": channels}

    def _email(self, session: Session, row: CaseNotification) -> str:
        user = (
            session.query(User)
            .filter(or_(User.user_id == row.user_id, User.username == row.user_id))
            .first()
        )
        if user is None or not user.email:
            return "no email address"
        body = row.message
        if row.case_id:
            body += f"\n\nCase: {row.case_id}"
        ok, detail = self._send_email(
            to=user.email, subject=f"[AutoSecOps] {row.title}", body=body
        )
        return detail

    @staticmethod
    def _event_data(row: CaseNotification, case: Optional[Case]) -> Dict[str, Any]:
        meta = {
            k: v
            for k, v in (row.notification_metadata or {}).items()
            if k not in ("dispatch", "event_key")
        }
        data: Dict[str, Any] = {
            "notification_type": row.notification_type,
            "title": row.title,
            "message": row.message,
            "priority": row.priority,
            "details": meta,
            "case": None,
        }
        if case is not None:
            data["case"] = {
                "case_id": case.case_id,
                "title": case.title,
                "status": case.status,
                "priority": case.priority,
                "assignee": case.assignee,
            }
        elif row.case_id:
            data["case"] = {"case_id": row.case_id}
        return data
