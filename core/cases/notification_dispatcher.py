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
  Slack integration's default channel. W0.46: also emailed to the
  ``CASE_NOTIFY_EMAIL_TO`` list when the row's priority is in
  ``CASE_NOTIFY_EMAIL_TO_PRIORITIES``, and posted to a Microsoft Teams channel
  when ``CASE_NOTIFY_TEAMS_ENABLED`` is on. W0.58: texted to the
  ``CASE_NOTIFY_SMS_TO`` numbers through the operator's SMS gateway when the
  row's priority is in ``CASE_NOTIFY_SMS_PRIORITIES``.
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
import re
from datetime import timedelta
from typing import Any, Callable, Dict, Optional, Tuple

import httpx
from sqlalchemy import or_
from sqlalchemy.orm import Session, object_session

from core.cases.case_notification_service import BROADCAST_CHANNEL, BROADCAST_USER_ID
from core.config import get_settings
from core.integrations import outbound_webhooks
from core.storage.canary_exclusion import case_canary_profile, is_canary_finding
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

    Hidden canaries (W1.5) carry no flag: their only record is their
    ``canary_injections`` row, so an entity with an id is also looked up there
    (``core.storage.canary_exclusion``): a finding by its ``finding_id``, a case
    when every finding it links is a canary (a mixed case is real work and
    keeps its notifications). A failed lookup raises, so the caller sends
    nothing for that entity this pass.
    """
    if entity is None:
        return False
    return _flagged(entity) or _hidden_canary(entity)


def _flagged(entity: Any) -> bool:
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
        return any(_flagged(f) for f in findings if not isinstance(f, str))
    return False


def _hidden_canary(entity: Any) -> bool:
    def _get(name: str) -> Any:
        if isinstance(entity, dict):
            return entity.get(name)
        return getattr(entity, name, None)

    finding_id, case_id = _get("finding_id"), _get("case_id")
    if not isinstance(finding_id, str) and not isinstance(case_id, str):
        return False
    session = None if isinstance(entity, dict) else object_session(entity)
    if isinstance(finding_id, str) and finding_id:
        return is_canary_finding(finding_id, session)
    return bool(case_canary_profile(case_id, session)["only_canaries"])


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


TEAMS_TIMEOUT_SECONDS = 10
TEAMS_URL_SECRET = "CASE_NOTIFY_TEAMS_WEBHOOK_URL"


def teams_card(title: str, text: str, facts: Dict[str, str]) -> Dict[str, Any]:
    """A Teams message with one Adaptive Card (what a Workflows webhook posts)."""
    body: list = [
        {"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True},
        {"type": "TextBlock", "text": text, "wrap": True},
    ]
    if facts:
        body.append(
            {
                "type": "FactSet",
                "facts": [{"title": k, "value": v} for k, v in facts.items() if v],
            }
        )
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "type": "AdaptiveCard",
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "version": "1.4",
                    "body": body,
                },
            }
        ],
    }


def post_teams_message(
    title: str, text: str, facts: Optional[Dict[str, str]] = None
) -> Tuple[bool, str]:
    """Post one card to the Teams workflow URL. Returns (ok, detail); the URL,
    which carries its signature, is never in the detail."""
    from core.platform.url_safety import UrlSafetyError, refuse_metadata_target
    from core.secrets import get_secret

    url = (get_secret(TEAMS_URL_SECRET) or "").strip()
    if not url:
        return False, "teams not configured"
    if not url.startswith("https://"):
        return False, "teams url must be https"
    try:
        refuse_metadata_target(url)
    except UrlSafetyError as exc:
        return False, f"teams url refused: {exc}"
    try:
        response = httpx.post(
            url,
            json=teams_card(title, text, facts or {}),
            timeout=TEAMS_TIMEOUT_SECONDS,
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        return False, f"teams request failed: {type(exc).__name__}"
    if 200 <= response.status_code < 300:
        return True, "sent"
    return False, f"teams answered HTTP {response.status_code}"


SMS_TIMEOUT_SECONDS = 10
SMS_URL_SECRET = "CASE_NOTIFY_SMS_GATEWAY_URL"
SMS_TOKEN_SECRET = "CASE_NOTIFY_SMS_GATEWAY_TOKEN"
# Three SMS segments; a longer case event is cut, the console has the rest.
SMS_MAX_CHARS = 459
_PHONE_RE = re.compile(r"^\+[1-9][0-9]{6,14}$")


def _numbers(raw: str) -> Tuple[str, ...]:
    """E.164 numbers (``+905321234567``); anything else is dropped."""
    out = []
    for part in (raw or "").split(","):
        number = re.sub(r"[\s()-]", "", part)
        if _PHONE_RE.match(number):
            out.append(number)
    return tuple(out)


def sms_text(title: str, case_id: Optional[str]) -> str:
    text = f"AutoSecOps: {title}" + (f" ({case_id})" if case_id else "")
    return text if len(text) <= SMS_MAX_CHARS else text[: SMS_MAX_CHARS - 1] + "…"


def send_sms_message(to: str, text: str) -> Tuple[bool, str]:
    """POST ``{"to", "message"}`` to the operator's SMS gateway (W0.58).

    The gateway is any HTTPS endpoint that takes that JSON: the provider's own
    API where it matches, otherwise a small relay in the customer network
    (which also keeps an air-gapped install's SMS on its own network). The URL
    and the optional bearer token are secrets and never in the detail.
    """
    from core.platform.url_safety import UrlSafetyError, refuse_metadata_target
    from core.secrets import get_secret

    url = (get_secret(SMS_URL_SECRET) or "").strip()
    if not url:
        return False, "sms not configured"
    if not url.startswith("https://"):
        return False, "sms gateway url must be https"
    try:
        refuse_metadata_target(url)
    except UrlSafetyError as exc:
        return False, f"sms gateway url refused: {exc}"
    token = (get_secret(SMS_TOKEN_SECRET) or "").strip()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        response = httpx.post(
            url,
            json={"to": to, "message": text},
            headers=headers,
            timeout=SMS_TIMEOUT_SECONDS,
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        return False, f"sms request failed: {type(exc).__name__}"
    if 200 <= response.status_code < 300:
        return True, "sent"
    return False, f"sms gateway answered HTTP {response.status_code}"


def _addresses(raw: str) -> Tuple[str, ...]:
    return tuple(a.strip() for a in (raw or "").split(",") if "@" in a)


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
        post_teams: Callable[..., Tuple[bool, str]] = post_teams_message,
        send_sms: Callable[..., Tuple[bool, str]] = send_sms_message,
    ):
        self._post_slack = post_slack
        self._send_email = send_email
        self._enqueue_webhook = enqueue_webhook
        self._post_teams = post_teams
        self._send_sms = send_sms

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
                # No "canary" on a hidden canary's row: the record is readable.
                return {"skipped": "canary" if _flagged(case) else "withheld"}

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
            channels.update(self._broadcast_extra(row, case))
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

    def _broadcast_extra(
        self, row: CaseNotification, case: Optional[Case]
    ) -> Dict[str, str]:
        """The W0.46 broadcast channels (a mail list, a Teams channel) and
        W0.58's SMS to on-call numbers."""
        settings = get_settings()
        out: Dict[str, str] = {}
        recipients = _addresses(settings.case_notify_email_to)
        wanted = _priorities(settings.case_notify_email_to_priorities)
        if recipients and (row.priority or "").lower() in wanted:
            body = row.message + (f"\n\nCase: {row.case_id}" if row.case_id else "")
            results = [
                self._send_email(
                    to=address, subject=f"[AutoSecOps] {row.title}", body=body
                )
                for address in recipients
            ]
            sent = sum(1 for ok, _ in results if ok)
            out["email_list"] = f"sent {sent}/{len(recipients)}"
        if settings.case_notify_teams_enabled:
            facts = {"Priority": row.priority or ""}
            if case is not None:
                facts.update(
                    {
                        "Case": case.case_id,
                        "Status": case.status or "",
                        "Assignee": case.assignee or "",
                    }
                )
            elif row.case_id:
                facts["Case"] = row.case_id
            ok, detail = self._post_teams(row.title, row.message, facts)
            out["teams"] = detail
        numbers = _numbers(settings.case_notify_sms_to)
        if numbers and (row.priority or "").lower() in _priorities(
            settings.case_notify_sms_priorities
        ):
            text = sms_text(row.title, row.case_id)
            results = [self._send_sms(to=n, text=text) for n in numbers]
            sent = sum(1 for ok, _ in results if ok)
            out["sms"] = f"sent {sent}/{len(numbers)}"
            failed = sorted({d for ok, d in results if not ok})
            if failed:
                out["sms"] += f" ({'; '.join(failed)})"
        return out

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
