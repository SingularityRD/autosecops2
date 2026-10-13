"""
Case Notification Service - Multi-channel notification management.

Handles notifications for case events via UI, email, Slack, Teams, and PagerDuty.
"""

import logging
import re
from typing import Dict, List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.storage.models import Case, CaseNotification, CaseWatcher
from core.storage.unit_of_work import unit_of_work

logger = logging.getLogger(__name__)

# The notification types a watcher can switch off via
# ``case_watchers.notification_preferences``. This is the whole vocabulary:
# ``notify_watchers`` reads the column with ``prefs.get(notification_type, True)``,
# so a key outside this set is stored but never consulted — it looks like a
# suppression switch and silently is not one. Register a type here when you add
# a ``notify_watchers`` call site. See #553.
#
# Types delivered by calling ``create_notification`` directly (``comment_mention``,
# ``stale_case``) never reach this lookup and so are deliberately absent.
WATCHER_NOTIFICATION_TYPES = frozenset(
    {
        "new_comment",  # core/cases/case_collaboration_service.py
        "sla_warning",  # notify_sla_warning, below
    }
)

# A broadcast row is the case event itself rather than a copy addressed to one
# person: exactly one per event, written whether or not the case has an
# assignee or watchers. The dispatcher (core/cases/notification_dispatcher.py)
# sends it to outbound webhooks and, when enabled, to the Slack channel; the
# per-person rows next to it go to their recipient. ``event_key`` in the
# metadata names the event, so the SLA monitor and stale-case detector can tell
# whether they already raised it.
BROADCAST_USER_ID = "system:broadcast"
BROADCAST_CHANNEL = "broadcast"
BROADCAST_NOTIFICATION_TYPES = frozenset({"sla_warning", "stale_case"})


def sla_event_key(case_id: str, sla_type: str, threshold_percent: int) -> str:
    return f"sla:{case_id}:{sla_type}:{int(threshold_percent)}"


def stale_event_key(case_id: str, day: str) -> str:
    return f"stale:{case_id}:{day}"


class CaseNotificationService:
    """Service for managing case notifications."""

    def __init__(self):
        """Initialize the notification service."""

    def create_notification(
        self,
        user_id: str,
        notification_type: str,
        title: str,
        message: str,
        case_id: Optional[str] = None,
        delivery_channel: str = "ui",
        priority: str = "normal",
        metadata: Optional[Dict] = None,
        session: Optional[Session] = None,
    ) -> Optional[CaseNotification]:
        """
        Create a notification for a user.

        Args:
            user_id: User ID to notify
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            case_id: Associated case ID
            delivery_channel: Delivery channel (ui, email, slack, teams, pagerduty)
            priority: Priority (low, normal, high, urgent)
            metadata: Additional metadata
            session: Database session (optional)

        Returns:
            Created CaseNotification or None
        """
        try:
            with unit_of_work(session) as session:
                notification = CaseNotification(
                    case_id=case_id,
                    user_id=user_id,
                    notification_type=notification_type,
                    title=title,
                    message=message,
                    delivery_channel=delivery_channel,
                    priority=priority,
                    # Must be notification_metadata: the column was renamed
                    # to avoid SQLAlchemy's reserved name, and `metadata=`
                    # lands on the declarative MetaData, not a column.
                    # See #559.
                    notification_metadata=metadata or {},
                    is_read=False,
                    is_sent=False,
                )

                session.add(notification)

                logger.info(f"Created notification for {user_id}: {notification_type}")
                return notification

        except Exception as e:
            logger.error(f"Error creating notification: {e}")
            return None

    def notify_comment_mention(
        self,
        case_id: str,
        mentioned_user: str,
        comment_author: str,
        comment_content: str,
        session: Optional[Session] = None,
    ) -> bool:
        """
        Notify user about being mentioned in a comment.

        Args:
            case_id: Case ID
            mentioned_user: User who was mentioned
            comment_author: Author of the comment
            comment_content: Comment content
            session: Database session (optional)

        Returns:
            True if successful
        """
        with unit_of_work(session) as session:
            case = session.query(Case).filter(Case.case_id == case_id).first()
            if not case:
                return False

            # Truncate comment for notification
            truncated_comment = (
                comment_content[:100] + "..."
                if len(comment_content) > 100
                else comment_content
            )

            self.create_notification(
                user_id=mentioned_user,
                notification_type="comment_mention",
                title="Mentioned in Comment",
                message=f'{comment_author} mentioned you in case "{case.title}": {truncated_comment}',
                case_id=case_id,
                delivery_channel="ui",
                priority="normal",
                metadata={
                    "comment_author": comment_author,
                    "comment_content": comment_content,
                },
                session=session,
            )

            return True

    def event_already_raised(self, event_key: str, session: Session) -> bool:
        """Whether a broadcast row for ``event_key`` exists (sent or not)."""
        return (
            session.query(CaseNotification.notification_id)
            .filter(
                CaseNotification.user_id == BROADCAST_USER_ID,
                CaseNotification.notification_metadata["event_key"].astext == event_key,
            )
            .first()
            is not None
        )

    def create_broadcast(
        self,
        notification_type: str,
        title: str,
        message: str,
        event_key: str,
        case_id: Optional[str] = None,
        priority: str = "normal",
        metadata: Optional[Dict] = None,
        session: Optional[Session] = None,
    ) -> Optional[CaseNotification]:
        """Write the one broadcast row for a case event (see BROADCAST_USER_ID).

        Returns None when the event was already raised. The unique index
        ``uq_case_notification_broadcast_event`` decides, not the
        ``event_already_raised`` read: two passes racing past that read both
        try to insert, and the loser's insert conflicts inside a savepoint,
        so the caller's transaction (and anything else it wrote) survives.
        """
        with unit_of_work(session) as session:
            notification = CaseNotification(
                case_id=case_id,
                user_id=BROADCAST_USER_ID,
                notification_type=notification_type,
                title=title,
                message=message,
                delivery_channel=BROADCAST_CHANNEL,
                priority=priority,
                notification_metadata={**(metadata or {}), "event_key": event_key},
                is_read=False,
                is_sent=False,
            )
            try:
                with session.begin_nested():
                    session.add(notification)
                    session.flush()
            except IntegrityError:
                logger.info("Case event %s already raised; not raising again", event_key)
                return None
            return notification

    def notify_sla_warning(
        self,
        case_id: str,
        threshold_percent: int,
        sla_type: str,
        session: Optional[Session] = None,
    ) -> bool:
        """
        Notify about approaching SLA deadline.

        Writes the broadcast row for the event (webhooks, Slack channel) and a
        row for the assignee and each watcher. Every row carries the same
        ``event_key``, which is how the SLA monitor raises each threshold once.

        Args:
            case_id: Case ID
            threshold_percent: Percentage of SLA elapsed
            sla_type: Type of SLA (response or resolution)
            session: Database session (optional)

        Returns:
            True if successful
        """
        with unit_of_work(session) as session:
            case = session.query(Case).filter(Case.case_id == case_id).first()
            if not case:
                return False

            urgency = "urgent" if threshold_percent >= 90 else "high"
            message = (
                f'Case "{case.title}" has reached {threshold_percent}% '
                f"of its {sla_type} SLA deadline"
            )
            metadata = {
                "threshold_percent": threshold_percent,
                "sla_type": sla_type,
                "event_key": sla_event_key(case_id, sla_type, threshold_percent),
            }

            if (
                self.create_broadcast(
                    notification_type="sla_warning",
                    title=f"SLA Warning: {threshold_percent}% Elapsed",
                    message=message,
                    event_key=metadata["event_key"],
                    case_id=case_id,
                    priority=urgency,
                    metadata=metadata,
                    session=session,
                )
                is None
            ):
                # Another pass raised this threshold first; its rows stand.
                return False

            # Notify assignee if assigned
            if case.assignee:
                self.create_notification(
                    user_id=case.assignee,
                    notification_type="sla_warning",
                    title=f"SLA Warning: {threshold_percent}% Elapsed",
                    message=message,
                    case_id=case_id,
                    delivery_channel="ui",
                    priority=urgency,
                    metadata=metadata,
                    session=session,
                )

            # Also notify watchers
            self.notify_watchers(
                case_id=case_id,
                notification_type="sla_warning",
                title=f"SLA Warning: {threshold_percent}%",
                message=message,
                metadata=metadata,
                session=session,
            )

            return True

    def notify_stale_case(
        self, case: Case, day: str, session: Optional[Session] = None
    ) -> bool:
        """Raise the stale-case event for ``case`` once per ``day`` (YYYY-MM-DD)."""
        with unit_of_work(session) as session:
            event_key = stale_event_key(case.case_id, day)
            if self.event_already_raised(event_key, session):
                return False
            message = f'Case "{case.title}" has had no activity for 7+ days'
            if (
                self.create_broadcast(
                    notification_type="stale_case",
                    title="Stale Case Alert",
                    message=message,
                    event_key=event_key,
                    case_id=case.case_id,
                    session=session,
                )
                is None
            ):
                return False
            if case.assignee:
                self.create_notification(
                    user_id=case.assignee,
                    notification_type="stale_case",
                    title="Stale Case Alert",
                    message=message,
                    case_id=case.case_id,
                    priority="normal",
                    metadata={"event_key": event_key},
                    session=session,
                )
            return True

    def notify_watchers(
        self,
        case_id: str,
        notification_type: str,
        title: str,
        message: str,
        priority: str = "normal",
        session: Optional[Session] = None,
        metadata: Optional[Dict] = None,
    ) -> int:
        """
        Notify all watchers of a case.

        Args:
            case_id: Case ID
            notification_type: Type of notification
            title: Notification title
            message: Notification message
            priority: Priority level
            session: Database session (optional)
            metadata: Stored on each watcher's row (optional)

        Returns:
            Number of notifications created
        """
        if notification_type not in WATCHER_NOTIFICATION_TYPES:
            # Warn rather than raise: the new_comment call site runs inside
            # add_comment's try/except, which rolls back and returns None, so
            # raising would turn a registration slip into a silently dropped
            # comment. Fail open — send, matching the absent-key default.
            logger.warning(
                "notify_watchers called with unregistered notification type %r; "
                "watcher preferences cannot suppress it. Add it to "
                "WATCHER_NOTIFICATION_TYPES.",
                notification_type,
            )

        with unit_of_work(session) as session:
            watchers = (
                session.query(CaseWatcher).filter(CaseWatcher.case_id == case_id).all()
            )

            count = 0
            for watcher in watchers:
                # Check if user wants this type of notification
                prefs = watcher.notification_preferences or {}
                if prefs.get(notification_type, True):  # Default to True
                    self.create_notification(
                        user_id=watcher.user_id,
                        notification_type=notification_type,
                        title=title,
                        message=message,
                        case_id=case_id,
                        delivery_channel="ui",
                        priority=priority,
                        metadata=metadata,
                        session=session,
                    )
                    count += 1

            return count

    def extract_mentions(self, text: str) -> List[str]:
        """
        Extract @mentions from text.

        Args:
            text: Text to parse

        Returns:
            List of mentioned usernames
        """
        # Pattern: @username (alphanumeric, underscore, hyphen, period)
        pattern = r"@([\w.-]+)"
        mentions = re.findall(pattern, text)
        return list(set(mentions))  # Remove duplicates
