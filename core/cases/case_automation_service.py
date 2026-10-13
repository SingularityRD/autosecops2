"""
Case Automation Service - Scheduled jobs and automated workflows.

Handles SLA monitoring, auto-assignment, escalation, and periodic tasks.
"""

import asyncio
import logging
from datetime import timedelta
from typing import Dict, List, Optional

from core.cases.case_metrics_service import CaseMetricsService
from core.cases.case_notification_service import (
    CaseNotificationService,
    sla_event_key,
)
from core.cases.case_sla_service import CaseSLAService
from core.cases.case_workflow_service import CaseWorkflowService
from core.cases.notification_dispatcher import CaseNotificationDispatcher, is_canary
from core.integrations.outbound_webhooks import WebhookSender
from core.storage.models import Case, CaseSLA
from core.storage.unit_of_work import unit_of_work
from core.time import utcnow

logger = logging.getLogger(__name__)

SLA_THRESHOLDS = (75, 90, 100)
SLA_INTERVAL_SECONDS = 60
DISPATCH_INTERVAL_SECONDS = 15
WEBHOOK_INTERVAL_SECONDS = 5


def highest_crossed(percent_elapsed: float) -> Optional[int]:
    crossed = [t for t in SLA_THRESHOLDS if percent_elapsed >= t]
    return max(crossed) if crossed else None


class CaseAutomationService:
    """Service for automated case workflows and scheduled tasks.

    Lifecycle: the daemon owns it (``services/daemon/main.py`` starts
    ``run(shutdown_event)`` as a component when ``CASE_AUTOMATION_ENABLED``).
    The API process never starts it, so each loop runs once per install.
    Sending stays safe even if two daemons ever run: webhook deliveries and
    notifications are claimed with ``SKIP LOCKED``.
    """

    def __init__(
        self,
        *,
        dispatcher: Optional[CaseNotificationDispatcher] = None,
        webhook_sender: Optional[WebhookSender] = None,
    ):
        """Initialize the automation service."""
        self.sla_service = CaseSLAService()
        self.workflow_service = CaseWorkflowService()
        self.notification_service = CaseNotificationService()
        self.metrics_service = CaseMetricsService()
        self.dispatcher = dispatcher
        self.webhook_sender = webhook_sender
        self.running = False

    def _loops(self):
        if self.dispatcher is None:
            self.dispatcher = CaseNotificationDispatcher()
        if self.webhook_sender is None:
            self.webhook_sender = WebhookSender()
        return [
            self.sla_monitor_task(),
            self.metrics_update_task(),
            self.stale_case_detector_task(),
            self.digest_generator_task(),
            self.notification_dispatch_task(),
            self.webhook_delivery_task(),
        ]

    async def run(self, shutdown_event: asyncio.Event):
        """Run every loop until ``shutdown_event`` is set (daemon component)."""
        self.running = True
        logger.info("Starting case automation service")
        tasks = [asyncio.create_task(loop) for loop in self._loops()]
        try:
            await shutdown_event.wait()
        finally:
            self.running = False
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            logger.info("Case automation service stopped")

    async def start(self):
        """Start all automation tasks (until ``stop``)."""
        self.running = True
        logger.info("Starting case automation service")
        await asyncio.gather(*self._loops(), return_exceptions=True)

    async def stop(self):
        """Stop automation service."""
        self.running = False
        logger.info("Stopping case automation service")

    async def sla_monitor_task(self):
        """Monitor SLAs and send alerts."""
        while self.running:
            try:
                logger.debug("Running SLA monitor")
                await asyncio.to_thread(self.check_sla_deadlines)
            except Exception as e:
                logger.error(f"Error in SLA monitor task: {e}")
            await asyncio.sleep(SLA_INTERVAL_SECONDS)

    async def notification_dispatch_task(self):
        """Send pending case notifications (email, Slack, webhook queue)."""
        while self.running:
            try:
                counts = await asyncio.to_thread(self.dispatcher.dispatch_pending)
                if counts:
                    logger.info("Dispatched case notifications: %s", counts)
            except Exception as e:
                logger.error("Error in notification dispatcher: %s", e)
            await asyncio.sleep(DISPATCH_INTERVAL_SECONDS)

    async def webhook_delivery_task(self):
        """Send due outbound webhook deliveries."""
        while self.running:
            try:
                counts = await self.webhook_sender.deliver_due()
                if counts:
                    logger.info("Webhook deliveries: %s", counts)
            except Exception as e:
                logger.error("Error in webhook sender: %s", e)
            await asyncio.sleep(WEBHOOK_INTERVAL_SECONDS)

    def check_sla_deadlines(self) -> int:
        try:
            return self._raise_sla_warnings()
        except Exception as e:
            logger.error(f"Error checking SLA deadlines: {e}")
            return 0

    def _raise_sla_warnings(self) -> int:
        """Raise each crossed SLA threshold once; mark breaches. Returns raised."""
        raised = 0
        with unit_of_work() as session:
            active_slas = (
                session.query(CaseSLA)
                .filter(
                    CaseSLA.resolution_completed_at.is_(None),
                    CaseSLA.is_paused.is_(False),
                )
                .all()
            )

            current_time = utcnow()

            for sla in active_slas:
                case = session.query(Case).filter(Case.case_id == sla.case_id).first()
                if case is None or is_canary(case):
                    continue
                status = self.sla_service.get_sla_status(sla.case_id, session)
                if not status:
                    continue

                response_pct = status.get("response_percent_elapsed", 0) or 0
                resolution_pct = status.get("resolution_percent_elapsed", 0) or 0

                # Only the highest threshold crossed is raised: a case first
                # seen at 95% gets the 90% warning, not 75% and 90% at once.
                pending = []
                if not sla.response_completed_at:
                    pending.append(("response", highest_crossed(response_pct)))
                if not sla.resolution_completed_at:
                    pending.append(("resolution", highest_crossed(resolution_pct)))
                for sla_type, threshold in pending:
                    if threshold is None:
                        continue
                    key = sla_event_key(sla.case_id, sla_type, threshold)
                    if self.notification_service.event_already_raised(key, session):
                        continue
                    if self.notification_service.notify_sla_warning(
                        sla.case_id, threshold, sla_type, session
                    ):
                        raised += 1

                # Mark as breached if over 100%
                if (resolution_pct >= 100 or response_pct >= 100) and not sla.breached:
                    sla.breached = True
                    sla.breach_time = current_time
                    sla.breach_reason = "SLA deadline exceeded"
        return raised

    async def metrics_update_task(self):
        """Update case metrics periodically."""
        while self.running:
            try:
                logger.debug("Running metrics update")
                await asyncio.to_thread(self._update_case_metrics)
            except Exception as e:
                logger.error(f"Error in metrics update task: {e}")
            await asyncio.sleep(3600)  # Update every hour

    def _update_case_metrics(self):
        try:
            return self._update_open_case_metrics()
        except Exception as e:
            logger.error(f"Error updating case metrics: {e}")
            return None

    def _update_open_case_metrics(self):
        """Update metrics for all open cases."""
        with unit_of_work() as session:
            open_cases = (
                session.query(Case)
                .filter(Case.status.in_(["open", "in-progress", "investigating"]))
                .all()
            )

            for case in open_cases:
                self.metrics_service.calculate_case_metrics(case.case_id, session)

            logger.info("Updated metrics for %d cases", len(open_cases))

    async def stale_case_detector_task(self):
        """Detect and flag stale cases."""
        while self.running:
            try:
                logger.debug("Running stale case detector")
                await asyncio.to_thread(self.detect_stale_cases)
            except Exception as e:
                logger.error(f"Error in stale case detector: {e}")
            await asyncio.sleep(86400)  # Check daily

    def detect_stale_cases(self) -> int:
        try:
            return self._raise_stale_cases()
        except Exception as e:
            logger.error(f"Error detecting stale cases: {e}")
            return 0

    def _raise_stale_cases(self) -> int:
        """Raise the stale-case event (once a day) for idle open cases."""
        now = utcnow()
        stale_threshold = now - timedelta(days=7)
        raised = 0
        with unit_of_work() as session:
            stale_cases = (
                session.query(Case)
                .filter(
                    Case.status.in_(["open", "in-progress", "investigating"]),
                    Case.updated_at < stale_threshold,
                )
                .all()
            )
            day = now.date().isoformat()
            for case in stale_cases:
                if is_canary(case):
                    continue
                if self.notification_service.notify_stale_case(case, day, session):
                    raised += 1

            logger.info(
                "Detected %d stale cases (%d newly raised)", len(stale_cases), raised
            )
        return raised

    async def digest_generator_task(self):
        """Generate daily digest emails."""
        while self.running:
            try:
                # Calculate time until next 9 AM
                now = utcnow()
                next_run = now.replace(hour=9, minute=0, second=0, microsecond=0)
                if now.hour >= 9:
                    next_run += timedelta(days=1)

                wait_seconds = (next_run - now).total_seconds()
                logger.info("Next digest in %.1f hours", wait_seconds / 3600)

                await asyncio.sleep(wait_seconds)

                logger.info("Generating daily digest")
                await asyncio.to_thread(self._generate_daily_digest)
            except Exception as e:
                logger.error(f"Error in digest generator: {e}")
                await asyncio.sleep(3600)

    def _generate_daily_digest(self):
        try:
            return self._log_daily_digest()
        except Exception as e:
            logger.error(f"Error generating digest: {e}")
            return None

    def _log_daily_digest(self):
        """Generate and send daily digest."""
        with unit_of_work() as session:
            # Get metrics for last 24 hours
            yesterday = utcnow() - timedelta(days=1)
            metrics = self.metrics_service.get_dashboard_metrics(
                start_date=yesterday, session=session
            )

            # Get breached cases
            breached = self.sla_service.get_breached_cases(session)

            logger.info(
                "Daily digest: %s total cases, %d breached",
                metrics.get("total_cases", 0),
                len(breached),
            )


# Singleton instance
automation_service = CaseAutomationService()


# ---------------------------------------------------------------------------
# VStrike attack-path clustering
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(findings: List[Dict]) -> str:
    best = "low"
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if _SEVERITY_ORDER.get(sev, 0) > _SEVERITY_ORDER.get(best, 0):
            best = sev
    return best


def cluster_findings_by_attack_path(finding_ids: List[str]) -> List[str]:
    """Group VStrike-enriched findings into cases by (segment, attack_path[0]).

    For each cluster with at least one finding, create a case titled
    "VStrike: {segment} via {initial_asset}". Returns the list of newly
    created case_ids.

    Findings without a `vstrike` sub-dict in `entity_context` are skipped —
    this function is VStrike-specific by design.
    """
    from core.storage.database_data_service import DatabaseDataService

    data_service = DatabaseDataService()

    clusters: Dict[tuple, List[Dict]] = {}
    for fid in finding_ids:
        finding = data_service.get_finding(fid)
        if not finding:
            continue
        ctx = finding.get("entity_context") or {}
        vstrike = ctx.get("vstrike") if isinstance(ctx, dict) else None
        if not vstrike:
            continue
        segment = vstrike.get("segment") or "unknown-segment"
        attack_path = vstrike.get("attack_path") or []
        initial_asset = (
            attack_path[0]
            if attack_path
            else (vstrike.get("asset_id") or "unknown-asset")
        )
        key = (segment, initial_asset)
        clusters.setdefault(key, []).append(finding)

    created_case_ids: List[str] = []
    for (segment, initial_asset), findings in clusters.items():
        ids = [f.get("finding_id") for f in findings if f.get("finding_id")]
        if not ids:
            continue

        severity = _max_severity(findings)
        priority = severity  # treat severity as priority for VStrike cases
        mission_systems = sorted(
            {
                (f.get("entity_context") or {}).get("vstrike", {}).get("mission_system")
                for f in findings
                if (f.get("entity_context") or {})
                .get("vstrike", {})
                .get("mission_system")
            }
        )
        mission_str = (
            f" Mission systems impacted: {', '.join(mission_systems)}."
            if mission_systems
            else ""
        )
        description = (
            f"{len(findings)} enriched finding(s) from the VStrike fusion layer "
            f"across segment '{segment}'. Attack path origin: {initial_asset}."
            f"{mission_str}"
        )
        title = f"VStrike: {segment} via {initial_asset}"

        case = data_service.create_case(
            title=title,
            finding_ids=ids,
            priority=priority,
            description=description,
            status="open",
        )
        if case and case.get("case_id"):
            created_case_ids.append(case["case_id"])
            logger.info(
                "Created VStrike auto-cluster case %s (%s findings)",
                case["case_id"],
                len(ids),
            )

    return created_case_ids
