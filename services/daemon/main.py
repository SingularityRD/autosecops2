"""SOC Daemon - Main entry point and orchestration."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Optional

# Add the repo root to sys.path (this file is services/daemon/main.py).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.config import validate_settings_or_exit
from services.daemon.leadership import LeadershipLost

if TYPE_CHECKING:
    from services.daemon.config import DaemonConfig

logger = logging.getLogger(__name__)


def build_case_automation():
    """The case automation component, or None when switched off.

    SLA monitor, stale-case detector, digest, notification dispatcher and the
    outbound webhook sender run here, in the daemon, and nowhere else: the API
    may run several workers, and each would start its own copy of every loop.
    """
    from core.config import get_settings

    if not get_settings().case_automation_enabled:
        logger.info("Case automation is disabled (CASE_AUTOMATION_ENABLED=false)")
        return None
    from core.cases.case_automation_service import CaseAutomationService

    return CaseAutomationService()


class SOCDaemon:
    """Main daemon orchestrator for autonomous SOC operations."""

    def __init__(self, config: Optional[DaemonConfig] = None):
        if config is None:
            from services.daemon.config import DaemonConfig

            config = DaemonConfig.from_env()
        self.config = config
        self.config.setup_logging()

        # Observe mode (#915): log declared-vs-effective intent, enforce nothing.
        try:
            from services.daemon.intent import report_intent

            report_intent(self.config)
        except Exception as _intent_err:
            logger.warning("Intent report failed (non-fatal): %s", _intent_err)

        # Initialize OTEL telemetry after logging is set up
        try:
            from core.telemetry import init_telemetry

            init_telemetry("vigil-daemon")
        except Exception as _tel_err:
            logger.warning("Telemetry init failed (non-fatal): %s", _tel_err)

        self._running = False
        self._shutdown_event = asyncio.Event()

        # Components (lazy loaded)
        self._poller = None
        self._kafka_ingestor = None
        self._processor = None
        self._responder = None
        self._scheduler = None
        self._orchestrator = None
        self._metrics_server = None
        self._mcp_client = None
        self._case_automation = None
        # Hot standby (W3.9): set by run() when leader election is on.
        self._leadership = None
        # W0.12 ingest spool; opened by the leader only (_init_components).
        self._spool = None

        logger.info("SOC Daemon initialized")

    def _setup_signal_handlers(self):
        """Setup graceful shutdown handlers."""
        loop = asyncio.get_running_loop()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._handle_shutdown)

    def _handle_shutdown(self):
        """Handle shutdown signal."""
        logger.info("Shutdown signal received")
        self._shutdown_event.set()

    def _on_task_done(self, name: str, task: asyncio.Task) -> None:
        """Log the moment a component task dies outside of shutdown."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.error(
                "Component task '%s' failed: %s", name, type(exc).__name__, exc_info=exc
            )
        elif not self._shutdown_event.is_set():
            logger.error("Component task '%s' exited unexpectedly", name)

    async def _init_components(self):
        """Initialize all daemon components."""
        logger.info("Initializing daemon components...")

        # Import here to avoid circular imports
        from core.integrations.mcp.client import (
            build_mcp_client,
            set_process_mcp_client,
        )
        from core.response.approval_service import ApprovalService
        from core.response.autonomous_response_service import AutonomousResponseService
        from core.response.executors.wiring import LiveExecutorRegistry
        from core.storage.connection import get_db_manager
        from services.daemon.kafka_ingestor import KafkaIngestor
        from services.daemon.metrics import MetricsServer
        from services.daemon.orchestrator import Orchestrator
        from services.daemon.poller import DataPoller
        from services.daemon.processor import FindingProcessor
        from services.daemon.responder import AutonomousResponder
        from services.daemon.scheduler import TaskScheduler

        # Resolve the DB credentials now so a missing password stops startup,
        # rather than surfacing on the first query inside a component task.
        get_db_manager()

        self._poller = DataPoller(self.config.polling)
        self._kafka_ingestor = KafkaIngestor(self.config.kafka)
        self._processor = FindingProcessor(
            self.config.processing, response_config=self.config.response
        )
        # The daemon owns its own copies: it is a separate process from the API, so
        # nothing on the API's app.state is reachable from here.
        self._mcp_client = build_mcp_client()
        set_process_mcp_client(self._mcp_client)
        approvals = ApprovalService(config=self.config.response)
        # The daemon's own, as the API lifespan builds its own. It re-reads the
        # stored integration config, so an executor enabled in Settings needs no
        # daemon restart (W0.37).
        response_service = AutonomousResponseService(
            approvals=approvals,
            config=self.config.response,
            executors=LiveExecutorRegistry(),
        )

        self._responder = AutonomousResponder(
            self.config.response,
            self.config.escalation,
            response_service=response_service,
            approvals=approvals,
        )
        self._scheduler = TaskScheduler(self.config.scheduler)
        self._orchestrator = Orchestrator(
            self.config.orchestrator,
            approvals=approvals,
            response=response_service,
        )

        # With leader election the health server is already up (standby).
        if self.config.metrics.enabled and self._metrics_server is None:
            self._metrics_server = MetricsServer(self.config.metrics)

        self._case_automation = build_case_automation()

        # W0.12: the webhook acknowledges into a durable spool the processor
        # drains; what a previous run left there is replayed from here.
        self._spool = await self._open_spool()
        self._processor.attach_spool(self._spool)
        self._poller.set_spool(self._spool)

        # Connect components via queues
        self._poller.set_output_queue(self._processor.input_queue)
        self._kafka_ingestor.set_output_queue(self._processor.input_queue)
        self._processor.set_response_queue(self._responder.input_queue)
        self._scheduler.set_processor_queue(self._processor.input_queue)

        # Wire up metrics server with component references
        if self._metrics_server:
            self._metrics_server.poller = self._poller
            self._metrics_server.kafka_ingestor = self._kafka_ingestor
            self._metrics_server.processor = self._processor
            self._metrics_server.responder = self._responder
            self._metrics_server.scheduler = self._scheduler
            self._metrics_server.orchestrator = self._orchestrator

        logger.info("All components initialized")

    async def _open_spool(self):
        """The opened ingest spool, or None (the webhook then acks on store).

        Only the leader gets here (W3.9), so only the leader replays. The
        directory is per pod (docs/operations/ingest-durability.md): with
        leader election a standby's own spool waits until that pod leads.
        """
        cfg = self.config.spool
        if not cfg.enabled:
            logger.warning(
                "Ingest spool disabled (DAEMON_INGEST_SPOOL_ENABLED=false): the "
                "webhook answers 200 only once each row is stored"
            )
            return None
        from core.ingestion.spool import IngestSpool, register_metrics

        try:
            spool = IngestSpool(
                cfg.resolved_directory(),
                max_findings=cfg.max_findings,
                max_bytes=cfg.max_mb * 1024 * 1024,
            )
            loaded = await asyncio.to_thread(spool.open)
        except Exception as exc:  # noqa: BLE001 - SpoolError, OSError, bad config
            logger.error(
                "Ingest spool unavailable (%s); the webhook answers 200 only once "
                "each row is stored, 503 otherwise",
                exc,
            )
            return None
        register_metrics(spool)
        logger.info(
            "Ingest spool %s open (%d to replay, max %d findings / %d MiB)",
            spool.directory,
            loaded,
            cfg.max_findings,
            cfg.max_mb,
        )
        return spool

    async def run(self):
        """Run the daemon (as leader or standby when leader election is on)."""
        logger.info("Starting SOC Daemon...")
        self._running = True

        try:
            self._setup_signal_handlers()
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            logger.warning("Signal handlers not supported on this platform")

        tasks = []

        def start(name: str, component, label: str):
            task = asyncio.create_task(component.run(self._shutdown_event))
            task.add_done_callback(lambda t: self._on_task_done(name, t))
            if self._metrics_server and component is not self._metrics_server:
                self._metrics_server.register_task(name, task)
            tasks.append(task)
            logger.info("%s started", label)

        leading = True
        if self._leader_election_enabled():
            leading = await self._await_leadership(start)

        if leading:
            if self._leadership is not None:
                # The heartbeat thread is already beating (started on
                # acquisition); this only turns a lost lease into shutdown.
                watch = asyncio.create_task(self._watch_leadership())
                tasks.append(watch)
            try:
                await self._start_components(start)
            except LeadershipLost as exc:
                logger.critical("Not starting components: %s", exc)
                self._shutdown_event.set()

        # Wait for shutdown signal (or loss of leadership)
        await self._shutdown_event.wait()

        logger.info("Shutting down daemon components...")

        # Cancel all tasks
        for task in tasks:
            task.cancel()

        demoted = self._leadership is not None and self._leadership.lost
        if demoted:
            # Bounded: the new leader is already running; a component stuck in
            # a blocking call must not hold this process up.
            if tasks:
                await asyncio.wait(tasks, timeout=10)
        else:
            # Wait for tasks to complete
            await asyncio.gather(*tasks, return_exceptions=True)

        self._running = False

        spool = getattr(self, "_spool", None)
        if spool is not None:
            # Unstored entries stay on disk for the next start.
            spool.close()

        if self._leadership is not None:
            if demoted:
                self._exit_demoted()
            # Components are stopped: hand over now rather than at lease expiry.
            await self._leadership.release()

        # Flush and shut down OTEL providers
        try:
            from core.telemetry import shutdown_telemetry

            shutdown_telemetry()
        except Exception as e:
            logger.warning("Telemetry shutdown error (non-fatal): %s", e)

        logger.info("SOC Daemon shutdown complete")

    @staticmethod
    def _leader_election_enabled() -> bool:
        from core.config import get_settings

        return bool(get_settings().daemon_leader_election_enabled)

    async def _await_leadership(self, start) -> bool:
        """Serve as standby until the leader lock is ours; False on shutdown."""
        from core.config import get_settings
        from services.daemon.leadership import StandbyWebhook, build_daemon_leadership
        from services.daemon.metrics import MetricsServer

        self._leadership = await asyncio.to_thread(build_daemon_leadership)
        if self.config.metrics.enabled:
            # Up before the election so the probes pass while standby.
            self._metrics_server = MetricsServer(self.config.metrics)
            self._metrics_server.leadership = self._leadership
            start("metrics", self._metrics_server, "Metrics server")

        self._report_waiting_spool()
        standby = None
        if self.config.polling.webhook_enabled:
            standby = StandbyWebhook(
                get_settings().daemon_bind_host, self.config.polling.webhook_port
            )
            await standby.start()
        try:
            return await self._leadership.wait_for_leadership(self._shutdown_event)
        finally:
            # Leading (or stopping): the spool is opened and counted by the
            # leader's own gauges from here, not by the standby gauge.
            self._stop_watching_spool()
            if standby is not None:
                # Frees the port for the real webhook in DataPoller.
                await standby.stop()

    def _report_waiting_spool(self) -> None:
        """A standby does not replay (only the leader does); say so when this
        pod's own spool holds findings a previous run acknowledged, and keep
        ``soc_daemon_ingest_spool_standby_pending`` up to date while standby
        (W0.12b) so a waiting spool can be alerted on."""
        cfg = getattr(self.config, "spool", None)
        if cfg is None or not cfg.enabled:
            return
        try:
            from core.ingestion.spool import (
                waiting_findings,
                waiting_segments,
                watch_standby,
            )

            directory = cfg.resolved_directory()
            watch_standby(directory)
            waiting = waiting_segments(directory)
            findings = waiting_findings(directory) if waiting else 0
        except Exception:  # noqa: BLE001 - informational only
            return
        if waiting:
            logger.warning(
                "Standby: %d ingest spool segment(s) (%d finding(s)) on this pod "
                "wait until it leads (docs/operations/ingest-durability.md: hand "
                "over by restarting the current leader pod)",
                waiting,
                findings,
            )

    @staticmethod
    def _stop_watching_spool() -> None:
        try:
            from core.ingestion.spool import watch_standby

            watch_standby(None)
        except Exception:  # noqa: BLE001 - informational only
            pass

    async def _start_components(self, start) -> None:
        leadership = self._leadership
        if leadership is not None:
            leadership.ensure_leader()
            unguarded = start

            def start(name: str, component, label: str):
                # Init may have outlasted the lease: never start a component
                # (vendor actions, Kafka, schedules) once it is gone.
                leadership.ensure_leader()
                unguarded(name, component, label)

        await self._init_components()
        if leadership is not None:
            leadership.ensure_leader()

        if self._poller:
            start("poller", self._poller, "Data poller")

        if self._kafka_ingestor:
            start("kafka", self._kafka_ingestor, "Kafka ingestor")

        if self._processor:
            start("processor", self._processor, "Finding processor")

        if self._responder:
            start("responder", self._responder, "Autonomous responder")

        if self._scheduler:
            start("scheduler", self._scheduler, "Task scheduler")

        if self._orchestrator:
            start("orchestrator", self._orchestrator, "Autonomous orchestrator")
            if not self.config.orchestrator.enabled:
                logger.info("Autonomous orchestrator is disabled")

        if self._case_automation:
            start("case_automation", self._case_automation, "Case automation")

        if self._metrics_server and self._leadership is None:
            start("metrics", self._metrics_server, "Metrics server")
        if self._metrics_server:
            logger.info(
                "Health :%d, prometheus :%d",
                self._metrics_server.health_port,
                self._metrics_server.metrics_port,
            )

        logger.info("SOC Daemon fully operational")

    async def _watch_leadership(self) -> None:
        """Heartbeat the lock; on loss, stop everything (run() then exits 75)."""
        await self._leadership.hold(self._shutdown_event)
        if self._leadership.lost:
            self._shutdown_event.set()

    def _exit_demoted(self) -> None:
        """Exit without the interpreter's orderly shutdown.

        A heartbeat or DB call may be stuck in a worker thread, and
        asyncio.run would wait on it; the process must be gone instead.
        """
        from services.daemon.leadership import DEMOTED_EXIT_CODE

        logger.critical(
            "Exiting with %d after losing leadership (%s)",
            DEMOTED_EXIT_CODE,
            self._leadership.lost_reason,
        )
        logging.shutdown()
        os._exit(DEMOTED_EXIT_CODE)

    async def stop(self):
        """Stop the daemon gracefully."""
        self._shutdown_event.set()


def main():
    """Entry point for the daemon."""
    validate_settings_or_exit()
    from services.daemon.config import DaemonConfig

    config = DaemonConfig.from_env()
    daemon = SOCDaemon(config)

    try:
        asyncio.run(daemon.run())
    except KeyboardInterrupt:
        logger.info("Daemon interrupted by user")
    except Exception as e:
        logger.error(f"Daemon error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
