"""Ingestion hosted in the SOC daemon: the Federation runner and the webhook.

* **Federation runner** (:class:`core.federation.runner.FederationRunner`) —
  the only path that polls a source, one task per adapter, each on its
  ``federation_sources`` row's interval.
* **Webhook** — pushed findings (generic senders). A 200
  means every finding of the request is durable (W0.12): fsync'd into the
  ingest spool (core/ingestion/spool.py), which the processor drains and a
  restarted daemon replays. When the spool is full or cannot be written the
  webhook answers 503 with ``Retry-After`` and the sender keeps its bookmark
  and retries. Without a spool (``DAEMON_INGEST_SPOOL_ENABLED=false``, or it
  could not be opened) the 200 waits for the database row instead, and a
  finding not stored in time is answered 503.
"""

import asyncio
import hmac
import logging
from typing import Any, Dict, List, Optional

from core.config import get_settings
from core.federation.runner import FederationRunner
from core.ingestion.ack import new_ack
from core.ingestion.dedup import RedisDedupSet
from core.ingestion.handoff import envelope
from core.ingestion.spool import IngestSpool, SpoolError, SpoolFull
from core.ingestion.spool import count as spool_count
from core.webhook_rejections import (
    BAD_TOKEN,
    DISABLED,
    NO_SECRET,
    record_rejection,
    rejection_counts,
)
from services.daemon.config import PollingConfig

logger = logging.getLogger(__name__)

# Seconds a webhook sender is asked to wait when the hand-off is full.
_BUSY_RETRY_AFTER = 5
# Without a spool: how long the webhook waits for the rows before a 503.
_SYNC_STORE_TIMEOUT = 15.0


def normalize_mitre_predictions(raw: Any, finding_id: str) -> Dict[str, float]:
    """Coerce a webhook ``mitre_predictions`` value to the canonical
    ``{technique_id: confidence}`` dict every consumer assumes.

    Accepted: dict (passed through as-is, values unvalidated), list/tuple of
    technique ids, list of ``{"technique"|"id": ..., "confidence"|"score": ...}``
    dicts, a single id string, or None. 1.0 is the "present, no score"
    precedent used by the internal producers. Any other type, or a list entry
    with no technique id, raises ValueError so the request fails with a 400
    rather than the field being silently emptied downstream.
    """
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        items: list = [raw]
    elif isinstance(raw, (list, tuple)):
        items = list(raw)
    else:
        raise ValueError(
            f"finding {finding_id}: mitre_predictions must be a dict, list or "
            f"string, got {type(raw).__name__}"
        )

    out: Dict[str, float] = {}
    for item in items:
        score: Any = 1.0
        if isinstance(item, dict):
            # `or` rather than .get(default): a present-but-null key falls through.
            technique = item.get("technique") or item.get("id")
            score = item.get("confidence")
            if score is None:
                score = item.get("score")
            # bool is an int subclass; True/False are not confidences.
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                score = 1.0
        else:
            technique = item
        if not isinstance(technique, str) or not technique.strip():
            raise ValueError(
                f"finding {finding_id}: mitre_predictions entry {item!r} has no "
                "technique id"
            )
        out[technique.strip()] = float(score)
    return out


class DataPoller:
    """Hosts the Federation runner and the ingest webhook."""

    def __init__(self, config: PollingConfig):
        self.config = config
        self._output_queue: Optional[asyncio.Queue] = None
        self._federation = FederationRunner(output_queue=None)
        self._webhook_dedup = RedisDedupSet("poller:webhook")
        self._spool: Optional[IngestSpool] = None
        # The runner's own dict, so /status reads its counts live.
        self.stats: Dict[str, Any] = {
            "webhook_findings": 0,
            "webhook_busy": 0,
            "webhook_not_stored": 0,
            "webhook_rejections": {},
            "federation": self._federation.stats,
        }

    def set_spool(self, spool: Optional[IngestSpool]) -> None:
        """Acknowledge webhook findings once they are in ``spool`` (W0.12)."""
        self._spool = spool

    def set_output_queue(self, queue: asyncio.Queue):
        """Set the output queue for processed findings."""
        self._output_queue = queue
        self._federation.set_output_queue(queue)

    async def run(self, shutdown_event: asyncio.Event):
        """Run the Federation runner, and the webhook when enabled."""
        logger.info("Data poller starting...")
        tasks = [asyncio.create_task(self._federation.run(shutdown_event))]
        if self.config.webhook_enabled:
            tasks.append(asyncio.create_task(self._run_webhook_server(shutdown_event)))
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Polling tasks cancelled")

    async def _run_webhook_server(self, shutdown_event: asyncio.Event):
        """Run a simple webhook server for external ingestion."""
        from aiohttp import web

        runner = web.AppRunner(self._webhook_app())
        await runner.setup()
        site = web.TCPSite(
            runner, get_settings().daemon_bind_host, self.config.webhook_port
        )

        logger.info(f"Webhook server starting on port {self.config.webhook_port}")
        try:
            await site.start()
        except OSError as e:
            # Don't re-raise: the Federation runner must keep running.
            logger.error(
                "Webhook server failed to bind port %s: %s", self.config.webhook_port, e
            )
            await runner.cleanup()
            return

        # Wait for shutdown
        await shutdown_event.wait()

        await runner.cleanup()
        logger.info("Webhook server stopped")

    async def _accept_spooled(self, findings: List[Dict[str, Any]]):
        """200 once ``findings`` are fsync'd in the spool; 503 if they cannot be."""
        from aiohttp import web

        spool = self._spool
        assert spool is not None
        try:
            taken = await asyncio.to_thread(spool.append, findings, "webhook")
        except SpoolFull as e:
            self.stats["webhook_busy"] += 1
            spool_count("rejected", reason="full")
            logger.warning("Webhook answered 503: %s", e)
            return _busy(0, "ingest busy: spool full")
        except SpoolError as e:
            self.stats["webhook_busy"] += 1
            spool_count("rejected", reason="error")
            logger.error("Webhook answered 503, ingest spool unusable: %s", e)
            return _busy(0, "ingest unavailable: spool write failed")
        spool_count("appended", len(taken))
        # Marked after the spool holds them: a marked id is always on disk or
        # stored, so skipping a re-send of it loses nothing.
        for finding_id in taken:
            await self._webhook_dedup.mark_processed(finding_id)
        self.stats["webhook_findings"] += len(taken)
        return web.json_response({"status": "ok", "ingested": len(taken)})

    async def _accept_stored(self, findings: List[Dict[str, Any]]):
        """No spool: 200 only once every row is stored, else 503."""
        from aiohttp import web

        if self._output_queue is None:
            return _busy(0, "ingest not ready: no processor queue")
        pending = []
        busy = False
        for finding_data in findings:
            item = envelope(finding_data, "webhook")
            item["ack"] = ack = new_ack()
            try:
                self._output_queue.put_nowait(item)
            except asyncio.QueueFull:
                busy = True
                break
            pending.append((finding_data["finding_id"], ack))
        if pending:
            await asyncio.wait([ack for _, ack in pending], timeout=_SYNC_STORE_TIMEOUT)
        stored = 0
        dedup = self._webhook_dedup
        for finding_id, ack in pending:
            if ack.done() and not ack.cancelled() and ack.result():
                await dedup.mark_processed(finding_id)
                stored += 1
            elif not ack.done():
                # Answered 503 but still queued: if it is stored later, the
                # sender's retry is skipped rather than processed twice.
                def _late(fut, finding_id=finding_id):
                    if not fut.cancelled() and fut.result():
                        asyncio.ensure_future(dedup.mark_processed(finding_id))

                ack.add_done_callback(_late)
        self.stats["webhook_findings"] += stored
        if busy:
            self.stats["webhook_busy"] += 1
            return _busy(stored, "ingest busy: processor queue full")
        if stored < len(pending):
            self.stats["webhook_not_stored"] += len(pending) - stored
            return _busy(stored, "ingest unavailable: findings not stored")
        return web.json_response({"status": "ok", "ingested": stored})

    def _webhook_app(self):
        from aiohttp import web

        def reject(request: web.Request, reason: str, detail: Optional[str] = None):
            record_rejection(
                f"daemon{request.path}", reason, request.remote, detail=detail
            )
            self.stats["webhook_rejections"] = rejection_counts("daemon/")

        async def handle_webhook(request: web.Request) -> web.Response:
            """Handle incoming webhook data."""
            # Fail closed: no token configured => ingestion is disabled, and every
            # request must present a matching bearer (constant-time compare).
            token = self.config.webhook_token
            if not token:
                reject(request, NO_SECRET, "DAEMON_WEBHOOK_TOKEN is not set")
                return web.json_response(
                    {"error": "ingest disabled: server missing DAEMON_WEBHOOK_TOKEN"},
                    status=503,
                )
            presented = (
                request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            )
            if not hmac.compare_digest(presented, token):
                reject(request, BAD_TOKEN)
                return web.json_response({"error": "unauthorized"}, status=401)
            try:
                data = await request.json()

                # Support batch or single finding
                findings = data if isinstance(data, list) else [data]

                # Block pushes for a disabled integration: 503 the whole batch so
                # the connector holds its cursor and retries (nothing dropped; feed
                # resumes on re-enable). Only registered-but-disabled sources are
                # blocked, so generic 'webhook'/'flow' pushes are unaffected.
                from core.storage.config_service import get_config_service

                # Run the sync SQLAlchemy lookup off the event loop so a slow or
                # locked DB can't freeze the whole daemon on the ingest hot path.
                disabled = await asyncio.to_thread(
                    lambda: get_config_service().get_disabled_integration_ids()
                )
                blocked = {
                    s for f in findings if (s := f.get("data_source")) in disabled
                }
                if blocked:
                    reject(
                        request,
                        DISABLED,
                        f"sources={sorted(blocked)[:10]}",
                    )
                    return web.json_response(
                        {
                            "error": f"ingestion disabled for source(s): {sorted(blocked)}"
                        },
                        status=503,
                    )

                for finding_data in findings:
                    finding_id = finding_data.get("finding_id")
                    if not finding_id:
                        import uuid

                        finding_id = f"webhook-{uuid.uuid4().hex[:16]}"
                        finding_data["finding_id"] = finding_id

                # Untrusted payload: coerce to the canonical {technique: score}
                # dict once here, before anything is enqueued, so a bad entry
                # 400s the whole batch (via the except below) instead of
                # breaking triage and dropping technique rows downstream.
                for finding_data in findings:
                    finding_data["mitre_predictions"] = normalize_mitre_predictions(
                        finding_data.get("mitre_predictions"),
                        finding_data["finding_id"],
                    )

                for finding_data in findings:
                    finding_data["data_source"] = finding_data.get(
                        "data_source", "webhook"
                    )
                fresh = [
                    f
                    for f in findings
                    if not await self._webhook_dedup.is_processed(f["finding_id"])
                ]
                if self._spool is not None:
                    return await self._accept_spooled(fresh)
                return await self._accept_stored(fresh)

            except Exception as e:
                logger.error(f"Webhook error: {e}")
                return web.json_response({"error": str(e)}, status=400)

        async def health_check(request: web.Request) -> web.Response:
            """Health check endpoint."""
            return web.json_response({"status": "healthy"})

        app = web.Application()
        app.router.add_post("/ingest", handle_webhook)
        app.router.add_post("/webhook", handle_webhook)
        app.router.add_get("/health", health_check)
        return app


def _busy(ingested: int, message: str):
    from aiohttp import web

    return web.json_response(
        {"error": message, "ingested": ingested},
        status=503,
        headers={"Retry-After": str(_BUSY_RETRY_AFTER)},
    )
