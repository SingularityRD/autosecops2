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
from typing import Any, Dict, List, Optional, Tuple

from core.config import get_settings
from core.federation.runner import FederationRunner
from core.ingestion.ack import new_ack
from core.ingestion.dedup import RedisDedupSet
from core.ingestion.handoff import envelope
from core.ingestion.spool import IngestSpool, SpoolError, SpoolFull
from core.ingestion.spool import count as spool_count
from core.ingestion.syslog_formats import parse_line as parse_syslog_line
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
# /ingest/syslog bounds (W0.41): a request is a relay's batch, not a dump.
_SYSLOG_BODY_MAX = 4 * 1024 * 1024
_SYSLOG_LINES_MAX = 5000


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
            # W0.41: lines read by the syslog listener and /ingest/syslog.
            "syslog": {
                "lines": 0,
                "findings": 0,
                "unparsed": 0,
                "refused": 0,
                "dropped": 0,
            },
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
        return _answer(*await self._admit_spooled(findings, "webhook"))

    async def _accept_stored(self, findings: List[Dict[str, Any]]):
        """No spool: 200 only once every row is stored, else 503."""
        return _answer(*await self._admit_stored(findings, "webhook"))

    async def admit(
        self, findings: List[Dict[str, Any]], via: str
    ) -> Tuple[int, Optional[str]]:
        """Hand ``findings`` on as the webhook does: ``(taken, None)`` once all
        are durable, else ``(taken, why)`` and the sender should retry (W0.41:
        the syslog listener and ``/ingest/syslog`` share this)."""
        if self._spool is not None:
            return await self._admit_spooled(findings, via)
        return await self._admit_stored(findings, via)

    async def _admit_spooled(
        self, findings: List[Dict[str, Any]], via: str
    ) -> Tuple[int, Optional[str]]:
        spool = self._spool
        assert spool is not None
        try:
            taken = await asyncio.to_thread(spool.append, findings, via)
        except SpoolFull as e:
            self.stats["webhook_busy"] += 1
            spool_count("rejected", reason="full")
            logger.warning("Ingest (%s) answered busy: %s", via, e)
            return 0, "ingest busy: spool full"
        except SpoolError as e:
            self.stats["webhook_busy"] += 1
            spool_count("rejected", reason="error")
            logger.error("Ingest (%s) answered busy, ingest spool unusable: %s", via, e)
            return 0, "ingest unavailable: spool write failed"
        spool_count("appended", len(taken))
        # Marked after the spool holds them: a marked id is always on disk or
        # stored, so skipping a re-send of it loses nothing.
        for finding_id in taken:
            await self._webhook_dedup.mark_processed(finding_id)
        self.stats["webhook_findings"] += len(taken)
        return len(taken), None

    async def _admit_stored(
        self, findings: List[Dict[str, Any]], via: str
    ) -> Tuple[int, Optional[str]]:
        if self._output_queue is None:
            return 0, "ingest not ready: no processor queue"
        pending = []
        busy = False
        for finding_data in findings:
            item = envelope(finding_data, via)
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
            return stored, "ingest busy: processor queue full"
        if stored < len(pending):
            self.stats["webhook_not_stored"] += len(pending) - stored
            return stored, "ingest unavailable: findings not stored"
        return stored, None

    async def ingest_syslog_lines(
        self, lines: List[str], peer: Optional[str], via: str
    ) -> Tuple[int, int, Optional[str]]:
        """Parse ``lines`` (W0.41) and admit the findings they carry.

        Returns ``(ingested, unparsed, why)``; ``why`` is set when the batch
        was not all taken and the sender should retry it.
        """
        stats = self.stats["syslog"]
        stats["lines"] += len(lines)
        findings: List[Dict[str, Any]] = []
        seen = set()
        unparsed = 0
        for line in lines:
            try:
                finding = parse_syslog_line(line, peer=peer)
            except Exception as e:  # one odd line must not drop its batch
                logger.debug("syslog line not read: %s", e)
                finding = None
            if finding is None:
                unparsed += 1
                continue
            if finding["finding_id"] in seen:
                continue
            seen.add(finding["finding_id"])
            findings.append(finding)
        stats["unparsed"] += unparsed
        fresh = [
            f
            for f in findings
            if not await self._webhook_dedup.is_processed(f["finding_id"])
        ]
        if not fresh:
            return 0, unparsed, None
        taken, why = await self.admit(fresh, via)
        stats["findings"] += taken
        return taken, unparsed, why

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

        async def handle_syslog(request: web.Request) -> web.Response:
            """Syslog lines over HTTP (W0.41): ``text/plain``, one line each.

            For a relay that forwards over HTTP (rsyslog omhttp, syslog-ng
            http(), Logsign, a QRadar or ArcSight forwarder). Same bearer as
            /ingest; a line that is not CEF, LEEF, FortiGate or JSON is
            counted, not stored. 200 means every finding is durable.
            """
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
            if request.content_length and request.content_length > _SYSLOG_BODY_MAX:
                return web.json_response({"error": "body too large"}, status=413)
            chunks: List[bytes] = []
            size = 0
            try:
                async for chunk in request.content.iter_chunked(65536):
                    size += len(chunk)
                    if size > _SYSLOG_BODY_MAX:
                        return web.json_response(
                            {"error": "body too large"}, status=413
                        )
                    chunks.append(chunk)
            except Exception as e:
                return web.json_response({"error": str(e)}, status=400)
            body = b"".join(chunks)
            lines = [
                line
                for line in body.decode("utf-8", "replace").split("\n")
                if line.strip()
            ]
            if len(lines) > _SYSLOG_LINES_MAX:
                return web.json_response(
                    {"error": f"at most {_SYSLOG_LINES_MAX} lines per request"},
                    status=413,
                )
            ingested, unparsed, why = await self.ingest_syslog_lines(
                lines, request.remote, "syslog"
            )
            if why is not None:
                return _busy(ingested, why)
            return web.json_response(
                {"status": "ok", "ingested": ingested, "unparsed": unparsed}
            )

        async def health_check(request: web.Request) -> web.Response:
            """Health check endpoint."""
            return web.json_response({"status": "healthy"})

        app = web.Application()
        app.router.add_post("/ingest", handle_webhook)
        app.router.add_post("/webhook", handle_webhook)
        app.router.add_post("/ingest/syslog", handle_syslog)
        app.router.add_get("/health", health_check)
        return app


def _answer(ingested: int, why: Optional[str]):
    from aiohttp import web

    if why is None:
        return web.json_response({"status": "ok", "ingested": ingested})
    return _busy(ingested, why)


def _busy(ingested: int, message: str):
    from aiohttp import web

    return web.json_response(
        {"error": message, "ingested": ingested},
        status=503,
        headers={"Retry-After": str(_BUSY_RETRY_AFTER)},
    )
