"""A store that fails must not leave the finding marked processed.

The processor retries ``_store_finding`` in place. On give-up it forgets the
dedup key that was marked at enqueue, on the same ``RedisDedupSet`` instance.

Federation and Kafka hold their cursor/offset until the store is acked
(test_ack_before_advance), so an unmarked id is queued again on the re-read.
The webhook does not: the HTTP response has already moved.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest
from aiohttp import ClientConnectorError, ClientSession

from core.config import get_settings
from core.ingestion.dedup import RedisDedupSet
from core.ingestion.handoff import envelope
from services.daemon.config import PollingConfig, ProcessingConfig
from services.daemon.poller import DataPoller
from services.daemon.processor import FindingProcessor, _STORE_ATTEMPTS

pytestmark = pytest.mark.unit


class _Ingest:
    def __init__(self, results: List[Any]):
        self._results = list(results)
        self.calls = 0
        self.finding_ids: List[str] = []

    def ingest_finding(self, finding: Dict[str, Any]) -> bool:
        self.calls += 1
        self.finding_ids.append(finding.get("finding_id"))
        outcome = self._results.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return bool(outcome)


def _dead_redis(monkeypatch) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    get_settings.cache_clear()


def _poller(monkeypatch) -> DataPoller:
    _dead_redis(monkeypatch)
    poller = DataPoller(PollingConfig(webhook_token="test-token", webhook_port=18781))
    poller.set_output_queue(asyncio.Queue())
    return poller


def _processor(monkeypatch) -> FindingProcessor:
    monkeypatch.setattr("services.daemon.processor._STORE_RETRY_BACKOFF", 0)
    processor = FindingProcessor(
        ProcessingConfig(
            auto_triage_enabled=False,
            auto_enrich_enabled=False,
            max_concurrent_tasks=1,
        )
    )
    processor._data_service = object()
    return processor


def _patch_ingest(monkeypatch, ingest: _Ingest) -> None:
    monkeypatch.setattr(
        "core.ingestion.ingestion_service.IngestionService",
        lambda: ingest,
    )


async def _drain(processor: FindingProcessor, queue: asyncio.Queue) -> Dict[str, Any]:
    item = queue.get_nowait()
    await processor._process_item(item)
    return item


def _down() -> List[Exception]:
    return [ConnectionError("could not connect to server: Connection refused")] * (
        _STORE_ATTEMPTS
    )


@pytest.mark.asyncio
async def test_one_store_failure_then_success_keeps_the_key(monkeypatch):
    _dead_redis(monkeypatch)
    processor = _processor(monkeypatch)
    dedup = RedisDedupSet("unit-retry-once")
    finding_id = "splunk-42:1001"
    await dedup.mark_processed(finding_id)
    queue: asyncio.Queue = asyncio.Queue()
    queue.put_nowait(
        envelope(
            {"finding_id": finding_id, "severity": "high"},
            "splunk",
            dedup=dedup,
            dedup_key=finding_id,
        )
    )
    ingest = _Ingest(
        [ConnectionError("could not connect to server: Connection refused"), True]
    )
    _patch_ingest(monkeypatch, ingest)

    item = await _drain(processor, queue)

    assert item["dedup"] is dedup
    assert item["dedup_key"] == finding_id
    assert ingest.calls == 2
    assert ingest.finding_ids == [finding_id, finding_id]
    assert processor.stats["processed"] == 1
    assert processor.stats["store_dropped"] == 0
    assert await dedup.is_processed(finding_id) is True
    assert queue.empty()


@pytest.mark.asyncio
async def test_a_store_that_keeps_failing_is_dropped_and_its_key_forgotten(
    monkeypatch, caplog
):
    """Give-up forgets the key on the producer's instance, so a re-read retries.

    Federation and Kafka re-read by holding their cursor/offset
    (test_ack_before_advance); the forgotten key is what lets that re-read
    enqueue the finding again.
    """
    _dead_redis(monkeypatch)
    processor = _processor(monkeypatch)
    dedup = RedisDedupSet("unit-retry-drop")
    finding_id = "splunk-42:1001"
    await dedup.mark_processed(finding_id)
    queue: asyncio.Queue = asyncio.Queue()
    queue.put_nowait(
        envelope(
            {"finding_id": finding_id, "severity": "high"},
            "splunk",
            dedup=dedup,
            dedup_key=finding_id,
        )
    )
    ingest = _Ingest(_down())
    _patch_ingest(monkeypatch, ingest)

    caplog.set_level(logging.ERROR)
    await _drain(processor, queue)

    assert ingest.calls == _STORE_ATTEMPTS
    assert processor.stats["processed"] == 0
    assert processor.stats["store_dropped"] == 1
    assert processor.stats["errors"] == 0
    assert f"Dropped finding {finding_id}" in caplog.text
    assert await dedup.is_processed(finding_id) is False


@pytest.mark.asyncio
async def test_missing_data_service_drops_and_unmarks(monkeypatch, caplog):
    _dead_redis(monkeypatch)
    monkeypatch.setattr("services.daemon.processor._STORE_RETRY_BACKOFF", 0)
    processor = FindingProcessor(
        ProcessingConfig(auto_triage_enabled=False, auto_enrich_enabled=False)
    )
    dedup = RedisDedupSet("unit-missing-db")
    await dedup.mark_processed("f-missing")

    caplog.set_level(logging.ERROR)
    await processor._process_finding(
        {"finding_id": "f-missing"},
        source="splunk",
        dedup=dedup,
        dedup_key="f-missing",
    )

    assert processor.stats["processed"] == 0
    assert processor.stats["store_dropped"] == 1
    assert "Dropped finding f-missing" in caplog.text
    assert await dedup.is_processed("f-missing") is False


@pytest.mark.asyncio
async def test_a_probe_without_a_dedup_key_is_dropped_quietly(monkeypatch):
    processor = _processor(monkeypatch)
    processor._data_service = None
    await processor._process_item(
        {
            "type": "finding",
            "source": "probe",
            "data": {"finding_id": "probe:canary:2026-10-01"},
        }
    )
    assert processor.stats["store_dropped"] == 1
    assert processor.stats["processed"] == 0


@pytest.mark.asyncio
async def test_webhook_does_not_redeliver(monkeypatch, caplog):
    """The 200 moves before the store is attempted."""
    _dead_redis(monkeypatch)
    processor = _processor(monkeypatch)
    ingest = _Ingest(_down())
    _patch_ingest(monkeypatch, ingest)
    caplog.set_level(logging.ERROR)

    # Webhook: the handler has already answered 200 by the time we store.
    poller = _poller(monkeypatch)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        poller.config.webhook_port = sock.getsockname()[1]
    disabled = set()

    class _Config:
        def get_disabled_integration_ids(self):
            return disabled

    shutdown = asyncio.Event()
    server = asyncio.create_task(poller._run_webhook_server(shutdown))
    try:
        with patch(
            "core.storage.config_service.get_config_service",
            return_value=_Config(),
        ):
            async with ClientSession() as session:
                response = await _post_when_up(session, poller.config.webhook_port)
                body = await response.json()
                status = response.status
        assert status == 200
        assert body == {"status": "ok", "ingested": 1}
        assert await poller._webhook_dedup.is_processed("wh-1") is True

        await _drain(processor, poller._output_queue)
        assert processor.stats["store_dropped"] == 1
        assert await poller._webhook_dedup.is_processed("wh-1") is False
        # Nothing in the webhook path asks the sender to try again.
        assert poller._output_queue.empty()
    finally:
        shutdown.set()
        await server


async def _post_when_up(session: ClientSession, port: int):
    url = f"http://127.0.0.1:{port}/ingest"
    headers = {"Authorization": "Bearer test-token"}
    body = {"finding_id": "wh-1", "severity": "high"}
    last_error: Optional[BaseException] = None
    for _ in range(50):
        try:
            return await session.post(url, json=body, headers=headers)
        except (ClientConnectorError, ConnectionError, OSError) as exc:
            last_error = exc
            await asyncio.sleep(0.05)
    raise RuntimeError(f"webhook server did not accept a connection: {last_error}")
