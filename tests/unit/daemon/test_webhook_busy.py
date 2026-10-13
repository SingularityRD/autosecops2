"""The ingest webhook over HTTP: a 200 is durable, otherwise 503 + Retry-After.

W0.12: with the ingest spool the 200 means "fsync'd in the spool"; a full or
unwritable spool answers 503. Without a spool the 200 waits for the stored
row; a full hand-off or a failed store answers 503.
"""

from __future__ import annotations

import asyncio

import pytest
from aiohttp.test_utils import TestClient, TestServer

from core.ingestion.ack import settle_ack
from core.ingestion.spool import IngestSpool
from services.daemon.config import PollingConfig
from services.daemon.poller import DataPoller

pytestmark = pytest.mark.unit

TOKEN = "t0ken"


class _Dedup:
    def __init__(self):
        self.processed: set = set()

    async def is_processed(self, key: str) -> bool:
        return key in self.processed

    async def mark_processed(self, key: str) -> None:
        self.processed.add(key)


@pytest.fixture(autouse=True)
def no_disabled_integrations(monkeypatch):
    class _Config:
        def get_disabled_integration_ids(self):
            return set()

    monkeypatch.setattr(
        "core.storage.config_service.get_config_service", lambda: _Config()
    )


def _poller(maxsize: int = 10, spool: IngestSpool | None = None) -> DataPoller:
    poller = DataPoller(PollingConfig(webhook_token=TOKEN))
    poller._webhook_dedup = _Dedup()  # type: ignore[assignment]
    poller.set_output_queue(asyncio.Queue(maxsize=maxsize))
    poller.set_spool(spool)
    return poller


def _spool(path, **kw) -> IngestSpool:
    spool = IngestSpool(path, **kw)
    spool.open()
    return spool


async def _post(poller: DataPoller, body):
    async with TestClient(TestServer(poller._webhook_app())) as client:
        resp = await client.post(
            "/ingest", json=body, headers={"Authorization": f"Bearer {TOKEN}"}
        )
        return resp.status, resp.headers.get("Retry-After"), await resp.json()


# -- with the spool ----------------------------------------------------------


@pytest.mark.asyncio
async def test_a_push_is_acknowledged_once_it_is_in_the_spool(tmp_path):
    spool = _spool(tmp_path)
    poller = _poller(spool=spool)

    status, _, body = await _post(poller, [{"finding_id": "a"}, {"finding_id": "b"}])

    assert status == 200
    assert body["ingested"] == 2
    assert [e.finding_id for e in spool.claim(10)] == ["a", "b"]
    # The processor's feeder, not the request, fills the hand-off.
    assert poller._output_queue.qsize() == 0
    assert poller._webhook_dedup.processed == {"a", "b"}


@pytest.mark.asyncio
async def test_a_full_spool_answers_503_and_the_retry_loses_nothing(tmp_path):
    spool = _spool(tmp_path, max_findings=1)
    poller = _poller(spool=spool)
    batch = [{"finding_id": "a"}, {"finding_id": "b"}]

    status, retry_after, body = await _post(poller, batch)

    assert status == 503
    assert retry_after is not None and int(retry_after) > 0
    assert body["ingested"] == 0
    assert len(spool) == 0
    assert poller._webhook_dedup.processed == set()

    spool.max_findings = 2  # room again (the processor stored some)
    status, _, body = await _post(poller, batch)
    assert status == 200
    assert body["ingested"] == 2


@pytest.mark.asyncio
async def test_an_unwritable_spool_answers_503(tmp_path):
    spool = IngestSpool(tmp_path)  # never opened: every write fails
    poller = _poller(spool=spool)

    status, retry_after, _ = await _post(poller, {"finding_id": "a"})

    assert status == 503
    assert retry_after is not None
    assert poller._webhook_dedup.processed == set()


@pytest.mark.asyncio
async def test_a_resend_of_a_spooled_finding_is_not_spooled_twice(tmp_path):
    spool = _spool(tmp_path)
    poller = _poller(spool=spool)
    await _post(poller, {"finding_id": "a"})
    poller._webhook_dedup.processed.clear()  # e.g. Redis restarted empty

    status, _, body = await _post(poller, {"finding_id": "a"})

    assert status == 200
    assert body["ingested"] == 0
    assert len(spool) == 1


# -- without a spool -----------------------------------------------------------


async def _store_all(queue: asyncio.Queue, stored: bool) -> None:
    while True:
        item = await queue.get()
        settle_ack(item.get("ack"), stored)


@pytest.mark.asyncio
async def test_without_a_spool_200_waits_for_the_rows():
    poller = _poller(maxsize=10)
    worker = asyncio.create_task(_store_all(poller._output_queue, True))
    try:
        status, _, body = await _post(
            poller, [{"finding_id": "a"}, {"finding_id": "b"}]
        )
    finally:
        worker.cancel()
    assert status == 200
    assert body["ingested"] == 2
    assert poller._webhook_dedup.processed == {"a", "b"}


@pytest.mark.asyncio
async def test_without_a_spool_a_failed_store_answers_503():
    poller = _poller(maxsize=10)
    worker = asyncio.create_task(_store_all(poller._output_queue, False))
    try:
        status, retry_after, body = await _post(poller, {"finding_id": "a"})
    finally:
        worker.cancel()
    assert status == 503
    assert retry_after is not None
    assert body["ingested"] == 0
    assert poller._webhook_dedup.processed == set()


@pytest.mark.asyncio
async def test_without_a_spool_a_full_hand_off_answers_503():
    poller = _poller(maxsize=1)
    poller._output_queue.put_nowait({"type": "finding", "data": {}})

    status, retry_after, body = await _post(poller, {"finding_id": "a"})

    assert status == 503
    assert retry_after is not None
    assert body["ingested"] == 0


@pytest.mark.asyncio
async def test_without_a_spool_a_slow_store_answers_503_and_marks_later(monkeypatch):
    monkeypatch.setattr("services.daemon.poller._SYNC_STORE_TIMEOUT", 0.05)
    poller = _poller(maxsize=10)

    status, _, _ = await _post(poller, {"finding_id": "a"})
    assert status == 503

    item = poller._output_queue.get_nowait()
    settle_ack(item["ack"], True)
    for _ in range(5):
        await asyncio.sleep(0)
    # Stored after all: a re-send is skipped instead of triaged twice.
    assert poller._webhook_dedup.processed == {"a"}
