"""Kafka commits only what reached the hand-off and was stored, partition by partition."""

from __future__ import annotations

import asyncio
import json
from typing import Iterable, NamedTuple

import pytest

from core.ingestion.kafka_config import KafkaConfig
from core.ingestion.kafka_consumer_service import KafkaConsumerService
from tests.unit._acking_queue import AckingQueue

pytestmark = pytest.mark.unit


class _TP(NamedTuple):
    topic: str
    partition: int


P0, P1, P2 = _TP("t", 0), _TP("t", 1), _TP("t", 2)


class _Msg:
    def __init__(self, offset: int):
        self.offset = offset
        self.value = json.dumps({"finding_id": f"f-{offset}"}).encode()


class _Consumer:
    def __init__(self, fail_commit_on=None):
        self.commits: list = []
        self.seeks: list = []
        self._fail_commit_on = fail_commit_on

    async def commit(self, offsets=None):
        assert offsets is not None, "a bare commit() commits every partition"
        if self._fail_commit_on in offsets:
            raise RuntimeError("commit failed")
        self.commits.append(offsets)

    def seek(self, tp, offset):
        self.seeks.append((tp, offset))


class _Dedup:
    def __init__(self):
        self.marked: set = set()

    async def are_processed(self, keys: Iterable[str]) -> set:
        return {k for k in keys if k in self.marked}

    async def mark_many(self, keys: Iterable[str]) -> None:
        self.marked.update(keys)


def _service(queue, consumer):
    cfg = KafkaConfig(enabled=True, bootstrap_servers="x:9092", topics=["t"])
    svc = KafkaConsumerService(cfg, queue, _Dedup())  # type: ignore[arg-type]
    svc._consumer = consumer
    return svc


def _msgs(*offsets):
    return [_Msg(o) for o in offsets]


@pytest.mark.asyncio
async def test_shutdown_during_a_full_hand_off_commits_only_the_partitions_handed_off():
    queue = AckingQueue(maxsize=3)
    consumer = _Consumer()
    svc = _service(queue, consumer)

    assert await svc._process_partition(P0, _msgs(100, 101)) is True

    drain = asyncio.create_task(svc._process_partition(P1, _msgs(500, 501, 502)))
    await asyncio.sleep(0.05)
    assert not drain.done()  # waiting on 501 with the queue full, not dropping it

    svc._shutdown.set()
    assert await asyncio.wait_for(drain, timeout=1) is False
    # P1 stays at its last commit and is not sought back: 501 and 502 are
    # re-read next start, and 500 (stored) is deduped then.
    assert consumer.commits == [{P0: 102}]
    assert consumer.seeks == []
    assert queue.qsize() == 3
    assert svc._dedup.marked == {"f-100", "f-101", "f-500"}


@pytest.mark.asyncio
async def test_an_error_rewinds_its_partition_and_the_others_still_commit(
    monkeypatch,
):
    consumer = _Consumer()
    svc = _service(AckingQueue(), consumer)
    handle = svc._handle_batch

    async def failing(topic, msgs):
        if any(m.offset == 501 for m in msgs):
            raise RuntimeError("redis down")
        return await handle(topic, msgs)

    monkeypatch.setattr(svc, "_handle_batch", failing)

    parts = ((P0, _msgs(100, 101)), (P1, _msgs(500, 501, 502)), (P2, _msgs(900)))
    results = [await svc._process_partition(tp, msgs) for tp, msgs in parts]

    assert results == [True, False, True]
    assert consumer.commits == [{P0: 102}, {P2: 901}]
    assert consumer.seeks == [(P1, 500)]


@pytest.mark.asyncio
async def test_a_failed_commit_rewinds_that_partition():
    consumer = _Consumer(fail_commit_on=P0)
    svc = _service(AckingQueue(), consumer)

    assert await svc._process_partition(P0, _msgs(100, 101)) is False
    assert await svc._process_partition(P1, _msgs(500)) is True

    # P0's rows were stored (and marked), so the re-read dedups them.
    assert consumer.seeks == [(P0, 100)]
    assert consumer.commits == [{P1: 501}]
    assert {"f-100", "f-101"} <= svc._dedup.marked
