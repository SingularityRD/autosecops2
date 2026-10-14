"""Cursor durability, retry and backpressure of the export pipeline (WP w3.6)."""

from __future__ import annotations

import asyncio
import json
import random
from datetime import datetime, timedelta, timezone

import pytest

from core.compliance.audit_export import (
    AuditEvent,
    AuditExportConfig,
    BatchTooLarge,
    DeliveryError,
    FileCursorStore,
    Pipeline,
    Redactor,
    Source,
    SyslogDestination,
    SyslogTransport,
    Transport,
)

from .conftest import SyslogReceiver

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


class ListSource(Source):
    """An append-only in-memory log with an integer cursor."""

    def __init__(self, name: str = "config") -> None:
        self.name = name
        self.events: list[AuditEvent] = []
        self.fetches = 0

    def add(self, n: int, **kw) -> None:
        for _ in range(n):
            i = len(self.events) + 1
            self.events.append(
                AuditEvent(
                    id=f"{self.name}:{i}",
                    source=self.name,
                    category="test",
                    action="test.event",
                    outcome="success",
                    severity=3,
                    timestamp=T0 + timedelta(seconds=i),
                    message=f"event {i}",
                    **kw,
                )
            )

    def initial_cursor(self, start_from: str) -> dict:
        return {"id": 0 if start_from == "beginning" else len(self.events)}

    def fetch(self, cursor: dict, limit: int):
        self.fetches += 1
        start = int(cursor["id"])
        return [
            (ev, {"id": start + i + 1})
            for i, ev in enumerate(self.events[start : start + limit])
        ]


class FakeTransport(Transport):
    def __init__(self, fail_first: int = 0) -> None:
        self.fail_first = fail_first
        self.down = False
        self.attempts = 0
        self.delivered: list[str] = []
        self.max_events: int | None = None
        self.closed = False

    async def send(self, events):
        self.attempts += 1
        if self.down or self.attempts <= self.fail_first:
            raise DeliveryError("connect_failed")
        if self.max_events is not None and len(events) > self.max_events:
            raise BatchTooLarge()
        self.delivered.extend(ev.id for ev in events)

    async def close(self):
        self.closed = True


def _cfg(**kw) -> AuditExportConfig:
    base = dict(
        start_from="beginning",
        poll_interval_s=0.05,
        settle_s=0,
        max_backoff_s=0.2,
        batch_size=10,
        queue_max=50,
    )
    base.update(kw)
    return AuditExportConfig(**base)


def _pipeline(tmp_path, transport, sources, **cfg) -> Pipeline:
    p = Pipeline(
        destination="siem",
        transport=transport,
        sources=sources,
        cursors=FileCursorStore(tmp_path / "cursors.json"),
        cfg=_cfg(**cfg),
        redactor=Redactor(),
        rng=random.Random(1),
    )
    p.backoff_base_s = 0.01
    return p


async def _until(pred, timeout: float = 10.0) -> None:
    async def loop():
        while not pred():
            await asyncio.sleep(0.02)

    await asyncio.wait_for(loop(), timeout)


def _cursor(tmp_path, source="config") -> dict:
    return json.loads((tmp_path / "cursors.json").read_text())[f"siem/{source}"]


async def test_cursor_resumes_after_restart_without_loss_or_duplicates(tmp_path):
    src = ListSource()
    src.add(25)
    t1 = FakeTransport()
    p1 = _pipeline(tmp_path, t1, [src])
    p1.start()
    await _until(lambda: len(t1.delivered) == 25)
    await p1.stop()
    assert t1.closed
    assert _cursor(tmp_path) == {"id": 25}

    src.add(7)  # written while the exporter was down
    t2 = FakeTransport()
    p2 = _pipeline(tmp_path, t2, [src])
    p2.start()
    await _until(lambda: len(t2.delivered) == 7)
    await asyncio.sleep(0.2)
    await p2.stop()
    assert t2.delivered == [f"config:{i}" for i in range(26, 33)]
    assert _cursor(tmp_path) == {"id": 32}


async def test_stop_mid_outage_rereads_everything_unacknowledged(tmp_path):
    src = ListSource()
    src.add(10)
    t1 = FakeTransport()
    p1 = _pipeline(tmp_path, t1, [src], batch_size=5)
    p1.start()
    await _until(lambda: len(t1.delivered) == 10)
    t1.down = True
    src.add(10)
    await _until(lambda: p1.metrics.delivery_failures >= 2)
    await p1.stop()
    # Read, queued, never acknowledged: the cursor did not move past them.
    assert _cursor(tmp_path) == {"id": 10}

    t2 = FakeTransport()
    p2 = _pipeline(tmp_path, t2, [src], batch_size=5)
    p2.start()
    await _until(lambda: len(t2.delivered) == 10)
    await p2.stop()
    assert t2.delivered == [f"config:{i}" for i in range(11, 21)]


async def test_receiver_outage_is_retried_with_backoff_and_loses_nothing(tmp_path):
    src = ListSource()
    src.add(40)
    tx = FakeTransport(fail_first=6)
    p = _pipeline(tmp_path, tx, [src])
    p.start()
    await _until(lambda: len(tx.delivered) == 40)
    await p.stop()
    assert tx.delivered == [f"config:{i}" for i in range(1, 41)]  # order kept
    assert p.metrics.delivery_failures == 6
    assert p.metrics.last_error == "connect_failed"
    assert p.metrics.events_sent == 40
    assert p.metrics.events_dropped == 0


def test_backoff_is_capped_jittered_and_honours_retry_after(tmp_path):
    p = _pipeline(tmp_path, FakeTransport(), [], max_backoff_s=8)
    p.backoff_base_s = 0.5
    delays = [p._delay(a, None) for a in range(1, 12)]
    assert all(0 < d <= 8 for d in delays)
    assert delays[0] <= 1.0 and max(delays[-3:]) >= 4
    assert p._delay(1, 5.0) >= 5.0
    assert p._delay(1, 999) <= 8


async def test_a_dead_receiver_applies_backpressure_not_memory_growth(tmp_path):
    src = ListSource()
    src.add(1000)
    tx = FakeTransport()
    tx.down = True
    p = _pipeline(tmp_path, tx, [src], queue_max=10, batch_size=5)
    p.start()
    await _until(lambda: p.metrics.delivery_failures >= 3)
    await asyncio.sleep(0.3)
    read = p.metrics.events_read
    await p.stop()
    # queue (10) + the batch held by the sender (5) + one blocked put
    assert read <= 16, read
    assert p._queue.qsize() <= 10
    assert _cursor(tmp_path) == {"id": 0}


async def test_start_from_now_pins_the_cursor_at_first_enable(tmp_path):
    src = ListSource()
    src.add(5)  # history before export was enabled
    tx = FakeTransport()
    p = _pipeline(tmp_path, tx, [src], start_from="now")
    p.start()
    await _until(lambda: (tmp_path / "cursors.json").exists())
    src.add(2)
    await _until(lambda: len(tx.delivered) == 2)
    await p.stop()
    assert tx.delivered == ["config:6", "config:7"]


async def test_too_large_batches_are_split_and_a_single_oversize_event_shrinks(
    tmp_path,
):
    src = ListSource()
    src.add(8)
    tx = FakeTransport()
    tx.max_events = 3
    p = _pipeline(tmp_path, tx, [src], batch_size=8)
    p.start()
    await _until(lambda: len(tx.delivered) == 8)
    await p.stop()
    assert sorted(tx.delivered, key=lambda s: int(s.split(":")[1])) == [
        f"config:{i}" for i in range(1, 9)
    ]
    assert p.metrics.events_dropped == 0


async def test_a_failing_source_does_not_stop_the_others(tmp_path):
    good = ListSource("config")
    good.add(3)

    class Broken(ListSource):
        def fetch(self, cursor, limit):
            raise RuntimeError("db down")

    bad = Broken("case_audit")
    tx = FakeTransport()
    p = _pipeline(tmp_path, tx, [bad, good])
    p.start()
    await _until(lambda: len(tx.delivered) == 3)
    await p.stop()
    assert p.metrics.source_errors >= 1
    assert p.metrics.last_error == "source_failed:case_audit"


async def test_events_are_redacted_before_they_are_queued(tmp_path):
    src = ListSource()
    src.add(1, details={"password": "hunter2"})
    seen = []

    class Capture(FakeTransport):
        async def send(self, events):
            seen.extend(events)

    p = _pipeline(tmp_path, Capture(), [src])
    p.start()
    await _until(lambda: len(seen) == 1)
    await p.stop()
    assert seen[0].details == {"password": "[REDACTED]"}
    assert p.metrics.redactions == 1


def test_corrupt_cursor_file_is_refused_not_reset(tmp_path):
    (tmp_path / "cursors.json").write_text("{not json")
    store = FileCursorStore(tmp_path / "cursors.json")
    with pytest.raises(RuntimeError):
        store.get("siem", "config")


def test_cursor_commit_is_atomic_and_durable(tmp_path):
    store = FileCursorStore(tmp_path / "state" / "cursors.json")
    store.commit("a", "config", {"id": 3})
    store.commit("b", "auth", {"segment": 1, "offset": 10})
    again = FileCursorStore(tmp_path / "state" / "cursors.json")
    assert again.get("a", "config") == {"id": 3}
    assert again.get("b", "auth") == {"segment": 1, "offset": 10}
    assert [p.name for p in (tmp_path / "state").iterdir()] == ["cursors.json"]


async def test_tcp_syslog_receiver_outage_end_to_end(tmp_path):
    """A real receiver goes away mid-stream and comes back on the same port:
    every event arrives (at least once; ids dedupe any replay)."""
    rx = await SyslogReceiver().start()
    port = rx.port
    src = ListSource()
    src.add(20)
    dest = SyslogDestination(
        type="syslog", name="siem", host="127.0.0.1", port=port, protocol="tcp"
    )
    p = _pipeline(tmp_path, SyslogTransport(dest, lambda _n: None, "soc"), [src])
    p.start()
    try:
        await rx.wait_for(20)
        await rx.stop()
        src.add(20)
        await _until(lambda: p.metrics.delivery_failures >= 1)
        rx2 = await SyslogReceiver().start(port)
        try:
            await _until(lambda: _cursor(tmp_path) == {"id": 40}, timeout=20)
            ids = {
                json.loads(m.split(b"\xef\xbb\xbf", 1)[1])["id"]
                for m in rx.messages + rx2.messages
            }
        finally:
            await rx2.stop()
    finally:
        await p.stop()
    assert ids == {f"config:{i}" for i in range(1, 41)}
