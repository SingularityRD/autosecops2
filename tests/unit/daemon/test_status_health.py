"""/status shows Federation and the hand-off; /health shows Federation's setup."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from services.daemon.config import MetricsConfig, PollingConfig
from services.daemon.metrics import MetricsServer
from services.daemon.poller import DataPoller

pytestmark = pytest.mark.unit


def _server():
    server = MetricsServer(MetricsConfig())
    server.poller = DataPoller(PollingConfig())
    queue: asyncio.Queue = asyncio.Queue(maxsize=5)
    queue.put_nowait("waiting")
    server.processor = SimpleNamespace(stats={"processed": 3}, input_queue=queue)
    return server


async def _forever():
    await asyncio.Event().wait()


def _all_alive(server):
    """Every component present with a live task, so only Federation varies."""
    server.kafka_ingestor = SimpleNamespace()
    server.responder = SimpleNamespace()
    server.scheduler = SimpleNamespace()
    server.orchestrator = SimpleNamespace(enabled=True)
    names = ("poller", "kafka", "processor", "responder", "scheduler", "orchestrator")
    for name in names:
        server.register_task(name, asyncio.create_task(_forever()))


async def _cleanup(server):
    for task in server._tasks.values():
        task.cancel()
    await asyncio.gather(*server._tasks.values(), return_exceptions=True)


def test_status_carries_federation_counts_live_and_the_queue_depth():
    server = _server()
    server.poller._federation.stats["polls"] = 7

    metrics = server._collect_metrics()

    assert metrics["poller"]["federation"]["polls"] == 7
    assert metrics["processor"]["processed"] == 3
    assert metrics["processor"]["queue_depth"] == 1
    assert metrics["processor"]["queue_maxsize"] == 5
    assert "handoff_full_waits" in metrics["processor"]


@pytest.mark.parametrize(
    "fed, component",
    [
        ({}, "degraded"),
        ({"setup_ok": False, "adapters": 6}, "degraded"),
        ({"setup_ok": True, "adapters": 0}, "degraded"),
        ({"setup_ok": True, "adapters": 6}, "running"),
    ],
    ids=["booting", "setup-retrying", "no-adapters", "ready"],
)
@pytest.mark.asyncio
async def test_health_reports_federation_without_failing_the_probes(fed, component):
    server = _server()
    _all_alive(server)
    server.poller._federation.stats.update(fed)

    resp = await server._handle_health(None)
    await _cleanup(server)

    assert resp.status == 200
    body = json.loads(resp.text)
    assert body["components"]["federation"] == component
    assert body["status"] == ("healthy" if component == "running" else "degraded")
