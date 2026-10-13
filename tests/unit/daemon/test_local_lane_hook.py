"""W2.3 in W2.2's small-model lane: the processor triages on the local lane.

``_get_ai_triage`` asks the local lane when this task's lane decision is the
small model and a local lane is configured; otherwise the LLM queue as before.
The lane's error is the finding's error: no fallback to the queue's model.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, Mock

import pytest

from core.lanes import alert_lanes
from core.llm import local_lane as ll
from services.daemon.config import ProcessingConfig
from services.daemon.processor import FindingProcessor

pytestmark = pytest.mark.unit

# The verdict object the daemon's prompt asks every lane for (W1.2).
VALID = {
    "verdict": "malicious",
    "confidence": 0.8,
    "category": "malware",
    "cited_fields": ["severity"],
    "gaps": [],
    "recommended_action": {"type": "isolate", "target": "WS-1"},
}
FINDING = {
    "finding_id": "f",
    "data_source": "crowdstrike",
    "severity": "medium",
    "title": "Unsigned binary",
    "entity_context": {"hostnames": ["WS-1"]},
}


def _lane(result):
    async def dispatch(**kwargs):
        if isinstance(result, Exception):
            raise result
        return result

    return ll.LocalModelLane(
        "qwen2.5:7b", bifrost_url="http://127.0.0.1:1", dispatch=dispatch
    )


def _processor():
    processor = FindingProcessor(ProcessingConfig())
    gateway = Mock()
    gateway.submit = AsyncMock(return_value={"content": "queue-answer"})
    processor._llm_gateway = gateway
    return processor, gateway


def _run(processor, small_target, meta=None):
    async def go():
        token = alert_lanes._TRIAGE_TARGET.set(small_target)
        try:
            return await processor._get_ai_triage("prompt", meta=meta)
        finally:
            alert_lanes._TRIAGE_TARGET.reset(token)

    return asyncio.run(go())


def test_small_lane_uses_the_local_lane(monkeypatch):
    lane = _lane({"content": json.dumps(VALID), "model": "ollama/qwen2.5:7b"})
    monkeypatch.setattr("services.daemon.processor.get_local_lane", lambda: lane)
    processor, gateway = _processor()
    meta = {}
    content, error = _run(processor, ("ollama", "tiny"), meta)
    assert error is None and content == ll.render_reply(VALID)
    gateway.submit.assert_not_called()
    # The verdict is stamped with the model the local lane routed to.
    assert meta == {"model": "ollama/qwen2.5:7b", "lane": "local"}
    finding = processor._apply_triage_result(
        dict(FINDING), content, model=meta["model"]
    )
    # Not inconclusive: the small lane's answer is a real verdict (Round 5).
    verdict = finding["ai_triage"]["verdict"]
    assert verdict["verdict"] == "malicious"
    assert verdict["model"] == "ollama/qwen2.5:7b"
    assert verdict["cited_fields"] == [{"field": "severity", "authored": "sensor"}]
    assert finding["severity"] == "high" and finding["triage_confidence"] == 0.8
    assert finding["recommended_action"] == "isolate"


def test_small_lane_end_to_end_through_triage_finding(monkeypatch):
    seen = []

    async def dispatch(**kwargs):
        seen.append(kwargs)
        return {"content": json.dumps(VALID), "model": "qwen2.5:7b"}

    lane = ll.LocalModelLane(
        "qwen2.5:7b", bifrost_url="http://127.0.0.1:1", dispatch=dispatch
    )
    monkeypatch.setattr("services.daemon.processor.get_local_lane", lambda: lane)
    processor, gateway = _processor()

    async def go():
        token = alert_lanes._TRIAGE_TARGET.set(("ollama", "tiny"))
        try:
            return await processor._triage_finding(dict(FINDING))
        finally:
            alert_lanes._TRIAGE_TARGET.reset(token)

    finding = asyncio.run(go())
    # Same prompt as the main lane, nothing added.
    assert seen[0]["messages"] == [
        {"role": "user", "content": processor._build_triage_prompt(dict(FINDING))}
    ]
    assert seen[0]["system_prompt"] is None
    assert seen[0]["response_format"] == ll.RESPONSE_FORMAT
    assert finding["ai_triage"]["verdict"]["verdict"] == "malicious"
    assert finding["ai_triage"]["verdict"]["model"] == "ollama/qwen2.5:7b"
    assert "ai_triage_error" not in finding
    gateway.submit.assert_not_called()


def test_local_lane_error_is_the_findings_error_not_a_fallback(monkeypatch):
    lane = _lane({"content": json.dumps(VALID), "model": "openai/gpt-4o"})
    monkeypatch.setattr("services.daemon.processor.get_local_lane", lambda: lane)
    processor, gateway = _processor()
    content, error = _run(processor, ("ollama", "tiny"))
    assert content is None and error.startswith("model:")
    gateway.submit.assert_not_called()


def test_no_local_lane_keeps_the_queue_path(monkeypatch):
    monkeypatch.setattr("services.daemon.processor.get_local_lane", lambda: None)
    processor, gateway = _processor()
    content, error = _run(processor, ("ollama", "tiny"))
    assert (content, error) == ("queue-answer", None)
    gateway.submit.assert_awaited_once()
    assert gateway.submit.await_args.kwargs["provider_id"] == "ollama"


def test_other_lanes_never_touch_the_local_lane(monkeypatch):
    called = []
    monkeypatch.setattr(
        "services.daemon.processor.get_local_lane", lambda: called.append(1)
    )
    monkeypatch.setattr(
        FindingProcessor, "_resolve_triage_target", staticmethod(lambda: ("p", "m"))
    )
    processor, gateway = _processor()
    content, error = _run(processor, None)
    assert (content, error) == ("queue-answer", None)
    assert called == []


# --------------------------------------------------------------------------
# Round 5: a local-lane outage is not a gateway outage
# --------------------------------------------------------------------------


def _breaker_processor(monkeypatch, lane, small_target):
    from services.daemon import processor as proc

    processor, gateway = _processor()
    processor.config.auto_triage_enabled = True
    processor.config.auto_enrich_enabled = False
    processor._data_service = None
    monkeypatch.setattr(proc, "get_local_lane", lambda: lane)

    async def lanes(finding):
        alert_lanes._TRIAGE_TARGET.set(small_target)
        return None

    monkeypatch.setattr(processor, "alert_lanes", lanes)
    monkeypatch.setattr(processor, "_evaluate_for_response", AsyncMock())
    monkeypatch.setattr(
        "core.quality.canary.withhold_response", AsyncMock(return_value=False)
    )
    return processor, gateway


def _enrich(processor, n):
    async def go():
        for i in range(n):
            finding = dict(FINDING, finding_id=f"f{i}")
            await asyncio.create_task(processor._enrich_in_background(finding))

    asyncio.run(go())


def test_local_lane_outage_does_not_trip_the_shared_breaker(monkeypatch):
    from services.daemon.processor import _ENRICH_BREAKER_THRESHOLD

    lane = _lane(ConnectionError("ollama down"))
    processor, _ = _breaker_processor(monkeypatch, lane, ("ollama", "tiny"))
    _enrich(processor, _ENRICH_BREAKER_THRESHOLD + 2)
    assert processor._enrich_failures == 0
    assert not processor._enrich_breaker_tripped
    assert processor._enrich_paused_until == 0.0


def test_local_lane_success_does_not_reset_the_shared_breaker(monkeypatch):
    lane = _lane({"content": json.dumps(VALID), "model": "ollama/qwen2.5:7b"})
    processor, _ = _breaker_processor(monkeypatch, lane, ("ollama", "tiny"))
    processor._enrich_failures = 5
    _enrich(processor, 1)
    assert processor._enrich_failures == 5


def test_gateway_failures_still_trip_the_breaker(monkeypatch):
    from services.daemon.processor import _ENRICH_BREAKER_THRESHOLD

    processor, gateway = _breaker_processor(monkeypatch, None, None)
    monkeypatch.setattr(
        FindingProcessor, "_resolve_triage_target", staticmethod(lambda: ("p", "m"))
    )
    gateway.submit = AsyncMock(return_value={"type": "error", "error": "no key"})
    _enrich(processor, _ENRICH_BREAKER_THRESHOLD)
    assert processor._enrich_breaker_tripped
