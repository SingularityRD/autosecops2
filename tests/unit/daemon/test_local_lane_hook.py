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

VALID = {
    "severity": "high",
    "confidence": 0.8,
    "category": "malware",
    "recommended_action": "isolate",
    "reasoning": "unsigned binary",
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
    gateway.submit = AsyncMock(return_value={"content": "SEVERITY: low"})
    processor._llm_gateway = gateway
    return processor, gateway


def _run(processor, small_target):
    async def go():
        token = alert_lanes._TRIAGE_TARGET.set(small_target)
        try:
            return await processor._get_ai_triage("prompt")
        finally:
            alert_lanes._TRIAGE_TARGET.reset(token)

    return asyncio.run(go())


def test_small_lane_uses_the_local_lane(monkeypatch):
    lane = _lane({"content": json.dumps(VALID), "model": "ollama/qwen2.5:7b"})
    monkeypatch.setattr("services.daemon.processor.get_local_lane", lambda: lane)
    processor, gateway = _processor()
    content, error = _run(processor, ("ollama", "tiny"))
    assert error is None and content == ll.render_legacy(VALID)
    gateway.submit.assert_not_called()
    finding = processor._apply_triage_result({"finding_id": "f"}, content)
    assert finding["severity"] == "high" and finding["triage_confidence"] == 0.8


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
    assert (content, error) == ("SEVERITY: low", None)
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
    assert (content, error) == ("SEVERITY: low", None)
    assert called == []
