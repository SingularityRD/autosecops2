# W0.30: no read of the agent layer hands a guarded run's {{h:...}} handle on
# verbatim -- defence in depth behind serve.ts, which already converts them.

from __future__ import annotations

import httpx
import pytest

from core.agents import projections

pytestmark = pytest.mark.unit

RUN = "5a2c2d3e-0000-4000-8000-0000000003c1"
HANDLE = "{{h:dd665b356q1.1.host}}"


def _serve(monkeypatch, body):
    monkeypatch.setattr(projections, "_headers", lambda: {"Authorization": "Bearer t"})
    real = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real(
            transport=httpx.MockTransport(lambda _r: httpx.Response(200, json=body)),
            **kw,
        ),
    )


@pytest.mark.asyncio
async def test_events_never_carry_a_handle(monkeypatch):
    _serve(
        monkeypatch,
        {
            "events": [
                {
                    "kind": "evidence",
                    "payload": {"summary": f"what else ran on {HANDLE}"},
                }
            ]
        },
    )

    events = await projections.read_events(RUN)

    assert events == [
        {
            "kind": "evidence",
            "payload": {"summary": f"what else ran on {projections.HANDLE_MARKER}"},
        }
    ]


@pytest.mark.asyncio
async def test_replay_never_carries_a_handle(monkeypatch):
    _serve(monkeypatch, {"decisions": [{"rationale": f"pivot to {HANDLE}"}]})

    report = await projections.read_replay(RUN)

    assert "{{h:" not in str(report)
    assert projections.HANDLE_MARKER in str(report)


def test_a_string_without_handles_is_untouched():
    value = {"a": ["plain {{ not a handle }}", 3, None]}
    assert projections.neutralise_handles(value) == value
