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


@pytest.mark.asyncio
async def test_the_event_log_carries_the_subject_values_beside_it(monkeypatch):
    # W0.30 round 6: serve sends markers in the prose and the values beside it.
    rows = [{"ref": 1, "field": "host", "value": "C:\\Windows\\System32\\svchost.exe"}]
    _serve(
        monkeypatch,
        {
            "events": [
                {"kind": "evidence", "payload": {"summary": "ran on [subject value 1]"}}
            ],
            "subject_values": rows,
        },
    )

    events, values = await projections.read_event_log(RUN)

    assert events[0]["payload"]["summary"] == "ran on [subject value 1]"
    assert values == rows


def test_a_handle_cut_short_is_neutralised_too():
    # Round 8: the verifier's narrate 502, clipped mid-handle.
    for tail in ("{{h:d50909378q1.1.v_modl}", "{{h:d50909378q1.1.v_mo", "{{h:"):
        out = projections.neutralise_handles(f"rejected: [x]({tail}")
        assert "{{h:" not in out
        assert projections.HANDLE_MARKER in out


@pytest.mark.asyncio
async def test_an_error_detail_is_neutralised_before_it_is_cut(monkeypatch):
    monkeypatch.setattr(projections, "_headers", lambda: {"Authorization": "Bearer t"})
    real = httpx.AsyncClient
    body = '{"detail":"' + "x" * 380 + '{{h:d50909378q1.1.v_modl}} and more"}'
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kw: real(
            transport=httpx.MockTransport(lambda _r: httpx.Response(502, text=body)),
            **kw,
        ),
    )
    with pytest.raises(RuntimeError) as raised:
        await projections.read_replay(RUN)
    assert "{{h:" not in str(raised.value)
