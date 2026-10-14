"""An approval of a parked tool call is bound to that call's arguments (W1.7b).

A checkpoint the agent layer parks on one gated tool call names the call
(``context.tool_call`` / the phase's ``tool`` and ``args``). The approval row
then carries the tool, the sha256 of the canonical arguments, and a summary the
person reads; ``/internal/tools/invoke`` runs the call only when the arguments
it is handed hash the same (tests/unit/agents/test_tool_gate.py).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from core.response.checkpoints import (
    ARGS_SUMMARY_CHARS,
    args_digest,
    canonical_args,
    raise_for_checkpoint,
    split_tool_call,
)

pytestmark = pytest.mark.unit

ARGS = {"machine_id": "host-a", "comment": "contain beacon"}


class _Approvals:
    def __init__(self) -> None:
        self.created: List[Dict[str, Any]] = []

    def list_actions(self, **_):
        return []

    def create_action(self, **kwargs):
        self.created.append(kwargs)
        return SimpleNamespace(**kwargs)


def _raise(approvals, **kwargs):
    defaults = dict(
        run_id="run-1",
        checkpoint_id="apr-1",
        title="investigator wants to call mde_isolate",
        description="investigator wants to call mde_isolate. Approve?",
        reason="r",
        approvals=approvals,
    )
    defaults.update(kwargs)
    return raise_for_checkpoint(**defaults)


def test_the_digest_ignores_key_order_and_whitespace():
    assert args_digest({"b": 1, "a": [1, 2]}) == args_digest({"a": [1, 2], "b": 1})
    assert canonical_args({"b": 1, "a": "x"}) == '{"a":"x","b":1}'
    assert args_digest({"machine_id": "host-a"}) != args_digest(
        {"machine_id": "host-b"}
    )


def test_a_tool_call_checkpoint_carries_tool_digest_and_shows_the_arguments():
    approvals = _Approvals()
    assert _raise(approvals, tool_call={"tool": "mde_isolate", "args": ARGS})

    [row] = approvals.created
    params = row["parameters"]
    assert params["checkpoint_id"] == "apr-1"
    assert params["tool"] == "mde_isolate"
    assert params["args_sha256"] == args_digest(ARGS)
    assert params["args_summary"] == canonical_args(ARGS)
    # The person reads exactly what would run, not just the tool's name.
    assert "Tool: mde_isolate" in row["description"]
    assert '"machine_id":"host-a"' in row["description"]
    assert row["human_only"] is True


def test_a_digest_the_sender_supplied_is_never_kept():
    approvals = _Approvals()
    forged = {
        "tool": "mde_isolate",
        "args_sha256": args_digest({"machine_id": "host-b"}),
        "args_summary": "harmless",
        "checkpoint_id": "apr-other",
    }
    _raise(approvals, parameters=forged)
    params = approvals.created[0]["parameters"]
    assert "args_sha256" not in params
    assert "tool" not in params
    assert params["checkpoint_id"] == "apr-1"

    approvals = _Approvals()
    _raise(
        approvals,
        parameters=forged,
        tool_call={"tool": "mde_isolate", "args": {"machine_id": "host-a"}},
    )
    params = approvals.created[0]["parameters"]
    assert params["args_sha256"] == args_digest({"machine_id": "host-a"})


def test_long_arguments_are_summarised_but_fully_digested():
    approvals = _Approvals()
    big = {"note": "x" * (ARGS_SUMMARY_CHARS * 2)}
    _raise(approvals, tool_call={"tool": "mde_isolate", "args": big})
    params = approvals.created[0]["parameters"]
    assert params["args_sha256"] == args_digest(big)
    assert len(params["args_summary"]) < len(canonical_args(big))
    assert "characters in all" in params["args_summary"]


def test_a_checkpoint_without_a_tool_call_binds_no_arguments():
    approvals = _Approvals()
    _raise(approvals, parameters={"checkpoint_class": "hypothesis_approval"})
    params = approvals.created[0]["parameters"]
    assert "args_sha256" not in params
    assert approvals.created[0]["description"].endswith("Approve?")


def test_split_tool_call_reads_the_harness_context():
    rest, call = split_tool_call(
        {"tool_call": {"tool": "mde_isolate", "args": ARGS}, "hypothesis_id": "h1"}
    )
    assert rest == {"hypothesis_id": "h1"}
    assert call == {"tool": "mde_isolate", "args": ARGS}
    assert split_tool_call(None) == ({}, None)
    assert split_tool_call({"tool_call": "not a call"})[1] is None


def test_the_bridge_binds_a_harness_checkpoint_and_a_parked_phase(monkeypatch):
    from core.workflows import run_bridge_router as bridge

    monkeypatch.setattr(bridge, "authorise", lambda *_: None)
    approvals = _Approvals()
    bridge.record_checkpoint(
        "run-1",
        bridge.CheckpointRaised(
            checkpoint_id="apr-1",
            checkpoint_class="tool_approval",
            question='lead wants to call mde_isolate with {"machine_id":"host-a"}. Approve?',
            context={"tool_call": {"tool": "mde_isolate", "args": ARGS}},
        ),
        "Bearer x",
        approvals,
    )
    params = approvals.created[0]["parameters"]
    assert params["args_sha256"] == args_digest(ARGS)
    assert "tool_call" not in params
    assert params["checkpoint_class"] == "tool_approval"


def test_a_parked_compose_phase_binds_its_call():
    from core.workflows import run_bridge_router as bridge

    approvals = _Approvals()
    bridge._raise_approval(
        "run-1",
        bridge.PhaseUpdate(
            phase_id="p1",
            agent="auto_responder",
            name="Respond",
            order=1,
            status="waiting",
            checkpoint_id="apr-1",
            question="parked on approval for mde_isolate",
            tool="mde_isolate",
            args=ARGS,
        ),
        approvals,
    )
    row = approvals.created[0]
    assert row["parameters"]["args_sha256"] == args_digest(ARGS)
    assert row["parameters"]["tool"] == "mde_isolate"
    assert "Arguments:" in row["description"]
