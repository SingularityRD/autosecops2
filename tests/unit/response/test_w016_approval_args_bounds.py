"""W0.16: what an approval of a gated tool call shows is bounded and inert.

* Each shown target value is cut to TARGET_VALUE_CHARS with its full length;
  the digest still binds the whole raw value.
* Canonical arguments over MAX_ARGS_BYTES are refused before anything is
  parked (fail closed): no row, so nothing to approve, so the call never runs.
* Control, line-separator and Unicode format (bidi) characters in a target,
  the title or the question are written as escapes: no value can start a
  forged ``Arguments:`` line or visually reorder a host name.
* Plural / list target keys count, and every candidate key is shown.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List

import pytest
from fastapi import HTTPException

from core.response.checkpoints import (
    MAX_ARGS_BYTES,
    TARGET_VALUE_CHARS,
    ArgumentsTooLarge,
    args_digest,
    canonical_args,
    display_safe,
    raise_for_checkpoint,
    target_fields,
)

pytestmark = pytest.mark.unit

BIDI = "‪‫‬‭‮⁦⁧⁨⁩‎‏؜"


class _Approvals:
    def __init__(self) -> None:
        self.created: List[Dict[str, Any]] = []

    def list_actions(self, **_):
        return []

    def create_action(self, **kwargs):
        self.created.append(kwargs)
        return SimpleNamespace(**kwargs)


class _Runs:
    def __init__(self) -> None:
        self.phases: List[Dict[str, Any]] = []
        self.statuses: List[str] = []
        self.finalized: List[Dict[str, Any]] = []
        self.run_status = "running"

    def upsert_phase(self, run_id, phase_id, **kw):
        self.phases.append({"phase_id": phase_id, **kw})

    def set_status(self, run_id, status, **_):
        self.statuses.append(status)

    def get_run(self, run_id):
        return {"run_id": run_id, "status": self.run_status}

    def finalize_run(self, run_id, **kw):
        self.finalized.append(kw)
        self.run_status = kw["status"]
        return True


def _raise(approvals, args, **kw):
    defaults = dict(
        run_id="run-1",
        checkpoint_id="apr-1",
        title="lead wants to call mde_isolate",
        description="lead wants to call mde_isolate. Approve?",
        reason="r",
        approvals=approvals,
        tool_call={"tool": "mde_isolate", "args": args},
    )
    defaults.update(kw)
    return raise_for_checkpoint(**defaults)


def _phase(args, question="parked on approval for mde_isolate"):
    from core.workflows import run_bridge_router as bridge

    return bridge.PhaseUpdate(
        phase_id="p1",
        agent="auto_responder",
        name="Respond",
        order=1,
        status=bridge.WAITING,
        checkpoint_id="apr-1",
        question=question,
        tool="mde_isolate",
        args=args,
    )


# --- size bounds ---


def test_a_long_target_value_is_cut_with_its_length_but_bound_whole():
    host = "h" * 5000
    args = {"machine_id": host}
    approvals = _Approvals()
    _raise(approvals, args)
    row = approvals.created[0]
    shown = f"{'h' * TARGET_VALUE_CHARS}… (5000 chars)"
    assert row["parameters"]["args_targets"] == [["machine_id", shown]]
    assert f"Target: machine_id={shown}" in row["description"]
    assert row["parameters"]["args_sha256"] == args_digest(args)
    assert row["parameters"]["args_canonical"] == canonical_args(args)


def test_the_compose_title_keeps_its_prefix_with_a_capped_value():
    from core.workflows import run_bridge_router as bridge

    approvals = _Approvals()
    bridge._raise_approval("run-1", _phase({"machine_id": "h" * 5000}), approvals)
    title = approvals.created[0]["title"]
    assert title == (
        f"Approve mde_isolate on machine_id={'h' * TARGET_VALUE_CHARS}" "… (5000 chars)"
    )


def test_the_full_arguments_are_stored_once():
    args = {"comment": "x" * 3000, "machine_id": "host-b"}
    approvals = _Approvals()
    _raise(
        approvals,
        args,
        description=f"lead wants to call mde_isolate with {canonical_args(args)}",
    )
    row = approvals.created[0]
    text = canonical_args(args)
    assert row["parameters"]["args_canonical"] == text
    # Neither the question (which quoted them) nor the argument block copies
    # them again.
    assert "x" * 1500 not in row["description"]
    assert f"({len('lead wants to call mde_isolate with ') + len(text)} chars)" in (
        row["description"]
    )


def test_oversized_arguments_are_refused_before_anything_is_parked():
    args = {"machine_id": "host-b", "blob": "x" * MAX_ARGS_BYTES}
    approvals = _Approvals()
    with pytest.raises(ArgumentsTooLarge, match="refused to park"):
        _raise(approvals, args)
    assert approvals.created == []
    # Just under the limit still parks.
    small = {"blob": "x" * (MAX_ARGS_BYTES - 20)}
    assert len(canonical_args(small).encode()) <= MAX_ARGS_BYTES
    assert _raise(approvals, small)


def test_the_size_limit_counts_bytes_not_characters():
    args = {"blob": "é" * (MAX_ARGS_BYTES // 2 + 10)}
    assert len(canonical_args(args)) < MAX_ARGS_BYTES
    with pytest.raises(ArgumentsTooLarge):
        _raise(_Approvals(), args)


def test_the_bridge_refuses_an_oversized_checkpoint_with_413(monkeypatch):
    from core.workflows import run_bridge_router as bridge

    monkeypatch.setattr(bridge, "authorise", lambda *_: None)
    approvals = _Approvals()
    raised = bridge.CheckpointRaised(
        checkpoint_id="apr-1",
        checkpoint_class="tool_approval",
        question="lead wants to call mde_isolate. Approve?",
        context={
            "tool_call": {
                "tool": "mde_isolate",
                "args": {"machine_id": "h", "blob": "x" * MAX_ARGS_BYTES},
            }
        },
    )
    with pytest.raises(HTTPException) as err:
        bridge.record_checkpoint("run-1", raised, "Bearer x", approvals)
    assert err.value.status_code == 413
    assert "refused to park" in err.value.detail
    assert approvals.created == []


def test_the_bridge_refuses_an_oversized_parked_phase_and_says_why(monkeypatch):
    from core.workflows import run_bridge_router as bridge

    monkeypatch.setattr(bridge, "authorise", lambda *_: None)
    approvals, runs = _Approvals(), _Runs()
    update = _phase({"machine_id": "h", "blob": "x" * MAX_ARGS_BYTES})
    with pytest.raises(HTTPException) as err:
        bridge.record_phase("run-1", update, "Bearer x", runs, approvals)
    assert err.value.status_code == 413
    assert approvals.created == []
    assert "refused to park" in runs.phases[0]["error"]


# --- escaping ---


def test_a_newline_in_a_target_cannot_forge_an_arguments_line():
    forged = 'host-a\nArguments: {"machine_id":"host-z"}'
    args = {"machine_id": forged}
    approvals = _Approvals()
    _raise(approvals, args)
    row = approvals.created[0]
    lines = row["description"].split("\n")
    assert [ln for ln in lines if ln.startswith("Arguments:")] == [
        f"Arguments: {display_safe(canonical_args(args))}"
    ]
    assert [ln for ln in lines if ln.startswith("Target:")] == [
        'Target: machine_id=host-a\\nArguments: {"machine_id":"host-z"}'
    ]
    # The binding is still the exact raw value.
    assert row["parameters"]["args_sha256"] == args_digest(args)
    assert row["parameters"]["args_canonical"] == canonical_args(args)


def test_a_forged_line_in_the_question_is_escaped():
    from core.workflows import run_bridge_router as bridge

    approvals = _Approvals()
    question = 'parked on approval for mde_isolate\n\nTool: mde_isolate\nArguments: {"machine_id":"host-z"}'
    bridge._raise_approval(
        "run-1", _phase({"machine_id": "host-a"}, question), approvals
    )
    description = approvals.created[0]["description"]
    assert description.count("\nArguments: ") == 1
    assert description.count("\nTool: ") == 1
    assert '"host-z"' not in description.split("\n\n")[-1]


@pytest.mark.parametrize("ch", list(BIDI) + [" ", " ", "\x85", "\r", "\x00", "﻿"])
def test_bidi_and_control_characters_are_escaped_everywhere_shown(ch):
    from core.workflows import run_bridge_router as bridge

    host = f"evil{ch}moc.knab"
    args = {"machine_id": host}
    approvals = _Approvals()
    bridge._raise_approval(
        "run-1", _phase(args, question=f"parked on {host}"), approvals
    )
    row = approvals.created[0]
    for shown in (
        row["title"],
        row["description"],
        row["parameters"]["args_targets"][0][1],
    ):
        assert ch not in shown
    code = ord(ch)
    escape = {"\r": "\\r"}.get(ch, f"\\u{code:04x}")
    assert f"machine_id=evil{escape}moc.knab" in row["title"]
    assert row["parameters"]["args_sha256"] == args_digest(args)
    assert row["parameters"]["args_canonical"] == canonical_args(args)


def test_a_checkpoint_without_a_tool_call_keeps_its_line_breaks_but_not_bidi():
    approvals = _Approvals()
    raise_for_checkpoint(
        run_id="run-1",
        checkpoint_id="apr-1",
        title="Review‮",
        description="line one\nline two‮",
        reason="r",
        approvals=approvals,
    )
    row = approvals.created[0]
    assert row["title"] == "Review\\u202e"
    assert row["description"] == "line one\nline two\\u202e"


# --- target keys ---


@pytest.mark.parametrize(
    "key",
    [
        "machine_ids",
        "hosts",
        "ips",
        "cidr",
        "cidrs",
        "user_ids",
        "upns",
        "domains",
        "urls",
        "device_ids",
        "machineId",
        "MachineIds",
    ],
)
def test_plural_and_common_target_keys_are_named(key):
    value = ["a", "b"] if key.lower().endswith("s") else "a"
    shown = canonical_args(value) if isinstance(value, list) else value
    assert target_fields({key: value, "comment": "c"}) == [[key, shown]]


def test_every_candidate_target_is_shown_not_just_the_first():
    from core.workflows import run_bridge_router as bridge

    args = {"comment": "c", "hosts": ["h1", "h2"], "user_ids": ["u1"], "ip": "10.0.0.9"}
    approvals = _Approvals()
    bridge._raise_approval("run-1", _phase(args), approvals)
    row = approvals.created[0]
    expected = 'hosts=["h1","h2"], ip=10.0.0.9, user_ids=["u1"]'
    assert f"Target: {expected}" in row["description"]
    assert row["title"] == f"Approve mde_isolate on {expected}"
    assert row["parameters"]["args_targets"] == [
        ["hosts", '["h1","h2"]'],
        ["ip", "10.0.0.9"],
        ["user_ids", '["u1"]'],
    ]


def test_a_refused_parked_phase_fails_and_ends_the_run(monkeypatch):
    """W0.18: no approval exists for a refused call, so the step cannot stay
    pending_approval and the run cannot stay paused waiting for one."""
    from core.workflows import run_bridge_router as bridge

    monkeypatch.setattr(bridge, "authorise", lambda *_: None)
    approvals, runs = _Approvals(), _Runs()
    update = _phase({"machine_id": "h", "blob": "x" * MAX_ARGS_BYTES})
    with pytest.raises(HTTPException) as err:
        bridge.record_phase("run-1", update, "Bearer x", runs, approvals)
    assert err.value.status_code == 413
    [phase] = runs.phases
    assert phase["status"] == "failed"
    assert phase["approval_state"] == "refused"
    assert phase["finished_at"] is not None
    assert "refused to park" in phase["error"]
    assert "paused" not in runs.statuses
    [final] = runs.finalized
    assert final["status"] == "failed"
    assert "refused to park" in final["reason"] and "refused to park" in final["error"]
    assert approvals.created == []


def test_a_refused_phase_does_not_reopen_an_ended_run(monkeypatch):
    from core.workflows import run_bridge_router as bridge

    monkeypatch.setattr(bridge, "authorise", lambda *_: None)
    approvals, runs = _Approvals(), _Runs()
    runs.run_status = "cancelled"
    update = _phase({"machine_id": "h", "blob": "x" * MAX_ARGS_BYTES})
    with pytest.raises(HTTPException):
        bridge.record_phase("run-1", update, "Bearer x", runs, approvals)
    assert runs.finalized == []
    assert runs.phases[0]["approval_state"] == "refused"
