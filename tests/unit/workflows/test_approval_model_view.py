# W0.30 round 11: approval rows reach a model masked by position. The bodies come
# from the real agent path (reader -> handle -> gated call -> park -> httpAnnounce;
# fixture kept current by services/agent/tests/hunt/guarded-approval-fixture.test.ts)
# and are filed by the real record_checkpoint / raise_for_checkpoint. Every
# model-facing approval tool, backend and /mcp, must hand back no subject text --
# not the display-escaped value, not a cut prefix -- and a row whose positions are
# unknown fails closed.

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from core.agents import tool_registry
from core.workflows import run_bridge_router as bridge
from core.workflows.subject_values import WITHHELD_NOTE

pytestmark = pytest.mark.unit

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "guarded_approvals.json").read_text()
)
# What each probe must never show a model, in any spelling.
TELLS = ["Per SOC lead", "tell the analyst", "Note to the reviewing assistant"]


@dataclasses.dataclass
class _Row:
    action_id: str
    title: str
    description: str
    parameters: Dict[str, Any]
    status: str = "pending"
    action_type: str = "workflow_phase"
    target: str = ""
    confidence: float = 0.0
    created_at: str = "2026-10-15T00:00:00Z"


class _Svc:
    def __init__(self) -> None:
        self.rows: List[_Row] = []

    def create_action(self, **kw: Any) -> Any:
        self.rows.append(
            _Row(
                action_id=kw["parameters"]["checkpoint_id"],
                title=kw["title"],
                description=kw["description"],
                parameters=kw["parameters"],
                target=kw.get("target", ""),
            )
        )
        return MagicMock()

    def get_action(self, action_id: str) -> _Row:
        return next(r for r in self.rows if r.action_id == action_id)

    def list_pending_approvals(self) -> List[_Row]:
        return self.rows

    def list_actions(self, **_k: Any) -> List[_Row]:
        return self.rows


def _filed(names) -> _Svc:
    svc = _Svc()
    with patch(
        "core.response.checkpoints.pending_for", return_value=None
    ), patch.object(bridge, "authorise"):
        for name in names:
            body = FIXTURE[name]["body"]
            bridge.record_checkpoint(
                FIXTURE[name]["run_id"],
                bridge.CheckpointRaised(**body),
                authorization="Bearer x",
                approvals=svc,
            )
    return svc


async def _model_views(svc: _Svc, monkeypatch) -> Dict[str, str]:
    from core.response.approval_service import ActionStatus, ActionType
    from tools.mcp import vigil

    monkeypatch.setattr(tool_registry, "_approvals", lambda: svc)
    monkeypatch.setattr(
        vigil, "get_approval_svc", lambda: (svc, ActionType, ActionStatus)
    )
    views = {}
    listed, _ = await tool_registry.execute_backend_tool("list_pending_approvals", {})
    views["backend list_pending_approvals"] = json.dumps(listed)
    for row in svc.rows:
        one, _ = await tool_registry.execute_backend_tool(
            "get_approval_action", {"action_id": row.action_id}
        )
        views[f"backend get_approval_action {row.action_id}"] = json.dumps(one)
        views[f"/mcp get_approval_action {row.action_id}"] = vigil.get_approval_action(
            action_id=row.action_id
        )
    views["/mcp list_approval_actions"] = vigil.list_approval_actions()
    return views


def _leaks(views: Dict[str, str]) -> List[str]:
    return [
        f"{where}: {tell}"
        for where, text in views.items()
        for tell in TELLS
        if tell in text
    ]


@pytest.mark.parametrize("name", ["zw", "bidi", "long600", "url250", "embedded"])
async def test_a_probe_reaches_no_model(monkeypatch, name):
    svc = _filed([name])
    stored = copy.deepcopy(dataclasses.asdict(svc.rows[0]))
    # The people's copy really holds the text, so the check means something.
    assert any(t in json.dumps(stored) for t in TELLS)

    views = await _model_views(svc, monkeypatch)
    assert _leaks(views) == []

    one, _ = await tool_registry.execute_backend_tool(
        "get_approval_action", {"action_id": svc.rows[0].action_id}
    )
    field = "url" if name == "url250" else "comment"
    # Masked by position: the subject's leaf is its marker, the rest is as bound.
    assert json.loads(one["parameters"]["args_canonical"]) == {
        "host": "WS01",
        field: "[subject value 1]",
    }
    assert "[subject value 1]" in one["description"]
    # Stored row, digest and the human view are untouched.
    assert dataclasses.asdict(svc.rows[0]) == stored
    assert one["parameters"]["args_sha256"] == stored["parameters"]["args_sha256"]


async def test_all_probes_in_one_list(monkeypatch):
    svc = _filed(list(FIXTURE))
    assert _leaks(await _model_views(svc, monkeypatch)) == []


async def test_a_row_without_positions_fails_closed(monkeypatch):
    svc = _filed(["long600"])
    svc.rows[0].parameters.pop("subject_paths")  # legacy, or a shape not anticipated
    views = await _model_views(svc, monkeypatch)
    assert _leaks(views) == []
    one, _ = await tool_registry.execute_backend_tool(
        "get_approval_action", {"action_id": svc.rows[0].action_id}
    )
    assert "args_canonical" not in one["parameters"]
    assert "args_targets" not in one["parameters"]
    assert one["parameters"]["args_withheld"] == WITHHELD_NOTE
    assert one["description"] == WITHHELD_NOTE
