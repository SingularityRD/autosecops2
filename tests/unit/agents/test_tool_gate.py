"""/internal/tools/invoke runs a gated tool only on an approved checkpoint (W1.7)."""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agents import internal_auth, mcp_tools, tools_router
from core.agents.mcp_tools import MCPFailure, approved_call, execute_mcp_tool
from core.integrations.mcp.registry import MCPRegistry

pytestmark = pytest.mark.unit

RUN = "run-1"
CHECKPOINT = "apr-0123456789ab"
TOOL = "microsoft-defender_mde_isolate"


def _action(checkpoint=CHECKPOINT, title=f"parked on approval for {TOOL}", **params):
    return SimpleNamespace(
        title=title,
        description=title,
        parameters={"checkpoint_id": checkpoint, **params},
    )


class _Approvals:
    def __init__(self, *actions):
        self.actions = list(actions)
        self.asked = []

    def list_actions(self, status=None, workflow_run_id=None, **_):
        self.asked.append((status.value, workflow_run_id))
        return self.actions if workflow_run_id == RUN else []


@pytest.fixture
def harness(monkeypatch):
    monkeypatch.setattr(internal_auth, "get_secret", lambda name: "shhh")
    ran = []

    async def backend(name, args, **kwargs):
        return None, False

    async def mcp(name, args, timeout_s, registry):
        ran.append((name, mcp_tools._approved.get()))
        return [{"isolated": True}], True

    monkeypatch.setattr(tools_router, "execute_backend_tool", backend)
    monkeypatch.setattr(tools_router, "execute_mcp_tool", mcp)
    app = FastAPI()
    app.state.mcp_registry = MCPRegistry()
    app.state.approvals = _Approvals()
    app.include_router(tools_router.router, prefix=tools_router.ROUTER_META.prefix)
    return TestClient(app), app.state, ran


def _invoke(client, tool=TOOL, approval=None):
    body = {"tool": tool, "args": {}, "bounds": {"max_rows": 5, "timeout_ms": 1000}}
    if approval is not None:
        body["approval"] = approval
    return client.post(
        "/internal/tools/invoke", json=body, headers={"Authorization": "Bearer shhh"}
    ).json()


def test_a_gated_tool_without_an_approval_is_refused_before_it_runs(harness):
    client, _, ran = harness
    body = _invoke(client)
    assert body["failure"]["kind"] == "refused"
    assert "approves" in body["failure"]["detail"]
    assert ran == []


def test_an_approved_checkpoint_about_this_tool_lets_it_run(harness):
    client, state, ran = harness
    state.approvals.actions = [_action()]
    body = _invoke(client, approval={"run_id": RUN, "checkpoint_id": CHECKPOINT})
    assert body["ok"] is True
    # The executor sees the binding, so its own check passes for this call only.
    assert ran == [(TOOL, TOOL)]
    assert state.approvals.asked == [("approved", RUN)]


def test_the_lead_question_form_names_the_tool(harness):
    client, state, ran = harness
    state.approvals.actions = [
        _action(title=f'investigator wants to call {TOOL} with {{"id": "h1"}}. Approve?')
    ]
    assert _invoke(client, approval={"run_id": RUN, "checkpoint_id": CHECKPOINT})["ok"]


def test_a_tool_named_on_the_action_parameters_is_enough(harness):
    client, state, ran = harness
    state.approvals.actions = [_action(title="Approve step", tool=TOOL)]
    assert _invoke(client, approval={"run_id": RUN, "checkpoint_id": CHECKPOINT})["ok"]


@pytest.mark.parametrize(
    "approval, action",
    [
        # Another checkpoint was approved, not this one.
        ({"run_id": RUN, "checkpoint_id": "apr-other"}, _action()),
        # Another run's approval.
        ({"run_id": "run-2", "checkpoint_id": CHECKPOINT}, _action()),
        # The checkpoint was about a different tool.
        (
            {"run_id": RUN, "checkpoint_id": CHECKPOINT},
            _action(title="parked on approval for palo-alto_pan_block_ip"),
        ),
        # A phase approval that merely mentions the tool is not an approval of it.
        (
            {"run_id": RUN, "checkpoint_id": CHECKPOINT},
            _action(title=f"Approve {TOOL}, run by responder?"),
        ),
        # Nor is a question about another tool whose arguments name this one.
        (
            {"run_id": RUN, "checkpoint_id": CHECKPOINT},
            _action(
                title=(
                    "lead wants to call palo-alto_pan_block_ip with "
                    f'{{"note": "{TOOL}"}}. Approve?'
                )
            ),
        ),
        # An action that names its tool outright names that one only.
        (
            {"run_id": RUN, "checkpoint_id": CHECKPOINT},
            _action(tool="palo-alto_pan_block_ip"),
        ),
    ],
)
def test_an_approval_for_something_else_is_refused(harness, approval, action):
    client, state, ran = harness
    state.approvals.actions = [action]
    assert _invoke(client, approval=approval)["failure"]["kind"] == "refused"
    assert ran == []


def test_an_unreadable_queue_is_not_a_yes(harness):
    client, state, ran = harness

    def boom(**_):
        raise RuntimeError("db down")

    state.approvals.list_actions = boom
    body = _invoke(client, approval={"run_id": RUN, "checkpoint_id": CHECKPOINT})
    assert body["failure"]["kind"] == "refused"
    assert ran == []


def test_a_read_tool_needs_no_approval(harness):
    client, state, ran = harness
    assert _invoke(client, tool="virustotal_get_ip_report")["ok"] is True
    assert ran == [("virustotal_get_ip_report", None)]
    assert state.approvals.asked == []


def test_call_integration_tool_is_judged_by_the_call_it_stands_for(
    harness, monkeypatch
):
    client, _, ran = harness
    monkeypatch.setattr(
        tools_router,
        "resolve_integration_call",
        lambda registry, raw: (TOOL, {}),
    )
    body = _invoke(client, tool="call_integration_tool")
    assert body["failure"]["kind"] == "refused"
    assert ran == []


class _Registry:
    def get_active_servers(self):
        return ["microsoft-defender"]

    def get_tool_names(self):
        return [TOOL]


def test_the_executor_refuses_a_gated_tool_nobody_cleared():
    with pytest.raises(MCPFailure) as refused:
        asyncio.run(execute_mcp_tool(TOOL, {}, 1.0, _Registry()))
    assert refused.value.kind == "refused"


def test_the_executor_refuses_a_gated_tool_cleared_for_another():
    with approved_call("palo-alto_pan_block_ip"):
        with pytest.raises(MCPFailure):
            asyncio.run(execute_mcp_tool(TOOL, {}, 1.0, _Registry()))
