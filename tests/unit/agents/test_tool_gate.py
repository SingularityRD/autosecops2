"""/internal/tools/invoke runs a gated tool only on an approved checkpoint (W1.7)."""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agents import internal_auth, mcp_tools, tools_router
from core.agents.mcp_tools import MCPFailure, approved_call, execute_mcp_tool
from core.integrations.mcp.registry import MCPRegistry
from core.response.checkpoints import args_digest

pytestmark = pytest.mark.unit

RUN = "run-1"
CHECKPOINT = "apr-0123456789ab"
TOOL = "microsoft-defender_mde_isolate"


def _action(
    checkpoint=CHECKPOINT,
    title=f"parked on approval for {TOOL}",
    args=None,
    **params,
):
    # Bound to the arguments a person was shown (W1.7b); {} unless said.
    return SimpleNamespace(
        title=title,
        description=title,
        parameters={
            "checkpoint_id": checkpoint,
            "args_sha256": args_digest({} if args is None else args),
            **params,
        },
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


def _invoke(client, tool=TOOL, approval=None, args=None):
    body = {
        "tool": tool,
        "args": {} if args is None else args,
        "bounds": {"max_rows": 5, "timeout_ms": 1000},
    }
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
        _action(
            title=f'investigator wants to call {TOOL} with {{"id": "h1"}}. Approve?'
        )
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
        # Nor when the arguments spell out a question about this tool (W0.10).
        (
            {"run_id": RUN, "checkpoint_id": CHECKPOINT},
            _action(
                title=(
                    "lead wants to call palo-alto_pan_block_ip with "
                    f'{{"note": "x wants to call {TOOL} with y"}}. Approve?'
                )
            ),
        ),
        # Or the compose reason on a line of their own.
        (
            {"run_id": RUN, "checkpoint_id": CHECKPOINT},
            _action(
                title=(
                    "lead wants to call palo-alto_pan_block_ip with "
                    f'{{"note": "x\nparked on approval for {TOOL}\n"}}. Approve?'
                ),
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


# --- W1.7b: an approval is of one call, with these arguments ------------------

HOST_A = {"machine_id": "host-a", "comment": "contain"}
HOST_B = {"machine_id": "host-b", "comment": "contain"}


def test_an_approval_runs_the_call_with_the_arguments_a_person_saw(harness):
    client, state, ran = harness
    state.approvals.actions = [_action(tool=TOOL, args=HOST_A)]
    approval = {"run_id": RUN, "checkpoint_id": CHECKPOINT}
    # Key order and spacing are the sender's; the digest is of the arguments.
    reordered = {"comment": "contain", "machine_id": "host-a"}
    assert _invoke(client, approval=approval, args=reordered)["ok"] is True
    assert ran == [(TOOL, TOOL)]


def test_an_approval_of_host_a_cannot_be_replayed_for_host_b(harness):
    client, state, ran = harness
    state.approvals.actions = [_action(tool=TOOL, args=HOST_A)]
    approval = {"run_id": RUN, "checkpoint_id": CHECKPOINT}
    body = _invoke(client, approval=approval, args=HOST_B)
    assert body["failure"]["kind"] == "refused"
    assert ran == []


def test_an_approval_that_binds_no_arguments_approves_nothing(harness):
    client, state, ran = harness
    action = _action(tool=TOOL)
    del action.parameters["args_sha256"]
    state.approvals.actions = [action]
    body = _invoke(client, approval={"run_id": RUN, "checkpoint_id": CHECKPOINT})
    assert body["failure"]["kind"] == "refused"
    assert ran == []


@pytest.mark.parametrize(
    "tool", ["approve_action", "reject_action", "jira_approve_request"]
)
def test_a_decision_is_refused_whatever_approval_comes_with_it(harness, tool):
    client, state, ran = harness
    state.approvals.actions = [_action(tool=tool, args={"action_id": "a"})]
    body = _invoke(
        client,
        tool=tool,
        args={"action_id": "a"},
        approval={"run_id": RUN, "checkpoint_id": CHECKPOINT},
    )
    assert body["failure"]["kind"] == "refused"
    assert "only a person" in body["failure"]["detail"]
    assert ran == []
    # Refused before the queue is even read.
    assert state.approvals.asked == []


def test_the_executor_refuses_a_decision_even_when_cleared():
    class _Reg:
        def get_active_servers(self):
            return ["jira"]

        def get_tool_names(self):
            return ["jira_approve_request"]

    with approved_call("jira_approve_request"):
        with pytest.raises(MCPFailure) as refused:
            asyncio.run(execute_mcp_tool("jira_approve_request", {}, 1.0, _Reg()))
    assert refused.value.kind == "refused"
