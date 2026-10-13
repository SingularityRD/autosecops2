"""Ratchet (W1.7b): no model decides an approval.

A model is not a person. Alert text, case notes, MCP tool output and every other
thing a model reads can tell it what to do, so a decision on the approval queue
that a model could make is one a prompt injection could make -- under the
signed-in person's name, and as the "second person" of a four-eyes rule (W2.4)
or a distinct-role rule (W3.2). This holds, on every model-facing surface:

* no tool list a model is handed -- chat (declared, and found / called through
  ``find_integration_tools`` / ``call_integration_tool``), compose, investigate,
  hunt, root-cause, the agents' recommended tools, the ``/mcp`` server -- carries
  a ``decision``-class tool (``core.llm.tool_effects.HUMAN_ONLY``), even when a
  connected server offers one;
* ``/internal/tools/invoke`` and the MCP executor refuse every such name, with or
  without an approved checkpoint, before any executor runs;
* the agent layer drops such a tool from what it declares (TS mirror carries
  ``HUMAN_ONLY``) and never calls an approvals route;
* in the Python tree, only the person-facing HTTP routes call
  ``ApprovalService.approve_action`` (and ``reject_action``; the run-end
  withdrawal and the stale-queue expiry may reject, never approve), and only
  they enqueue run directives (which answer hunt checkpoints);
* those routes take the signed-in user and are not CSRF-exempt.

Loosening any of these is a deliberate edit to this file.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List, Set

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agents import internal_auth, tools_router
from core.agents.integration_tools import resolve_integration_call
from core.agents.mcp_tools import MCPFailure, approved_call, execute_mcp_tool
from core.integrations.mcp.registry import MCPRegistry
from core.llm import tool_effects
from core.llm.chat_layers import chat_config, integration_tools
from core.llm.tool_effects import DECISION, HUMAN_ONLY, classify, is_human_only
from core.llm.tool_schemas import ALL_TOOLS, INTEGRATION_TOOLS
from core.response.checkpoints import args_digest
from core.workflows.playbook_resolver import resolve_hunt, resolve_root_cause
from tests.unit._ratchets.test_no_ungated_write_tools import (
    _compose_config,
    agent_tools,
    catalogue_names,
    full_registry,
    vigil_mcp_tools,
)

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]

# Names a server might offer that decide something a person must decide. The
# first two are what AutoSecOps itself served before W1.7b (an older copy of its
# MCP server may still offer them); the rest reach the class by the heuristic.
DECISION_NAMES = (
    "approve_action",
    "reject_action",
    "acme_approve_request",
    "jira_reject_change",
    "servicenow_authorize_change",
    "okta_approveAccessRequest",
)


@pytest.fixture
def no_disabled_agents(monkeypatch):
    from core.workflows import playbook_resolver

    monkeypatch.setattr(playbook_resolver, "disabled_agent_ids", lambda: set())


@pytest.fixture
def no_refresh(monkeypatch):
    monkeypatch.setattr(
        "core.integrations.mcp.registry.refresh_from_client", lambda registry: 0
    )


def hostile_registry() -> MCPRegistry:
    """Every in-repo server, AutoSecOps's own tools, and a server offering decisions."""
    registry = full_registry()
    registry.register_server(
        "acme",
        {},
        [
            {
                "name": name,
                "description": f"Approve or reject: {name}",
                "input_schema": {"type": "object"},
            }
            for name in DECISION_NAMES
        ],
    )
    return registry


# --- the class -----------------------------------------------------------------


def test_decision_is_the_human_only_class():
    assert HUMAN_ONLY == frozenset({DECISION})
    assert not (HUMAN_ONLY & tool_effects.GATED)


@pytest.mark.parametrize("name", DECISION_NAMES)
def test_every_approve_or_reject_name_is_human_only(name):
    assert is_human_only(name), classify(name)


def test_the_typescript_mirror_carries_human_only():
    mirror = tool_effects.MIRROR_PATH.read_text(encoding="utf-8")
    assert (
        'export const HUMAN_ONLY: ReadonlySet<Effect> = new Set<Effect>(["decision"]);'
        in mirror
    )


# --- every model tool list -----------------------------------------------------


def _human_only(names) -> List[str]:
    return sorted({n for n in names if is_human_only(n)})


def test_no_builtin_decides():
    names = {t["name"] for t in (*ALL_TOOLS, *INTEGRATION_TOOLS) if t.get("name")}
    assert _human_only(names) == []
    assert _human_only(tool_effects.BUILTIN) == []


def test_the_mcp_surface_serves_no_decision():
    assert _human_only(vigil_mcp_tools()) == []
    assert _human_only(tool_effects.VIGIL_MCP) == []


def test_no_agent_recommends_a_decision():
    assert _human_only(agent_tools()) == []


def _chat_reach(registry: MCPRegistry, wanted=None) -> Dict[str, List[str]]:
    reachable = registry.get_all_tools()
    config = yaml.safe_load(chat_config("m", tools=wanted, mcp_tools=reachable))
    resolved = []
    for name in [t["name"] for t in reachable] + list(DECISION_NAMES):
        try:
            resolve_integration_call(registry, {"name": name, "arguments": {}})
        except MCPFailure:
            continue
        resolved.append(name)
    return {
        "declared": _human_only(t["id"] for t in config["tools"]),
        "findable": _human_only(t["name"] for t in integration_tools(reachable)),
        "callable": _human_only(resolved),
    }


def test_chat_reaches_no_decision(no_refresh):
    registry = hostile_registry()
    empty = {"declared": [], "findable": [], "callable": []}
    assert _chat_reach(registry) == empty
    # Not even when an agent's tool list asks for one by name.
    assert _chat_reach(registry, wanted=["approve_action", "reject_action"]) == empty


def test_compose_and_investigate_bind_no_decision(no_disabled_agents, no_refresh):
    registry = hostile_registry()
    assert _human_only(catalogue_names(registry)) == []
    for run_kind in ("compose", "investigate"):
        config = _compose_config(registry, run_kind)
        assert _human_only(t["id"] for t in config["tools"]) == [], run_kind


def test_hunts_and_traces_bind_no_decision(no_disabled_agents, no_refresh):
    registry = hostile_registry()
    for resolver, workflow in (
        (resolve_hunt, "threat-hunt"),
        (resolve_root_cause, "root-cause-analysis"),
    ):
        _, text = resolver(workflow, registry=registry)
        config = yaml.safe_load(text)
        assert _human_only(t["id"] for t in config["tools"]) == [], workflow


# --- the doors a tool call goes through ----------------------------------------


class _AlwaysApproved:
    """A queue in which every checkpoint for every call was approved."""

    def __init__(self):
        self.asked = []

    def list_actions(self, status=None, workflow_run_id=None, **_):
        self.asked.append(workflow_run_id)
        from types import SimpleNamespace

        return [
            SimpleNamespace(
                title="t",
                description="t",
                parameters={
                    "checkpoint_id": "apr-1",
                    "tool": name,
                    "args_sha256": args_digest({"action_id": "a"}),
                },
            )
            for name in DECISION_NAMES
        ]


@pytest.fixture
def invoke_client(monkeypatch):
    monkeypatch.setattr(internal_auth, "get_secret", lambda name: "shhh")
    ran: List[str] = []

    async def backend(name, args, **kwargs):
        ran.append(name)
        return {"ok": True}, True

    async def mcp(name, args, timeout_s, registry):
        ran.append(name)
        return [], True

    monkeypatch.setattr(tools_router, "execute_backend_tool", backend)
    monkeypatch.setattr(tools_router, "execute_mcp_tool", mcp)
    app = FastAPI()
    app.state.mcp_registry = MCPRegistry()
    app.state.approvals = _AlwaysApproved()
    app.include_router(tools_router.router, prefix=tools_router.ROUTER_META.prefix)
    return TestClient(app), ran


@pytest.mark.parametrize("approval", [None, {"run_id": "r", "checkpoint_id": "apr-1"}])
def test_invoke_refuses_every_decision_approved_or_not(invoke_client, approval):
    client, ran = invoke_client
    names = sorted(
        {n for n, e in tool_effects.TOOL_EFFECTS.items() if e in HUMAN_ONLY}
        | set(DECISION_NAMES)
    )
    reached = []
    for name in names:
        ran.clear()
        body = {
            "tool": name,
            "args": {"action_id": "a"},
            "bounds": {"max_rows": 5, "timeout_ms": 1000},
        }
        if approval is not None:
            body["approval"] = approval
        answer = client.post(
            "/internal/tools/invoke",
            json=body,
            headers={"Authorization": "Bearer shhh"},
        ).json()
        if answer.get("ok") or ran or answer["failure"]["kind"] != "refused":
            reached.append(name)
    assert reached == []


@pytest.mark.parametrize("name", DECISION_NAMES)
def test_the_mcp_executor_refuses_every_decision_even_cleared(name):
    import asyncio

    class _Registry:
        def get_active_servers(self):
            return ["acme"]

        def get_tool_names(self):
            return [name]

    with approved_call(name):
        with pytest.raises(MCPFailure) as refused:
            asyncio.run(execute_mcp_tool(name, {}, 1.0, _Registry()))
    assert refused.value.kind == "refused"


def test_the_agent_layer_drops_decisions_and_calls_no_approvals_route():
    stream = (REPO / "services/agent/core/stream.ts").read_text(encoding="utf-8")
    assert ".filter((tool) => !isHumanOnly(tool))" in stream
    offenders = []
    for path in sorted((REPO / "services/agent").rglob("*.ts")):
        relative = path.relative_to(REPO).as_posix()
        if "/node_modules/" in f"/{relative}" or "/tests/" in f"/{relative}":
            continue
        text = path.read_text(encoding="utf-8")
        if "approve_action" in text and not relative.endswith(
            "contracts/tool-effects.ts"
        ):
            offenders.append(relative)
        if "/approvals/" in text:
            offenders.append(relative)
    assert offenders == []


# --- who may decide, in the Python tree ----------------------------------------

# Every caller of a decision, and why it may. Approval only from a person's own
# HTTP request; a rejection also when a run ended or the queue aged a row out,
# which only ever holds an action back.
DECIDERS: Dict[str, Set[str]] = {
    # POST /api/v1/approvals/{id}/approve|reject: the signed-in user, CSRF-checked.
    "core/api/v1/approvals_router.py": {"approve_action", "reject_action"},
    # POST /api/workflows/runs/{id}/resume|cancel: the signed-in user, CSRF-checked.
    "core/workflows/workflows_router.py": {"approve_action", "reject_action"},
    # withdraw_for_run / expire_stale: reject only, attributed "agent"/"system".
    "core/response/checkpoints.py": {"reject_action"},
}

# Run directives answer hunt checkpoints (approve / reject a hypothesis, a
# verdict, a scope extension); only a person's HTTP request enqueues one.
DIRECTIVE_SENDERS: Dict[str, str] = {
    "core/api/v1/agent_runs_router.py": "POST /api/v1/agent-runs/{id}/directives",
    "core/workflows/run_cancel.py": "abort only, from the cancel route",
}


def _python_sources() -> List[Path]:
    found = []
    for top in ("core", "services", "tools"):
        for path in (REPO / top).rglob("*.py"):
            relative = path.relative_to(REPO).as_posix()
            parts = set(relative.split("/"))
            if parts & {"tests", "node_modules", "__pycache__", "venv"}:
                continue
            found.append(path)
    return sorted(found)


def _called(path: Path, names: Set[str]) -> Set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            called = getattr(func, "attr", None) or getattr(func, "id", None)
            if called in names:
                hits.add(called)
    return hits


def test_only_person_facing_routes_decide_an_approval():
    found: Dict[str, Set[str]] = {}
    for path in _python_sources():
        relative = path.relative_to(REPO).as_posix()
        if relative == "core/response/approval_service.py":
            continue  # the definitions
        hits = _called(path, {"approve_action", "reject_action"})
        if hits:
            found[relative] = hits
    assert found == DECIDERS


def test_only_person_facing_routes_send_directives():
    found = {
        path.relative_to(REPO).as_posix()
        for path in _python_sources()
        if path.name != "directives.py" and _called(path, {"enqueue_directive"})
    }
    assert found == set(DIRECTIVE_SENDERS)


def _route(router, path: str, method: str = "POST"):
    for route in router.routes:
        if getattr(route, "path", None) == path and method in route.methods:
            return route
    raise AssertionError(f"no {method} {path}")


def _dependency_names(dependant) -> Set[str]:
    names = set()
    for sub in dependant.dependencies:
        if sub.call is not None:
            names.add(getattr(sub.call, "__name__", repr(sub.call)))
        names |= _dependency_names(sub)
    return names


@pytest.mark.parametrize(
    "module, path",
    [
        ("core.api.v1.approvals_router", "/approvals/{action_id}/approve"),
        ("core.api.v1.approvals_router", "/approvals/{action_id}/reject"),
        ("core.workflows.workflows_router", "/workflows/runs/{run_id}/resume"),
        ("core.workflows.workflows_router", "/workflows/runs/{run_id}/cancel"),
    ],
)
def test_a_decision_route_is_a_signed_in_persons_csrf_checked_request(module, path):
    import importlib

    from services.api.middleware.csrf import _ALWAYS_EXEMPT

    loaded = importlib.import_module(module)
    route = _route(loaded.router, path)
    assert "get_current_user" in _dependency_names(route.dependant)
    prefixes = [loaded.ROUTER_META.prefix, *loaded.ROUTER_META.legacy_prefixes]
    for prefix in prefixes:
        full = f"{prefix}{path}"
        assert not any(full.startswith(exempt) for exempt in _ALWAYS_EXEMPT), full
