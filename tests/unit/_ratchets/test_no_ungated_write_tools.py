"""Ratchet (W1.7): no tool that changes the world runs without a person.

Enumerates every tool on every surface -- the built-ins, AutoSecOps's own MCP
server (what ``/mcp`` serves), every in-repo integration ``tool.py``, the
agents' recommended tools, the agent layer's local tools, and the catalog a
compose / investigate / hunt / root-cause run is resolved against -- and holds:

* every in-repo tool has an explicit class in ``core.llm.tool_effects``
  (never the name heuristic), and the table names no tool that does not exist;
* the TypeScript mirror of that table is current;
* on each surface the number of gated (write / destructive) tools reachable
  without the approval pipeline is **zero**:

  - chat declares none and resolves none through ``call_integration_tool``;
  - ``/mcp`` serves none;
  - compose / investigate put every gated grant on ``config.approvals``, so the
    agent layer parks the call for a person;
  - hunts and root-cause traces bind none;
  - ``/internal/tools/invoke`` refuses every one that arrives without an
    approved checkpoint, before any executor runs;
  - no agent is labelled ``on_its_own``.

Loosening any of these is a deliberate edit to this file.
"""

from __future__ import annotations

import ast
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Set

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.agents import internal_auth, tools_router
from core.agents.builtins import BUILTIN_AGENTS
from core.agents.integration_tools import resolve_integration_call
from core.agents.mcp_tools import MCPFailure
from core.integrations.mcp import in_process
from core.integrations.mcp.registry import MCPRegistry
from core.llm import tool_effects
from core.llm.chat_layers import (
    changes_for_tool,
    changes_for_tools,
    chat_config,
    integration_tools,
)
from core.llm.tool_effects import GATED, MANIFEST_SOURCE, classify, is_gated
from core.llm.tool_schemas import ALL_TOOLS, INTEGRATION_TOOLS
from core.workflows import playbook_resolver
from core.workflows.playbook_resolver import (
    CAPABILITIES,
    resolve,
    resolve_hunt,
    resolve_root_cause,
)
from core.workflows.workflows_service import WorkflowDefinition

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]


# --- enumeration -------------------------------------------------------------


def builtin_tools() -> Set[str]:
    return {t["name"] for t in (*ALL_TOOLS, *INTEGRATION_TOOLS) if t.get("name")}


def vigil_mcp_tools() -> Set[str]:
    """What /mcp serves, read off the live server object."""
    return {t["name"] for t in in_process.list_tools()}


def _tool_py_names(path: Path) -> Set[str]:
    names: Set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        called = getattr(func, "attr", None) or getattr(func, "id", None)
        if called != "Tool":
            continue
        for keyword in node.keywords:
            if keyword.arg == "name" and isinstance(keyword.value, ast.Constant):
                names.add(str(keyword.value.value))
    return names


def integration_tools_by_server() -> Dict[str, Set[str]]:
    """Every in-repo ``tool.py``, under the server name mcp-config.json gives it."""
    servers = json.loads((REPO / "mcp-config.json").read_text())["mcpServers"]
    by_path = {}
    for server, entry in servers.items():
        if not isinstance(entry, dict):
            continue
        for arg in entry.get("args") or []:
            if str(arg).endswith("/tool.py"):
                by_path[str(arg)] = server
    found: Dict[str, Set[str]] = {}
    for path in sorted((REPO / "core" / "integrations").glob("*/tool.py")):
        relative = str(path.relative_to(REPO))
        assert (
            relative in by_path
        ), f"{relative} is not served by any mcp-config.json entry"
        found[by_path[relative]] = _tool_py_names(path)
    return found


def flattened_integration_tools() -> Set[str]:
    return {
        f"{server}_{name}"
        for server, names in integration_tools_by_server().items()
        for name in names
    }


def local_tools() -> Set[str]:
    python_side = {
        playbook_resolver._record_tool()["id"],
        playbook_resolver._finish_tool()["id"],
        playbook_resolver._expand_tool()["id"],
    }
    tally = (REPO / "services/agent/workflows/tally/tool.ts").read_text()
    return python_side | {"bump"} if 'id: "bump"' in tally else python_side


def agent_tools() -> Set[str]:
    held: Set[str] = set()
    for row in BUILTIN_AGENTS:
        tools = (
            row.get("recommended_tools")
            if isinstance(row, dict)
            else getattr(row, "recommended_tools", ())
        )
        held |= set(tools or ())
    return held


def full_registry() -> MCPRegistry:
    """A registry carrying every in-repo server and AutoSecOps's own tools."""
    registry = MCPRegistry()
    for server, names in integration_tools_by_server().items():
        registry.register_server(
            server,
            {},
            [
                {
                    "name": name,
                    "description": f"{server} {name}",
                    "input_schema": {"type": "object"},
                }
                for name in sorted(names)
            ],
        )
    in_process.register(registry)
    return registry


def catalogue_names(registry: MCPRegistry) -> List[str]:
    return sorted(playbook_resolver._tool_catalogue(registry))


class _Workflows:
    def __init__(self, tools: List[str], run_kind: str = "compose"):
        self._def = WorkflowDefinition(
            workflow_id="everything",
            file_path=None,
            metadata={
                "name": "every tool",
                "description": "d",
                "use_case": "",
                "trigger_examples": [],
                "run_kind": run_kind,
                "phases": [
                    {
                        "id": "act",
                        "agent": "auto_responder",
                        "name": "Act",
                        "tools": tools,
                        "instructions": "act",
                    }
                ],
            },
            body="",
            source="custom",
        )

    def get_workflow(self, _id):
        return self._def


@pytest.fixture
def no_disabled_agents(monkeypatch):
    monkeypatch.setattr(playbook_resolver, "disabled_agent_ids", lambda: set())


# --- the table covers what exists, and only that -----------------------------


def test_every_builtin_is_in_the_table_and_the_table_lists_no_other():
    assert set(tool_effects.BUILTIN) == builtin_tools()


def test_every_mcp_surface_tool_is_in_the_table_and_the_table_lists_no_other():
    assert set(tool_effects.VIGIL_MCP) == vigil_mcp_tools()


def test_every_integration_tool_is_in_the_table_and_the_table_lists_no_other():
    declared = {
        server: set(tools) for server, tools in tool_effects.INTEGRATIONS.items()
    }
    assert declared == integration_tools_by_server()


def test_every_local_tool_is_in_the_table():
    assert local_tools() <= set(tool_effects.LOCAL)


@pytest.mark.parametrize(
    "name",
    sorted(
        builtin_tools()
        | vigil_mcp_tools()
        | flattened_integration_tools()
        | {n for names in integration_tools_by_server().values() for n in names}
        | local_tools()
    ),
)
def test_an_in_repo_tool_is_classified_by_the_table_not_by_its_name(name):
    assert classify(name).source == MANIFEST_SOURCE


def test_every_capability_candidate_is_classified_by_the_table():
    names = {n for c in CAPABILITIES for n in playbook_resolver._candidate_names(c)}
    assert {n for n in names if classify(n).source != MANIFEST_SOURCE} == set()


def test_the_typescript_mirror_is_current():
    assert (
        tool_effects.MIRROR_PATH.read_text(encoding="utf-8")
        == tool_effects.render_mirror()
    ), "run: python -m core.llm.tool_effects --write"


# --- surface by surface: zero ungated ----------------------------------------


def _ungated_in_chat(registry: MCPRegistry) -> List[str]:
    reachable = registry.get_all_tools()
    config = yaml.safe_load(chat_config("m", mcp_tools=reachable))
    declared = [t["id"] for t in config["tools"]]
    found = [t for t in declared if is_gated(t)]
    found += [t["name"] for t in integration_tools(reachable) if is_gated(t["name"])]
    for name in [t["name"] for t in reachable if is_gated(t["name"])]:
        try:
            resolve_integration_call(registry, {"name": name, "arguments": {}})
        except MCPFailure:
            continue
        found.append(name)
    return found


def test_chat_reaches_no_gated_tool(monkeypatch):
    registry = full_registry()
    monkeypatch.setattr(
        "core.integrations.mcp.registry.refresh_from_client", lambda registry: 0
    )
    assert _ungated_in_chat(registry) == []


def test_mcp_surface_serves_no_gated_tool():
    # /mcp has no approval-resume path: a gated tool there would be ungated.
    assert [t for t in vigil_mcp_tools() if is_gated(t)] == []


def _compose_config(registry: MCPRegistry, run_kind: str = "compose"):
    tools = catalogue_names(registry)
    _, config = resolve(
        "everything", workflows=_Workflows(tools, run_kind), registry=registry
    )
    return yaml.safe_load(config)


def _ungated_in_compose(config) -> List[str]:
    approvals = set(config["approvals"])
    return [
        t["id"]
        for t in config["tools"]
        if is_gated(t["id"]) and t["id"] not in approvals
    ]


def test_compose_puts_every_gated_grant_on_approvals(no_disabled_agents):
    config = _compose_config(full_registry())
    gated = [t["id"] for t in config["tools"] if is_gated(t["id"])]
    # A vacuous pass is the one way this fails silently.
    assert {
        "microsoft-defender_mde_isolate",
        "carbon-black_cb_quarantine",
        "azure-ad_aad_disable_user",
        "palo-alto_pan_block_ip",
        "cloudflare_cf_waf_block_ip",
    } <= set(gated)
    assert _ungated_in_compose(config) == []
    for tool in config["tools"]:
        assert tool["effect"] == classify(tool["id"]).effect, tool["id"]


def test_investigate_puts_every_gated_grant_on_approvals(no_disabled_agents):
    config = _compose_config(full_registry(), run_kind="investigate")
    assert _ungated_in_compose(config) == []


def test_hunts_and_traces_bind_no_gated_tool(no_disabled_agents):
    registry = full_registry()
    for resolver in (resolve_hunt, resolve_root_cause):
        _, text = resolver(
            "threat-hunt" if resolver is resolve_hunt else "root-cause-analysis",
            registry=registry,
        )
        config = yaml.safe_load(text)
        assert [t["id"] for t in config["tools"] if is_gated(t["id"])] == []


@pytest.fixture
def invoke_client(monkeypatch):
    monkeypatch.setattr(internal_auth, "get_secret", lambda name: "shhh")
    ran: List[str] = []

    async def backend(name, args, **kwargs):
        ran.append(name)
        return [], True

    async def mcp(name, args, timeout_s, registry):
        ran.append(name)
        return [], True

    monkeypatch.setattr(tools_router, "execute_backend_tool", backend)
    monkeypatch.setattr(tools_router, "execute_mcp_tool", mcp)
    app = FastAPI()
    app.state.mcp_registry = MCPRegistry()
    app.include_router(tools_router.router, prefix=tools_router.ROUTER_META.prefix)
    return TestClient(app), ran


def _all_gated_names() -> List[str]:
    return sorted(
        {name for name, effect in tool_effects.TOOL_EFFECTS.items() if effect in GATED}
        | {"acme-edr_isolate_host", "okta_suspend_user", "acme_frobnicate"}
    )


def _ungated_at_invoke(client, ran) -> List[str]:
    found = []
    for name in _all_gated_names():
        ran.clear()
        body = client.post(
            "/internal/tools/invoke",
            json={
                "tool": name,
                "args": {},
                "bounds": {"max_rows": 5, "timeout_ms": 1000},
            },
            headers={"Authorization": "Bearer shhh"},
        ).json()
        if body.get("ok") or ran or body["failure"]["kind"] != "refused":
            found.append(name)
    return found


def test_invoke_refuses_every_gated_tool_without_an_approval(invoke_client):
    client, ran = invoke_client
    assert _ungated_at_invoke(client, ran) == []


def test_no_agent_acts_on_its_own():
    names = agent_tools() | set(tool_effects.TOOL_EFFECTS)
    assert [n for n in sorted(names) if changes_for_tool(n) == "on_its_own"] == []
    assert changes_for_tools(sorted(names)) != "on_its_own"


# --- the count ---------------------------------------------------------------


def inventory() -> Dict[str, Counter]:
    """Effect classes per surface, for the record."""
    registry = full_registry()
    surfaces = {
        "builtin": builtin_tools(),
        "mcp_surface": vigil_mcp_tools(),
        "integration_tool_py": {
            n for names in integration_tools_by_server().values() for n in names
        },
        "agent_recommended": agent_tools(),
        "agent_layer_local": local_tools(),
        "compose_catalog": set(catalogue_names(registry)),
    }
    return {
        surface: Counter(classify(name).effect for name in names)
        for surface, names in surfaces.items()
    }


def test_the_count_of_ungated_write_tools_is_zero(
    no_disabled_agents, invoke_client, monkeypatch
):
    monkeypatch.setattr(
        "core.integrations.mcp.registry.refresh_from_client", lambda registry: 0
    )
    registry = full_registry()
    client, ran = invoke_client
    ungated = {
        "chat": _ungated_in_chat(registry),
        "mcp_surface": [t for t in vigil_mcp_tools() if is_gated(t)],
        "compose": _ungated_in_compose(_compose_config(registry)),
        "investigate": _ungated_in_compose(_compose_config(registry, "investigate")),
        "internal_invoke": _ungated_at_invoke(client, ran),
        "agents": [
            n for n in sorted(agent_tools()) if changes_for_tool(n) == "on_its_own"
        ],
    }
    print("\ntool effect inventory:")
    for surface, counts in inventory().items():
        print(f"  {surface}: {dict(sorted(counts.items()))}")
    counts = {surface: len(names) for surface, names in ungated.items()}
    print(f"  ungated: {counts}")
    assert sum(len(v) for v in ungated.values()) == 0, ungated
