"""Compose approvals: ART execute is gated; incident-response is not (#837)."""

from __future__ import annotations

from typing import List

import pytest
import yaml

from core.integrations.atomic_red_team.descriptor import (
    EXECUTE_TOOL,
    MCP_EXECUTE_TOOL,
)
from core.workflows.playbook_resolver import resolve, resolve_hunt
from core.workflows.workflows_service import WorkflowDefinition

pytestmark = pytest.mark.unit


class _Registry:
    def __init__(self, *names: str):
        self._names = names

    def get_all_tools(self):
        return [
            {
                "name": name,
                "description": f"stub {name}",
                "input_schema": {"type": "object"},
            }
            for name in self._names
        ]


class _Workflows:
    def __init__(self, tools: List[str]):
        self._def = WorkflowDefinition(
            workflow_id="art-grant",
            file_path=None,
            metadata={
                "name": "ART grant",
                "description": "d",
                "use_case": "",
                "trigger_examples": [],
                "phases": [
                    {
                        "id": "assess",
                        "agent": "mitre_analyst",
                        "name": "Assess",
                        "tools": tools,
                        "instructions": "assess coverage then execute",
                    }
                ],
            },
            body="",
            source="custom",
        )

    def get_workflow(self, _id):
        return self._def


def _config(tools: List[str], *catalogue: str):
    _, config = resolve(
        "art-grant",
        workflows=_Workflows(tools),
        registry=_Registry(*catalogue),
    )
    return yaml.safe_load(config)


@pytest.mark.parametrize("execute_id", [EXECUTE_TOOL, MCP_EXECUTE_TOOL])
def test_compose_phase_that_grants_execute_puts_it_in_approvals(execute_id):
    config = _config([execute_id, "analyze_coverage"], execute_id)
    ids = [tool["id"] for tool in config["tools"]]
    assert execute_id in ids
    assert "analyze_coverage" in ids
    assert config["approvals"] == [execute_id]


def test_incident_response_stays_ungated():
    _, config = resolve("incident-response")
    assert yaml.safe_load(config)["approvals"] == []


def test_hunt_stays_ungated():
    _, config = resolve_hunt("threat-hunt")
    assert yaml.safe_load(config)["approvals"] == []


# W1.7: every gated grant parks, not only ART execute.
@pytest.mark.parametrize(
    "tool",
    [
        "microsoft-defender_mde_isolate",
        "carbon-black_cb_quarantine",
        "azure-ad_aad_disable_user",
        "palo-alto_pan_block_ip",
        "cloudflare_cf_waf_block_ip",
        "slack_slack_send_alert",
    ],
)
def test_compose_phase_that_grants_a_write_tool_puts_it_in_approvals(tool):
    config = _config([tool, "analyze_coverage"], tool)
    assert config["approvals"] == [tool]
    effects = {t["id"]: t["effect"] for t in config["tools"]}
    assert effects["analyze_coverage"] == "read_only"
    assert effects[tool] in ("write", "destructive")


def test_a_capability_never_binds_a_gated_candidate(monkeypatch):
    from core.workflows import playbook_resolver
    from core.workflows.playbook_resolver import Candidate, _bound_capabilities

    monkeypatch.setitem(
        playbook_resolver.CAPABILITIES,
        "findings_search",
        (Candidate(None, ("pan_block_ip", "search_findings")),),
    )
    catalogue = {
        name: {"name": name, "description": name, "input_schema": {}}
        for name in ("pan_block_ip", "search_findings")
    }
    bound = _bound_capabilities(["findings_search"], catalogue)
    assert [tool["id"] for tool in bound] == ["search_findings"]
