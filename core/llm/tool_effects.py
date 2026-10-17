"""What every tool does to the world: the one table every surface reads.

Each tool AutoSecOps can reach is declared here with an **effect class**:

``read_only``
    Reads and answers. Nothing anywhere changes.
``records``
    Writes AutoSecOps's own records only (cases, notes, IOCs, an export file,
    a run's own trace). Reversible bookkeeping inside this product; never an
    outside change. Never inferred from a name: only a tool listed here is one.
``approval``
    Puts a request in the approval queue (``create_approval_action``). This is
    the gate itself: it changes nothing but the queue, and a person releases it.
``decision``
    Decides a queued approval (approve / reject). **Human-only** (W1.7b): no
    model-facing surface -- chat, compose, investigate, hunt, root-cause, the
    ``/mcp`` server, ``/internal/tools/invoke`` -- declares, resolves or runs
    one. A decision is made only by a person's own authenticated, CSRF-checked
    HTTP request (``/api/v1/approvals/{id}/approve|reject``, the run resume /
    cancel routes). A model is not a second person: alert text, case notes and
    tool output reach its context, so a decision it could make is a decision a
    prompt injection could make under the signed-in person's name.
``write``
    Changes or sends something outside AutoSecOps (posts a message, submits a
    sample to a sandbox). Gated.
``destructive``
    Containment or an irreversible outside action (isolate a host, block an IP,
    disable a user, run an attack technique). Gated.

``write`` and ``destructive`` are :data:`GATED`: such a tool runs only through
the approval pipeline -- a checkpoint a person answers -- on every surface.
Chat has no resume path, so it never reaches one; compose / investigate park on
it (``config.approvals``); ``/internal/tools/invoke`` refuses it without an
approved checkpoint; hunts and root-cause bind read capabilities only.

A name that is not in the table falls back to a verb heuristic which defaults
to the most restrictive class: a name carrying a decision verb (approve,
reject, ...) is ``decision`` and so human-only; only a name that plainly reads
(a read lead verb and no write or destructive verb) is ``read_only``; anything
else is ``destructive``.

The agent layer (TypeScript) reads the same table through a generated mirror,
``services/agent/contracts/tool-effects.ts``; a ratchet holds the two equal.
Regenerate with ``python -m core.llm.tool_effects --write``.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Tuple

READ_ONLY = "read_only"
RECORDS = "records"
APPROVAL = "approval"
DECISION = "decision"
WRITE = "write"
DESTRUCTIVE = "destructive"

EFFECTS: Tuple[str, ...] = (READ_ONLY, RECORDS, APPROVAL, DECISION, WRITE, DESTRUCTIVE)

# Runs only once a person approves it, on every surface.
GATED = frozenset({WRITE, DESTRUCTIVE})

# Never reachable from a model's tool list, on any surface, approved or not.
HUMAN_ONLY = frozenset({DECISION})

MANIFEST_SOURCE = "manifest"
HEURISTIC_SOURCE = "heuristic"


@dataclass(frozen=True)
class Effect:
    """A tool's class and where it came from (the table, or the fallback)."""

    effect: str
    source: str

    @property
    def gated(self) -> bool:
        return self.effect in GATED


# --- the table --------------------------------------------------------------

# Built-in backend tools (core.llm.tool_schemas.ALL_TOOLS) and chat's two
# integration tools. ``call_integration_tool`` is a proxy: /internal/tools/invoke
# classifies the call it stands for, and chat only resolves read-class ones.
BUILTIN: Dict[str, str] = {
    "analyze_coverage": READ_ONLY,
    "search_detections": READ_ONLY,
    "identify_gaps": READ_ONLY,
    "get_coverage_stats": READ_ONLY,
    "get_detection_count": READ_ONLY,
    "lint_detections": READ_ONLY,
    "check_detection_candidate": READ_ONLY,
    "reconstruct_run": READ_ONLY,
    "list_findings": READ_ONLY,
    "search_findings": READ_ONLY,
    "get_findings_stats": READ_ONLY,
    "get_finding": READ_ONLY,
    "list_cases": READ_ONLY,
    "get_case": READ_ONLY,
    "case_records": READ_ONLY,
    "create_case": RECORDS,
    "add_finding_to_case": RECORDS,
    "update_case": RECORDS,
    "add_resolution_step": RECORDS,
    "list_completed_hunts": READ_ONLY,
    "list_learning_episodes": READ_ONLY,
    "export_learning_episodes": RECORDS,
    "replay_hunt": READ_ONLY,
    "get_technique_rollup": READ_ONLY,
    "lookup_indicators": READ_ONLY,
    "propose_feed_hunts": READ_ONLY,
    "list_pending_approvals": READ_ONLY,
    "get_approval_action": READ_ONLY,
    "get_approval_stats": READ_ONLY,
    "recall_entity": READ_ONLY,
    "check_hunt_coverage": READ_ONLY,
    "read_skill": READ_ONLY,
    "find_integration_tools": READ_ONLY,
    "call_integration_tool": READ_ONLY,
}

# AutoSecOps's own MCP server (tools/mcp/vigil.py): what /mcp serves, and what
# the registry carries unprefixed.
VIGIL_MCP: Dict[str, str] = {
    "list_findings": READ_ONLY,
    "get_finding": READ_ONLY,
    "list_completed_hunts": READ_ONLY,
    "replay_hunt": READ_ONLY,
    "get_technique_rollup": READ_ONLY,
    "list_cases": READ_ONLY,
    "get_case": READ_ONLY,
    "create_case": RECORDS,
    "update_case": RECORDS,
    "add_finding_to_case": RECORDS,
    "remove_finding_from_case": RECORDS,
    "add_case_activity": RECORDS,
    "add_case_timeline_entry": RECORDS,
    "add_case_mitre_techniques": RECORDS,
    "add_resolution_step": RECORDS,
    "bulk_add_findings_to_case": RECORDS,
    "create_case_from_killchain": RECORDS,
    "add_case_comment": RECORDS,
    "get_case_comments": READ_ONLY,
    "add_case_evidence": RECORDS,
    "add_case_ioc": RECORDS,
    "bulk_add_iocs": RECORDS,
    "get_case_iocs": READ_ONLY,
    "add_case_task": RECORDS,
    "update_case_task": RECORDS,
    "get_case_tasks": READ_ONLY,
    "link_related_cases": RECORDS,
    "escalate_case": RECORDS,
    "close_case": RECORDS,
    "create_approval_action": APPROVAL,
    "list_approval_actions": READ_ONLY,
    "get_approval_action": READ_ONLY,
}

# Decisions on the approval queue. No tool body implements these any more
# (W1.7b): they are the names a model-facing surface once carried, held here so
# a server that still offers one -- an old AutoSecOps, a copy of its MCP server
# -- is classified human-only by the table rather than by its name.
HUMAN_ONLY_TOOLS: Dict[str, str] = {
    "approve_action": DECISION,
    "reject_action": DECISION,
}

# The in-repo integration servers (core/integrations/<vendor>/tool.py), by the
# server name mcp-config.json gives them. The registry flattens a tool to
# ``{server}_{tool}``, so both spellings are classified.
INTEGRATIONS: Dict[str, Dict[str, str]] = {
    "alienvault-otx": {
        "otx_check_ip": READ_ONLY,
        "otx_check_domain": READ_ONLY,
        "otx_check_hash": READ_ONLY,
    },
    "anyrun": {
        "anyrun_get_report": READ_ONLY,
        "anyrun_search_hash": READ_ONLY,
    },
    "atomic-red-team": {
        # Runs an attack technique on a host.
        "atomic_red_team_execute": DESTRUCTIVE,
    },
    "azure-ad": {
        "aad_get_user": READ_ONLY,
        "aad_disable_user": DESTRUCTIVE,
        "aad_get_sign_ins": READ_ONLY,
    },
    "cape-sandbox": {
        # A submission hands a sample to a third party and detonates it.
        "cape_submit_file": WRITE,
        "cape_submit_url": WRITE,
        "cape_get_report": READ_ONLY,
        "cape_get_iocs": READ_ONLY,
        "cape_get_pcap": READ_ONLY,
        "cape_list_tasks": READ_ONLY,
        "cape_search_hash": READ_ONLY,
        "cape_task_status": READ_ONLY,
    },
    "carbon-black": {
        "cb_get_alerts": READ_ONLY,
        "cb_search_device": READ_ONLY,
        "cb_quarantine": DESTRUCTIVE,
    },
    "cloudflare": {
        "cf_waf_block_ip": DESTRUCTIVE,
        # Lifting a block is as much a change to the edge as placing one.
        "cf_waf_unblock_ip": DESTRUCTIVE,
        "cf_gateway_block_domain": DESTRUCTIVE,
        "cf_access_revoke_session": DESTRUCTIVE,
        "cf_lookup_ip_threat": READ_ONLY,
        "cf_lookup_domain_threat": READ_ONLY,
    },
    "elastic": {
        "elastic_search_logs": READ_ONLY,
        "elastic_search_by_ioc": READ_ONLY,
        "elastic_get_indices": READ_ONLY,
        "elastic_get_detection_alerts": READ_ONLY,
    },
    "hybrid-analysis": {
        "ha_search_hash": READ_ONLY,
        "ha_get_report": READ_ONLY,
    },
    "ip-geolocation": {
        "geolocate_ip": READ_ONLY,
        "geolocate_batch": READ_ONLY,
    },
    "microsoft-defender": {
        "mde_get_alerts": READ_ONLY,
        "mde_get_machine": READ_ONLY,
        "mde_isolate": DESTRUCTIVE,
    },
    "microsoft-teams": {
        "teams_send_alert": WRITE,
    },
    "misp": {
        "misp_search_ioc": READ_ONLY,
        "misp_get_events": READ_ONLY,
    },
    "opensearch": {
        "opensearch_search_logs": READ_ONLY,
        "opensearch_search_by_ioc": READ_ONLY,
        "opensearch_get_indices": READ_ONLY,
        "opensearch_get_findings": READ_ONLY,
    },
    "qradar": {
        "qradar_list_offenses": READ_ONLY,
        "qradar_get_offense": READ_ONLY,
    },
    "palo-alto": {
        "pan_block_ip": DESTRUCTIVE,
        "pan_get_threats": READ_ONLY,
    },
    "slack": {
        "slack_send_alert": WRITE,
    },
    "splunk-selfhosted": {
        "splunk_generate_spl": READ_ONLY,
        # A search, bound as telemetry_search.
        "splunk_execute": READ_ONLY,
        "splunk_search_ip": READ_ONLY,
        "splunk_search_host": READ_ONLY,
        "splunk_nl_search": READ_ONLY,
    },
    "url-analysis": {
        "analyze_url": READ_ONLY,
        "extract_iocs": READ_ONLY,
    },
    "vstrike": {
        "vstrike_get_asset_topology": READ_ONLY,
        "vstrike_list_adjacent_assets": READ_ONLY,
        "vstrike_get_blast_radius": READ_ONLY,
        "vstrike_get_segment_findings": READ_ONLY,
        "vstrike_node_search": READ_ONLY,
        "vstrike_node_drift_get": READ_ONLY,
        "vstrike_storyline_list": READ_ONLY,
        "vstrike_storyline_events_get": READ_ONLY,
        "vstrike_legend_run_list": READ_ONLY,
        "vstrike_legend_run_results_get": READ_ONLY,
        "vstrike_network_graph_get": READ_ONLY,
        # View state of the operator's own embedded console, nothing upstream.
        "vstrike_ui_legend_apply": READ_ONLY,
        "vstrike_ui_rightpanel_focus": READ_ONLY,
    },
}

# Third-party servers a capability binds to (playbook_resolver.CAPABILITIES),
# by the flattened name the registry reports. Unverifiable from this repo, so
# only the search and lookup tools a read capability prefers are listed.
THIRD_PARTY: Dict[str, str] = {
    "splunk_run_splunk_search": READ_ONLY,
    "splunk_search": READ_ONLY,
    "splunk_oneshot_search": READ_ONLY,
    "azure-sentinel_query": READ_ONLY,
    "azure-sentinel_run_query": READ_ONLY,
    "azure-sentinel_search": READ_ONLY,
    "gcp-secops_search_security_events": READ_ONLY,
    "gcp-secops_search": READ_ONLY,
    "crowdstrike_falcon_search_detects": READ_ONLY,
    "crowdstrike_query": READ_ONLY,
    "crowdstrike_search": READ_ONLY,
    "virustotal_get_ip_report": READ_ONLY,
    "virustotal_get_domain_report": READ_ONLY,
}

# Tools the agent layer answers in its own process. A run's own trace is its
# record; expand only rewrites the hunt's own scope.
LOCAL: Dict[str, str] = {
    "expand": READ_ONLY,
    "record": RECORDS,
    "finish": RECORDS,
    # The tally workflow's counter: in-memory, per run.
    "bump": READ_ONLY,
}


def _flatten(server: str, tool: str) -> str:
    return f"{server}_{tool}"


def _build() -> Dict[str, str]:
    table: Dict[str, str] = {}

    def put(name: str, effect: str) -> None:
        if effect not in EFFECTS:
            raise ValueError(f"{name}: unknown effect {effect!r}")
        held = table.get(name)
        if held is not None and held != effect:
            raise ValueError(f"{name} is declared both {held} and {effect}")
        table[name] = effect

    for source in (BUILTIN, VIGIL_MCP, HUMAN_ONLY_TOOLS, THIRD_PARTY, LOCAL):
        for name, effect in source.items():
            put(name, effect)
    for server, tools in INTEGRATIONS.items():
        for name, effect in tools.items():
            put(name, effect)
            put(_flatten(server, name), effect)
    # splunk backs two servers (descriptor mcp_server_names): the same tool.py
    # answers under either name.
    for name, effect in INTEGRATIONS["splunk-selfhosted"].items():
        put(_flatten("splunk", name), effect)
    return table


TOOL_EFFECTS: Mapping[str, str] = _build()


# --- the fallback -----------------------------------------------------------

# Verbs that decide something a person is meant to decide. Checked before every
# other verb: a name that approves anything is human-only, whatever else it does.
DECISION_VERBS = frozenset(
    {
        "approve",
        "reject",
        "decline",
        "authorize",
        "authorise",
    }
)

# Direct-action verbs: calling one changes the world and a later read cannot
# undo it.
DESTRUCTIVE_VERBS = frozenset(
    {
        "isolate",
        "unisolate",
        "contain",
        "quarantine",
        "block",
        "unblock",
        "kill",
        "terminate",
        "shutdown",
        "disable",
        "deactivate",
        "suspend",
        "delete",
        "remove",
        "purge",
        "wipe",
        "revoke",
        "ban",
        "remediate",
        "detonate",
        "reset",
        "release",
    }
)

# Verbs that change or send something without destroying it.
WRITE_VERBS = frozenset(
    {
        "create",
        "update",
        "set",
        "add",
        "send",
        "post",
        "put",
        "patch",
        "write",
        "submit",
        "upload",
        "run",
        "execute",
        "exec",
        "start",
        "stop",
        "restart",
        "trigger",
        "invoke",
        "assign",
        "apply",
        "push",
        "merge",
        "modify",
        "edit",
        "enable",
        "notify",
        "rename",
        "restore",
        "rollback",
        "escalate",
        "install",
        "deploy",
        # Move data out of or into the tenant: not a read, whatever follows.
        "export",
        "import",
        "share",
        "transfer",
        "copy",
        "move",
        "forward",
    }
)

# Lead verbs that only read.
READ_VERBS = frozenset(
    {
        "get",
        "list",
        "search",
        "describe",
        "fetch",
        "query",
        "show",
        "read",
        "lookup",
        "count",
        "stats",
        "status",
        "check",
        "find",
        "analyze",
        "identify",
        "lint",
        "validate",
        "explain",
        "summarize",
        "inspect",
        "view",
        "extract",
        "geolocate",
        "enrich",
        "retrieve",
    }
)


_WORD = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_ALL_VERBS = DECISION_VERBS | DESTRUCTIVE_VERBS | WRITE_VERBS | READ_VERBS
# Server and vendor prefixes a tool name may lead with, in front of its verb.
_PREFIX_SEGMENTS = 2
_SHORT_PREFIX = 4  # vendor abbreviations: mde, cb, pan, aad, xdr, otx, jira


def _words(segment: str) -> List[str]:
    """``getHostStatus`` / ``get-host`` / ``get`` -> lower-case words."""
    return [w.lower() for w in _WORD.findall(segment)]


def _known_namespaces() -> frozenset:
    """Integration server ids and the vendor prefix their tools lead with."""
    names = set()
    vendor_tools = list(THIRD_PARTY)
    for server, tools in INTEGRATIONS.items():
        names.add(server.lower())
        vendor_tools.extend(tools)
    for tool in vendor_tools:
        head = tool.split("_", 1)[0]
        if "_" in tool and head:
            names.add(head.lower())
    return frozenset(n for n in names if not (set(_words(n)) & _ALL_VERBS))


_KNOWN_NAMESPACES = _known_namespaces()


def _is_prefix(segment: str, position: int) -> bool:
    """Whether ``segment`` at ``position`` reads as a server or vendor prefix.

    The first segment may be any non-verb: the registry flattens every MCP tool
    to ``{server}_{tool}``, so it is the server name (``shodan_search_host``).
    A second one must look like a vendor prefix -- hyphenated, a known
    namespace, or a short abbreviation -- so an unknown word there
    (``acme_frobnicate_get``) is taken for the verb, not skipped.
    """
    words = _words(segment)
    if not words or any(w in _ALL_VERBS for w in words[:1]):
        return False
    if position == 0:
        return True
    return (
        "-" in segment
        or segment.lower() in _KNOWN_NAMESPACES
        or len(segment) <= _SHORT_PREFIX
    )


def heuristic(name: str) -> str:
    """The class of a name the table does not hold, erring restrictive.

    The name is split into words on ``_``, ``-`` and camelCase, so
    ``get_hostAndIsolate`` and ``list-users-delete`` show their verbs. A
    decision verb anywhere (``approve``, ``reject``, ...) is ``decision``,
    which no model surface reaches. A destructive verb anywhere is ``destructive`` and a write verb anywhere is
    ``write``, whatever leads. Otherwise the name is ``read_only`` only when
    its leading verb reads: the first word after at most two server or vendor
    prefixes (``shodan_search_host``, ``acme-edr_xdr_get_host``; see
    :func:`_is_prefix`, and a prefix is never a verb). A read word further in
    (``acme_frobnicate_get``) is not the verb, and a
    destructive-looking noun after a read verb (``get_isolation_status``) is
    not one either. Everything else is ``destructive``: a name that says
    nothing is not evidence that the tool does nothing.
    """
    segments = [seg for seg in name.split("_") if seg]
    words = [w for seg in segments for w in _words(seg)]
    if any(w in DECISION_VERBS for w in words):
        return DECISION
    if any(w in DESTRUCTIVE_VERBS for w in words):
        return DESTRUCTIVE
    if any(w in WRITE_VERBS for w in words):
        return WRITE
    skipped = 0
    while (
        skipped < _PREFIX_SEGMENTS
        and skipped < len(segments) - 1
        and _is_prefix(segments[skipped], skipped)
    ):
        skipped += 1
    lead = _words(segments[skipped]) if skipped < len(segments) else []
    if lead and lead[0] in READ_VERBS:
        return READ_ONLY
    return DESTRUCTIVE


# --- the lookups ------------------------------------------------------------


def classify(name: str) -> Effect:
    """The effect of ``name``: from the table when listed, else the fallback."""
    effect = TOOL_EFFECTS.get(name)
    if effect is not None:
        return Effect(effect, MANIFEST_SOURCE)
    return Effect(heuristic(name), HEURISTIC_SOURCE)


def effect_of(name: str) -> str:
    return classify(name).effect


def is_gated(name: str) -> bool:
    """True when ``name`` may run only once a person approves it."""
    return effect_of(name) in GATED


def is_human_only(name: str) -> bool:
    """True when ``name`` decides an approval: only a person's HTTP request may."""
    return effect_of(name) in HUMAN_ONLY


def model_may_call(name: str) -> bool:
    """Whether ``name`` may appear on any model's tool list at all (W1.7b)."""
    return not is_human_only(name)


def gated_ids(names: Iterable[str]) -> List[str]:
    """The names among ``names`` that need an approval, in their order."""
    return [name for name in names if is_gated(name)]


def integration_tool_names(server: str) -> List[str]:
    return list(INTEGRATIONS.get(server, {}))


def server_for(name: str) -> Optional[str]:
    """The in-repo server a flattened integration name belongs to, if any."""
    for server, tools in INTEGRATIONS.items():
        for tool in tools:
            if name == _flatten(server, tool):
                return server
    return None


# --- the TypeScript mirror --------------------------------------------------

MIRROR_PATH = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "agent"
    / "contracts"
    / "tool-effects.ts"
)


def render_mirror() -> str:
    """The generated TypeScript module, byte for byte."""
    lines = [
        "// GENERATED by `python -m core.llm.tool_effects --write` from",
        "// core/llm/tool_effects.py, the one table of what each tool does to the",
        "// world. Do not edit by hand: a ratchet holds this file equal to that one.",
        "",
        f"export const EFFECTS = {json.dumps(list(EFFECTS))} as const;",
        "",
        "export type Effect = (typeof EFFECTS)[number];",
        "",
        "// Runs only once a person approves it, on every surface.",
        f"export const GATED: ReadonlySet<Effect> = new Set<Effect>({json.dumps(sorted(GATED))});",
        "",
        "// Never on a model's tool list, approved or not: a person decides these over HTTP.",
        f"export const HUMAN_ONLY: ReadonlySet<Effect> = new Set<Effect>({json.dumps(sorted(HUMAN_ONLY))});",
        "",
        "export const TOOL_EFFECTS: Readonly<Record<string, Effect>> = {",
    ]
    for name in sorted(TOOL_EFFECTS):
        lines.append(f"  {json.dumps(name)}: {json.dumps(TOOL_EFFECTS[name])},")
    lines += ["};", ""]
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    rendered = render_mirror()
    if "--write" in argv:
        MIRROR_PATH.write_text(rendered, encoding="utf-8")
        return 0
    current = MIRROR_PATH.read_text(encoding="utf-8") if MIRROR_PATH.exists() else ""
    if current != rendered:
        sys.stderr.write(f"{MIRROR_PATH} is stale; run with --write\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
