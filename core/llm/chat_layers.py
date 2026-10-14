# The config layer a chat turn runs under. Assembled per request because which
# tools a conversation may reach depends on the agent the operator picked, and
# the agent registry lives on this side of the boundary.

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

import yaml

from core.integrations.atomic_red_team.descriptor import EXECUTE_IDS
from core.llm.tool_effects import (
    APPROVAL,
    DECISION,
    DESTRUCTIVE,
    READ_ONLY,
    RECORDS,
    WRITE,
    effect_of,
    is_gated,
    is_human_only,
)
from core.llm.tool_schemas import (
    ALL_TOOLS,
    CALL_INTEGRATION_TOOL,
    FIND_INTEGRATION_TOOLS,
    INTEGRATION_TOOLS,
)

REMOTE = "remote"


# What a tool does to the world comes from one table, ``core.llm.tool_effects``.
# Chat has no approval-resume path -- a parked call would hang forever, never
# gate -- so a gated tool (``write`` / ``destructive``) is out of its reach.
# Real containment goes through the approval queue (``create_approval_action``)
# and workflows, not ad-hoc chat calls. Deciding that queue (``decision``) is
# human-only and out of every model's reach (W1.7b): see ``_declare``.
def _is_destructive_mcp(name: str) -> bool:
    """True for a tool that may run only once a person approves it.

    Read from the effect table; a name the table does not hold falls back to
    the verb heuristic there, which errs towards gating. A spurious gate means
    chat recommends the action instead of calling it, whereas a missed one is
    an ungated detonation.
    """
    return is_gated(name)


# Weakest to strongest, so an agent is as hands-on as its most hands-on tool.
# ``on_its_own`` is kept in the vocabulary for the console, and is what a gated
# tool would be if any surface ran it unasked; none does, and a ratchet
# (tests/unit/_ratchets/test_no_ungated_write_tools.py) holds that at zero.
_CHANGES_RANK = ("read_only", "asks_first", "on_its_own")

# How each effect class reads on the Agents tab. AutoSecOps's own records and a
# decision a person makes on the approvals screen are not outside changes.
_CHANGES_BY_EFFECT = {
    READ_ONLY: "read_only",
    RECORDS: "read_only",
    DECISION: "read_only",
    APPROVAL: "asks_first",
    WRITE: "asks_first",
    DESTRUCTIVE: "asks_first",
}


def changes_for_tool(name: str) -> str:
    """What one tool does to the outside world, as the console words it.

    ``asks_first`` for the approval tool and for every gated tool, which each
    surface either parks for a person or refuses; otherwise ``read_only``.
    """
    return _CHANGES_BY_EFFECT[effect_of(name)]


def changes_for_tools(tools: List[str]) -> str:
    """What an agent with these tools does: the strongest of its tools' answers."""
    return max(
        (changes_for_tool(t) for t in tools),
        key=_CHANGES_RANK.index,
        default="read_only",
    )


# A conversation is one answer at a time with a person waiting, so the ceiling is
# per turn rather than per run: they will say so long before a budget would.
DEFAULT_BUDGETS = {"max_calls": 12, "max_wall_ms": 300_000, "max_cost_usd": 2.0}
DEFAULT_RUNTIME = {"max_turns": 8, "result_cap": 20_000, "recall_limit": 3}

# A session id is the console's and is not a uuid; a run id is. Derived rather
# than generated so every turn of one conversation lands on the same run.
CONVERSATIONS = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")


def run_id_for(session_id: str) -> str:
    return str(uuid.uuid5(CONVERSATIONS, session_id))


# The MCP tools chat may reach through find/call_integration_tool: every
# connected one except direct-action tools (see ``_is_destructive_mcp``), which
# chat cannot safely gate, and those sharing a built-in's name — the backend
# answers those, and an agent's ``wanted`` list decides whether it may.
def integration_tools(
    mcp_tools: Optional[List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    static = {t["name"] for t in ALL_TOOLS if t.get("name")}
    return [
        t
        for t in mcp_tools or []
        if t.get("name")
        and t["name"] not in static
        and not _is_destructive_mcp(t["name"])
        and not is_human_only(t["name"])
    ]


def integrations_line(
    mcp_tools: Optional[List[Dict[str, Any]]], servers: Dict[str, str]
) -> str:
    """The system-prompt sentence naming what is connected, or "" for nothing."""
    names = sorted(
        {
            servers[t["name"]]
            for t in integration_tools(mcp_tools)
            if t["name"] in servers
        }
    )
    if not names:
        return ""
    return (
        f"Connected integrations: {', '.join(names)}. Their tools are not listed "
        f"here: call {FIND_INTEGRATION_TOOLS} to find one, then "
        f"{CALL_INTEGRATION_TOOL} to run it."
    )


# A tool with no description is dropped rather than declared: the agent layer
# refuses one, because a model cannot choose between two blank tools.
def _declare(
    wanted: Optional[List[str]],
    mcp_tools: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    # A fixed core. The built-ins are curated, and a per-agent recommended-tools
    # list (``wanted``) narrows them. The connected integrations are not declared
    # one by one -- a default install's ran past 100 tools, which providers
    # refused and models chose among badly -- but found and called on demand
    # through two tools, declared whenever any is reachable, whatever ``wanted``
    # says: a user who connected an integration expects the assistant to use it.
    # Hunts curate separately (playbook_resolver).
    #
    # Chat has no approval-resume path, so a gated built-in is dropped by class
    # (none is today; ART execute, which is not a built-in, was the reason).
    #
    # A decision on the approval queue is dropped too, and by class rather than
    # by name (W1.7b). Chat once declared ``approve_action`` on the reading that
    # it only released what a person had queued -- but the model is what calls
    # it, and the model reads alert text, case notes and tool output, so any of
    # those could approve a pending isolation under the signed-in person's name,
    # or supply the "second person" of a four-eyes rule. A person decides on the
    # approvals screen; no built-in decides at all any more, and this filter is
    # what keeps one that comes back out of a model's hands.
    static = {t["name"]: t for t in ALL_TOOLS if t.get("name")}
    names = list(static) if wanted is None else [n for n in wanted if n in static]
    entries = [
        static[n]
        for n in names
        if n not in EXECUTE_IDS and not is_gated(n) and not is_human_only(n)
    ]
    if integration_tools(mcp_tools):
        entries += INTEGRATION_TOOLS
    declared = []
    for entry in entries:
        description = (entry.get("description") or "").strip()
        if not description:
            continue
        declared.append(
            {
                "id": entry["name"],
                "kind": REMOTE,
                "description": description,
                "parameters": entry.get("input_schema") or {"type": "object"},
                "effect": effect_of(entry["name"]),
            }
        )
    return declared


def granted_ids(wanted: Optional[List[str]]) -> List[str]:
    """Ids of the built-in tools a turn with this tool list will declare."""
    return [t["id"] for t in _declare(wanted)]


def chat_config(
    model: str,
    tools: Optional[List[str]] = None,
    mcp_tools: Optional[List[Dict[str, Any]]] = None,
    provider: Optional[str] = None,
    effort: Optional[str] = None,
    context_window: Optional[int] = None,
) -> str:
    """Render the agent layer's config document.

    ``provider`` is the gateway's provider name, carried separately from the
    model rather than folded into it: Bifrost routes ``<provider>/<model>`` but
    the price catalogue is keyed by the bare id, so the agent needs both. Left
    out when unknown, which is what every caller did before this existed.
    ``effort`` is the reasoning effort set on the model, left out when unset.
    ``context_window`` is the model's window in tokens, left out when unknown
    (0 or None); the agent layer only uses it to lower how much history it sends.
    """
    document = {
        "model": model,
        **({"provider": provider} if provider else {}),
        **({"effort": effort} if effort else {}),
        **(
            {"context_window": context_window}
            if context_window and context_window > 0
            else {}
        ),
        "budgets": DEFAULT_BUDGETS,
        "runtime": DEFAULT_RUNTIME,
        "tools": _declare(tools, mcp_tools),
        # A chat tool asks the person directly rather than parking on a
        # checkpoint: they are already in the conversation.
        "approvals": [],
        "thresholds": {},
    }
    return yaml.safe_dump(
        document, default_flow_style=False, sort_keys=False, allow_unicode=True
    )
