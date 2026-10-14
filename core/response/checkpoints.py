# A checkpoint the agent layer parked on, as an approval a human can answer. The
# answer goes back via /internal/runs/{id}/decisions; this side never writes the ledger.

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Top-level argument names that say *what* a gated call acts on. The approval
# names them on a line of their own so a person reads the target before the
# rest of the arguments, wherever sorted keys put it (W0.14).
TARGET_KEYS = (
    "machine_id",
    "device_id",
    "host",
    "hostname",
    "ip",
    "ip_address",
    "user",
    "username",
    "user_id",
    "upn",
    "account",
    "email",
    "domain",
    "url",
    "sha256",
    "file_hash",
    "hash",
    "indicator",
    "target",
)


def canonical_args(args: Any) -> str:
    """One spelling of a tool call's arguments, whatever order they came in.

    Both sides of the binding are computed here, from the arguments as this
    process parsed them off the wire: once when the checkpoint is raised and
    once when the approved call arrives at /internal/tools/invoke. Key order
    and whitespace are the sender's; sorted keys and fixed separators are not.
    """
    return json.dumps(
        args, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def args_digest(args: Any) -> str:
    """The sha256 an approval is bound to (W1.7b): approving ``mde_isolate`` of
    host A approves that call, and replaying the approval for host B fails."""
    return hashlib.sha256(canonical_args(args).encode("utf-8")).hexdigest()


def target_fields(args: Any) -> List[List[str]]:
    """The ``[name, value]`` pairs of ``args`` that name what the call acts on."""
    if not isinstance(args, dict):
        return []
    found: List[List[str]] = []
    for key in TARGET_KEYS:
        if key not in args or args[key] is None:
            continue
        value = args[key]
        text = value if isinstance(value, str) else canonical_args(value)
        found.append([key, text])
    return found


def target_line(args: Any) -> str:
    return ", ".join(f"{k}={v}" for k, v in target_fields(args))


def tool_call_parameters(tool: str, args: Any) -> Dict[str, Any]:
    """What an approval row carries about the one call it approves.

    ``args_canonical`` is the whole canonical text the digest covers, never a
    cut of it: an approval shows a person exactly the call it binds, so no
    padding argument can push the real target out of what they read (W0.14).
    """
    return {
        "tool": tool,
        "args_sha256": args_digest(args),
        "args_canonical": canonical_args(args),
        "args_targets": target_fields(args),
    }


# The key under which the agent layer's checkpoint context names the one tool
# call a harness checkpoint parks (services/agent/core/stream.ts park()).
TOOL_CALL_KEY = "tool_call"


def split_tool_call(
    context: Optional[Dict[str, Any]],
) -> "tuple[Dict[str, Any], Optional[Dict[str, Any]]]":
    """A checkpoint's context, and the tool call it parks (if it parks one)."""
    rest = dict(context or {})
    call = rest.pop(TOOL_CALL_KEY, None)
    if not isinstance(call, dict) or not call.get("tool"):
        return rest, None
    return rest, {"tool": str(call["tool"]), "args": call.get("args")}


def tool_call_prompt(tool: str, args: Any) -> str:
    """The lines a person reads under the question: exactly what would run,
    the whole of it, with the target named first."""
    lines = [f"Tool: {tool}"]
    targets = target_line(args)
    if targets:
        lines.append(f"Target: {targets}")
    lines.append(f"Arguments: {canonical_args(args)}")
    return "\n".join(lines)


def pending_for(run_id: str, checkpoint_id: str, approvals=None):
    from core.response.approval_service import ActionStatus, ApprovalService

    service = approvals or ApprovalService()
    for action in service.list_actions(
        status=ActionStatus.PENDING, workflow_run_id=run_id
    ):
        if (action.parameters or {}).get("checkpoint_id") == checkpoint_id:
            return action
    return None


# Idempotent by checkpoint, because a supervisor reads the same open checkpoint on
# every tick: raising per read would queue the same question hundreds of times.
def raise_for_checkpoint(
    *,
    run_id: str,
    checkpoint_id: str,
    title: str,
    description: str,
    reason: str,
    parameters: Optional[Dict[str, Any]] = None,
    phase_id: Optional[str] = None,
    approvals=None,
    tool_call: Optional[Dict[str, Any]] = None,
) -> bool:
    """Queue the question a parked run is waiting on.

    ``tool_call`` (``{"tool": ..., "args": ...}``) is set when the checkpoint
    parks one gated tool call. The row then names that tool, carries the
    digest of those arguments -- /internal/tools/invoke runs the call only
    when the arguments it is handed hash the same (W1.7b) -- and the person is
    shown the arguments, not just the tool's name. Computed here, never taken
    from the caller: a digest the sender supplied would bind nothing.
    """
    from core.response.approval_service import ActionType, ApprovalService

    service = approvals or ApprovalService()
    if pending_for(run_id, checkpoint_id, service) is not None:
        return False

    parameters = dict(parameters or {})
    # Only this function writes these, from tool_call.
    for key in (
        "tool",
        "args_sha256",
        "args_canonical",
        "args_targets",
        "args_summary",
    ):
        parameters.pop(key, None)
    if tool_call and tool_call.get("tool"):
        tool = str(tool_call["tool"])
        call_args = tool_call.get("args")
        parameters.update(tool_call_parameters(tool, call_args))
        description = f"{description}\n\n{tool_call_prompt(tool, call_args)}"

    service.create_action(
        action_type=ActionType.WORKFLOW_PHASE,
        title=title,
        description=description,
        target=run_id,
        confidence=0.0,
        reason=reason,
        # A checkpoint is always a person's call: no confidence was compared, so
        # no threshold belongs on the row.
        human_only=True,
        annotate_rule=False,
        evidence=[run_id],
        created_by="agent",
        parameters={**parameters, "checkpoint_id": checkpoint_id},
        workflow_run_id=run_id,
        workflow_phase_id=phase_id,
    )
    logger.info("raised approval for %s at checkpoint %s", run_id, checkpoint_id)
    return True


# A run that ended is not waiting for anything, and nothing withdrew its question:
# the approvals queue kept filling with questions whose run was over, until a real
# one was buried in them. Rejected rather than deleted, because who asked and why
# it went unanswered is the record.
def withdraw_for_run(run_id: str, reason: str, approvals=None) -> int:
    from core.response.approval_service import ActionStatus, ApprovalService

    service = approvals or ApprovalService()
    open_ones = service.list_actions(
        status=ActionStatus.PENDING, workflow_run_id=run_id
    )
    for action in open_ones:
        service.reject_action(action.action_id, reason, rejected_by="agent")
    if open_ones:
        logger.info("withdrew %d unanswered approvals for %s", len(open_ones), run_id)
    return len(open_ones)


# The run-less siblings of withdraw_for_run. That function keys on
# workflow_run_id, so approvals raised without a run behind them are unreachable
# and nothing else ages them out: the queue only grows and the one question that
# matters ends up buried (#675). It is also a safety line, not housekeeping —
# these are containment proposals, and approving a weeks-old "isolate host" out
# of a cluttered queue acts on a reason that stopped being true. Rejected rather
# than deleted, and attributed to "system", so the record distinguishes the queue
# ageing a question out from an analyst declining it.
def expire_stale(older_than_days: int, approvals=None) -> int:
    from datetime import timedelta

    from core.response.approval_service import ApprovalService
    from core.time import utcnow

    if older_than_days < 1:
        raise ValueError(
            "older_than_days must be at least 1, got "
            f"{older_than_days}: a zero or negative window expires approvals "
            "raised seconds ago, including the one an operator is reading"
        )

    service = approvals or ApprovalService()
    cutoff = utcnow() - timedelta(days=older_than_days)
    reason = f"expired: unanswered for more than {older_than_days} days"
    stale = service.list_stale_pending(cutoff)
    for action_id in stale:
        service.reject_action(action_id, reason, rejected_by="system")
    if stale:
        logger.info(
            "expired %d approvals unanswered since before %s",
            len(stale),
            cutoff.isoformat(),
        )
    return len(stale)
