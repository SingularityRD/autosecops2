"""A case's response actions and each one's lifecycle, for the case page.

Read-only. An approval action belongs to a case by the same order
``needs_you`` resolves (#1301): ``parameters.case_id``, else the workflow
run's ``trigger_context.case_id``, else the case of
``parameters.investigation_id``. A row that undoes another (``reverse_of``)
belongs to the case of the row it undoes, so a revert written without a case
id still shows next to what it reverted.

Lifecycle columns are described in
``infra/database/init/49_approval_action_lifecycle.sql``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from core.response.config import split_decision_rule
from core.storage.models import ApprovalAction, Investigation, WorkflowRun

# A state summary shows this many keys and cuts each value at this many chars.
_SUMMARY_KEYS = 12
_SUMMARY_CHARS = 120
# A case with more actions than this is cut; the response says so.
_LIMIT = 500


def _stamp(value: Optional[datetime]) -> Optional[str]:
    """The table's TIMESTAMPs are naive UTC; say so on the wire."""
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.isoformat()
    return value.isoformat() + "Z"


def _text(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _cut(text: str) -> str:
    return text if len(text) <= _SUMMARY_CHARS else text[: _SUMMARY_CHARS - 1] + "…"


def summarize_state(state: Any) -> Optional[List[Dict[str, str]]]:
    """``[{key, value}]`` for the first keys of a before/after state.

    Scalars print as themselves, nested objects and lists as their size, so a
    large observed state cannot swell the response. None when there is none.
    """
    if not isinstance(state, dict) or not state:
        return None
    rows: List[Dict[str, str]] = []
    for key in sorted(state, key=str)[:_SUMMARY_KEYS]:
        value = state[key]
        if isinstance(value, dict):
            shown = f"{{{len(value)} keys}}"
        elif isinstance(value, (list, tuple)):
            shown = f"[{len(value)} items]"
        elif value is None:
            shown = "null"
        elif isinstance(value, bool):
            shown = "true" if value else "false"
        else:
            shown = str(value)
        rows.append({"key": _cut(str(key)), "value": _cut(shown)})
    extra = len(state) - _SUMMARY_KEYS
    if extra > 0:
        rows.append({"key": "…", "value": f"{extra} more"})
    return rows


def _case_filter(case_id: str):
    """SQL predicate for rows that can resolve to ``case_id``.

    Wide on purpose (a row naming another case directly can still match by
    its run); ``_resolves_to`` narrows it to the exact #1301 order.
    """
    run_ids = select(WorkflowRun.run_id).where(
        WorkflowRun.trigger_context["case_id"].astext == case_id
    )
    investigation_ids = select(Investigation.investigation_id).where(
        Investigation.case_id == case_id
    )
    return or_(
        ApprovalAction.parameters["case_id"].astext == case_id,
        ApprovalAction.workflow_run_id.in_(run_ids),
        ApprovalAction.parameters["investigation_id"].astext.in_(investigation_ids),
    )


def _resolves_to(
    session: Session, rows: Iterable[ApprovalAction], case_id: str
) -> List[ApprovalAction]:
    rows = list(rows)
    run_ids = {row.workflow_run_id for row in rows if row.workflow_run_id}
    runs: Dict[str, Any] = {}
    if run_ids:
        for run in session.execute(
            select(WorkflowRun.run_id, WorkflowRun.trigger_context).where(
                WorkflowRun.run_id.in_(run_ids)
            )
        ):
            runs[run.run_id] = (
                run.trigger_context if isinstance(run.trigger_context, dict) else {}
            )
    investigation_ids = {
        _text((row.parameters or {}).get("investigation_id"))
        for row in rows
        if isinstance(row.parameters, dict)
    } - {None}
    investigations: Dict[str, Optional[str]] = {}
    if investigation_ids:
        for inv in session.execute(
            select(Investigation.investigation_id, Investigation.case_id).where(
                Investigation.investigation_id.in_(investigation_ids)
            )
        ):
            investigations[inv.investigation_id] = inv.case_id

    kept: List[ApprovalAction] = []
    for row in rows:
        params = row.parameters if isinstance(row.parameters, dict) else {}
        resolved = _text(params.get("case_id"))
        if not resolved and row.workflow_run_id:
            resolved = _text((runs.get(row.workflow_run_id) or {}).get("case_id"))
        if not resolved:
            investigation_id = _text(params.get("investigation_id"))
            if investigation_id:
                resolved = _text(investigations.get(investigation_id))
        if resolved == case_id:
            kept.append(row)
    return kept


def _events(row: ApprovalAction) -> List[Dict[str, Any]]:
    """The lifecycle as dated steps, oldest first. Expiry is not an event."""
    events: List[Dict[str, Any]] = [
        {"kind": "proposed", "at": _stamp(row.created_at), "actor": row.created_by}
    ]
    if row.status == "rejected":
        events.append(
            {
                "kind": "rejected",
                "at": _stamp(row.approved_at),
                "actor": row.approved_by,
                "detail": row.rejection_reason,
            }
        )
    elif row.approved_at or row.approved_by:
        actor = row.approved_by
        if row.second_approver:
            actor = f"{row.approved_by} + {row.second_approver}"
        events.append(
            {"kind": "approved", "at": _stamp(row.approved_at), "actor": actor}
        )
    if row.executed_at:
        result = row.execution_result if isinstance(row.execution_result, dict) else {}
        failed = row.status == "failed"
        detail = result.get("error") if failed else result.get("message")
        events.append(
            {
                "kind": "failed" if failed else "executed",
                "at": _stamp(row.executed_at),
                "actor": None,
                "detail": _text(detail),
            }
        )
    if row.verified_at or row.verify_status:
        events.append(
            {
                "kind": "verified",
                "at": _stamp(row.verified_at),
                "actor": None,
                "detail": row.verify_status,
            }
        )
    if row.reversed_at:
        events.append(
            {"kind": "reversed", "at": _stamp(row.reversed_at), "actor": None}
        )
    for event in events:
        event.setdefault("detail", None)
    return events


def _item(row: ApprovalAction, reverted_by: Optional[str]) -> Dict[str, Any]:
    narrative, rule = split_decision_rule(row.reason)
    result = row.execution_result if isinstance(row.execution_result, dict) else None
    can_revert = (
        row.status == "executed"
        and row.reversibility == "reversible"
        and row.reversed_at is None
        and row.reverse_of is None
        and reverted_by is None
    )
    return {
        "action_id": row.action_id,
        "action_type": row.action_type,
        "title": row.title,
        "target": row.target,
        "status": row.status,
        "reversibility": row.reversibility,
        "can_revert": can_revert,
        "proposed_at": _stamp(row.created_at),
        "proposed_by": row.created_by,
        "confidence": float(row.confidence) if row.confidence is not None else None,
        "reason": narrative,
        "policy": {
            "requires_approval": bool(row.requires_approval),
            "decision_rule": rule,
        },
        "approved_at": _stamp(row.approved_at) if row.status != "rejected" else None,
        "approved_by": row.approved_by if row.status != "rejected" else None,
        "second_approver": row.second_approver,
        "rejection_reason": row.rejection_reason,
        "executed_at": _stamp(row.executed_at),
        "execution": (
            {
                "success": result.get("success"),
                "status": _text(result.get("status")),
                "message": _text(result.get("message")),
                "error": _text(result.get("error")),
            }
            if result is not None
            else None
        ),
        "verified_at": _stamp(row.verified_at),
        "verify_status": row.verify_status,
        "expires_at": _stamp(row.expires_at),
        "reversed_at": _stamp(row.reversed_at),
        "reverse_of": row.reverse_of,
        "reverted_by": reverted_by,
        "before_state": summarize_state(row.before_state),
        "after_state": summarize_state(row.after_state),
        "events": _events(row),
    }


def case_action_timeline(session: Session, case_id: str) -> Dict[str, Any]:
    """Every response action on ``case_id``, newest first, with its lifecycle."""
    candidates = session.execute(
        select(ApprovalAction)
        .where(_case_filter(case_id))
        .order_by(ApprovalAction.created_at.desc())
        .limit(_LIMIT + 1)
    ).scalars()
    rows = _resolves_to(session, candidates, case_id)
    truncated = len(rows) > _LIMIT
    rows = rows[:_LIMIT]
    seen = {row.action_id for row in rows}
    if seen:
        # Reverts of these rows, whether or not they name the case themselves.
        for undo in session.execute(
            select(ApprovalAction).where(ApprovalAction.reverse_of.in_(seen))
        ).scalars():
            if undo.action_id not in seen:
                rows.append(undo)
                seen.add(undo.action_id)
    reverted_by: Dict[str, str] = {}
    for row in sorted(rows, key=lambda r: r.created_at or datetime.min):
        if row.reverse_of and row.status != "failed" and row.status != "rejected":
            reverted_by.setdefault(row.reverse_of, row.action_id)
    rows.sort(key=lambda r: r.created_at or datetime.min, reverse=True)
    actions = [_item(row, reverted_by.get(row.action_id)) for row in rows]
    return {
        "case_id": case_id,
        "count": len(actions),
        "truncated": truncated,
        "actions": actions,
    }
