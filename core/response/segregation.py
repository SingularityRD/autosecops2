"""Segregation-of-duties report over approval actions (W3.2).

For each action in a window: who proposed it, who approved it (and the
second approver under the two-person rule), who executed it, the role each
person held, and every segregation-of-duties violation found. Roles come from
``approval_decisions`` (the role at the moment of the decision,
``61_approval_decisions.sql``); for a decision with no recorded row (made
before the table existed, or by a proposer, who is never recorded there) the
person's current role is used and ``role_source`` says so.

Violations, checked against the response policy in force when the report is
built:

``self_approval``
    the proposer is also an approver (names compared case-insensitively).
``same_person``
    the first and second approver are the same person.
``missing_second_approver``
    a four-eyes type was approved or executed with no second approver.
``same_role``
    a distinct-role type's two approvers held the same role.
``unknown_role``
    a distinct-role type's approver has no role on record or now.
``executed_without_approval``
    an action that required approval was executed with nobody's name on it.
"""

from __future__ import annotations

import csv
import io
import logging
from collections import Counter
from datetime import datetime
from typing import Any, Iterable, Optional

from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError

from core.response.policy import PolicyConfig
from core.storage.models import ApprovalAction as ApprovalActionRow
from core.storage.models import Role, User

logger = logging.getLogger(__name__)

#: ``executed_by`` for a forward action: the dispatcher ran it, nobody by hand.
DISPATCHER = "system:dispatcher"

VIOLATIONS = (
    "self_approval",
    "same_person",
    "missing_second_approver",
    "same_role",
    "unknown_role",
    "executed_without_approval",
)

#: The statuses at which an approval has been given (pending rows are not yet decided).
_DECIDED = frozenset({"approved", "executed", "failed"})

CSV_COLUMNS = (
    "action_id",
    "action_type",
    "target",
    "status",
    "created_at",
    "proposed_by",
    "proposed_role",
    "approved_by",
    "approved_role",
    "second_approver",
    "second_role",
    "executed_by",
    "executed_at",
    "reverse_of",
    "four_eyes",
    "distinct_role",
    "role_source",
    "violations",
)

_DECISIONS = text("""
    SELECT action_id, step, actor, actor_role_id, actor_role
    FROM approval_decisions
    WHERE action_id = ANY(:ids)
    ORDER BY id
    """)


def _key(name: Optional[str]) -> str:
    return (name or "").strip().casefold()


def _recorded_roles(session, ids: list[str]) -> dict[tuple[str, str], tuple]:
    """``(action_id, step) -> (role_id, role)`` from approval_decisions; {} if absent."""
    if not ids:
        return {}
    try:
        with session.begin_nested():
            rows = session.execute(_DECISIONS, {"ids": ids}).all()
    except SQLAlchemyError as e:
        logger.warning("approval_decisions unreadable; using current roles: %s", e)
        return {}
    found: dict[tuple[str, str], tuple] = {}
    for action_id, step, _actor, role_id, role in rows:
        # The latest row per step wins (there is one in practice).
        found[(action_id, step)] = (role_id, role)
    return found


def _current_roles(session, names: Iterable[str]) -> dict[str, tuple]:
    """``casefolded username -> (role_id, role)`` for the accounts named."""
    wanted = sorted({_key(n) for n in names if _key(n)})
    if not wanted:
        return {}
    rows = session.execute(
        select(func.lower(User.username), User.role_id, Role.name)
        .join(Role, Role.role_id == User.role_id)
        .where(func.lower(User.username).in_(wanted))
    ).all()
    return {r[0]: (r[1], r[2]) for r in rows}


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def build_report(
    session,
    policy: PolicyConfig,
    *,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    action_type: Optional[str] = None,
    violations_only: bool = False,
    limit: int = 5000,
) -> dict[str, Any]:
    """The report for actions created in ``[since, until)``, newest first."""
    stmt = select(ApprovalActionRow).order_by(ApprovalActionRow.created_at.desc())
    if since is not None:
        stmt = stmt.where(ApprovalActionRow.created_at >= since)
    if until is not None:
        stmt = stmt.where(ApprovalActionRow.created_at < until)
    if action_type:
        stmt = stmt.where(ApprovalActionRow.action_type == action_type)
    actions = session.execute(stmt.limit(limit)).scalars().all()

    recorded = _recorded_roles(session, [a.action_id for a in actions])
    current = _current_roles(
        session,
        [
            n
            for a in actions
            for n in (a.created_by, a.approved_by, a.second_approver)
            if n
        ],
    )

    rows = []
    for a in actions:
        rows.append(_row(a, policy, recorded, current))
    if violations_only:
        rows = [r for r in rows if r["violations"]]

    counts: Counter[str] = Counter(v for r in rows for v in r["violations"])
    return {
        "since": _iso(since),
        "until": _iso(until),
        "action_type": action_type,
        "policy": {
            "four_eyes_types": sorted(policy.four_eyes_types),
            "distinct_role_types": sorted(policy.distinct_role_types),
        },
        "summary": {
            "total": len(rows),
            "with_violations": sum(1 for r in rows if r["violations"]),
            "by_kind": {k: counts.get(k, 0) for k in VIOLATIONS},
        },
        "rows": rows,
    }


def _row(
    a: ApprovalActionRow,
    policy: PolicyConfig,
    recorded: dict[tuple[str, str], tuple],
    current: dict[str, tuple],
) -> dict[str, Any]:
    four_eyes = policy.needs_second_approver(a.action_type) and not a.reverse_of
    distinct = policy.needs_distinct_role(a.action_type) and not a.reverse_of
    rejected = a.status == "rejected"

    sources: set[str] = set()

    def role(step: str, name: Optional[str]) -> tuple:
        if not name:
            return (None, None)
        hit = recorded.get((a.action_id, step))
        if hit and hit[0]:
            sources.add("recorded")
            return hit
        sources.add("current")
        return current.get(_key(name), (None, None))

    proposed_role = (
        current.get(_key(a.created_by), (None, None)) if a.created_by else (None, None)
    )
    if four_eyes and not rejected:
        approved_role = role("first_approval", a.approved_by)
        second_role = role("second_approval", a.second_approver)
    else:
        approved_role = role("reject" if rejected else "approve", a.approved_by)
        second_role = (None, None)

    if a.reverse_of:
        executed_by = a.created_by if a.executed_at else None
    elif a.status == "executed":
        executed_by = DISPATCHER
    else:
        executed_by = None

    violations: list[str] = []
    decided = a.status in _DECIDED
    proposer = _key(a.created_by)
    if (
        decided
        and not a.reverse_of
        and proposer
        and proposer in {_key(a.approved_by), _key(a.second_approver)}
    ):
        violations.append("self_approval")
    if a.second_approver and _key(a.second_approver) == _key(a.approved_by):
        violations.append("same_person")
    if four_eyes and decided and not a.second_approver:
        violations.append("missing_second_approver")
    if distinct and decided and a.second_approver:
        if approved_role[0] is None or second_role[0] is None:
            violations.append("unknown_role")
        elif approved_role[0] == second_role[0]:
            violations.append("same_role")
    if (
        a.status == "executed"
        and not a.reverse_of
        and a.requires_approval
        and not a.approved_by
    ):
        violations.append("executed_without_approval")

    return {
        "action_id": a.action_id,
        "action_type": a.action_type,
        "target": a.target,
        "status": a.status,
        "created_at": _iso(a.created_at),
        "proposed_by": a.created_by,
        "proposed_role": proposed_role[1] or proposed_role[0],
        "approved_by": a.approved_by,
        "approved_role": approved_role[1] or approved_role[0],
        "second_approver": a.second_approver,
        "second_role": second_role[1] or second_role[0],
        "executed_by": executed_by,
        "executed_at": _iso(a.executed_at),
        "reverse_of": a.reverse_of,
        "four_eyes": four_eyes,
        "distinct_role": distinct,
        "role_source": (
            "mixed" if len(sources) > 1 else (next(iter(sources)) if sources else None)
        ),
        "violations": violations,
    }


def _cell(value: Any) -> str:
    """A CSV cell that a spreadsheet will not run as a formula."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        value = ";".join(str(v) for v in value)
    text_value = str(value)
    if text_value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text_value
    return text_value


def to_csv(report: dict[str, Any]) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(CSV_COLUMNS)
    for row in report["rows"]:
        writer.writerow([_cell(row.get(col)) for col in CSV_COLUMNS])
    return out.getvalue()


__all__ = ["CSV_COLUMNS", "DISPATCHER", "VIOLATIONS", "build_report", "to_csv"]
