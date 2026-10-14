"""Writes alert lane decisions to ``alert_lane_decisions`` (infra/database/init/56_*.sql).

The table is SQL-owned (no ORM model), so this speaks plain SQL. One row per
decision, tenant-scoped; the finding's ``ai_enrichment.alert_lane`` carries the
same decision for the UI.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Iterable, Sequence

from core.lanes.alert_lanes import DEFAULT_TENANT, LaneDecision, log_decision

logger = logging.getLogger(__name__)

_INSERT = """
INSERT INTO alert_lane_decisions (
    tenant_id, finding_id, lane, reason, risk, factors, rule_kind, rule_id,
    outcome, deferred_verdict, degraded_from, verdict_run_id, model, decided_at
) VALUES (
    :tenant_id, :finding_id, :lane, :reason, :risk, CAST(:factors AS jsonb),
    :rule_kind, :rule_id, CAST(:outcome AS jsonb), :deferred_verdict,
    :degraded_from, :verdict_run_id, :model, CAST(:decided_at AS timestamptz)
)
"""


def decision_row(decision: LaneDecision) -> Dict[str, Any]:
    """Bind parameters for one ``alert_lane_decisions`` row."""
    rule = decision.rule or {}
    return {
        "tenant_id": decision.tenant_id,
        "finding_id": decision.finding_id,
        "lane": decision.lane,
        "reason": decision.reason,
        "risk": min(1.0, max(0.0, float(decision.risk))),
        "factors": json.dumps(list(decision.factors)),
        "rule_kind": rule.get("kind"),
        "rule_id": rule.get("id"),
        "outcome": (
            None
            if decision.outcome is None
            else json.dumps(decision.outcome, default=str)
        ),
        "deferred_verdict": bool(decision.deferred_verdict),
        "degraded_from": decision.degraded_from,
        "verdict_run_id": decision.verdict_run_id,
        "model": decision.model,
        "decided_at": decision.decided_at,
    }


def _session_scope():
    from core.storage.connection import get_db_manager

    return get_db_manager().session_scope()


def insert_decision(decision: LaneDecision) -> None:
    """Insert one row. Raises when the database can't be written."""
    from sqlalchemy import text

    with _session_scope() as session:
        session.execute(text(_INSERT), decision_row(decision))


def record_decision(decision: LaneDecision) -> None:
    """The daemon's recorder: a log line, then the row; best effort, never raises.

    A failed write loses only the audit row: the decision itself is already on
    the finding (``ai_enrichment.alert_lane``) and the finding is never dropped.
    """
    log_decision(decision)
    try:
        insert_decision(decision)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "alert lane decision for %s not written: %s", decision.finding_id, exc
        )


# W0.15: the earliest decision per finding that settled it on its own (a rules
# outcome, or a verdict run that was enqueued). Mirrors wants_llm_triage().
_SETTLING = """
SELECT DISTINCT ON (finding_id)
       finding_id, tenant_id, lane, reason, risk, factors, rule_kind, rule_id,
       outcome, deferred_verdict, degraded_from, verdict_run_id, model, decided_at
FROM alert_lane_decisions
WHERE tenant_id = :tenant
  AND finding_id = ANY(:ids)
  AND (lane = :rules OR (lane = :verdict AND verdict_run_id IS NOT NULL))
ORDER BY finding_id, decided_at, id
"""


def settling_decisions(
    finding_ids: Iterable[str], tenant: str = DEFAULT_TENANT
) -> Dict[str, LaneDecision]:
    """``{finding_id: decision}`` for the findings a recorded lane decision
    already settled (``tenant``'s decisions: the daemon writes its own).
    Raises when the database can't be read: the caller (the backfill sweep)
    must then not route anything, never assume "unsettled".
    """
    ids = sorted({i for i in finding_ids if i})
    if not ids:
        return {}
    with _session_scope() as session:
        return query_settling(session, ids, tenant)


def query_settling(conn: Any, ids: Sequence[str], tenant: str) -> Dict[str, LaneDecision]:
    """``settling_decisions`` on an open connection or session."""
    from sqlalchemy import text

    from core.lanes.alert_lanes import LANE_RULES, LANE_VERDICT

    rows = conn.execute(
        text(_SETTLING),
        {
            "tenant": tenant,
            "ids": list(ids),
            "rules": LANE_RULES,
            "verdict": LANE_VERDICT,
        },
    ).mappings()
    out: Dict[str, LaneDecision] = {}
    for r in rows:
        rule = (
            {"kind": r["rule_kind"], "id": r["rule_id"]}
            if r["rule_kind"] or r["rule_id"]
            else None
        )
        decided = r["decided_at"]
        out[r["finding_id"]] = LaneDecision(
            finding_id=r["finding_id"],
            tenant_id=r["tenant_id"],
            lane=r["lane"],
            reason=r["reason"],
            risk=float(r["risk"] or 0.0),
            factors=tuple(r["factors"] or ()),
            rule=rule,
            outcome=r["outcome"],
            deferred_verdict=bool(r["deferred_verdict"]),
            degraded_from=r["degraded_from"],
            verdict_run_id=r["verdict_run_id"],
            model=r["model"],
            decided_at=(
                decided.isoformat() if hasattr(decided, "isoformat") else str(decided)
            ),
        )
    return out
