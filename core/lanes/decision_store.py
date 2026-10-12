"""Writes alert lane decisions to ``alert_lane_decisions`` (infra/database/init/56_*.sql).

The table is SQL-owned (no ORM model), so this speaks plain SQL. One row per
decision, tenant-scoped; the finding's ``ai_enrichment.alert_lane`` carries the
same decision for the UI.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

from core.lanes.alert_lanes import LaneDecision, log_decision

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
