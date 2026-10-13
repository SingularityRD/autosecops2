"""AI decision rows for the QA tests."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from core.storage.models import AIDecisionLog
from core.storage.unit_of_work import unit_of_work

# Decision ids the QA tests write, so cleanup touches nothing else.
PREFIX = "qa-test-"


def verdict_doc(verdict: str, category: str, confidence: float = 0.9) -> dict:
    return {
        "verdict": verdict,
        "confidence": confidence,
        "category": category,
        "cited_fields": [{"field": "edr.process.name", "authored": "sensor"}],
        "gaps": [],
        "recommended_action": None,
        "model": "test-model",
        "prompt_version": "v1",
    }


def add_decisions(
    rows: list[dict],
    *,
    at: datetime,
) -> None:
    """Each row: id, and either verdict+category or decision_type (+ meta)."""
    with unit_of_work() as session:
        for r in rows:
            meta: Optional[dict] = dict(r.get("meta") or {})
            if "verdict" in r:
                meta["verdict"] = verdict_doc(
                    r["verdict"], r["category"], r.get("confidence", 0.9)
                )
            session.add(
                AIDecisionLog(
                    decision_id=f"{PREFIX}{r['id']}",
                    agent_id="triage",
                    decision_type=r.get("decision_type", "triage"),
                    confidence_score=r.get("confidence", 0.9),
                    reasoning=r.get("reasoning", "looked fine"),
                    recommended_action=r.get("action", "review"),
                    decision_metadata=meta or None,
                    timestamp=r.get("at", at),
                )
            )
