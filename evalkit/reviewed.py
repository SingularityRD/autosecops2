"""The findings analysts reviewed, as labelled eval cases (W0.49).

QA sampling (W1.6) puts AI triage decisions in front of an analyst, who records
the verdict they judge right (``qa_samples.review_verdict``). That is a
customer's own ground truth on the customer's own alerts. This writes each
reviewed finding in the corpus row shape, so
``python -m evalkit run --cases <file>`` scores the triage path against it.

Only the finding as it was stored goes into ``alert``: the AI verdict, the
review and its notes stay out (``meta`` keeps who reviewed and when). Canary
findings are left out. A finding reviewed more than once keeps its latest
review. The file holds the customer's alert content: keep it where the alerts
themselves may be kept.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from sqlalchemy import text

_SQL = """
SELECT DISTINCT ON (f.finding_id)
       f.finding_id, f.data_source, f.title, f.description, f.entity_context,
       f.severity, f.timestamp, f.anomaly_score, f.external_id,
       q.review_verdict, q.reviewer, q.reviewed_at, q.sampling_kind
FROM qa_samples q
JOIN ai_decision_logs d ON q.subject_kind = 'ai_decision' AND d.decision_id = q.subject_id
JOIN findings f ON f.finding_id = d.finding_id
WHERE q.tenant_id = :t
  AND q.reviewed_at IS NOT NULL
  AND q.review_verdict = ANY(:verdicts)
  {not_canary}
ORDER BY f.finding_id, q.reviewed_at DESC
"""

_NOT_CANARY = "AND NOT EXISTS (SELECT 1 FROM canary_injections ci WHERE ci.finding_id = f.finding_id)"


def _iso(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value


def reviewed_rows(
    session, *, tenant_id: str = "default", include_inconclusive: bool = False
) -> List[Dict[str, Any]]:
    from core.storage.canary_exclusion import canary_table_present

    verdicts = ["malicious", "benign"] + (
        ["inconclusive"] if include_inconclusive else []
    )
    sql = _SQL.format(not_canary=_NOT_CANARY if canary_table_present(session) else "")
    rows = session.execute(text(sql), {"t": tenant_id, "verdicts": verdicts}).mappings()
    out = []
    for row in rows:
        alert = {
            "finding_id": row["finding_id"],
            "data_source": row["data_source"],
            "title": row["title"],
            "description": row["description"],
            "entity_context": row["entity_context"] or {},
            "severity": row["severity"],
            "status": "new",
            "timestamp": _iso(row["timestamp"]),
            "anomaly_score": row["anomaly_score"],
            "external_id": row["external_id"],
        }
        out.append(
            {
                "alert": {k: v for k, v in alert.items() if v is not None},
                "labels": {"verdict": row["review_verdict"]},
                "meta": {
                    "source": "qa_review",
                    "reviewer": row["reviewer"],
                    "reviewed_at": _iso(row["reviewed_at"]),
                    "sampling_kind": row["sampling_kind"],
                },
            }
        )
    return out


def export_reviewed(
    path: Path, *, tenant_id: str = "default", include_inconclusive: bool = False
) -> int:
    from core.storage.connection import get_db_manager
    from core.storage.unit_of_work import unit_of_work

    manager = get_db_manager()
    if manager.engine is None:
        manager.initialize()
    with unit_of_work() as session:
        rows = reviewed_rows(
            session, tenant_id=tenant_id, include_inconclusive=include_inconclusive
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    return len(rows)
