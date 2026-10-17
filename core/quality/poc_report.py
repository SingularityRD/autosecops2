"""The POC report: what this install measured over a window (W0.49).

For a proof of concept the customer needs one document that says, on their own
alerts, what AutoSecOps did: how much came in from where, what triage decided,
what analysts found when they checked it, what the canaries showed, what was
proposed and approved, and the latest offline eval runs. Every figure here is
counted from this install's tables; a section whose tables are missing or empty
says so rather than showing a number it does not have. Canary findings are left
out of the operational counts.

``build`` returns a dict; ``to_markdown`` renders it. Served by
``GET /api/qa/poc-report`` (core/quality/qa_router.py).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.time import utcnow

MAX_DAYS = 365


def _not_canary(session: Session, column: str) -> str:
    from core.storage.canary_exclusion import canary_table_present

    if not canary_table_present(session):
        return ""
    return (
        f" AND NOT EXISTS (SELECT 1 FROM canary_injections ci"
        f" WHERE ci.finding_id = {column})"
    )


def _rows(session: Session, sql: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [dict(r) for r in session.execute(text(sql), params).mappings()]


def _section(session: Session, fn: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
    """One section; a missing table or column makes it unavailable, not a 500."""
    try:
        with session.begin_nested():
            return {"available": True, **fn()}
    except Exception as exc:  # noqa: BLE001 - one section must not sink the report
        return {"available": False, "why": type(exc).__name__}


def build(
    session: Session, *, days: int = 30, now: Optional[datetime] = None
) -> Dict[str, Any]:
    days = max(1, min(int(days), MAX_DAYS))
    now = now or utcnow()
    since = now - timedelta(days=days)
    p = {"since": since}
    nc = _not_canary(session, "f.finding_id")

    def intake():
        rows = _rows(
            session,
            "SELECT f.data_source AS source, count(*) AS n FROM findings f"
            f" WHERE f.created_at >= :since{nc} GROUP BY 1 ORDER BY 2 DESC",
            p,
        )
        return {"total": sum(r["n"] for r in rows), "by_source": rows}

    def triage():
        rows = _rows(
            session,
            "SELECT COALESCE(f.ai_enrichment->'ai_triage'->'verdict'->>'verdict',"
            " CASE WHEN f.ai_enrichment ? 'ai_triage_error' THEN 'failed' END,"
            " 'not_triaged') AS verdict, count(*) AS n FROM findings f"
            f" WHERE f.created_at >= :since{nc} GROUP BY 1 ORDER BY 2 DESC",
            p,
        )
        return {"by_verdict": rows}

    def lanes():
        rows = _rows(
            session,
            "SELECT d.lane, count(*) AS n FROM alert_lane_decisions d"
            " WHERE d.decided_at >= :since"
            + _not_canary(session, "d.finding_id")
            + " GROUP BY 1 ORDER BY 2 DESC",
            p,
        )
        return {"by_lane": rows}

    def review():
        from core.quality import sampling

        card = sampling.scorecard(session)
        reviewed = sum(c["reviewed"] for c in card["categories"])
        disagreements = sum(c["disagreements"] for c in card["categories"])
        return {
            "reviewed": reviewed,
            "disagreements": disagreements,
            "agreement_rate": (
                round((reviewed - disagreements) / reviewed, 4) if reviewed else None
            ),
            "target": card["target"],
            "confidence": card["confidence"],
            "categories": [
                {
                    k: c[k]
                    for k in (
                        "category",
                        "reviewed",
                        "misses",
                        "fn_upper_bound",
                        "status",
                    )
                }
                for c in card["categories"]
            ],
            "note": "All reviews to date (simple-random samples), not only the window.",
        }

    def canaries():
        rows = _rows(
            session,
            "SELECT COALESCE(outcome, 'pending') AS outcome, count(*) AS n"
            " FROM canary_injections WHERE injected_at >= :since GROUP BY 1 ORDER BY 2 DESC",
            p,
        )
        return {"by_outcome": rows}

    def cases():
        created = _rows(
            session,
            "SELECT priority, count(*) AS n FROM cases WHERE created_at >= :since"
            " GROUP BY 1 ORDER BY 2 DESC",
            p,
        )
        closed = session.execute(
            text(
                "SELECT count(*) FROM cases WHERE created_at >= :since"
                " AND status IN ('resolved', 'closed')"
            ),
            p,
        ).scalar()
        return {
            "created": sum(r["n"] for r in created),
            "closed": int(closed or 0),
            "by_priority": created,
        }

    def actions():
        rows = _rows(
            session,
            "SELECT action_type, status, count(*) AS n FROM approval_actions"
            " WHERE created_at >= :since GROUP BY 1, 2 ORDER BY 3 DESC",
            p,
        )
        return {"by_type_and_status": rows}

    def evals():
        rows = _rows(
            session,
            "SELECT suite, model, prompt_version, status, metrics, finished_at"
            " FROM eval_runs ORDER BY finished_at DESC NULLS LAST LIMIT 10",
            {},
        )
        for row in rows:
            if isinstance(row.get("finished_at"), datetime):
                row["finished_at"] = row["finished_at"].isoformat()
        return {"latest": rows}

    return {
        "window": {"days": days, "since": since.isoformat(), "until": now.isoformat()},
        "generated_at": now.isoformat(),
        "intake": _section(session, intake),
        "triage": _section(session, triage),
        "lanes": _section(session, lanes),
        "analyst_review": _section(session, review),
        "canaries": _section(session, canaries),
        "cases": _section(session, cases),
        "response_actions": _section(session, actions),
        "offline_eval": _section(session, evals),
    }


def _table(rows: List[Dict[str, Any]], columns: List[str]) -> List[str]:
    if not rows:
        return ["_None in this window._", ""]
    lines = ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(c, "")) for c in columns) + " |")
    return lines + [""]


def _metric(metrics: Any, *keys: str) -> str:
    value = metrics
    for key in keys:
        if not isinstance(value, dict):
            return "—"
        value = value.get(key)
    if isinstance(value, dict) and "value" in value:
        value = value["value"]
    return "—" if value is None else str(value)


def to_markdown(report: Dict[str, Any]) -> str:
    w = report["window"]
    out = [
        "# AutoSecOps POC report",
        "",
        f"Window: last {w['days']} days ({w['since'][:10]} – {w['until'][:10]}, UTC). "
        f"Generated {report['generated_at'][:16]} UTC. Every figure is counted from "
        "this install; canary findings are left out of the operational counts.",
        "",
    ]

    def head(title: str, section: Dict[str, Any]) -> bool:
        out.extend([f"## {title}", ""])
        if not section.get("available"):
            out.extend([f"_Not available on this install ({section.get('why')})._", ""])
            return False
        return True

    s = report["intake"]
    if head("Alerts received", s):
        out.append(f"Total: **{s['total']}**")
        out.append("")
        out.extend(_table(s["by_source"], ["source", "n"]))
    s = report["triage"]
    if head("AI triage verdicts", s):
        out.extend(_table(s["by_verdict"], ["verdict", "n"]))
    s = report["lanes"]
    if head("Alert lanes", s):
        out.extend(_table(s["by_lane"], ["lane", "n"]))
    s = report["analyst_review"]
    if head("Analyst review of AI decisions (QA sampling)", s):
        rate = s["agreement_rate"]
        out.append(
            f"Reviewed: **{s['reviewed']}**, disagreements: **{s['disagreements']}**, "
            f"agreement: **{'—' if rate is None else f'{rate:.1%}'}**. "
            f"False-negative upper bound at {s['confidence']:.0%} confidence against a "
            f"{s['target']:.0%} target, per category. {s['note']}"
        )
        out.append("")
        out.extend(
            _table(
                s["categories"],
                ["category", "reviewed", "misses", "fn_upper_bound", "status"],
            )
        )
    s = report["canaries"]
    if head("Known-answer canaries", s):
        out.extend(_table(s["by_outcome"], ["outcome", "n"]))
    s = report["cases"]
    if head("Cases", s):
        out.append(
            f"Created: **{s['created']}**, resolved or closed: **{s['closed']}**"
        )
        out.append("")
        out.extend(_table(s["by_priority"], ["priority", "n"]))
    s = report["response_actions"]
    if head("Response actions proposed", s):
        out.extend(_table(s["by_type_and_status"], ["action_type", "status", "n"]))
    s = report["offline_eval"]
    if head("Offline evaluation runs (evalkit)", s):
        rows = [
            {
                "suite": r.get("suite"),
                "model": r.get("model"),
                "prompt": r.get("prompt_version"),
                "f1": _metric(r.get("metrics"), "overall", "f1"),
                "asr": _metric(r.get("metrics"), "asr"),
                "finished": (r.get("finished_at") or "")[:16],
            }
            for r in s["latest"]
        ]
        out.extend(_table(rows, ["suite", "model", "prompt", "f1", "asr", "finished"]))
    return "\n".join(out).rstrip() + "\n"
