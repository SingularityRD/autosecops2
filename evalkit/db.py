"""Write a run to ``eval_runs`` / ``eval_results`` (infra/database/init/46_eval_qa_canary.sql).

One ``eval_runs`` row per suite (``suite`` = ``corpus-v1/<split>`` or
``injection-v1``) with the suite's report as ``metrics``, and one
``eval_results`` row per case. The tables are SQL-owned (no ORM model), so this
writes plain SQL through a SQLAlchemy session.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from core.contracts.verdict import CATEGORIES, VERDICTS
from evalkit.corpus import suite_db_name
from evalkit.runner import CaseResult
from evalkit.scoring import case_passed

DEFAULT_TENANT = "default"

INSERT_RUN = """
INSERT INTO eval_runs
    (id, tenant_id, suite, model, prompt_version, git_sha, status,
     config, metrics, triggered_by, started_at, finished_at)
VALUES
    (:id, :tenant_id, :suite, :model, :prompt_version, :git_sha, :status,
     CAST(:config AS JSONB), CAST(:metrics AS JSONB), :triggered_by,
     CAST(:started_at AS TIMESTAMPTZ), CAST(:finished_at AS TIMESTAMPTZ))
"""

INSERT_RESULT = """
INSERT INTO eval_results
    (run_id, tenant_id, case_id, expected_verdict, expected_category,
     actual_verdict, actual_category, confidence, passed, verdict,
     latency_ms, cost_usd, error)
VALUES
    (:run_id, :tenant_id, :case_id, :expected_verdict, :expected_category,
     :actual_verdict, :actual_category, :confidence, :passed,
     CAST(:verdict AS JSONB), :latency_ms, :cost_usd, :error)
"""


def _enum(value: Optional[str], allowed: Sequence[str]) -> Optional[str]:
    return value if value in allowed else None


def result_params(run_id: str, tenant_id: str, r: CaseResult) -> Dict[str, Any]:
    errored = bool(r.error)
    return {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "case_id": r.case_id,
        "expected_verdict": r.expected_verdict,
        "expected_category": _enum(r.expected_category, CATEGORIES),
        # An errored case has no answer; its placeholder verdict is not stored.
        "actual_verdict": None if errored else _enum(r.actual_verdict, VERDICTS),
        "actual_category": None if errored else _enum(r.actual_category, CATEGORIES),
        "confidence": None if errored else round(float(r.confidence), 3),
        "passed": case_passed(r),
        "verdict": None if r.verdict is None else json.dumps(r.verdict, sort_keys=True),
        "latency_ms": r.latency_ms,
        "cost_usd": r.cost_usd,
        "error": r.error,
    }


def write_run(
    session: Any,
    *,
    suite: str,
    results: Sequence[CaseResult],
    metrics: Mapping[str, Any],
    run: Mapping[str, Any],
    tenant_id: str = DEFAULT_TENANT,
    run_id: Optional[str] = None,
) -> str:
    """Insert one run and its results; returns the run id. Caller commits."""
    from sqlalchemy import text

    run_id = run_id or str(uuid.uuid4())
    session.execute(
        text(INSERT_RUN),
        {
            "id": run_id,
            "tenant_id": tenant_id,
            "suite": suite_db_name(suite),
            "model": run["backend"]["model"],
            "prompt_version": run["prompt_version"],
            "git_sha": run.get("git_sha"),
            "status": "completed",
            "config": json.dumps(dict(run), sort_keys=True, default=str),
            "metrics": json.dumps(dict(metrics), sort_keys=True),
            "triggered_by": run.get("triggered_by") or "evalkit",
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
        },
    )
    rows: List[Dict[str, Any]] = [result_params(run_id, tenant_id, r) for r in results]
    if rows:
        session.execute(text(INSERT_RESULT), rows)
    return run_id


def write_all(
    results_by_suite: Mapping[str, Sequence[CaseResult]],
    report: Mapping[str, Any],
    *,
    tenant_id: str = DEFAULT_TENANT,
    session_factory: Optional[Callable[[], Any]] = None,
) -> Dict[str, str]:
    """Write every suite in one transaction; returns ``{suite: run_id}``."""
    if session_factory is None:
        from core.storage.connection import get_db_session

        session_factory = get_db_session
    session = session_factory()
    try:
        ids = {
            suite: write_run(
                session,
                suite=suite,
                results=rs,
                metrics=report["suites"][suite],
                run=report["run"],
                tenant_id=tenant_id,
            )
            for suite, rs in results_by_suite.items()
        }
        session.commit()
        return ids
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
