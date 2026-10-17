"""POC report and reviewed-findings export against a real Postgres (W0.49).

One rolled-back transaction: findings with and without a triage verdict, a
canary, an analyst review, a case and an approval; the report counts them and
the export turns the review into a labelled eval case.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.quality import poc_report, qa_router
from core.routing import request_unit_of_work
from core.storage.connection import get_db_manager
from evalkit.corpus import load_cases_file
from evalkit.reviewed import reviewed_rows

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

SOURCE = "w049-src"
INIT_46 = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "46_eval_qa_canary.sql"
)
VERDICT = {
    "verdict": "malicious",
    "confidence": 0.9,
    "category": "network",
    "cited_fields": [],
    "gaps": [],
    "model": "m",
    "prompt_version": "p",
}


def _finding(s, fid, enrichment=None):
    s.execute(
        text(
            "INSERT INTO findings (finding_id, data_source, title, description,"
            " entity_context, timestamp, severity, status, ai_enrichment, created_at,"
            " updated_at) VALUES (:f, :src, :t, 'd', '{}'::jsonb, now(), 'high', 'new',"
            " CAST(:e AS jsonb), now(), now())"
        ),
        {
            "f": fid,
            "src": SOURCE,
            "t": f"title {fid}",
            "e": json.dumps(enrichment) if enrichment else None,
        },
    )


@pytest.fixture()
def session():
    manager = get_db_manager()
    if manager.engine is None:
        manager.initialize()
    with manager.engine.connect() as conn:
        tx = conn.begin()
        try:
            if conn.execute(text("SELECT to_regclass('qa_samples')")).scalar() is None:
                # A create_all database has no init-SQL tables; 46 brings
                # eval_runs, qa_samples and canary_injections (rolled back).
                conn.execute(text(INIT_46.read_text(encoding="utf-8")))
            with Session(bind=conn, join_transaction_mode="create_savepoint") as s:
                _finding(s, "w049-f1", {"ai_triage": {"verdict": VERDICT}})
                _finding(s, "w049-f2", {"ai_triage_error": "timeout"})
                _finding(s, "w049-f3")
                _finding(s, "w049-canary", {"ai_triage": {"verdict": VERDICT}})
                s.execute(
                    text(
                        "INSERT INTO canary_injections (tenant_id, marker, canary_kind,"
                        " expected_verdict, payload, injected_at, finding_id)"
                        " VALUES ('default', 'w049-m', 'known_malicious', 'malicious',"
                        " '{}'::jsonb, now(), 'w049-canary')"
                    )
                )
                s.execute(
                    text(
                        "INSERT INTO ai_decision_logs (decision_id, agent_id, finding_id,"
                        " decision_type, confidence_score, reasoning, recommended_action,"
                        " timestamp) VALUES ('w049-d1', 'triage', 'w049-f1', 'triage', 0.9,"
                        " 'r', 'monitor', now())"
                    )
                )
                s.execute(
                    text(
                        "INSERT INTO qa_samples (tenant_id, sampling_kind,"
                        " inclusion_probability, subject_kind, subject_id, verdict,"
                        " sampled_at, reviewer, reviewed_at, review_verdict, agrees)"
                        " VALUES ('default', 'simple_random', 0.1, 'ai_decision', 'w049-d1',"
                        " CAST(:v AS jsonb), now(), 'ayse', now(), 'benign', false)"
                    ),
                    {"v": json.dumps(VERDICT)},
                )
                yield s
        finally:
            tx.rollback()


def test_the_report_counts_this_install(session):
    report = poc_report.build(session, days=7)
    intake = report["intake"]
    assert intake["available"] is True
    mine = next(r for r in intake["by_source"] if r["source"] == SOURCE)
    assert mine["n"] == 3  # the canary is left out
    verdicts = {r["verdict"]: r["n"] for r in report["triage"]["by_verdict"]}
    assert verdicts.get("malicious", 0) >= 1
    assert verdicts.get("failed", 0) >= 1
    assert verdicts.get("not_triaged", 0) >= 1
    assert report["analyst_review"]["available"] is True
    assert report["window"]["days"] == 7
    md = poc_report.to_markdown(report)
    assert md.startswith("# AutoSecOps POC report")
    assert "## Analyst review of AI decisions (QA sampling)" in md
    assert "| source | n |" in md


def test_a_missing_table_is_a_section_not_an_error(session):
    session.execute(text("ALTER TABLE eval_runs RENAME TO eval_runs_w049"))
    report = poc_report.build(session)
    assert report["offline_eval"] == {"available": False, "why": "ProgrammingError"}
    assert report["intake"]["available"] is True
    assert "_Not available on this install" in poc_report.to_markdown(report)


def test_the_route_serves_json_and_a_markdown_download(authenticate_app, session):
    app = FastAPI()
    authenticate_app(app)
    app.include_router(qa_router.router, prefix=qa_router.ROUTER_META.prefix)
    app.dependency_overrides[request_unit_of_work] = lambda: session
    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/api/qa/poc-report?days=7").json()["window"]["days"] == 7
    md = client.get("/api/qa/poc-report?format=markdown")
    assert md.status_code == 200
    assert "attachment" in md.headers["content-disposition"]
    assert md.text.startswith("# AutoSecOps POC report")
    assert client.get("/api/qa/poc-report?days=0").status_code == 422


def test_reviewed_findings_become_labelled_cases(session, tmp_path):
    rows = [
        r for r in reviewed_rows(session) if r["alert"]["finding_id"].startswith("w049")
    ]
    assert len(rows) == 1
    row = rows[0]
    assert row["labels"] == {"verdict": "benign"}  # the analyst's verdict, not the AI's
    assert row["alert"]["title"] == "title w049-f1"
    assert "ai_enrichment" not in row["alert"]
    assert row["meta"]["reviewer"] == "ayse"
    path = tmp_path / "cases.jsonl"
    path.write_text(json.dumps(row) + "\n")
    [case] = load_cases_file(path)
    assert case.suite == "customer" and case.expected_verdict == "benign"
