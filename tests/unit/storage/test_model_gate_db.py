"""The model-change gate against real eval_runs rows (W0.53)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.quality import model_gate
from core.storage.connection import get_db_manager

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

INIT_46 = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "46_eval_qa_canary.sql"
)
PV = "daemon-triage-w053"


@pytest.fixture()
def session():
    manager = get_db_manager()
    if manager.engine is None:
        manager.initialize()
    with manager.engine.connect() as conn:
        tx = conn.begin()
        try:
            if conn.execute(text("SELECT to_regclass('eval_runs')")).scalar() is None:
                conn.execute(text(INIT_46.read_text(encoding="utf-8")))
            with Session(bind=conn, join_transaction_mode="create_savepoint") as s:
                yield s
        finally:
            tx.rollback()


def _run(s, suite, model, metrics, *, pv=PV + "@abc123", minutes_ago=0):
    s.execute(
        text(
            "INSERT INTO eval_runs (id, tenant_id, suite, model, prompt_version, status,"
            " config, metrics, triggered_by, started_at, finished_at) VALUES"
            " (gen_random_uuid(), 'default', :suite, :model, :pv, 'completed', '{}'::jsonb,"
            " CAST(:m AS jsonb), 'test', now(), now() - make_interval(mins => :ago))"
        ),
        {
            "suite": suite,
            "model": model,
            "pv": pv,
            "m": json.dumps(metrics),
            "ago": minutes_ago,
        },
    )


def _good(s, model="ollama/qwen2.5:7b"):
    _run(s, "corpus-v1/test", model, {"overall": {"f1": 0.91}})
    _run(s, "corpus-v1/test_unseen", model, {"overall": {"f1": 0.88}})
    _run(s, "injection-v1", model, {"asr": {"value": 0.03}})


def test_a_model_with_good_runs_passes(session):
    _good(session)
    result = model_gate.evaluate(session, "qwen2.5:7b", PV)
    assert result["state"] == "passed", result
    assert result["suites"]["injection-v1"]["asr"] == 0.03


def test_no_runs_is_not_evaluated(session):
    result = model_gate.evaluate(session, "never-run-model", PV)
    assert result["state"] == "not_evaluated"
    assert len(result["reasons"]) == 3


def test_a_high_attack_success_rate_fails(session):
    _good(session)
    _run(
        session,
        "injection-v1",
        "ollama/qwen2.5:7b",
        {"asr": {"value": 0.2}},
        minutes_ago=-5,
    )
    result = model_gate.evaluate(session, "qwen2.5:7b", PV)
    assert result["state"] == "failed"
    assert any("attack success rate" in r for r in result["reasons"])


def test_the_latest_run_counts_and_another_prompt_does_not(session):
    _run(session, "corpus-v1/test", "m1", {"overall": {"f1": 0.5}}, minutes_ago=60)
    _run(session, "corpus-v1/test", "m1", {"overall": {"f1": 0.95}})
    _run(session, "corpus-v1/test_unseen", "m1", {"overall": {"f1": 0.95}})
    _run(session, "injection-v1", "m1", {"asr": {"value": 0.0}}, pv="other-prompt@x")
    result = model_gate.evaluate(session, "m1", PV)
    assert result["suites"]["corpus-v1/test"]["f1"] == 0.95
    assert result["state"] == "not_evaluated"  # the injection run is another prompt


def test_a_failing_customer_run_fails_the_gate(session):
    _good(session)
    _run(session, "customer", "ollama/qwen2.5:7b", {"overall": {"f1": 0.6}})
    assert model_gate.evaluate(session, "qwen2.5:7b", PV)["state"] == "failed"


def test_thresholds_are_settings(monkeypatch):
    from core.config import get_settings

    monkeypatch.setattr(get_settings(), "model_gate_min_f1", 0.7)
    monkeypatch.setattr(get_settings(), "model_gate_max_asr", 0.1)
    assert model_gate.thresholds() == {"min_f1": 0.7, "max_asr": 0.1}
