"""Alert lane decisions are recorded per tenant in alert_lane_decisions (W2.2)."""

from __future__ import annotations

import json
import logging

import pytest

from core.lanes import decision_store
from core.lanes.alert_lanes import LANE_RULES, LANE_SMALL, LANE_VERDICT, LaneDecision, LaneHook

pytestmark = pytest.mark.unit


def _decision(**kw):
    base = dict(finding_id="f-1", tenant_id="acme", lane=LANE_SMALL, reason="low_difficulty", risk=0.2)
    base.update(kw)
    return LaneDecision(**base)


def test_row_carries_tenant_lane_rule_and_json():
    d = _decision(
        lane=LANE_RULES,
        reason="suppression_rule",
        factors=("severity:low",),
        rule={"kind": "suppression", "id": "r-1", "name": "scanner"},
        outcome={"suppressed": True, "recommended_action": "dismiss"},
    )
    row = decision_store.decision_row(d)
    assert row["tenant_id"] == "acme" and row["finding_id"] == "f-1" and row["lane"] == LANE_RULES
    assert (row["rule_kind"], row["rule_id"]) == ("suppression", "r-1")
    assert json.loads(row["factors"]) == ["severity:low"]
    assert json.loads(row["outcome"])["suppressed"] is True
    assert row["decided_at"] == d.decided_at


def test_row_without_rule_or_outcome():
    row = decision_store.decision_row(_decision(lane=LANE_VERDICT, reason="high_risk", verdict_run_id="run-9"))
    assert row["rule_kind"] is None and row["rule_id"] is None and row["outcome"] is None
    assert row["verdict_run_id"] == "run-9" and row["deferred_verdict"] is False


def test_record_decision_writes_the_row(monkeypatch):
    written = []
    monkeypatch.setattr(decision_store, "insert_decision", written.append)
    d = _decision()
    decision_store.record_decision(d)
    assert written == [d]


def test_record_decision_never_raises(monkeypatch, caplog):
    def down(_d):
        raise RuntimeError("db down")

    monkeypatch.setattr(decision_store, "insert_decision", down)
    with caplog.at_level(logging.WARNING, logger="core.lanes.decision_store"):
        decision_store.record_decision(_decision())
    assert "not written" in caplog.text


def test_daemon_hook_records_to_the_table(monkeypatch):
    from core.config import get_settings

    monkeypatch.setattr(get_settings(), "alert_lanes_small_provider", "")
    monkeypatch.setattr(get_settings(), "alert_lanes_small_model", "")
    lanes = LaneHook(enabled=lambda: True)._build()
    assert lanes._recorder is decision_store.record_decision


@pytest.mark.external_service
@pytest.mark.database
def test_init_sql_accepts_a_decision_and_refuses_a_bad_lane():
    from pathlib import Path

    from sqlalchemy import text
    from sqlalchemy.exc import IntegrityError

    from core.storage.connection import get_db_manager

    sql = (
        Path(__file__).resolve().parents[3] / "infra" / "database" / "init" / "56_alert_lane_decisions.sql"
    ).read_text(encoding="utf-8")
    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            conn.execute(text(sql))
            conn.execute(text(sql))  # rerunnable
            d = _decision(
                lane=LANE_RULES,
                reason="known_playbook",
                rule={"kind": "playbook", "id": "eicar", "name": "eicar"},
                outcome={"recommended_action": "dismiss"},
            )
            conn.execute(text(decision_store._INSERT), decision_store.decision_row(d))
            got = conn.execute(
                text("SELECT tenant_id, lane, rule_kind, outcome FROM alert_lane_decisions WHERE finding_id = 'f-1'")
            ).one()
            assert (got.tenant_id, got.lane, got.rule_kind) == ("acme", LANE_RULES, "playbook")
            assert got.outcome == {"recommended_action": "dismiss"}

            sp = conn.begin_nested()
            with pytest.raises(IntegrityError):
                conn.execute(
                    text(decision_store._INSERT), decision_store.decision_row(_decision(lane="dropped"))
                )
            sp.rollback()
        finally:
            tx.rollback()
