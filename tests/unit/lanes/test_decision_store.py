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


def test_settling_decisions_skips_the_query_for_no_ids(monkeypatch):
    def boom():
        raise AssertionError("no query for an empty batch")

    monkeypatch.setattr(decision_store, "_session_scope", boom)
    assert decision_store.settling_decisions([None, ""]) == {}


@pytest.mark.external_service
@pytest.mark.database
def test_query_settling_reads_rules_and_enqueued_verdicts_only():
    """W0.15: what the backfill treats as already settled."""
    from pathlib import Path

    from sqlalchemy import text

    from core.storage.connection import get_db_manager

    sql = (
        Path(__file__).resolve().parents[3] / "infra" / "database" / "init" / "56_alert_lane_decisions.sql"
    ).read_text(encoding="utf-8")
    rows = [
        _decision(finding_id="w15-r", tenant_id="default", lane=LANE_RULES, reason="suppression_rule",
                  rule={"kind": "suppression", "id": "r-1", "name": "x"}, decided_at="2026-10-14T10:00:00+00:00"),
        _decision(finding_id="w15-r", tenant_id="default", lane=LANE_RULES, reason="suppression_rule",
                  rule={"kind": "suppression", "id": "r-2", "name": "y"}, decided_at="2026-10-14T10:05:00+00:00"),
        # Round 2: the latest decision is the finding's routing. Re-routed to
        # the model after a rules decision: a triage is owed, not settled.
        _decision(finding_id="w15-rs", tenant_id="default", lane=LANE_RULES, reason="suppression_rule",
                  decided_at="2026-10-14T10:00:00+00:00"),
        _decision(finding_id="w15-rs", tenant_id="default", decided_at="2026-10-14T10:05:00+00:00"),
        # ... and the other way round: settled by the later rules decision.
        _decision(finding_id="w15-sr", tenant_id="default", decided_at="2026-10-14T10:00:00+00:00"),
        _decision(finding_id="w15-sr", tenant_id="default", lane=LANE_RULES, reason="suppression_rule",
                  decided_at="2026-10-14T10:05:00+00:00"),
        _decision(finding_id="w15-v", tenant_id="default", lane=LANE_VERDICT, reason="high_risk",
                  verdict_run_id="run-1"),
        _decision(finding_id="w15-d", tenant_id="default", lane=LANE_VERDICT, reason="high_risk",
                  deferred_verdict=True),
        _decision(finding_id="w15-s", tenant_id="default"),
        _decision(finding_id="w15-o", tenant_id="other", lane=LANE_RULES, reason="suppression_rule"),
    ]
    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            conn.execute(text(sql))
            for d in rows:
                conn.execute(text(decision_store._INSERT), decision_store.decision_row(d))
            got = decision_store.query_settling(
                conn,
                ["w15-r", "w15-v", "w15-d", "w15-s", "w15-o", "w15-rs", "w15-sr", "w15-none"],
                "default",
            )
            assert set(got) == {"w15-r", "w15-v", "w15-sr"}
            assert got["w15-r"].rule == {"kind": "suppression", "id": "r-2"}
            from datetime import datetime, timezone

            latest = datetime.fromisoformat(got["w15-r"].decided_at)
            assert latest == datetime(2026, 10, 14, 10, 5, tzinfo=timezone.utc)
            assert got["w15-sr"].lane == LANE_RULES
            assert got["w15-v"].verdict_run_id == "run-1"
        finally:
            tx.rollback()


class _UndefinedTable(Exception):
    pgcode = "42P01"


@pytest.mark.parametrize(
    "error",
    [
        _UndefinedTable('relation "alert_lane_decisions" does not exist'),
        RuntimeError('relation "alert_lane_decisions" does not exist'),
    ],
)
def test_settling_decisions_names_a_missing_table(monkeypatch, error):
    """W0.15 round 2: 56_*.sql not applied is told apart from an outage."""
    from sqlalchemy.exc import ProgrammingError

    def scope():
        raise ProgrammingError("SELECT ... FROM alert_lane_decisions", {}, error)

    monkeypatch.setattr(decision_store, "_session_scope", scope)
    with pytest.raises(decision_store.DecisionTableMissing):
        decision_store.settling_decisions(["f-1"])


def test_settling_decisions_passes_an_outage_through(monkeypatch):
    def scope():
        raise ConnectionError("could not connect to server")

    monkeypatch.setattr(decision_store, "_session_scope", scope)
    with pytest.raises(ConnectionError):
        decision_store.settling_decisions(["f-1"])


class _SqlState(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.pgcode = code


@pytest.mark.parametrize(
    "code, msg",
    [
        ("42703", 'column "verdict_run_id" of relation "alert_lane_decisions" does not exist'),
        ("42883", "operator does not exist: integer = text"),
        ("42501", "permission denied for table alert_lane_decisions"),
    ],
)
def test_settling_decisions_takes_only_42p01_for_a_missing_table(monkeypatch, code, msg):
    """W0.18: SQLAlchemy's message quotes the SQL (FROM alert_lane_decisions);
    another SQLSTATE must not read as a missing table and fail the backfill open."""
    from sqlalchemy.exc import ProgrammingError

    def scope():
        raise ProgrammingError(
            "SELECT ... FROM alert_lane_decisions WHERE ... does not exist", {}, _SqlState(code, msg)
        )

    monkeypatch.setattr(decision_store, "_session_scope", scope)
    with pytest.raises(ProgrammingError):
        decision_store.settling_decisions(["f-1"])


@pytest.mark.external_service
@pytest.mark.database
def test_real_postgres_sqlstates_classify_the_missing_table_only(monkeypatch):
    """W0.18: against a real Postgres, in a throwaway schema that the rollback removes."""
    import contextlib
    import uuid

    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    from core.storage.connection import get_db_manager

    suffix = uuid.uuid4().hex[:10]
    schema, role = f"w018_tmp_{suffix}", f"w018_noperm_{suffix}"

    def run(conn, setup):
        sp = conn.begin_nested()
        try:
            for stmt in setup:
                conn.execute(text(stmt))

            @contextlib.contextmanager
            def scope():
                yield conn

            monkeypatch.setattr(decision_store, "_session_scope", scope)
            try:
                decision_store.settling_decisions(["f-1"])
            except decision_store.DecisionTableMissing:
                return "missing"
            except DBAPIError as exc:
                return getattr(exc.orig, "pgcode", None)
            return "ok"
        finally:
            sp.rollback()

    with get_db_manager().engine.connect() as conn:
        tx = conn.begin()
        try:
            conn.execute(text(f"CREATE SCHEMA {schema}"))
            conn.execute(text(f"SET LOCAL search_path TO {schema}"))
            assert run(conn, []) == "missing"  # 42P01
            assert run(conn, ["CREATE TABLE alert_lane_decisions (finding_id text)"]) == "42703"
            cols = (
                "id bigserial, finding_id integer, tenant_id text, lane text, reason text, risk real,"
                " factors jsonb, rule_kind text, rule_id text, outcome jsonb, deferred_verdict boolean,"
                " degraded_from text, verdict_run_id text, model text, decided_at timestamptz"
            )
            assert run(conn, [f"CREATE TABLE alert_lane_decisions ({cols})"]) == "42883"
            assert (
                run(
                    conn,
                    [
                        f"CREATE TABLE alert_lane_decisions ({cols.replace('finding_id integer', 'finding_id text')})",
                        f"CREATE ROLE {role}",
                        f"GRANT USAGE ON SCHEMA {schema} TO {role}",
                        f"SET LOCAL ROLE {role}",
                    ],
                )
                == "42501"
            )
        finally:
            tx.rollback()
