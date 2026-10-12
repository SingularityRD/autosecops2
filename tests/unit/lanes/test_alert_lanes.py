"""Alert lane decisions (W2.2): rules / small model / verdict, never a drop."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.lanes.alert_lanes import (
    LANE_RULES,
    LANE_SMALL,
    LANE_VERDICT,
    AlertLanes,
    BudgetPressure,
    KnownPlaybook,
    LaneThresholds,
    SuppressionRule,
    decide_lane,
    load_thresholds,
    matches,
    score_risk,
    thresholds_from_mapping,
)
from core.llm.cost.budget import BudgetExceeded

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
REPO = Path(__file__).resolve().parents[3]


def rule(name="scanner", match=None, tenant="default", expires_in=None, enabled=True):
    return SuppressionRule(
        id=f"id-{name}",
        tenant_id=tenant,
        name=name,
        match=match if match is not None else {"data_source": "nessus"},
        reason="known scanner",
        enabled=enabled,
        expires_at=None if expires_in is None else NOW + expires_in,
    )


PLAYBOOK = KnownPlaybook(
    "eicar", {"title": {"contains": "eicar"}}, "dismiss", "test file"
)
TH = LaneThresholds(known_playbooks=(PLAYBOOK,), high_risk_sources=frozenset({"edr"}))


def f(**kw):
    base = {"finding_id": "f-1", "severity": "low", "data_source": "siem"}
    base.update(kw)
    return base


# --- table-driven lane decisions ---------------------------------------------

CASES = [
    # (id, finding, rules, pressure, verdict_available, lane, reason, deferred)
    ("low_is_small", f(), [], False, True, LANE_SMALL, "low_difficulty", False),
    ("medium_is_small", f(severity="medium"), [], False, True, LANE_SMALL, "low_difficulty", False),
    ("critical_is_verdict", f(severity="critical"), [], False, True, LANE_VERDICT, "verdict_severity", False),
    (
        "high_plus_critical_asset",
        f(severity="high", entity_context={"criticality": "critical"}),
        [], False, True, LANE_VERDICT, "high_risk", False,
    ),
    (
        "high_risk_source_and_low_confidence",
        f(severity="high", data_source="edr", triage_confidence=0.4),
        [], False, True, LANE_VERDICT, "high_risk", False,
    ),
    (
        "high_with_confident_prior_stays_small",
        f(severity="high", verdict={"verdict": "benign", "confidence": 0.95}),
        [], False, True, LANE_SMALL, "low_difficulty", False,
    ),
    (
        "inconclusive_prior_escalates",
        f(severity="high", verdict={"verdict": "inconclusive", "confidence": 0.5}),
        [], False, True, LANE_VERDICT, "high_risk", False,
    ),
    ("suppressed", f(data_source="nessus", severity="high"), [rule()], False, True, LANE_RULES, "suppression_rule", False),
    (
        "critical_never_suppressed",
        f(data_source="nessus", severity="critical"),
        [rule()], False, True, LANE_VERDICT, "verdict_severity", False,
    ),
    ("other_tenant_rule_ignored", f(data_source="nessus"), [rule(tenant="acme")], False, True, LANE_SMALL, "low_difficulty", False),
    ("disabled_rule_ignored", f(data_source="nessus"), [rule(enabled=False)], False, True, LANE_SMALL, "low_difficulty", False),
    ("playbook", f(title="EICAR test string"), [], False, True, LANE_RULES, "known_playbook", False),
    ("budget_degrades_verdict", f(severity="critical"), [], True, True, LANE_SMALL, "budget_pressure", True),
    ("budget_leaves_small_alone", f(), [], True, True, LANE_SMALL, "low_difficulty", False),
    ("budget_keeps_rules", f(data_source="nessus"), [rule()], True, True, LANE_RULES, "suppression_rule", False),
    ("no_verdict_lane_degrades", f(severity="critical"), [], False, False, LANE_SMALL, "verdict_lane_unavailable", True),
]


@pytest.mark.parametrize(
    "finding,rules,pressure,available,lane,reason,deferred",
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_lane_decisions(finding, rules, pressure, available, lane, reason, deferred):
    d = decide_lane(
        finding,
        now=NOW,
        rules=rules,
        thresholds=TH,
        budget_pressure=pressure,
        verdict_available=available,
    )
    assert (d.lane, d.reason, d.deferred_verdict) == (lane, reason, deferred)
    assert d.tenant_id == "default"
    if deferred:
        assert d.degraded_from == LANE_VERDICT


def test_suppression_outcome_names_the_rule():
    d = decide_lane(f(data_source="nessus"), now=NOW, rules=[rule()])
    assert d.rule == {"kind": "suppression", "id": "id-scanner", "name": "scanner"}
    assert d.outcome["suppressed"] is True
    assert d.outcome["recommended_action"] == "dismiss"


def test_critical_suppression_is_noted_in_factors():
    d = decide_lane(f(data_source="nessus", severity="critical"), now=NOW, rules=[rule()])
    assert "suppression_ignored:scanner" in d.factors


# --- suppression expiry -----------------------------------------------------


@pytest.mark.parametrize(
    "expires_in,suppressed",
    [
        (None, True),
        (timedelta(minutes=5), True),
        (timedelta(seconds=0), False),  # expires_at == now: expired
        (timedelta(minutes=-1), False),
    ],
)
def test_suppression_expiry(expires_in, suppressed):
    d = decide_lane(f(data_source="nessus"), now=NOW, rules=[rule(expires_in=expires_in)])
    assert (d.lane == LANE_RULES) is suppressed


def test_naive_expiry_is_read_as_utc():
    r = rule()
    r = SuppressionRule(**{**r.__dict__, "expires_at": (NOW - timedelta(minutes=1)).replace(tzinfo=None)})
    assert not r.active(NOW)


# --- predicate documents ----------------------------------------------------


@pytest.mark.parametrize(
    "match,expected",
    [
        ({}, False),  # empty never matches
        ({"data_source": "NESSUS"}, True),
        ({"data_source": ["x", "nessus"]}, True),
        ({"data_source": {"in": ["nessus"]}}, True),
        ({"title": {"contains": "scan"}}, True),
        ({"title": {"regex": ".*"}}, False),  # unknown operator
        ({"entity_context.hostname": "web-1"}, True),
        ({"entity_context.src_ips": "10.0.0.9"}, True),  # any list element
        ({"entity_context.hostname": "web-2"}, False),
        ({"missing.path": "x"}, False),
        ({"data_source": "nessus", "severity": "high"}, False),  # all keys must hold
    ],
)
def test_matches(match, expected):
    finding = {
        "data_source": "nessus",
        "severity": "low",
        "title": "Weekly Scan",
        "entity_context": {"hostname": "web-1", "src_ips": ["10.0.0.1", "10.0.0.9"]},
    }
    assert matches(match, finding) is expected


def test_risk_is_clamped_and_explained():
    score, factors = score_risk(
        f(severity="critical", data_source="edr", entity_context={"criticality": "critical"},
          ai_triage_error="timeout", triage_confidence=0.1),
        TH,
    )
    assert score == 1.0
    assert {"severity:critical", "entity_criticality:critical", "inconclusive"} <= set(factors)


# --- thresholds from INTENT.md ---------------------------------------------


def test_shipped_intent_thresholds_equal_code_defaults():
    assert load_thresholds(REPO / "INTENT.md") == LaneThresholds()


def test_thresholds_from_mapping_and_bad_values(caplog):
    th = thresholds_from_mapping(
        {
            "verdict_risk_threshold": 0.4,
            "verdict_severities": ["Critical", "high"],
            "low_confidence": 7,  # out of range -> default
            "suppress_max_severity": "medium",
            "known_playbooks": [
                {"name": "eicar", "match": {"title": "x"}, "recommended_action": "dismiss"},
                {"name": "bad", "match": {}, "recommended_action": "dismiss"},
                {"name": "bad2", "match": {"a": 1}, "recommended_action": "wipe"},
            ],
            "nonsense": 1,
        }
    )
    assert th.verdict_risk_threshold == 0.4
    assert th.verdict_severities == {"critical", "high"}
    assert th.low_confidence == LaneThresholds().low_confidence
    assert th.suppress_max_severity == "medium"
    assert [p.name for p in th.known_playbooks] == ["eicar"]
    assert "nonsense" in caplog.text


def test_missing_intent_file_uses_defaults(tmp_path):
    assert load_thresholds(tmp_path / "nope.md") == LaneThresholds()


def test_thresholds_are_enforced(tmp_path):
    path = tmp_path / "INTENT.md"
    path.write_text("---\nalert_lanes:\n  verdict_risk_threshold: 0.1\n---\n", encoding="utf-8")
    th = load_thresholds(path)
    assert decide_lane(f(severity="medium"), now=NOW, thresholds=th, verdict_available=True).lane == LANE_VERDICT


# --- router: enqueue, degrade, defer, record, never drop --------------------


class Recorder:
    def __init__(self):
        self.rows = []

    def __call__(self, decision):
        self.rows.append(decision)


def router(**kw):
    kw.setdefault("clock", lambda: NOW)
    kw.setdefault("thresholds", TH)
    return AlertLanes(**kw)


@pytest.mark.asyncio
async def test_verdict_lane_enqueues_and_records_run_id():
    calls, rec = [], Recorder()

    async def enqueue(finding, decision):
        calls.append(finding["finding_id"])
        return "run-1"

    lanes = router(verdict_enqueuer=enqueue, verdict_enabled=True, recorder=rec)
    d = await lanes.route(f(severity="critical"))
    assert (d.lane, d.verdict_run_id) == (LANE_VERDICT, "run-1")
    assert calls == ["f-1"]
    assert rec.rows == [d]


@pytest.mark.asyncio
async def test_verdict_flag_off_degrades_even_with_enqueuer():
    lanes = router(verdict_enqueuer=lambda *_: "run", verdict_enabled=False)
    d = await lanes.route(f(severity="critical"))
    assert (d.lane, d.deferred_verdict, d.reason) == (LANE_SMALL, True, "verdict_lane_unavailable")
    assert lanes.deferred_count == 0  # nothing can drain it; the enrichment mark is durable


@pytest.mark.asyncio
async def test_budget_pressure_defers_then_drains_when_it_lifts():
    pressure = {"on": True}
    sent = []
    lanes = router(
        budget_pressure=lambda: pressure["on"],
        verdict_enqueuer=lambda finding, d: sent.append((finding["finding_id"], d.lane)) or "r",
        verdict_enabled=True,
    )
    d1 = await lanes.route(f(finding_id="a", severity="critical"))
    d2 = await lanes.route(f(finding_id="b", severity="critical"))
    assert {d1.lane, d2.lane} == {LANE_SMALL}
    assert d1.deferred_verdict and d2.deferred_verdict
    assert lanes.deferred_count == 2 and sent == []

    pressure["on"] = False
    d3 = await lanes.route(f(finding_id="c"))
    assert d3.lane == LANE_SMALL
    assert sent == [("a", LANE_VERDICT), ("b", LANE_VERDICT)]
    assert lanes.deferred_count == 0


@pytest.mark.asyncio
async def test_budget_exceeded_from_enqueue_trips_the_fuse():
    clock = [0.0]
    fuse = BudgetPressure(cooldown_seconds=60, clock=lambda: clock[0])

    def enqueue(finding, decision):
        raise BudgetExceeded(tier="virtual_key")

    lanes = router(budget_pressure=fuse, verdict_enqueuer=enqueue, verdict_enabled=True)
    d = await lanes.route(f(severity="critical"))
    assert (d.lane, d.reason, d.deferred_verdict) == (LANE_SMALL, "budget_pressure", True)
    assert fuse() is True
    d2 = await lanes.route(f(finding_id="f-2", severity="critical"))
    assert d2.reason == "budget_pressure"
    clock[0] = 61
    assert fuse() is False
    assert lanes.deferred_count == 2


@pytest.mark.asyncio
async def test_enqueue_failure_degrades_and_keeps_the_finding():
    def enqueue(finding, decision):
        raise RuntimeError("queue down")

    lanes = router(verdict_enqueuer=enqueue, verdict_enabled=True)
    d = await lanes.route(f(severity="critical"))
    assert (d.lane, d.reason, d.deferred_verdict) == (LANE_SMALL, "verdict_enqueue_failed", True)
    assert lanes.deferred_count == 1


@pytest.mark.asyncio
async def test_failed_drain_puts_the_item_back():
    state = {"pressure": True, "fail": True}

    def enqueue(finding, decision):
        if state["fail"]:
            raise RuntimeError("down")
        return "ok"

    lanes = router(budget_pressure=lambda: state["pressure"], verdict_enqueuer=enqueue, verdict_enabled=True)
    await lanes.route(f(finding_id="a", severity="critical"))
    state["pressure"] = False
    assert await lanes.drain_deferred() == 0
    assert lanes.deferred_count == 1
    state["fail"] = False
    assert await lanes.drain_deferred() == 1
    assert lanes.deferred_count == 0


@pytest.mark.asyncio
async def test_unreadable_budget_reads_as_pressure():
    def boom():
        raise RuntimeError("db down")

    lanes = router(budget_pressure=boom, verdict_enqueuer=lambda *_: "r", verdict_enabled=True)
    d = await lanes.route(f(severity="critical"))
    assert (d.lane, d.reason) == (LANE_SMALL, "budget_pressure")


@pytest.mark.asyncio
async def test_deferred_overflow_keeps_durable_mark_only(caplog):
    lanes = router(budget_pressure=lambda: True, verdict_enqueuer=lambda *_: "r", verdict_enabled=True, max_deferred=1)
    d1 = await lanes.route(f(finding_id="a", severity="critical"))
    d2 = await lanes.route(f(finding_id="b", severity="critical"))
    assert d1.deferred_verdict and d2.deferred_verdict
    assert lanes.deferred_count == 1
    assert lanes.stats["deferred_overflow"] == 1


NO_DROP_FINDINGS = [
    f(),
    f(severity="critical"),
    f(data_source="nessus"),
    f(title="eicar"),
    {"finding_id": None},
    {"severity": 5, "entity_context": "not a dict", "verdict": ["odd"]},
]


@pytest.mark.asyncio
@pytest.mark.parametrize("pressure", [False, True])
@pytest.mark.parametrize("enqueue_ok", [False, True])
async def test_no_drop_every_finding_gets_a_recorded_decision(pressure, enqueue_ok):
    rec = Recorder()

    def enqueue(finding, decision):
        if not enqueue_ok:
            raise RuntimeError("down")
        return "run"

    def rules(_tenant):
        return [rule()]

    lanes = router(
        rules_source=rules,
        budget_pressure=lambda: pressure,
        verdict_enqueuer=enqueue,
        verdict_enabled=True,
        recorder=rec,
    )
    for finding in NO_DROP_FINDINGS:
        d = await lanes.route(dict(finding))
        # Either settled by rules, triaged on the small lane, or enqueued.
        assert d.lane in (LANE_RULES, LANE_SMALL) or d.verdict_run_id
        if d.degraded_from == LANE_VERDICT:
            assert d.deferred_verdict
    assert len(rec.rows) == len(NO_DROP_FINDINGS)


@pytest.mark.asyncio
async def test_router_errors_fall_back_to_the_small_lane():
    lanes = router()

    def bad_decide(*_a, **_k):
        raise RuntimeError("bug")

    lanes._route = bad_decide  # type: ignore[assignment]
    d = await lanes.route(f())
    assert (d.lane, d.reason) == (LANE_SMALL, "router_error")


@pytest.mark.asyncio
async def test_rules_source_failure_is_not_a_drop():
    def rules(_tenant):
        raise RuntimeError("db down")

    d = await router(rules_source=rules).route(f(data_source="nessus"))
    assert d.lane == LANE_SMALL


@pytest.mark.asyncio
async def test_suppression_hit_is_counted_once():
    hits = []
    lanes = router(rules_source=lambda t: [rule()], on_suppression_hit=hits.append)
    d = await lanes.route(f(data_source="nessus"))
    assert d.lane == LANE_RULES
    assert [h.name for h in hits] == ["scanner"]


# --- decision records (tenant-scoped) ---------------------------------------


@pytest.mark.asyncio
async def test_each_decision_is_recorded_with_its_tenant():
    rec = Recorder()
    lanes = router(
        rules_source=lambda t: [rule(tenant="acme")],
        recorder=rec,
        small_target=("ollama", "llama3.1:8b"),
    )
    await lanes.route(f(finding_id="a", tenant_id="acme", data_source="nessus"))
    await lanes.route(f(finding_id="b"))
    assert [(r.finding_id, r.tenant_id, r.lane) for r in rec.rows] == [
        ("a", "acme", LANE_RULES),
        ("b", "default", LANE_SMALL),
    ]
    row = rec.rows[1].to_enrichment()
    assert row["model"] == "ollama/llama3.1:8b"
    assert set(row) >= {"lane", "reason", "risk", "factors", "tenant_id", "deferred_verdict", "decided_at"}


@pytest.mark.asyncio
async def test_recorder_failure_does_not_lose_the_decision():
    def recorder(_d):
        raise RuntimeError("sink down")

    d = await router(recorder=recorder).route(f())
    assert d.lane == LANE_SMALL


def test_default_recorder_logs(caplog):
    import asyncio

    caplog.set_level(logging.INFO, logger="core.lanes.alert_lanes")
    asyncio.run(router().route(f(finding_id="logged")))
    assert "alert lane small_model for logged" in caplog.text
