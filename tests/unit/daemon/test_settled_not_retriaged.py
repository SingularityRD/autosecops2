"""W0.15: a Redis outage must not get a settled finding triaged a second time.

In the ``redis_restart`` chaos scenario every gateway call fails while Redis
is down (the LLM queue lives there), the enrichment breaker opens, and rules
lane findings arriving meanwhile were decided but never written back: still
unrated, they were routed again by the backfill after their verdict. The
recorded lane decision is authoritative; the sweep fails closed without it.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import pytest

from core.lanes.alert_lanes import (
    LANE_RULES,
    LANE_VERDICT,
    AlertLanes,
    LaneDecision,
    LaneHook,
    SuppressionRule,
)
from services.daemon.config import ProcessingConfig
from services.daemon.processor import BACKFILL_SOURCE, FindingProcessor

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)
SCANNER = SuppressionRule("r1", "default", "scanner", {"data_source": "nessus"}, "noise")


class _Data:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.updates: List[Dict[str, Any]] = []

    def update_finding(self, finding_id, **updates):
        self.updates.append({"finding_id": finding_id, **updates})
        return True

    def get_findings_missing_enrichment(self, limit, max_age_hours):
        return [dict(r) for r in self.rows]


def _processor(monkeypatch, **cfg):
    processor = FindingProcessor(
        ProcessingConfig(
            auto_triage_enabled=True,
            auto_enrich_enabled=False,
            enrich_backfill_interval=0,
            **cfg,
        )
    )
    processor._data_service = _Data()
    processor.alert_lanes = LaneHook(
        AlertLanes(clock=lambda: NOW, rules_source=lambda t: [SCANNER]),
        enabled=lambda: True,
    )
    triaged: List[str] = []

    async def triage(finding):
        triaged.append(finding["finding_id"])
        finding["ai_triage"] = {"result": {}}
        return finding

    async def no_response(_finding):
        return None

    monkeypatch.setattr(processor, "_triage_finding", triage)
    monkeypatch.setattr(processor, "_evaluate_for_response", no_response)
    return processor, triaged


def _open_breaker(processor) -> float:
    until = time.monotonic() + 120
    processor._enrich_paused_until = until
    processor._enrich_breaker_tripped = True
    processor._enrich_failures = 3
    return until


# -- breaker open: a rules-lane decision is still written --------------------


@pytest.mark.asyncio
async def test_open_breaker_still_persists_a_rules_lane_finding(monkeypatch):
    processor, triaged = _processor(monkeypatch)
    until = _open_breaker(processor)
    finding = {"finding_id": "r1", "data_source": "nessus", "severity": "low"}

    await asyncio.create_task(processor._enrich_in_background(finding, "webhook"))

    assert triaged == []
    [update] = processor._data_service.updates
    assert update["finding_id"] == "r1"
    assert update["ai_enrichment"]["alert_lane"]["lane"] == LANE_RULES
    # Not a gateway answer: the breaker is neither reset nor pushed further.
    assert processor._enrich_paused_until == until
    assert processor._enrich_breaker_tripped is True
    assert processor._enrich_failures == 3


@pytest.mark.asyncio
async def test_open_breaker_still_skips_a_finding_that_needs_the_model(monkeypatch):
    processor, triaged = _processor(monkeypatch)
    _open_breaker(processor)
    finding = {"finding_id": "s1", "data_source": "edr", "severity": "high"}

    await asyncio.create_task(processor._enrich_in_background(finding, "webhook"))

    assert triaged == []
    assert processor._data_service.updates == []  # the backfill's, as before


# -- the backfill: the recorded decision is authoritative --------------------


def _settled(fid: str, lane: str = LANE_RULES, run=None) -> LaneDecision:
    return LaneDecision(
        finding_id=fid,
        tenant_id="default",
        lane=lane,
        reason="suppression_rule",
        risk=0.1,
        verdict_run_id=run,
        decided_at="2026-10-14T10:48:31+00:00",
    )


async def _sweep_once(processor, rows):
    processor._data_service = _Data(rows)
    spawned: List[Any] = []
    shutdown = asyncio.Event()

    async def spawn(finding, source=None):
        spawned.append((finding["finding_id"], source))
        shutdown.set()

    processor._spawn_enrich = spawn  # type: ignore[method-assign]
    calls = []
    real = processor._drop_settled

    async def once(batch):
        calls.append(batch)
        rest = await real(batch)
        if not rest:  # nothing left to spawn: one sweep is enough
            shutdown.set()
        return rest

    processor._drop_settled = once  # type: ignore[method-assign]
    await asyncio.wait_for(processor._backfill_loop(shutdown), timeout=10)
    return spawned


@pytest.mark.asyncio
async def test_backfill_records_instead_of_rerouting_a_settled_finding(monkeypatch):
    processor, _ = _processor(monkeypatch)
    seen = []

    def lookup(ids, tenant):
        seen.append((list(ids), tenant))
        return {"done": _settled("done"), "verd": _settled("verd", LANE_VERDICT, "run-1")}

    processor._settling_decisions = lookup
    spawned = await _sweep_once(
        processor,
        [
            {"finding_id": "done", "ai_enrichment": None},
            {"finding_id": "verd", "ai_enrichment": {"ai_triage_error": "redis down"}},
            {"finding_id": "open", "ai_enrichment": None},
        ],
    )

    assert spawned == [("open", BACKFILL_SOURCE)]
    assert seen == [(["done", "verd", "open"], "default")]
    by_id = {u["finding_id"]: u["ai_enrichment"] for u in processor._data_service.updates}
    assert by_id["done"]["alert_lane"]["lane"] == LANE_RULES
    assert by_id["verd"]["alert_lane"]["verdict_run_id"] == "run-1"
    # Out of the unrated set: no error left without a triage.
    assert "ai_triage_error" not in by_id["verd"]
    assert processor.stats["backfill_skipped_settled"] == 2


@pytest.mark.asyncio
async def test_backfill_fails_closed_when_decisions_are_unreadable(monkeypatch):
    processor, _ = _processor(monkeypatch)

    def down(ids, tenant):
        raise ConnectionError("database unavailable")

    processor._settling_decisions = down
    spawned = await _sweep_once(processor, [{"finding_id": "x"}, {"finding_id": "y"}])

    assert spawned == []
    assert processor._data_service.updates == []
    assert processor.stats["backfill_settled_lookup_failed"] == 1


@pytest.mark.asyncio
async def test_rules_finding_during_outage_is_never_routed_twice(monkeypatch):
    """End to end in-process: breaker open (outage), rules finding decided,
    then a backfill sweep with the decision table saying it is settled."""
    processor, triaged = _processor(monkeypatch)
    _open_breaker(processor)
    decisions: List[LaneDecision] = []
    lanes = processor.alert_lanes.lanes
    lanes._recorder = decisions.append
    finding = {"finding_id": "r9", "data_source": "nessus", "severity": "low"}
    await asyncio.create_task(processor._enrich_in_background(finding, "webhook"))
    assert [d.lane for d in decisions] == [LANE_RULES]

    # The row is rated now; even if a sweep still saw it, the table settles it.
    processor._enrich_paused_until = 0.0
    processor._settling_decisions = lambda ids, tenant: {
        d.finding_id: d for d in decisions if d.finding_id in ids
    }
    spawned = await _sweep_once(processor, [{"finding_id": "r9", "ai_enrichment": None}])
    assert spawned == []
    assert [d.lane for d in decisions] == [LANE_RULES]  # no second decision
    assert triaged == []
