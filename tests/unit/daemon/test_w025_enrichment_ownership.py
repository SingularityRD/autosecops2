"""W0.25 adapt(upstream 7eea6a18): ai_enrichment ownership with this fork's lanes.

Upstream made triage and the on-demand AI analysis each replace only their own
``ai_enrichment`` keys (#2316). This fork's daemon also writes the W2.2 lane
decision (``alert_lane``) there and records settled decisions from the backfill
(W0.15). Three regressions guarded here:

1. ``alert_lane`` is a daemon key: otherwise the daemon's own write filters the
   lane decision out, and Generate deletes it.
2. ``_persist_settled`` writes as the daemon (``write_ai_enrichment``), not with
   a full replace that wipes a generated analysis.
3. The backfill predicate (``UNRATED_WHERE``, one string shared with the partial
   index) counts ``alert_lane`` as triaged, so a row settled without a model is
   not re-queued on every sweep, while an analysis-only row is.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import text

from core.ingestion.store_outcome import has_triage
from core.lanes.alert_lanes import ENRICHMENT_KEY, LANE_RULES, LaneDecision
from core.storage.models.finding import UNRATED_WHERE
from core.storage.service import (
    ALERT_LANE_KEY,
    DAEMON_ENRICHMENT_KEYS,
    DAEMON_TRIAGE_KEYS,
    merge_ai_enrichment,
)
from core.time import utcnow
from services.daemon.config import ProcessingConfig
from services.daemon.processor import FindingProcessor

LANE = {"lane": "rules", "reason": "suppression_rule", "decided_at": "2026-10-15"}
TRIAGE = {"ai_triage": {"result": {}}, "enriched_at": "2026-10-15T00:00:00"}
ANALYSIS = {"threat_summary": "Beaconing", "generated_at": "2026-10-15T01:00:00"}

# -- 1. alert_lane belongs to the daemon --------------------------------------


def test_the_lane_key_is_a_daemon_key():
    assert ALERT_LANE_KEY == ENRICHMENT_KEY
    assert ENRICHMENT_KEY in DAEMON_ENRICHMENT_KEYS
    # The payload-scrub / lift tuple stays the triage outputs only.
    assert ENRICHMENT_KEY not in DAEMON_TRIAGE_KEYS


def test_a_daemon_write_stores_its_lane_decision():
    merged = merge_ai_enrichment(ANALYSIS, {**TRIAGE, "alert_lane": LANE}, daemon=True)
    assert merged == {**ANALYSIS, **TRIAGE, "alert_lane": LANE}


def test_generate_keeps_the_lane_decision():
    stored = {**TRIAGE, "alert_lane": LANE, "threat_summary": "old"}
    merged = merge_ai_enrichment(stored, ANALYSIS, daemon=False)
    assert merged == {**TRIAGE, "alert_lane": LANE, **ANALYSIS}


def test_a_daemon_write_without_a_lane_keeps_the_recorded_one():
    """Lanes off on a later run: the earlier decision is evidence, not stale triage."""
    stored = {"ai_triage_error": "timeout", "alert_lane": LANE}
    merged = merge_ai_enrichment(stored, {"ai_triage": {"result": {}}}, daemon=True)
    assert merged == {"ai_triage": {"result": {}}, "alert_lane": LANE}


def test_a_new_lane_decision_replaces_the_old_one():
    newer = {**LANE, "decided_at": "2026-10-16"}
    merged = merge_ai_enrichment({"alert_lane": LANE}, {"alert_lane": newer}, daemon=True)
    assert merged == {"alert_lane": newer}


# -- 2. _persist_settled writes as the daemon ---------------------------------


def _decision(fid: str) -> LaneDecision:
    return LaneDecision(
        finding_id=fid,
        tenant_id="default",
        lane=LANE_RULES,
        reason="suppression_rule",
        risk=0.1,
        decided_at="2026-10-15T10:00:00+00:00",
    )


class _Recording:
    def __init__(self):
        self.calls = []

    def write_ai_enrichment(self, finding_id, ai_enrichment, *, daemon, **updates):
        self.calls.append((finding_id, ai_enrichment, daemon, updates))
        return True

    def update_finding(self, finding_id, **updates):  # pragma: no cover - must not run
        raise AssertionError("_persist_settled must not full-replace ai_enrichment")


def test_persist_settled_uses_the_daemon_writer():
    processor = FindingProcessor(ProcessingConfig())
    processor._data_service = _Recording()
    row = {"finding_id": "s1", "ai_enrichment": {"ai_triage_error": "redis down"}}

    assert asyncio.run(processor._persist_settled(row, _decision("s1")))

    [(fid, enrichment, daemon, updates)] = processor._data_service.calls
    assert (fid, daemon, updates) == ("s1", True, {})
    assert enrichment["alert_lane"]["lane"] == LANE_RULES
    assert "ai_triage_error" not in enrichment


# -- 3. the backfill predicate ------------------------------------------------


@pytest.mark.parametrize(
    "enrichment, triaged",
    [
        (None, False),
        (ANALYSIS, False),  # Generate only: triage never reached it (#2316)
        ({"alert_lane": LANE}, True),  # settled without a model (W0.15)
        ({**ANALYSIS, "alert_lane": LANE}, True),
        ({"alert_lane": LANE, "ai_triage_error": "timeout"}, False),  # #965
        (TRIAGE, True),
        ({"enriched_at": "2026-10-15"}, True),
    ],
)
def test_has_triage_reads_the_lane_as_triaged(enrichment, triaged):
    assert has_triage(enrichment) is triaged


def _service():
    from core.storage.service import DatabaseService

    return DatabaseService()


def _finding(ai_enrichment) -> str:
    service = _service()
    finding_id = f"w025-{uuid.uuid4().hex[:12]}"
    assert service.create_finding(
        finding_id=finding_id,
        mitre_predictions={},
        anomaly_score=0.5,
        timestamp=utcnow(),
        data_source="w025",
        severity="medium",
        status="new",
    )
    if ai_enrichment is not None:
        assert service.update_finding(finding_id, ai_enrichment=ai_enrichment)
    return finding_id


def _unrated(ids) -> set:
    from core.storage.connection import get_db_manager

    with get_db_manager().session_scope() as session:
        rows = session.execute(
            text(
                f"SELECT finding_id FROM findings WHERE {UNRATED_WHERE} "
                "AND finding_id = ANY(:ids)"
            ),
            {"ids": list(ids)},
        )
        return {r[0] for r in rows}


@pytest.mark.external_service
@pytest.mark.database
def test_unrated_where_matches_has_triage_in_postgres(throwaway_database):
    samples = [
        None,
        ANALYSIS,
        {"alert_lane": LANE},
        {**ANALYSIS, "alert_lane": LANE},
        {"alert_lane": LANE, "ai_triage_error": "timeout"},
        TRIAGE,
        {"enriched_at": "2026-10-15"},
        {"ai_triage_error": "boom"},
    ]
    ids = {_finding(sample): sample for sample in samples}
    unrated = _unrated(ids)
    for fid, sample in ids.items():
        assert (fid in unrated) is (not has_triage(sample)), sample


@pytest.mark.external_service
@pytest.mark.database
def test_a_settled_row_leaves_the_backfill_and_keeps_its_analysis(throwaway_database):
    """The whole W0.15 + #2316 path against Postgres: a row holding a generated
    analysis and a failed triage is settled by its lane decision. The analysis
    survives (merged against the locked row, not the sweep's stale copy), the
    lane decision is stored, and the row is no longer unrated."""
    from core.storage.database_data_service import DatabaseDataService

    fid = _finding({**ANALYSIS, "ai_triage_error": "redis down"})
    processor = FindingProcessor(ProcessingConfig())
    processor._data_service = DatabaseDataService()
    # The sweep's copy predates the analysis.
    row = {"finding_id": fid, "ai_enrichment": {"ai_triage_error": "redis down"}}

    assert asyncio.run(processor._persist_settled(row, _decision(fid)))

    stored = _service().get_finding(fid).ai_enrichment
    assert stored["threat_summary"] == "Beaconing"
    assert stored["generated_at"] == ANALYSIS["generated_at"]
    assert stored["alert_lane"]["lane"] == LANE_RULES
    assert "ai_triage_error" not in stored
    assert _unrated([fid]) == set()


@pytest.mark.external_service
@pytest.mark.database
def test_generate_after_a_lane_decision_keeps_it_in_postgres(throwaway_database):
    service = _service()
    fid = _finding(None)
    assert service.write_ai_enrichment(
        fid, {**TRIAGE, "alert_lane": LANE}, daemon=True, severity="high"
    )
    assert service.write_ai_enrichment(fid, ANALYSIS, daemon=False)

    stored = service.get_finding(fid).ai_enrichment
    assert stored == {**TRIAGE, "alert_lane": LANE, **ANALYSIS}
    assert service.get_finding(fid).severity == "high"
    assert _unrated([fid]) == set()
