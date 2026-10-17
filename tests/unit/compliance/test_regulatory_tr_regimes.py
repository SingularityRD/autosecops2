"""KVKK, BDDK and USOM clocks and drafts next to DORA and NIS2 (W0.42)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.compliance import clocks
from core.compliance.clocks import (
    CLOCKS,
    DEFAULT_DURATIONS,
    INSTANTS,
    REGIMES,
    TARGET_DURATIONS,
    ClockConfig,
    Duration,
    evaluate,
)
from core.compliance.regulatory_drafts import (
    KINDS,
    TITLES,
    TO_COMPLETE,
    TURKISH_REGIMES,
    build_evidence_pack,
    generate_draft,
)
from core.compliance.regulatory_service import (
    MemoryClockStore,
    RegulatoryService,
    fold_instants,
)

pytestmark = pytest.mark.unit

UTC = timezone.utc
NOW = datetime(2026, 3, 3, 12, 0, tzinfo=UTC)
AWARE = datetime(2026, 3, 2, 8, 0, tzinfo=UTC)


def _clock(key):
    return next(c for c in CLOCKS if c.key == key)


def _status(key, instants, now=NOW, config=None):
    return clocks.evaluate_clock(_clock(key), instants, config or ClockConfig(), now)


def test_the_five_regimes_and_their_instants():
    assert REGIMES == ("dora", "nis2", "kvkk", "bddk", "usom")
    assert INSTANTS["kvkk"] == ("aware_at", "notified_at", "subjects_notified_at")
    assert INSTANTS["bddk"] == ("aware_at", "notified_at", "final_at")
    assert INSTANTS["usom"] == ("aware_at", "notified_at")
    assert {c.regime for c in CLOCKS} == set(REGIMES)


def test_kvkk_board_notification_is_due_72_hours_after_awareness():
    status = _status("kvkk.board_notification", {"aware_at": AWARE})
    assert status.state == "running"
    assert status.due_at == datetime(2026, 3, 5, 8, 0, tzinfo=UTC)
    assert status.bound_to == "aware_at"
    assert DEFAULT_DURATIONS["kvkk.board_after_awareness"] == Duration(hours=72)


def test_kvkk_met_late_after_72_hours():
    status = _status(
        "kvkk.board_notification",
        {"aware_at": AWARE, "notified_at": datetime(2026, 3, 5, 9, 0, tzinfo=UTC)},
        now=datetime(2026, 3, 6, tzinfo=UTC),
    )
    assert status.state == "met_late"


def test_kvkk_has_not_started_before_awareness():
    status = _status("kvkk.board_notification", {})
    assert status.state == "not_started"
    assert status.waiting_for == "aware_at"


def test_bddk_notification_then_final_a_month_after_it():
    first = _status("bddk.notification", {"aware_at": AWARE})
    assert first.due_at == datetime(2026, 3, 3, 8, 0, tzinfo=UTC)
    assert first.state == "overdue"
    notified = datetime(2026, 3, 3, 7, 0, tzinfo=UTC)
    final = _status("bddk.final", {"aware_at": AWARE, "notified_at": notified})
    assert final.state == "running"
    # one calendar month in the tenant's zone (Europe/Istanbul has no DST)
    assert final.due_at == datetime(2026, 4, 3, 7, 0, tzinfo=UTC)


def test_usom_notification_is_due_24_hours_after_awareness():
    status = _status("usom.notification", {"aware_at": AWARE})
    assert status.due_at == datetime(2026, 3, 3, 8, 0, tzinfo=UTC)


def test_bddk_and_usom_durations_are_marked_as_in_house_targets():
    assert TARGET_DURATIONS == {
        "bddk.notification_after_awareness",
        "bddk.final_after_notification",
        "usom.notification_after_awareness",
    }
    # KVKK's 72 hours is set by a Board decision, so it is not a target.
    assert "kvkk.board_after_awareness" not in TARGET_DURATIONS
    assert set(TARGET_DURATIONS) <= set(DEFAULT_DURATIONS)
    assert ClockConfig().to_dict()["targets"] == sorted(TARGET_DURATIONS)
    for key in ("bddk.notification", "bddk.final", "usom.notification"):
        assert "kurum içi hedef" in _clock(key).label


def test_a_tenant_can_shorten_the_kvkk_clock():
    config = ClockConfig(
        durations={
            **DEFAULT_DURATIONS,
            "kvkk.board_after_awareness": Duration(hours=48),
        }
    )
    status = _status("kvkk.board_notification", {"aware_at": AWARE}, config=config)
    assert status.due_at == datetime(2026, 3, 4, 8, 0, tzinfo=UTC)


def test_evaluate_lists_every_clock_of_every_regime():
    keys = [c.key for c in evaluate({}, ClockConfig(), NOW)]
    assert keys == [c.key for c in CLOCKS]
    assert {
        "kvkk.board_notification",
        "bddk.notification",
        "bddk.final",
        "usom.notification",
    } <= set(keys)


# --- drafts ------------------------------------------------------------------

CASE = {
    "case_id": "CASE-9",
    "title": "Müşteri verisi sızıntısı",
    "priority": "high",
    "status": "in_progress",
    "description": "Kimlik bilgileri dışarı aktarıldı",
    "created_at": datetime(2026, 3, 2, 8, 30),
}
FINDINGS = [
    {
        "finding_id": "f-1",
        "title": "Exfil over DNS",
        "severity": "high",
        "data_source": "ndr",
    }
]


@pytest.fixture()
def events():
    store = MemoryClockStore(cases={"CASE-9"})
    service = RegulatoryService(store, now=lambda: NOW)
    for regime in ("kvkk", "bddk", "usom"):
        service.record_instant("CASE-9", regime, "aware_at", AWARE, "ayse")
    return store.events("CASE-9")


def _draft(events, regime, kind):
    pack = build_evidence_pack(CASE, FINDINGS, [], [], events)
    found = evaluate(fold_instants(events), ClockConfig(), NOW)
    return pack, generate_draft(pack, regime, kind, found, events, "ayse", NOW)


def test_turkish_regimes_have_their_report_kinds():
    assert KINDS["kvkk"] == ("board_notification",)
    assert KINDS["bddk"] == ("notification", "final")
    assert KINDS["usom"] == ("notification",)
    assert TURKISH_REGIMES == {"kvkk", "bddk", "usom"}
    for regime in TURKISH_REGIMES:
        for kind in KINDS[regime]:
            assert TITLES[(regime, kind)]
            assert TO_COMPLETE[(regime, kind)]


@pytest.mark.parametrize(
    "regime,kind", [(r, k) for r in sorted(TURKISH_REGIMES) for k in KINDS[r]]
)
def test_turkish_drafts_have_turkish_headings_and_cite_only_the_pack(
    events, regime, kind
):
    pack, draft = _draft(events, regime, kind)
    headings = [s["heading"] for s in draft["sections"]]
    assert "Olayın tanımı" in headings
    assert "Incident identification" not in headings
    assert draft["title"] == TITLES[(regime, kind)]
    assert set(draft["cited_ids"]) <= pack.ids
    assert draft["to_complete"] == list(TO_COMPLETE[(regime, kind)])


def test_eu_drafts_keep_english_headings(events):
    _, draft = _draft(events, "dora", "initial")
    assert "Incident identification" in [s["heading"] for s in draft["sections"]]


def test_a_kind_from_another_regime_is_refused(events):
    with pytest.raises(ValueError):
        _draft(events, "kvkk", "final")
