"""Start instants on a case: audited, hash-chained, never silently changed (W3.8)."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from core.compliance.clocks import ClockConfigError
from core.compliance.regulatory_service import (
    InstantRefused,
    MemoryClockStore,
    RegulatoryService,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)


def T(text: str) -> datetime:
    return datetime.fromisoformat(text)


@pytest.fixture()
def store():
    return MemoryClockStore(cases={"c-1", "c-2"})


@pytest.fixture()
def service(store):
    return RegulatoryService(store, now=lambda: NOW)


def _clock(status, key):
    return next(c for c in status["clocks"] if c["key"] == key)


def test_first_value_needs_no_reason_and_is_audited(service, store):
    event = service.record_instant(
        "c-1", "nis2", "aware_at", T("2026-03-02T08:00:00+00:00"), "ayse"
    )
    assert event.seq == 1 and event.previous_value is None and event.reason is None
    assert event.actor == "ayse" and event.recorded_at == NOW
    assert store.audits == [
        {
            "case_id": "c-1",
            "field_name": "regulatory.nis2.aware_at",
            "old_value": None,
            "new_value": "2026-03-02T08:00:00+00:00",
            "change_summary": "Set NIS2 aware_at",
            "changed_by": "ayse",
        }
    ]


def test_changing_a_recorded_instant_needs_a_reason(service, store):
    service.record_instant(
        "c-1", "nis2", "aware_at", T("2026-03-02T08:00:00+00:00"), "ayse"
    )
    for reason in (None, "", "   "):
        with pytest.raises(InstantRefused, match="needs a reason"):
            service.record_instant(
                "c-1",
                "nis2",
                "aware_at",
                T("2026-03-02T07:00:00+00:00"),
                "mehmet",
                reason,
            )
    assert len(store.events("c-1")) == 1
    assert len(store.audits) == 1


def test_a_change_keeps_the_old_value_actor_and_reason(service, store):
    service.record_instant(
        "c-1", "nis2", "aware_at", T("2026-03-02T08:00:00+00:00"), "ayse"
    )
    event = service.record_instant(
        "c-1",
        "nis2",
        "aware_at",
        T("2026-03-02T07:00:00+00:00"),
        "mehmet",
        "SIEM alert seen earlier",
    )
    assert event.seq == 2
    assert event.previous_value == T("2026-03-02T08:00:00+00:00")
    assert (event.actor, event.reason) == ("mehmet", "SIEM alert seen earlier")
    audit = store.audits[-1]
    assert audit["old_value"] == "2026-03-02T08:00:00+00:00"
    assert audit["new_value"] == "2026-03-02T07:00:00+00:00"
    assert audit["changed_by"] == "mehmet"
    assert audit["change_summary"] == "Changed NIS2 aware_at: SIEM alert seen earlier"
    # the clock moved with it
    status = service.status("c-1")
    assert _clock(status, "nis2.early_warning")["due_at"] == "2026-03-03T07:00:00+00:00"
    assert status["instants"]["nis2"]["aware_at"]["actor"] == "mehmet"


def test_clearing_needs_a_reason_and_stops_the_clock(service, store):
    service.record_instant(
        "c-1", "nis2", "aware_at", T("2026-03-02T08:00:00+00:00"), "ayse"
    )
    with pytest.raises(InstantRefused):
        service.record_instant("c-1", "nis2", "aware_at", None, "ayse")
    event = service.record_instant(
        "c-1", "nis2", "aware_at", None, "ayse", "wrong case"
    )
    assert event.value is None
    assert store.audits[-1]["change_summary"] == "Cleared NIS2 aware_at: wrong case"
    assert _clock(service.status("c-1"), "nis2.early_warning")["state"] == "not_started"


def test_the_same_value_again_records_nothing(service, store):
    service.record_instant(
        "c-1", "dora", "aware_at", T("2026-03-02T08:00:00+00:00"), "ayse"
    )
    again = service.record_instant(
        "c-1", "dora", "aware_at", T("2026-03-02T11:00:00+03:00"), "ayse"
    )
    assert again is None
    assert len(store.events("c-1")) == 1 and len(store.audits) == 1


@pytest.mark.parametrize(
    "regime,instant,value,actor,why",
    [
        ("gdpr", "aware_at", T("2026-03-02T08:00:00+00:00"), "a", "unknown regime"),
        (
            "nis2",
            "classification_at",
            T("2026-03-02T08:00:00+00:00"),
            "a",
            "no instant",
        ),
        ("dora", "early_warning_at", T("2026-03-02T08:00:00+00:00"), "a", "no instant"),
        ("dora", "aware_at", datetime(2026, 3, 2, 8), "a", "UTC offset"),
        ("dora", "aware_at", NOW + timedelta(hours=1), "a", "future"),
        ("dora", "aware_at", T("2026-03-02T08:00:00+00:00"), "", "actor"),
    ],
)
def test_bad_instants_are_refused(service, store, regime, instant, value, actor, why):
    with pytest.raises(InstantRefused, match=why):
        service.record_instant("c-1", regime, instant, value, actor)
    assert store.rows == [] and store.audits == []


def test_a_few_minutes_of_clock_skew_is_allowed(service):
    assert service.record_instant(
        "c-1", "dora", "aware_at", NOW + timedelta(minutes=2), "a"
    )


def test_each_case_has_its_own_chain(service, store):
    service.record_instant(
        "c-1", "dora", "aware_at", T("2026-03-02T08:00:00+00:00"), "a"
    )
    first = service.record_instant(
        "c-2", "dora", "aware_at", T("2026-03-02T08:00:00+00:00"), "a"
    )
    assert first.seq == 1 and first.prev_hash == ""


def test_the_chain_links_every_event(service, store):
    service.record_instant(
        "c-1", "dora", "aware_at", T("2026-03-02T08:00:00+00:00"), "a"
    )
    service.record_instant(
        "c-1", "dora", "classification_at", T("2026-03-02T09:00:00+00:00"), "b"
    )
    service.record_instant(
        "c-1", "dora", "aware_at", T("2026-03-02T07:00:00+00:00"), "c", "earlier"
    )
    events = store.events("c-1")
    assert [e.prev_hash for e in events[1:]] == [e.row_hash for e in events[:-1]]
    assert service.verify_chain("c-1") == {
        "ok": True,
        "broken_at": None,
        "why": None,
        "rows": 3,
    }


def test_an_edited_row_breaks_the_chain(service, store):
    service.record_instant(
        "c-1", "dora", "aware_at", T("2026-03-02T08:00:00+00:00"), "a"
    )
    service.record_instant(
        "c-1", "dora", "classification_at", T("2026-03-02T09:00:00+00:00"), "b"
    )
    # someone moves the classification an hour later behind the service's back
    store.rows[1] = replace(store.rows[1], value=T("2026-03-02T10:00:00+00:00"))
    assert service.verify_chain("c-1") == {
        "ok": False,
        "broken_at": 2,
        "why": "hash mismatch",
    }
    assert service.status("c-1")["chain"]["ok"] is False


def test_a_deleted_row_breaks_the_chain(service, store):
    for hour in (5, 6, 7):
        service.record_instant(
            "c-1", "dora", "aware_at", T(f"2026-03-02T0{hour}:00:00+00:00"), "a", "fix"
        )
    del store.rows[1]
    assert service.verify_chain("c-1")["ok"] is False


def test_status_shows_due_remaining_and_overdue(store):
    service = RegulatoryService(store, now=lambda: T("2026-03-03T09:00:00+00:00"))
    service.record_instant(
        "c-1", "nis2", "aware_at", T("2026-03-02T08:00:00+00:00"), "a"
    )
    status = service.status("c-1")
    early = _clock(status, "nis2.early_warning")
    assert early["due_at"] == "2026-03-03T08:00:00+00:00"
    assert early["overdue"] is True and early["remaining_seconds"] == -3600
    note = _clock(status, "nis2.notification")
    assert note["state"] == "running" and note["remaining_seconds"] == 47 * 3600
    assert status["timezone"] == "Europe/Istanbul"


def test_the_tenant_configuration_drives_status(service, store):
    service.set_config(
        "Europe/Berlin", {"nis2.early_warning_after_awareness": {"hours": 12}}, "admin"
    )
    service.record_instant(
        "c-1", "nis2", "aware_at", T("2026-03-02T08:00:00+00:00"), "a"
    )
    status = service.status("c-1")
    assert status["timezone"] == "Europe/Berlin"
    assert _clock(status, "nis2.early_warning")["due_at"] == "2026-03-02T20:00:00+00:00"
    assert store.config_rows["default"]["durations"] == {
        "nis2.early_warning_after_awareness": {"hours": 12, "months": 0}
    }
    assert store.config_audits[-1]["changed_by"] == "admin"
    assert store.config_audits[-1]["old"] is None


def test_configuration_changes_are_audited_with_the_old_value(service, store):
    service.set_config("Europe/Berlin", {}, "admin")
    service.set_config(
        "Europe/Istanbul", {"dora.initial_after_classification": {"hours": 2}}, "root"
    )
    assert store.config_audits[-1]["old"] == {
        "timezone": "Europe/Berlin",
        "durations": {},
    }
    assert store.config_audits[-1]["changed_by"] == "root"


def test_bad_configuration_is_not_stored(service, store):
    with pytest.raises(ClockConfigError):
        service.set_config("Nowhere/City", {}, "admin")
    with pytest.raises(ClockConfigError):
        service.set_config("Europe/Berlin", {"x": {"hours": 1}}, "admin")
    with pytest.raises(ClockConfigError):
        service.set_config("Europe/Berlin", {}, "")
    assert store.config_rows == {} and store.config_audits == []
