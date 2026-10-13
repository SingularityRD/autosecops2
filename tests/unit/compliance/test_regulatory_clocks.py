"""DORA and NIS2 clock arithmetic (W3.8): table tests over core/compliance/clocks.py."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from core.compliance import clocks
from core.compliance.clocks import (
    CLOCKS,
    DEFAULT_DURATIONS,
    ClockConfig,
    ClockConfigError,
    Duration,
    add_duration,
    add_months,
    evaluate,
)

pytestmark = pytest.mark.unit

UTC = timezone.utc
BERLIN = ZoneInfo("Europe/Berlin")
ISTANBUL = ZoneInfo("Europe/Istanbul")


def T(text: str) -> datetime:
    return datetime.fromisoformat(text)


def _clock(key):
    return next(c for c in CLOCKS if c.key == key)


def _status(key, instants, now, config=None):
    return clocks.evaluate_clock(_clock(key), instants, config or ClockConfig(), now)


# --- every clock, from its own start instant ---------------------------------

CLOCK_TABLE = [
    # key, instants, expected due (UTC), bound_to
    (
        "dora.initial",
        {
            "classification_at": T("2026-03-02T10:00:00+00:00"),
            "aware_at": T("2026-03-02T08:00:00+00:00"),
        },
        T("2026-03-02T14:00:00+00:00"),
        "classification_at",
    ),
    (
        "dora.intermediate",
        {"notified_at": T("2026-03-02T13:00:00+00:00")},
        T("2026-03-05T13:00:00+00:00"),
        "notified_at",
    ),
    (
        "dora.final",
        {"last_intermediate_at": T("2026-03-05T12:00:00+00:00")},
        # 13:00 Istanbul (UTC+3, no DST) one calendar month later
        T("2026-04-05T12:00:00+00:00"),
        "last_intermediate_at",
    ),
    (
        "nis2.early_warning",
        {"aware_at": T("2026-03-02T08:00:00+00:00")},
        T("2026-03-03T08:00:00+00:00"),
        "aware_at",
    ),
    (
        "nis2.notification",
        {"aware_at": T("2026-03-02T08:00:00+00:00")},
        T("2026-03-05T08:00:00+00:00"),
        "aware_at",
    ),
    (
        "nis2.final",
        {"notified_at": T("2026-03-05T08:00:00+00:00")},
        T("2026-04-05T08:00:00+00:00"),
        "notified_at",
    ),
]


@pytest.mark.parametrize("key,instants,due,bound_to", CLOCK_TABLE)
def test_each_clock_runs_from_its_own_start(key, instants, due, bound_to):
    now = T("2026-03-02T12:00:00+00:00")
    status = _status(key, instants, now)
    assert status.due_at == due
    assert status.bound_to == bound_to
    assert status.started_at == instants[bound_to]
    assert status.remaining_seconds == int((due - now).total_seconds())
    assert status.state == "running" and status.overdue is False


@pytest.mark.parametrize("key", [c.key for c in CLOCKS])
def test_no_start_instant_means_not_started(key):
    status = _status(key, {}, T("2026-03-02T12:00:00+00:00"))
    assert status.state == "not_started"
    assert status.due_at is None and status.remaining_seconds is None
    assert status.waiting_for == _clock(key).requires


# --- the DORA initial rule: min(classification + 4h, awareness + 24h) -------

MIN_RULE = [
    # classification, awareness, due, bound_to
    (
        "2026-03-02T10:00:00+00:00",
        "2026-03-02T08:00:00+00:00",
        "2026-03-02T14:00:00+00:00",
        "classification_at",
    ),
    # classified 22h after awareness: the 24h cap binds (2h after classification)
    (
        "2026-03-03T06:00:00+00:00",
        "2026-03-02T08:00:00+00:00",
        "2026-03-03T08:00:00+00:00",
        "aware_at",
    ),
    # classified 30h after awareness: due before it was even classified
    (
        "2026-03-03T14:00:00+00:00",
        "2026-03-02T08:00:00+00:00",
        "2026-03-03T08:00:00+00:00",
        "aware_at",
    ),
    # exactly 20h after awareness: both give the same instant; classification is named
    (
        "2026-03-03T04:00:00+00:00",
        "2026-03-02T08:00:00+00:00",
        "2026-03-03T08:00:00+00:00",
        "classification_at",
    ),
    # awareness unknown: classification + 4h
    (
        "2026-03-02T10:00:00+00:00",
        None,
        "2026-03-02T14:00:00+00:00",
        "classification_at",
    ),
]


@pytest.mark.parametrize("cls,aware,due,bound_to", MIN_RULE)
def test_dora_initial_takes_the_earlier_deadline(cls, aware, due, bound_to):
    instants = {"classification_at": T(cls), "aware_at": T(aware) if aware else None}
    status = _status("dora.initial", instants, T("2026-03-01T00:00:00+00:00"))
    assert (status.due_at, status.bound_to) == (T(due), bound_to)


def test_dora_initial_does_not_start_before_classification():
    status = _status(
        "dora.initial",
        {"aware_at": T("2026-03-02T08:00:00+00:00")},
        T("2026-03-04T00:00:00+00:00"),
    )
    assert status.state == "not_started"
    assert status.waiting_for == "classification_at"
    assert status.overdue is False


# --- states ------------------------------------------------------------------

STATES = [
    # now, met_at, state, overdue, remaining
    ("2026-03-03T07:59:00+00:00", None, "running", False, 60),
    ("2026-03-03T08:00:00+00:00", None, "running", False, 0),
    ("2026-03-03T08:00:01+00:00", None, "overdue", True, -1),
    ("2026-03-04T08:00:00+00:00", None, "overdue", True, -86400),
    ("2026-03-04T08:00:00+00:00", "2026-03-03T07:00:00+00:00", "met", False, None),
    ("2026-03-04T08:00:00+00:00", "2026-03-03T08:00:00+00:00", "met", False, None),
    ("2026-03-04T08:00:00+00:00", "2026-03-03T09:00:00+00:00", "met_late", False, None),
]


@pytest.mark.parametrize("now,met_at,state,overdue,remaining", STATES)
def test_running_overdue_and_met(now, met_at, state, overdue, remaining):
    instants = {
        "aware_at": T("2026-03-02T08:00:00+00:00"),
        "early_warning_at": T(met_at) if met_at else None,
    }
    status = _status("nis2.early_warning", instants, T(now))
    assert (status.state, status.overdue, status.remaining_seconds) == (
        state,
        overdue,
        remaining,
    )
    assert status.due_at == T("2026-03-03T08:00:00+00:00")


def test_evaluate_lists_every_clock_in_order():
    out = evaluate({}, ClockConfig(), T("2026-03-02T12:00:00+00:00"))
    assert [c.key for c in out] == [c.key for c in CLOCKS]
    only = evaluate(
        {}, ClockConfig(), T("2026-03-02T12:00:00+00:00"), regimes=("nis2",)
    )
    assert {c.regime for c in only} == {"nis2"}


def test_the_regimes_do_not_share_instants():
    """NIS2 awareness does not start the DORA clocks, nor the other way round."""
    instants = {"nis2": {"aware_at": T("2026-03-02T08:00:00+00:00")}}
    out = {
        c.key: c
        for c in evaluate(instants, ClockConfig(), T("2026-03-02T12:00:00+00:00"))
    }
    assert out["nis2.early_warning"].state == "running"
    assert out["dora.initial"].state == "not_started"


# --- DST: hours are elapsed time, months are local calendar time -------------

DST_HOURS = [
    # Europe/Berlin springs forward 2026-03-29 02:00 CET -> 03:00 CEST
    ("2026-03-28T12:00:00+01:00", 24, "2026-03-29T13:00:00+02:00"),
    # and falls back 2026-10-25 03:00 CEST -> 02:00 CET
    ("2026-10-24T12:00:00+02:00", 24, "2026-10-25T11:00:00+01:00"),
    ("2026-10-24T12:00:00+02:00", 72, "2026-10-27T11:00:00+01:00"),
    ("2026-03-29T00:30:00+01:00", 4, "2026-03-29T05:30:00+02:00"),
]


@pytest.mark.parametrize("start,hours,expected", DST_HOURS)
def test_hours_are_elapsed_across_berlin_dst(start, hours, expected):
    due = add_duration(T(start), Duration(hours=hours), BERLIN)
    assert due == T(expected)
    assert due - T(start) == timedelta(hours=hours)
    assert due.astimezone(BERLIN).isoformat() == expected


DST_MONTHS = [
    # wall-clock kept across the spring change: 12:00 CET -> 12:00 CEST
    ("2026-03-10T12:00:00+01:00", "2026-04-10T12:00:00+02:00"),
    # and across the autumn change: 12:00 CEST -> 12:00 CET
    ("2026-10-10T12:00:00+02:00", "2026-11-10T12:00:00+01:00"),
    # the day before the change: still CET
    ("2026-02-28T02:30:00+01:00", "2026-03-28T02:30:00+01:00"),
]


@pytest.mark.parametrize("start,expected", DST_MONTHS)
def test_months_keep_the_berlin_wall_clock(start, expected):
    assert add_months(T(start), 1, BERLIN) == T(expected)


def test_month_into_the_spring_gap_reads_an_hour_later():
    # 02:30 on 29 March 2026 does not exist in Berlin
    start = T("2026-01-29T02:30:00+01:00")
    two = add_months(start, 2, BERLIN)
    assert two.astimezone(BERLIN).isoformat() == "2026-03-29T03:30:00+02:00"
    assert two == T("2026-03-29T01:30:00+00:00")


def test_month_into_the_autumn_overlap_takes_the_first_occurrence():
    start = T("2026-09-25T02:30:00+02:00")
    due = add_months(start, 1, BERLIN)  # 25 October 02:30 happens twice
    assert due == T("2026-10-25T02:30:00+02:00")


def test_istanbul_has_no_dst():
    start = T("2026-03-28T12:00:00+03:00")
    assert add_duration(start, Duration(hours=24), ISTANBUL) == T(
        "2026-03-29T12:00:00+03:00"
    )
    assert add_months(start, 1, ISTANBUL) == T("2026-04-28T12:00:00+03:00")


# --- month arithmetic ----------------------------------------------------------

MONTHS = [
    ("2026-01-31T10:00:00+03:00", 1, "2026-02-28T10:00:00+03:00"),
    ("2028-01-31T10:00:00+03:00", 1, "2028-02-29T10:00:00+03:00"),  # leap year
    ("2026-03-31T10:00:00+03:00", 1, "2026-04-30T10:00:00+03:00"),
    ("2026-01-30T10:00:00+03:00", 1, "2026-02-28T10:00:00+03:00"),
    ("2026-02-28T10:00:00+03:00", 1, "2026-03-28T10:00:00+03:00"),
    ("2026-12-15T10:00:00+03:00", 1, "2027-01-15T10:00:00+03:00"),
    ("2026-11-30T10:00:00+03:00", 3, "2027-02-28T10:00:00+03:00"),
    ("2026-01-31T10:00:00+03:00", 12, "2027-01-31T10:00:00+03:00"),
]


@pytest.mark.parametrize("start,months,expected", MONTHS)
def test_calendar_months_clamp_the_day(start, months, expected):
    assert add_months(T(start), months, ISTANBUL) == T(expected)


def test_month_is_counted_in_the_tenant_zone_not_utc():
    # 31 Jan 22:30 UTC is already 1 Feb 01:30 in Istanbul: + 1 month = 1 March local
    start = T("2026-01-31T22:30:00+00:00")
    assert add_months(start, 1, ISTANBUL) == T("2026-03-01T01:30:00+03:00")
    # in UTC the same start would have clamped to 28 Feb
    assert add_months(start, 1, ZoneInfo("UTC")) == T("2026-02-28T22:30:00+00:00")


def test_dora_final_from_jan_31():
    status = _status(
        "dora.final",
        {"last_intermediate_at": T("2026-01-31T09:00:00+03:00")},
        T("2026-02-01T00:00:00+00:00"),
    )
    assert status.due_at == T("2026-02-28T09:00:00+03:00")


# --- configurability -------------------------------------------------------------


def test_defaults_match_the_regulations():
    assert DEFAULT_DURATIONS == {
        "dora.initial_after_classification": Duration(hours=4),
        "dora.initial_after_awareness": Duration(hours=24),
        "dora.intermediate_after_initial": Duration(hours=72),
        "dora.final_after_intermediate": Duration(months=1),
        "nis2.early_warning_after_awareness": Duration(hours=24),
        "nis2.notification_after_awareness": Duration(hours=72),
        "nis2.final_after_notification": Duration(months=1),
    }
    assert ClockConfig().timezone == "Europe/Istanbul"


def test_overrides_change_the_deadline():
    config = ClockConfig.from_overrides(
        "Europe/Berlin",
        {
            "dora.initial_after_classification": {"hours": 2},
            "nis2.final_after_notification": {"months": 2},
        },
    )
    instants = {
        "classification_at": T("2026-03-02T10:00:00+00:00"),
        "aware_at": T("2026-03-02T08:00:00+00:00"),
    }
    assert _status(
        "dora.initial", instants, T("2026-03-02T10:00:00+00:00"), config
    ).due_at == T("2026-03-02T12:00:00+00:00")
    final = _status(
        "nis2.final",
        {"notified_at": T("2026-01-31T12:00:00+01:00")},
        T("2026-02-01T00:00:00+00:00"),
        config,
    )
    assert final.due_at == T("2026-03-31T12:00:00+02:00")
    assert config.overrides() == {
        "dora.initial_after_classification": {"hours": 2, "months": 0},
        "nis2.final_after_notification": {"hours": 0, "months": 2},
    }


def test_a_longer_awareness_cap_lets_classification_bind():
    config = ClockConfig.from_overrides(
        None, {"dora.initial_after_awareness": {"hours": 48}}
    )
    instants = {
        "classification_at": T("2026-03-03T06:00:00+00:00"),
        "aware_at": T("2026-03-02T08:00:00+00:00"),
    }
    status = _status("dora.initial", instants, T("2026-03-03T06:00:00+00:00"), config)
    assert (status.due_at, status.bound_to) == (
        T("2026-03-03T10:00:00+00:00"),
        "classification_at",
    )


@pytest.mark.parametrize(
    "tz,overrides",
    [
        ("Mars/Olympus", {}),
        ("", {}),
        (None, {"dora.unknown": {"hours": 1}}),
        (None, {"dora.initial_after_classification": {"hours": 0}}),
        (None, {"dora.initial_after_classification": {"hours": -4}}),
        (None, {"dora.initial_after_classification": {"hours": 1.5}}),
        (None, {"dora.initial_after_classification": {"hours": True}}),
        (None, {"dora.initial_after_classification": {"days": 1}}),
        (None, {"dora.initial_after_classification": 4}),
        (None, {"dora.final_after_intermediate": {"months": 99}}),
    ],
)
def test_bad_configuration_is_refused(tz, overrides):
    with pytest.raises(ClockConfigError):
        if tz == "":
            ClockConfig(timezone="")
        else:
            ClockConfig.from_overrides(tz, overrides)


def test_naive_instants_are_refused():
    with pytest.raises(ValueError):
        _status(
            "nis2.early_warning",
            {"aware_at": datetime(2026, 3, 2, 8)},
            T("2026-03-02T12:00:00+00:00"),
        )
    with pytest.raises(ValueError):
        _status("nis2.early_warning", {}, datetime(2026, 3, 2, 12))


def test_status_serialises_in_utc():
    status = _status(
        "nis2.early_warning",
        {"aware_at": T("2026-03-02T11:00:00+03:00")},
        T("2026-03-02T12:00:00+00:00"),
    )
    body = status.to_dict()
    assert body["due_at"] == "2026-03-03T08:00:00+00:00"
    assert body["started_at"] == "2026-03-02T08:00:00+00:00"
