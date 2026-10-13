"""Regulatory notification clocks for a case: DORA and NIS2. Pure functions.

Every clock runs from a start instant recorded on the case and is met by
another recorded instant. Nothing here reads the database or the wall clock:
the caller passes the instants, the tenant's configuration and ``now``.

DORA (Regulation (EU) 2022/2554, Art. 19, and the RTS/ITS on incident reporting):

    dora.initial       due at min(classification_at + 4h, aware_at + 24h);
                       starts only once the incident is classified as major
                       (classification_at), met by notified_at
    dora.intermediate  due 72h after the initial notification (notified_at),
                       met by last_intermediate_at
    dora.final         due 1 month after the last intermediate report
                       (last_intermediate_at), met by final_at

NIS2 (Directive (EU) 2022/2555, Art. 23(4)):

    nis2.early_warning  due 24h after awareness (aware_at), met by early_warning_at
    nis2.notification   due 72h after awareness (aware_at), met by notified_at
    nis2.final          due 1 month after the incident notification (notified_at),
                        met by final_at

Durations are configurable per tenant (:class:`ClockConfig`). An hour duration
is elapsed time: 24h across a DST change is 24 real hours, so the local wall
clock moves by one hour. A month duration is calendar arithmetic in the
tenant's time zone: the local wall-clock time is kept and the day is clamped
to the target month's length (31 January + 1 month = 28 or 29 February).
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

REGIMES: Tuple[str, ...] = ("dora", "nis2")

# The instants a case can carry, per regime. Each is a fact with an actor and a
# time; changing one is an audited event (core/compliance/regulatory_service.py).
INSTANTS: Dict[str, Tuple[str, ...]] = {
    "dora": (
        "aware_at",
        "classification_at",
        "notified_at",
        "last_intermediate_at",
        "final_at",
    ),
    "nis2": ("aware_at", "early_warning_at", "notified_at", "final_at"),
}

DEFAULT_TIMEZONE = "Europe/Istanbul"

# Upper bounds that keep a typo from producing a clock nobody can read.
MAX_HOURS = 24 * 366
MAX_MONTHS = 24


class ClockConfigError(ValueError):
    """A configuration value that cannot be used."""


@dataclass(frozen=True)
class Duration:
    """Calendar months, then elapsed hours. Exactly one is normally non-zero."""

    hours: int = 0
    months: int = 0

    def __post_init__(self) -> None:
        for name, value, limit in (
            ("hours", self.hours, MAX_HOURS),
            ("months", self.months, MAX_MONTHS),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ClockConfigError(f"{name} must be an integer")
            if value < 0 or value > limit:
                raise ClockConfigError(f"{name} must be between 0 and {limit}")
        if self.hours == 0 and self.months == 0:
            raise ClockConfigError("a duration must be longer than zero")

    def to_dict(self) -> Dict[str, int]:
        return {"hours": self.hours, "months": self.months}

    @classmethod
    def from_value(cls, value: Any) -> "Duration":
        if isinstance(value, Duration):
            return value
        if not isinstance(value, Mapping):
            raise ClockConfigError("a duration is an object with hours and/or months")
        unknown = set(value) - {"hours", "months"}
        if unknown:
            raise ClockConfigError(f"unknown duration field(s): {sorted(unknown)}")
        return cls(hours=value.get("hours", 0), months=value.get("months", 0))

    def label(self) -> str:
        parts = []
        if self.months:
            parts.append(f"{self.months} month{'s' if self.months != 1 else ''}")
        if self.hours:
            parts.append(f"{self.hours} h")
        return " + ".join(parts)


DEFAULT_DURATIONS: Dict[str, Duration] = {
    "dora.initial_after_classification": Duration(hours=4),
    "dora.initial_after_awareness": Duration(hours=24),
    "dora.intermediate_after_initial": Duration(hours=72),
    "dora.final_after_intermediate": Duration(months=1),
    "nis2.early_warning_after_awareness": Duration(hours=24),
    "nis2.notification_after_awareness": Duration(hours=72),
    "nis2.final_after_notification": Duration(months=1),
}


def _zone(name: str) -> ZoneInfo:
    if not isinstance(name, str) or not name:
        raise ClockConfigError("timezone must be an IANA zone name")
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ClockConfigError(f"unknown timezone {name!r}") from None


@dataclass(frozen=True)
class ClockConfig:
    """A tenant's clock settings: the zone month arithmetic runs in, and durations."""

    timezone: str = DEFAULT_TIMEZONE
    durations: Mapping[str, Duration] = field(
        default_factory=lambda: dict(DEFAULT_DURATIONS)
    )

    def __post_init__(self) -> None:
        _zone(self.timezone)
        unknown = set(self.durations) - set(DEFAULT_DURATIONS)
        if unknown:
            raise ClockConfigError(f"unknown duration key(s): {sorted(unknown)}")
        missing = set(DEFAULT_DURATIONS) - set(self.durations)
        if missing:
            raise ClockConfigError(f"missing duration key(s): {sorted(missing)}")

    @property
    def zone(self) -> ZoneInfo:
        return _zone(self.timezone)

    @classmethod
    def from_overrides(
        cls, timezone_name: Optional[str], overrides: Optional[Mapping[str, Any]]
    ) -> "ClockConfig":
        """Defaults with the tenant's stored overrides on top; unknown keys refused."""
        durations = dict(DEFAULT_DURATIONS)
        for key, value in (overrides or {}).items():
            if key not in DEFAULT_DURATIONS:
                raise ClockConfigError(f"unknown duration key {key!r}")
            durations[key] = Duration.from_value(value)
        return cls(timezone=timezone_name or DEFAULT_TIMEZONE, durations=durations)

    def overrides(self) -> Dict[str, Dict[str, int]]:
        """Only the durations that differ from the defaults."""
        return {
            key: value.to_dict()
            for key, value in self.durations.items()
            if value != DEFAULT_DURATIONS[key]
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timezone": self.timezone,
            "durations": {k: v.to_dict() for k, v in self.durations.items()},
            "defaults": {k: v.to_dict() for k, v in DEFAULT_DURATIONS.items()},
        }


def _require_aware(value: datetime, what: str) -> None:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{what} must carry a UTC offset")


def add_months(start: datetime, months: int, zone: ZoneInfo) -> datetime:
    """``start`` plus calendar months in ``zone``; wall-clock time kept, day clamped.

    A wall-clock time that does not exist on the target day (it falls in a
    spring-forward gap) resolves to the same elapsed instant the zone's
    pre-transition offset gives, which reads one hour later on the wall clock.
    """
    _require_aware(start, "start")
    local = start.astimezone(zone)
    index = local.month - 1 + months
    year, month = local.year + index // 12, index % 12 + 1
    day = min(local.day, calendar.monthrange(year, month)[1])
    target = local.replace(tzinfo=None, year=year, month=month, day=day)
    # fold=0: an ambiguous time (autumn overlap) is its first occurrence, and a
    # time in the gap takes the earlier offset.
    resolved = target.replace(tzinfo=zone, fold=0)
    return resolved.astimezone(timezone.utc)


def add_duration(start: datetime, duration: Duration, zone: ZoneInfo) -> datetime:
    """Months first (calendar, in ``zone``), then hours (elapsed). Result in UTC."""
    _require_aware(start, "start")
    result = start.astimezone(timezone.utc)
    if duration.months:
        result = add_months(result, duration.months, zone)
    if duration.hours:
        result = result + timedelta(hours=duration.hours)
    return result


@dataclass(frozen=True)
class ClockDef:
    """One clock: the start instants it may run from, and the instant that meets it.

    ``starts`` pairs an instant with a duration key. With more than one start,
    the earliest resulting deadline binds. ``requires`` is the instant without
    which the clock has not started at all, even if another start is known.
    """

    key: str
    regime: str
    label: str
    starts: Tuple[Tuple[str, str], ...]
    met_by: str
    requires: str


CLOCKS: Tuple[ClockDef, ...] = (
    ClockDef(
        key="dora.initial",
        regime="dora",
        label="DORA initial notification",
        starts=(
            ("classification_at", "dora.initial_after_classification"),
            ("aware_at", "dora.initial_after_awareness"),
        ),
        met_by="notified_at",
        requires="classification_at",
    ),
    ClockDef(
        key="dora.intermediate",
        regime="dora",
        label="DORA intermediate report",
        starts=(("notified_at", "dora.intermediate_after_initial"),),
        met_by="last_intermediate_at",
        requires="notified_at",
    ),
    ClockDef(
        key="dora.final",
        regime="dora",
        label="DORA final report",
        starts=(("last_intermediate_at", "dora.final_after_intermediate"),),
        met_by="final_at",
        requires="last_intermediate_at",
    ),
    ClockDef(
        key="nis2.early_warning",
        regime="nis2",
        label="NIS2 early warning",
        starts=(("aware_at", "nis2.early_warning_after_awareness"),),
        met_by="early_warning_at",
        requires="aware_at",
    ),
    ClockDef(
        key="nis2.notification",
        regime="nis2",
        label="NIS2 incident notification",
        starts=(("aware_at", "nis2.notification_after_awareness"),),
        met_by="notified_at",
        requires="aware_at",
    ),
    ClockDef(
        key="nis2.final",
        regime="nis2",
        label="NIS2 final report",
        starts=(("notified_at", "nis2.final_after_notification"),),
        met_by="final_at",
        requires="notified_at",
    ),
)

CLOCK_KEYS: Tuple[str, ...] = tuple(c.key for c in CLOCKS)

# Clock states, in the order the UI ranks them.
NOT_STARTED = "not_started"
RUNNING = "running"
OVERDUE = "overdue"
MET = "met"
MET_LATE = "met_late"


@dataclass(frozen=True)
class ClockStatus:
    key: str
    regime: str
    label: str
    state: str
    due_at: Optional[datetime]
    bound_to: Optional[str]  # the start instant whose deadline binds
    started_at: Optional[datetime]  # value of bound_to
    met_at: Optional[datetime]
    met_by: str
    waiting_for: Optional[str]  # the missing instant while not started
    remaining_seconds: Optional[int]  # due_at - now; negative once overdue
    overdue: bool

    def to_dict(self) -> Dict[str, Any]:
        def iso(value: Optional[datetime]) -> Optional[str]:
            return value.astimezone(timezone.utc).isoformat() if value else None

        return {
            "key": self.key,
            "regime": self.regime,
            "label": self.label,
            "state": self.state,
            "due_at": iso(self.due_at),
            "bound_to": self.bound_to,
            "started_at": iso(self.started_at),
            "met_at": iso(self.met_at),
            "met_by": self.met_by,
            "waiting_for": self.waiting_for,
            "remaining_seconds": self.remaining_seconds,
            "overdue": self.overdue,
        }


Instants = Mapping[str, Mapping[str, Optional[datetime]]]


def due_at(
    clock: ClockDef, instants: Mapping[str, Optional[datetime]], config: ClockConfig
) -> Tuple[Optional[datetime], Optional[str]]:
    """The binding deadline and the start instant it came from, or (None, None)."""
    if instants.get(clock.requires) is None:
        return None, None
    best: Optional[Tuple[datetime, str]] = None
    for instant, duration_key in clock.starts:
        start = instants.get(instant)
        if start is None:
            continue
        _require_aware(start, instant)
        deadline = add_duration(start, config.durations[duration_key], config.zone)
        # Ties go to the earlier-listed start: the regulation's primary trigger.
        if best is None or deadline < best[0]:
            best = (deadline, instant)
    return best if best else (None, None)


def evaluate_clock(
    clock: ClockDef,
    instants: Mapping[str, Optional[datetime]],
    config: ClockConfig,
    now: datetime,
) -> ClockStatus:
    _require_aware(now, "now")
    due, bound_to = due_at(clock, instants, config)
    met_at = instants.get(clock.met_by)
    if met_at is not None:
        _require_aware(met_at, clock.met_by)
    started_at = instants.get(bound_to) if bound_to else None
    if due is None:
        # A clock that has not started cannot be met: DORA's notified_at
        # recorded before the incident is classified as major does not satisfy
        # an initial-notification clock that does not exist yet. met_at is still
        # reported so the UI can show what was recorded.
        return ClockStatus(
            key=clock.key,
            regime=clock.regime,
            label=clock.label,
            state=NOT_STARTED,
            due_at=None,
            bound_to=None,
            started_at=None,
            met_at=met_at,
            met_by=clock.met_by,
            waiting_for=clock.requires,
            remaining_seconds=None,
            overdue=False,
        )
    if met_at is not None:
        late = met_at > due
        return ClockStatus(
            key=clock.key,
            regime=clock.regime,
            label=clock.label,
            state=MET_LATE if late else MET,
            due_at=due,
            bound_to=bound_to,
            started_at=started_at,
            met_at=met_at,
            met_by=clock.met_by,
            waiting_for=None,
            remaining_seconds=None,
            overdue=False,
        )
    remaining = int((due - now).total_seconds() // 1)
    overdue = now > due
    return ClockStatus(
        key=clock.key,
        regime=clock.regime,
        label=clock.label,
        state=OVERDUE if overdue else RUNNING,
        due_at=due,
        bound_to=bound_to,
        started_at=started_at,
        met_at=None,
        met_by=clock.met_by,
        waiting_for=None,
        remaining_seconds=remaining,
        overdue=overdue,
    )


def evaluate(
    instants: Instants,
    config: ClockConfig,
    now: datetime,
    regimes: Sequence[str] = REGIMES,
) -> list[ClockStatus]:
    """Every clock of ``regimes``, in :data:`CLOCKS` order."""
    return [
        evaluate_clock(clock, instants.get(clock.regime, {}), config, now)
        for clock in CLOCKS
        if clock.regime in regimes
    ]


# The order the instants of a regime happen in: each pair is (earlier, later),
# and a later instant may not be recorded before an earlier one when both are
# known (equal is fine: an early warning can go out the minute you are aware).
# DORA's chain is strict -- classification, initial notification,
# intermediate, final. NIS2's early warning and incident notification both
# follow awareness but either may come first.
INSTANT_ORDER: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "dora": tuple(
        (a, b)
        for i, a in enumerate(INSTANTS["dora"])
        for b in INSTANTS["dora"][i + 1 :]
    ),
    "nis2": (
        ("aware_at", "early_warning_at"),
        ("aware_at", "notified_at"),
        ("aware_at", "final_at"),
        ("early_warning_at", "final_at"),
        ("notified_at", "final_at"),
    ),
}


def order_violations(
    regime: str,
    instants: Mapping[str, Optional[datetime]],
    involving: Optional[str] = None,
) -> list[Tuple[str, str]]:
    """The (earlier, later) pairs ``instants`` breaks, optionally only those
    that involve the instant ``involving``. Unset instants break nothing."""
    out = []
    for earlier, later in INSTANT_ORDER.get(regime, ()):
        if involving is not None and involving not in (earlier, later):
            continue
        a, b = instants.get(earlier), instants.get(later)
        if a is not None and b is not None and b < a:
            out.append((earlier, later))
    return out


def validate_instant(regime: str, instant: str) -> None:
    if regime not in INSTANTS:
        raise ValueError(f"unknown regime {regime!r}")
    if instant not in INSTANTS[regime]:
        raise ValueError(f"{regime} has no instant {instant!r}")
