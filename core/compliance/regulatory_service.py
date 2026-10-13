"""Regulatory clocks on a case: recorded start instants, their audit chain, status.

A start instant (``aware_at``, ``classification_at``, ``notified_at``, ...) is
never a column someone overwrites. Each set, change or clear is appended to
``regulatory_clock_events`` with the actor, the time it was recorded, the value
it replaced and, for a change or clear of a known value, a mandatory reason.
Rows of one case form a hash chain (``prev_hash`` -> ``row_hash``), so an
edited or missing row shows in :meth:`RegulatoryService.verify_chain`; the
table also refuses UPDATE (``50_regulatory_clocks.sql``). The chain alone
cannot show that its last rows were deleted, so a trigger keeps the case's
chain head (last seq and row hash) in ``regulatory_clock_heads``, which only
that trigger and a case deletion may change
(``58_broadcast_unique_and_clock_heads.sql``); verify_chain compares the two. Every event writes a
``case_audit_logs`` row too, so it appears in the case record.

Storage sits behind :class:`ClockStore`; :class:`SqlClockStore` is the
Postgres one, :class:`MemoryClockStore` the one unit tests use.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Protocol

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.compliance.clocks import (
    INSTANTS,
    REGIMES,
    ClockConfig,
    ClockConfigError,
    evaluate,
    order_violations,
    validate_instant,
)
from core.time import utcnow

DEFAULT_TENANT = "default"
REASON_MAX = 1000
# A start instant is a past fact. A little slack absorbs clock skew between the
# analyst's browser and the server.
FUTURE_SLACK = timedelta(minutes=5)


class InstantRefused(ValueError):
    """The requested start-instant change is not allowed (422)."""


class AnchorUnavailable(RuntimeError):
    """The store keeps no chain head (the table is not installed)."""


@dataclass(frozen=True)
class ClockEvent:
    case_id: str
    seq: int
    regime: str
    instant: str
    value: Optional[datetime]
    previous_value: Optional[datetime]
    actor: str
    reason: Optional[str]
    recorded_at: datetime
    prev_hash: str = ""
    row_hash: str = ""
    tenant_id: str = DEFAULT_TENANT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "regime": self.regime,
            "instant": self.instant,
            "value": _iso(self.value),
            "previous_value": _iso(self.previous_value),
            "actor": self.actor,
            "reason": self.reason,
            "recorded_at": _iso(self.recorded_at),
            "prev_hash": self.prev_hash,
            "row_hash": self.row_hash,
        }


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def event_hash(event: ClockEvent, prev_hash: str) -> str:
    """sha256 over prev_hash and the event's fields, in a fixed JSON form."""
    body = json.dumps(
        {
            "case_id": event.case_id,
            "seq": event.seq,
            "regime": event.regime,
            "instant": event.instant,
            "value": _iso(event.value),
            "previous_value": _iso(event.previous_value),
            "actor": event.actor,
            "reason": event.reason,
            "recorded_at": _iso(event.recorded_at),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


def fold_instants(
    events: List[ClockEvent],
) -> Dict[str, Dict[str, Optional[datetime]]]:
    """The current value of every instant: the last event for it wins."""
    current: Dict[str, Dict[str, Optional[datetime]]] = {
        regime: {instant: None for instant in INSTANTS[regime]} for regime in REGIMES
    }
    for event in sorted(events, key=lambda e: e.seq):
        if event.regime in current and event.instant in current[event.regime]:
            current[event.regime][event.instant] = event.value
    return current


def fold_sources(events: List[ClockEvent]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Who recorded each current instant, when, and at which seq."""
    sources: Dict[str, Dict[str, Dict[str, Any]]] = {r: {} for r in REGIMES}
    for event in sorted(events, key=lambda e: e.seq):
        sources.setdefault(event.regime, {})[event.instant] = {
            "value": _iso(event.value),
            "actor": event.actor,
            "recorded_at": _iso(event.recorded_at),
            "seq": event.seq,
            "reason": event.reason,
        }
    return sources


class ClockStore(Protocol):
    def case_exists(self, case_id: str) -> bool: ...

    def events(self, case_id: str) -> List[ClockEvent]: ...

    def append(self, event: ClockEvent) -> None: ...

    # Optional: the case's chain head as {"seq", "row_hash", "broken_at"} or
    # None when no event was ever appended. Raises AnchorUnavailable when the
    # store keeps none.
    # def head(self, case_id: str) -> Optional[Dict[str, Any]]: ...

    def audit(
        self,
        case_id: str,
        field_name: str,
        old: Optional[str],
        new: Optional[str],
        summary: str,
        actor: str,
    ) -> None: ...

    def load_config(self, tenant_id: str) -> Optional[Dict[str, Any]]: ...

    def save_config(
        self,
        tenant_id: str,
        timezone_name: str,
        overrides: Dict[str, Any],
        actor: str,
        old: Optional[Dict[str, Any]],
    ) -> None: ...

    def add_draft(self, draft: Dict[str, Any]) -> None: ...

    def drafts(self, case_id: str) -> List[Dict[str, Any]]: ...


@dataclass
class MemoryClockStore:
    """In-process store for tests; mirrors the SQL store's behaviour."""

    cases: set = field(default_factory=set)
    rows: List[ClockEvent] = field(default_factory=list)
    audits: List[Dict[str, Any]] = field(default_factory=list)
    config_rows: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    config_audits: List[Dict[str, Any]] = field(default_factory=list)
    draft_rows: List[Dict[str, Any]] = field(default_factory=list)
    heads: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def case_exists(self, case_id: str) -> bool:
        return case_id in self.cases

    def head(self, case_id: str) -> Optional[Dict[str, Any]]:
        head = self.heads.get(case_id)
        return dict(head) if head else None

    def events(self, case_id: str) -> List[ClockEvent]:
        return sorted(
            (e for e in self.rows if e.case_id == case_id), key=lambda e: e.seq
        )

    def append(self, event: ClockEvent) -> None:
        if any(e.case_id == event.case_id and e.seq == event.seq for e in self.rows):
            raise RuntimeError("duplicate seq")
        self.rows.append(event)
        # What the trigger in 58_broadcast_unique_and_clock_heads.sql does:
        # the head moves to every appended row, and the first append that did
        # not extend it (wrong seq or prev_hash) is remembered for good.
        head = self.heads.get(event.case_id)
        if head is None:
            follows = event.seq == 1 and event.prev_hash == ""
            broken_at = None
        else:
            follows = (
                event.seq == head["seq"] + 1 and event.prev_hash == head["row_hash"]
            )
            broken_at = head["broken_at"]
        if broken_at is None and not follows:
            broken_at = event.seq
        self.heads[event.case_id] = {
            "seq": event.seq,
            "row_hash": event.row_hash,
            "broken_at": broken_at,
        }

    def audit(self, case_id, field_name, old, new, summary, actor) -> None:
        self.audits.append(
            {
                "case_id": case_id,
                "field_name": field_name,
                "old_value": old,
                "new_value": new,
                "change_summary": summary,
                "changed_by": actor,
            }
        )

    def load_config(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        return self.config_rows.get(tenant_id)

    def save_config(self, tenant_id, timezone_name, overrides, actor, old) -> None:
        self.config_rows[tenant_id] = {
            "timezone": timezone_name,
            "durations": overrides,
            "updated_by": actor,
        }
        self.config_audits.append(
            {"old": old, "new": self.config_rows[tenant_id], "changed_by": actor}
        )

    def add_draft(self, draft: Dict[str, Any]) -> None:
        self.draft_rows.append(draft)

    def drafts(self, case_id: str) -> List[Dict[str, Any]]:
        rows = [d for d in self.draft_rows if d["case_id"] == case_id]
        return sorted(rows, key=lambda d: d["created_at"], reverse=True)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class SqlClockStore:
    """The Postgres store over the tables in ``50_regulatory_clocks.sql``."""

    def __init__(self, session: Session, tenant_id: str = DEFAULT_TENANT):
        self.session = session
        self.tenant_id = tenant_id

    def case_exists(self, case_id: str) -> bool:
        from core.storage.models import Case

        return (
            self.session.query(Case.case_id).filter(Case.case_id == case_id).first()
            is not None
        )

    def events(self, case_id: str) -> List[ClockEvent]:
        rows = self.session.execute(
            text(
                "SELECT case_id, seq, regime, instant, value, previous_value, actor, "
                "reason, recorded_at, prev_hash, row_hash, tenant_id "
                "FROM regulatory_clock_events "
                "WHERE tenant_id = :tenant AND case_id = :case_id ORDER BY seq"
            ),
            {"tenant": self.tenant_id, "case_id": case_id},
        ).all()
        return [
            ClockEvent(
                case_id=r[0],
                seq=r[1],
                regime=r[2],
                instant=r[3],
                value=_aware(r[4]),
                previous_value=_aware(r[5]),
                actor=r[6],
                reason=r[7],
                recorded_at=_aware(r[8]),
                prev_hash=r[9],
                row_hash=r[10],
                tenant_id=r[11],
            )
            for r in rows
        ]

    def head(self, case_id: str) -> Optional[Dict[str, Any]]:
        if (
            self.session.execute(
                text("SELECT to_regclass('regulatory_clock_heads')")
            ).scalar()
            is None
        ):
            raise AnchorUnavailable("regulatory_clock_heads is not installed")
        row = self.session.execute(
            text(
                "SELECT seq, row_hash, broken_at FROM regulatory_clock_heads "
                "WHERE tenant_id = :tenant AND case_id = :case_id"
            ),
            {"tenant": self.tenant_id, "case_id": case_id},
        ).first()
        if row is None:
            return None
        return {"seq": row[0], "row_hash": row[1], "broken_at": row[2]}

    def lock_case(self, case_id: str) -> None:
        """Serialise appends per case so two writers cannot take the same seq."""
        self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": f"regulatory_clock_events:{self.tenant_id}:{case_id}"},
        )

    def append(self, event: ClockEvent) -> None:
        self.session.execute(
            text(
                "INSERT INTO regulatory_clock_events (tenant_id, case_id, seq, regime, "
                "instant, value, previous_value, actor, reason, recorded_at, prev_hash, "
                "row_hash) VALUES (:tenant, :case_id, :seq, :regime, :instant, :value, "
                ":previous_value, :actor, :reason, :recorded_at, :prev_hash, :row_hash)"
            ),
            {
                "tenant": self.tenant_id,
                "case_id": event.case_id,
                "seq": event.seq,
                "regime": event.regime,
                "instant": event.instant,
                "value": event.value,
                "previous_value": event.previous_value,
                "actor": event.actor,
                "reason": event.reason,
                "recorded_at": event.recorded_at,
                "prev_hash": event.prev_hash,
                "row_hash": event.row_hash,
            },
        )

    def audit(self, case_id, field_name, old, new, summary, actor) -> None:
        from core.storage.models import CaseAuditLog

        self.session.add(
            CaseAuditLog(
                entity_type="case",
                entity_id=case_id,
                action="update",
                field_name=field_name[:100],
                old_value=old,
                new_value=new,
                change_summary=summary,
                changed_by=actor[:100],
            )
        )
        self.session.flush()

    def load_config(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        row = self.session.execute(
            text(
                "SELECT timezone, durations, updated_by, updated_at "
                "FROM regulatory_clock_config WHERE tenant_id = :tenant"
            ),
            {"tenant": tenant_id},
        ).first()
        if row is None:
            return None
        return {
            "timezone": row[0],
            "durations": dict(row[1] or {}),
            "updated_by": row[2],
            "updated_at": _iso(_aware(row[3])),
        }

    def save_config(self, tenant_id, timezone_name, overrides, actor, old) -> None:
        from core.storage.models import ConfigAuditLog

        self.session.execute(
            text(
                "INSERT INTO regulatory_clock_config (tenant_id, timezone, durations, "
                "updated_by, updated_at) VALUES (:tenant, :tz, CAST(:durations AS jsonb), "
                ":actor, now()) ON CONFLICT (tenant_id) DO UPDATE SET "
                "timezone = EXCLUDED.timezone, durations = EXCLUDED.durations, "
                "updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at"
            ),
            {
                "tenant": tenant_id,
                "tz": timezone_name,
                "durations": json.dumps(overrides, sort_keys=True),
                "actor": actor,
            },
        )
        self.session.add(
            ConfigAuditLog(
                config_type="regulatory_clocks",
                config_key=tenant_id,
                action="update" if old else "create",
                old_value=old,
                new_value={"timezone": timezone_name, "durations": overrides},
                changed_by=actor[:100],
            )
        )
        self.session.flush()

    def add_draft(self, draft: Dict[str, Any]) -> None:
        self.session.execute(
            text(
                "INSERT INTO regulatory_report_drafts (draft_id, tenant_id, case_id, "
                "regime, kind, generator, body, cited_ids, pack_digest, created_by, "
                "created_at) VALUES (CAST(:draft_id AS uuid), :tenant, :case_id, :regime, "
                ":kind, :generator, CAST(:body AS jsonb), CAST(:cited AS jsonb), "
                ":digest, :actor, :created_at)"
            ),
            {
                "draft_id": draft["draft_id"],
                "tenant": self.tenant_id,
                "case_id": draft["case_id"],
                "regime": draft["regime"],
                "kind": draft["kind"],
                "generator": draft["generator"],
                "body": json.dumps(draft, sort_keys=True, default=str),
                "cited": json.dumps(draft["cited_ids"]),
                "digest": draft["pack_digest"],
                "actor": draft["created_by"],
                "created_at": datetime.fromisoformat(draft["created_at"]),
            },
        )

    def drafts(self, case_id: str) -> List[Dict[str, Any]]:
        rows = self.session.execute(
            text(
                "SELECT body FROM regulatory_report_drafts WHERE tenant_id = :tenant "
                "AND case_id = :case_id ORDER BY created_at DESC LIMIT 50"
            ),
            {"tenant": self.tenant_id, "case_id": case_id},
        ).all()
        return [dict(r[0]) for r in rows]


class RegulatoryService:
    def __init__(
        self,
        store: ClockStore,
        tenant_id: str = DEFAULT_TENANT,
        now: Callable[[], datetime] = lambda: utcnow().replace(tzinfo=timezone.utc),
    ):
        self.store = store
        self.tenant_id = tenant_id
        self._now = now

    def now(self) -> datetime:
        value = self._now()
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    # -- configuration ---------------------------------------------------

    def config(self) -> ClockConfig:
        row = self.store.load_config(self.tenant_id)
        if not row:
            return ClockConfig()
        return ClockConfig.from_overrides(row.get("timezone"), row.get("durations"))

    def set_config(
        self, timezone_name: str, durations: Mapping[str, Any], actor: str
    ) -> ClockConfig:
        """Replace the tenant's settings. ``durations`` lists only overrides."""
        if not actor:
            raise ClockConfigError("a configuration change needs an actor")
        config = ClockConfig.from_overrides(timezone_name, durations)
        old = self.store.load_config(self.tenant_id)
        old_view = (
            {"timezone": old.get("timezone"), "durations": old.get("durations")}
            if old
            else None
        )
        self.store.save_config(
            self.tenant_id, config.timezone, config.overrides(), actor, old_view
        )
        return config

    # -- start instants --------------------------------------------------

    def events(self, case_id: str) -> List[ClockEvent]:
        return self.store.events(case_id)

    def record_instant(
        self,
        case_id: str,
        regime: str,
        instant: str,
        value: Optional[datetime],
        actor: str,
        reason: Optional[str] = None,
    ) -> Optional[ClockEvent]:
        """Append one event. Returns None when the value is already current.

        Setting a first value needs no reason. Changing or clearing a value
        that is already recorded needs one: it is never silent.
        """
        try:
            validate_instant(regime, instant)
        except ValueError as exc:
            raise InstantRefused(str(exc)) from None
        if not actor:
            raise InstantRefused("an instant needs an actor")
        reason = (reason or "").strip() or None
        if reason and len(reason) > REASON_MAX:
            raise InstantRefused(f"reason is longer than {REASON_MAX} characters")
        now = self.now()
        if value is not None:
            if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
                raise InstantRefused("the instant must carry a UTC offset")
            value = value.astimezone(timezone.utc)
            if value > now + FUTURE_SLACK:
                raise InstantRefused("a start instant cannot be in the future")

        lock = getattr(self.store, "lock_case", None)
        if lock:
            lock(case_id)
        events = self.store.events(case_id)
        current = fold_instants(events)[regime]
        previous = current[instant]
        if previous == value:
            return None
        if previous is not None and not reason:
            raise InstantRefused(
                f"{instant} is already recorded; changing or clearing it needs a reason"
            )
        broken = order_violations(regime, {**current, instant: value}, instant)
        if broken:
            earlier, later = broken[0]
            raise InstantRefused(f"{regime.upper()} {later} cannot be before {earlier}")
        last = events[-1] if events else None
        event = ClockEvent(
            case_id=case_id,
            seq=(last.seq + 1) if last else 1,
            regime=regime,
            instant=instant,
            value=value,
            previous_value=previous,
            actor=actor,
            reason=reason,
            recorded_at=now,
            tenant_id=self.tenant_id,
        )
        prev_hash = last.row_hash if last else ""
        event = replace(
            event, prev_hash=prev_hash, row_hash=event_hash(event, prev_hash)
        )
        self.store.append(event)
        verb = (
            "Set" if previous is None else ("Cleared" if value is None else "Changed")
        )
        summary = f"{verb} {regime.upper()} {instant}"
        if reason:
            summary += f": {reason}"
        self.store.audit(
            case_id,
            f"regulatory.{regime}.{instant}",
            _iso(previous),
            _iso(value),
            summary,
            actor,
        )
        return event

    def verify_chain(self, case_id: str) -> Dict[str, Any]:
        """Recompute every row hash; report the first row that does not match.

        Then hold the last row against the chain head the store keeps: a chain
        whose last rows were deleted is still internally consistent, and only
        the head shows that it used to be longer.
        """
        prev_hash = ""
        expected_seq = 1
        events = self.store.events(case_id)
        for event in events:
            if event.seq != expected_seq:
                return {"ok": False, "broken_at": event.seq, "why": "missing row"}
            if event.prev_hash != prev_hash or event.row_hash != event_hash(
                event, prev_hash
            ):
                return {"ok": False, "broken_at": event.seq, "why": "hash mismatch"}
            prev_hash = event.row_hash
            expected_seq += 1

        anchored = False
        head_of = getattr(self.store, "head", None)
        if head_of is not None:
            try:
                head = head_of(case_id)
                anchored = True
            except AnchorUnavailable:
                head = None
            if anchored:
                last = events[-1] if events else None
                if head is None:
                    if last is not None:
                        return {
                            "ok": False,
                            "broken_at": 1,
                            "why": "chain head missing",
                        }
                elif head.get("broken_at") is not None:
                    return {
                        "ok": False,
                        "broken_at": head["broken_at"],
                        "why": "append out of sequence",
                    }
                elif last is None or last.seq < head["seq"]:
                    return {
                        "ok": False,
                        "broken_at": (last.seq + 1) if last else 1,
                        "why": "missing row",
                    }
                elif last.seq != head["seq"] or last.row_hash != head["row_hash"]:
                    return {
                        "ok": False,
                        "broken_at": last.seq,
                        "why": "chain head mismatch",
                    }
        return {
            "ok": True,
            "broken_at": None,
            "why": None,
            "rows": len(events),
            "anchored": anchored,
        }

    # -- status -----------------------------------------------------------

    def status(self, case_id: str) -> Dict[str, Any]:
        events = self.store.events(case_id)
        config = self.config()
        now = self.now()
        clocks = evaluate(fold_instants(events), config, now)
        return {
            "case_id": case_id,
            "now": _iso(now),
            "timezone": config.timezone,
            "durations": {k: v.to_dict() for k, v in config.durations.items()},
            "instants": fold_sources(events),
            "clocks": [c.to_dict() for c in clocks],
            "chain": self.verify_chain(case_id),
            "events": len(events),
        }
