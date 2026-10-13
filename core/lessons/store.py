"""Lesson storage: an in-memory store for tests and the SQL store.

The tables are SQL-owned (``48_autonomy_lessons_suppression_retention.sql``
and ``55_lessons_promotion.sql``), with no ORM model, so the SQL store writes
plain parameterised SQL through the request's session. It never commits.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.lessons.model import Lesson, LessonEvent

DEFAULT_TENANT = "default"

_COLUMNS = (
    "id, tenant_id, source_kind, source_id, category, lesson, applies_to, status, "
    "created_by, created_at, approved_by, approved_at, retired_at, effect, expires_at, "
    "provenance, provenance_detail, replay, replay_passed, replayed_at, retired_by, "
    "retire_reason"
)


class LessonStore(Protocol):
    def add(self, lesson: Lesson) -> Lesson: ...

    def get(self, lesson_id: str) -> Optional[Lesson]: ...

    def list(self, status: Optional[str] = None) -> List[Lesson]: ...

    def update(self, lesson: Lesson) -> None: ...

    def add_event(self, event: LessonEvent) -> LessonEvent: ...

    def events(self, lesson_id: str) -> List[LessonEvent]: ...


class MemoryLessonStore:
    def __init__(self) -> None:
        self.rows: Dict[str, Lesson] = {}
        self.event_rows: List[LessonEvent] = []

    def add(self, lesson: Lesson) -> Lesson:
        self.rows[lesson.id] = replace(lesson)
        return lesson

    def get(self, lesson_id: str) -> Optional[Lesson]:
        row = self.rows.get(lesson_id)
        return replace(row) if row else None

    def list(self, status: Optional[str] = None) -> List[Lesson]:
        rows = [r for r in self.rows.values() if status in (None, r.status)]
        return [
            replace(r) for r in sorted(rows, key=lambda r: r.created_at, reverse=True)
        ]

    def update(self, lesson: Lesson) -> None:
        self.rows[lesson.id] = replace(lesson)

    def add_event(self, event: LessonEvent) -> LessonEvent:
        event = replace(event, id=len(self.event_rows) + 1)
        self.event_rows.append(event)
        return event

    def events(self, lesson_id: str) -> List[LessonEvent]:
        return [e for e in self.event_rows if e.lesson_id == lesson_id]

    def active(self, now: datetime) -> List[Lesson]:
        return [
            replace(r)
            for r in self.rows.values()
            if r.status == "active" and r.provenance == "analyst" and not r.expired(now)
        ]


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _json(value: Any) -> Optional[str]:
    return None if value is None else json.dumps(value, sort_keys=True)


def _loaded(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


class SqlLessonStore:
    def __init__(self, session: Session, tenant_id: str = DEFAULT_TENANT):
        self.session = session
        self.tenant_id = tenant_id

    def _row(self, r) -> Lesson:
        m = r._mapping
        return Lesson(
            id=str(m["id"]),
            tenant_id=m["tenant_id"],
            source_kind=m["source_kind"],
            source_id=m["source_id"],
            category=m["category"],
            lesson=m["lesson"],
            applies_to=_loaded(m["applies_to"]) or {},
            status=m["status"],
            created_by=m["created_by"],
            created_at=_aware(m["created_at"]),
            approved_by=m["approved_by"],
            approved_at=_aware(m["approved_at"]),
            retired_at=_aware(m["retired_at"]),
            effect=m["effect"],
            expires_at=_aware(m["expires_at"]),
            provenance=m["provenance"],
            provenance_detail=_loaded(m["provenance_detail"]) or {},
            replay=_loaded(m["replay"]),
            replay_passed=bool(m["replay_passed"]),
            replayed_at=_aware(m["replayed_at"]),
            retired_by=m["retired_by"],
            retire_reason=m["retire_reason"],
        )

    def add(self, lesson: Lesson) -> Lesson:
        lesson_id = lesson.id or str(uuid.uuid4())
        self.session.execute(
            text(
                "INSERT INTO lessons (id, tenant_id, source_kind, source_id, category, "
                "lesson, applies_to, status, created_by, created_at, effect, expires_at, "
                "provenance, provenance_detail) VALUES (CAST(:id AS UUID), :tenant, "
                ":source_kind, :source_id, :category, :lesson, CAST(:applies_to AS JSONB), "
                ":status, :created_by, :created_at, :effect, :expires_at, :provenance, "
                "CAST(:provenance_detail AS JSONB))"
            ),
            {
                "id": lesson_id,
                "tenant": self.tenant_id,
                "source_kind": lesson.source_kind,
                "source_id": lesson.source_id,
                "category": lesson.category,
                "lesson": lesson.lesson,
                "applies_to": _json(lesson.applies_to),
                "status": lesson.status,
                "created_by": lesson.created_by,
                "created_at": lesson.created_at,
                "effect": lesson.effect,
                "expires_at": lesson.expires_at,
                "provenance": lesson.provenance,
                "provenance_detail": _json(lesson.provenance_detail),
            },
        )
        return replace(lesson, id=lesson_id, tenant_id=self.tenant_id)

    def get(self, lesson_id: str) -> Optional[Lesson]:
        try:
            uuid.UUID(lesson_id)
        except ValueError:
            return None
        row = self.session.execute(
            text(
                f"SELECT {_COLUMNS} FROM lessons "  # noqa: S608 — fixed column list
                "WHERE tenant_id = :tenant AND id = CAST(:id AS UUID)"
            ),
            {"tenant": self.tenant_id, "id": lesson_id},
        ).first()
        return self._row(row) if row else None

    def list(self, status: Optional[str] = None) -> List[Lesson]:
        rows = self.session.execute(
            text(
                f"SELECT {_COLUMNS} FROM lessons "  # noqa: S608 — fixed column list
                "WHERE tenant_id = :tenant "
                "AND (CAST(:status AS TEXT) IS NULL OR status = :status) "
                "ORDER BY created_at DESC LIMIT 500"
            ),
            {"tenant": self.tenant_id, "status": status},
        ).all()
        return [self._row(r) for r in rows]

    def update(self, lesson: Lesson) -> None:
        """Write the mutable columns: status, approval, replay and retirement."""
        self.session.execute(
            text(
                "UPDATE lessons SET status = :status, approved_by = :approved_by, "
                "approved_at = :approved_at, replay = CAST(:replay AS JSONB), "
                "replay_passed = :replay_passed, replayed_at = :replayed_at, "
                "retired_at = :retired_at, retired_by = :retired_by, "
                "retire_reason = :retire_reason "
                "WHERE tenant_id = :tenant AND id = CAST(:id AS UUID)"
            ),
            {
                "tenant": self.tenant_id,
                "id": lesson.id,
                "status": lesson.status,
                "approved_by": lesson.approved_by,
                "approved_at": lesson.approved_at,
                "replay": _json(lesson.replay),
                "replay_passed": lesson.replay_passed,
                "replayed_at": lesson.replayed_at,
                "retired_at": lesson.retired_at,
                "retired_by": lesson.retired_by,
                "retire_reason": lesson.retire_reason,
            },
        )

    def add_event(self, event: LessonEvent) -> LessonEvent:
        new_id = self.session.execute(
            text(
                "INSERT INTO lesson_events (tenant_id, lesson_id, action, actor, at, detail) "
                "VALUES (:tenant, CAST(:lesson_id AS UUID), :action, :actor, :at, "
                "CAST(:detail AS JSONB)) RETURNING id"
            ),
            {
                "tenant": self.tenant_id,
                "lesson_id": event.lesson_id,
                "action": event.action,
                "actor": event.actor,
                "at": event.at,
                "detail": _json(event.detail),
            },
        ).scalar_one()
        return replace(event, id=int(new_id))

    def events(self, lesson_id: str) -> List[LessonEvent]:
        rows = self.session.execute(
            text(
                "SELECT id, lesson_id, action, actor, at, detail FROM lesson_events "
                "WHERE tenant_id = :tenant AND lesson_id = CAST(:id AS UUID) ORDER BY id"
            ),
            {"tenant": self.tenant_id, "id": lesson_id},
        ).all()
        return [
            LessonEvent(
                id=int(r[0]),
                lesson_id=str(r[1]),
                action=r[2],
                actor=r[3],
                at=_aware(r[4]),
                detail=_loaded(r[5]) or {},
            )
            for r in rows
        ]

    def active(self, now: datetime) -> List[Lesson]:
        """Lessons that may apply now: active, unexpired, analyst provenance."""
        rows = self.session.execute(
            text(
                f"SELECT {_COLUMNS} FROM lessons "  # noqa: S608 — fixed column list
                "WHERE tenant_id = :tenant AND status = 'active' "
                "AND provenance = 'analyst' AND expires_at > :now"
            ),
            {"tenant": self.tenant_id, "now": now},
        ).all()
        return [self._row(r) for r in rows]
