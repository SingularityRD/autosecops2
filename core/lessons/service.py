"""Lesson lifecycle: propose, replay, promote, roll back.

    proposed --promote (replay passes)--> active --rollback--> retired
        \\------------------rollback (reject)----------------/

Every transition and every replay writes a ``lesson_events`` row. A refused
promotion is recorded too, so the audit shows who tried and why it failed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from core.lessons.model import (
    CATEGORIES,
    DEFAULT_EXPIRY_DAYS,
    EFFECTS,
    MAX_EXPIRY_DAYS,
    SOURCE_KINDS,
    TRUSTED_PROVENANCE,
    Lesson,
    LessonEvent,
    ScopeError,
    validate_scope,
)
from core.lessons.provenance import assess
from core.lessons.replay import ReplayCase, replay
from core.lessons.store import LessonStore

#: Builds the replay baseline: ``(cases, harness metadata)``. Raises when the
#: harness cannot run; promotion then fails closed.
Baseline = Callable[[], Tuple[Sequence[ReplayCase], Mapping[str, Any]]]

MAX_LESSON_LEN = 4000
MAX_REASON_LEN = 1000


class LessonInvalid(ValueError):
    """The request is malformed (HTTP 422)."""


class LessonConflict(ValueError):
    """The lesson is not in a state that allows this (HTTP 409)."""


class LessonNotFound(LookupError):
    pass


class ReplayUnavailable(RuntimeError):
    """The replay harness could not run (HTTP 503)."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


class LessonService:
    def __init__(
        self,
        store: LessonStore,
        baseline: Optional[Baseline] = None,
        *,
        now: Callable[[], datetime] = _now,
    ):
        self.store = store
        self.baseline = baseline
        self.now = now

    # -- reads -----------------------------------------------------------
    def get(self, lesson_id: str) -> Lesson:
        lesson = self.store.get(lesson_id)
        if lesson is None:
            raise LessonNotFound(lesson_id)
        return lesson

    def list(self, status: Optional[str] = None) -> List[Lesson]:
        return self.store.list(status)

    def events(self, lesson_id: str) -> List[LessonEvent]:
        self.get(lesson_id)
        return self.store.events(lesson_id)

    def _event(self, lesson_id: str, action: str, actor: str, **detail: Any) -> None:
        self.store.add_event(
            LessonEvent(
                lesson_id=lesson_id,
                action=action,
                actor=actor,
                at=self.now(),
                detail=detail,
            )
        )

    # -- propose -----------------------------------------------------------
    def propose(
        self,
        *,
        lesson_text: str,
        effect: str,
        applies_to: Mapping[str, Any],
        actor: str,
        source_kind: str = "analyst_override",
        source_id: Optional[str] = None,
        category: Optional[str] = None,
        expires_in_days: int = DEFAULT_EXPIRY_DAYS,
        source_alert: Optional[Mapping[str, Any]] = None,
        provenance: Optional[str] = None,
    ) -> Lesson:
        """A new ``proposed`` lesson.

        ``provenance`` is computed from ``source_alert`` for a person's
        request; automation passes ``"system"`` and its lesson can never
        apply until a person writes it again.
        """
        text = (lesson_text or "").strip()
        if not text or len(text) > MAX_LESSON_LEN:
            raise LessonInvalid(f"lesson text must be 1..{MAX_LESSON_LEN} characters")
        if effect not in EFFECTS:
            raise LessonInvalid(f"effect must be one of {', '.join(EFFECTS)}")
        if source_kind not in SOURCE_KINDS:
            raise LessonInvalid(f"source_kind must be one of {', '.join(SOURCE_KINDS)}")
        if category is not None and category not in CATEGORIES:
            raise LessonInvalid(f"category must be one of {', '.join(CATEGORIES)}")
        if not 1 <= int(expires_in_days) <= MAX_EXPIRY_DAYS:
            raise LessonInvalid(f"expires_in_days must be 1..{MAX_EXPIRY_DAYS}")
        try:
            scope = validate_scope(applies_to)
        except ScopeError as exc:
            raise LessonInvalid(str(exc)) from None
        tag, detail = assess(scope, text, source_alert)
        if provenance is not None:
            tag = provenance
            detail = {**detail, "set_by": "caller"}
        now = self.now()
        lesson = Lesson(
            id=str(uuid.uuid4()),
            lesson=text,
            effect=effect,
            applies_to=scope,
            category=category,
            created_by=actor,
            created_at=now,
            expires_at=now + timedelta(days=int(expires_in_days)),
            status="proposed",
            provenance=tag,
            provenance_detail=detail,
            source_kind=source_kind,
            source_id=source_id,
        )
        lesson = self.store.add(lesson)
        self._event(lesson.id, "proposed", actor, provenance=tag)
        return lesson

    # -- replay --------------------------------------------------------------
    def _replay(self, lesson: Lesson) -> Dict[str, Any]:
        if self.baseline is None:
            raise ReplayUnavailable("no replay harness is configured")
        try:
            cases, meta = self.baseline()
        except Exception as exc:  # noqa: BLE001 — any harness failure fails closed
            raise ReplayUnavailable(
                f"replay harness failed: {type(exc).__name__}"
            ) from None
        if not cases:
            raise ReplayUnavailable("replay harness returned no historical alerts")
        return replay(lesson, cases, self.now(), meta=meta)

    def run_replay(self, lesson_id: str, actor: str) -> Tuple[Lesson, Dict[str, Any]]:
        """Replay without changing status; the report is kept on the lesson."""
        lesson = self.get(lesson_id)
        if lesson.status == "retired":
            raise LessonConflict("a retired lesson is not replayed")
        report = self._replay(lesson)
        lesson.replay, lesson.replay_passed, lesson.replayed_at = (
            report,
            bool(report["passed"]),
            self.now(),
        )
        self.store.update(lesson)
        self._event(lesson.id, "replayed", actor, **_summary(report))
        return lesson, report

    # -- promote -------------------------------------------------------------
    def promote(
        self, lesson_id: str, actor: str
    ) -> Tuple[Lesson, Dict[str, Any], bool]:
        """Replay now and, when it passes, make the lesson active.

        Returns ``(lesson, report, promoted)``. A refusal after replay is
        recorded as a ``promotion_refused`` event and returned, not raised, so
        the caller can show the report and the audit row is kept.
        """
        lesson = self.get(lesson_id)
        if lesson.status != "proposed":
            raise LessonConflict(
                f"only a proposed lesson can be promoted (it is {lesson.status})"
            )
        if lesson.provenance != TRUSTED_PROVENANCE:
            raise LessonConflict(
                f"a lesson with {lesson.provenance} provenance cannot be promoted: "
                "it was traced to text the alert's author controls or to automation"
            )
        if lesson.expired(self.now()):
            raise LessonConflict("the lesson has expired; propose it again")
        report = self._replay(lesson)
        lesson.replay, lesson.replay_passed, lesson.replayed_at = (
            report,
            bool(report["passed"]),
            self.now(),
        )
        if not report["passed"]:
            self.store.update(lesson)
            self._event(
                lesson.id,
                "promotion_refused",
                actor,
                reasons=report["reasons"],
                **_summary(report),
            )
            return lesson, report, False
        lesson.status = "active"
        lesson.approved_by = actor
        lesson.approved_at = self.now()
        self.store.update(lesson)
        self._event(lesson.id, "promoted", actor, **_summary(report))
        return lesson, report, True

    # -- rollback ------------------------------------------------------------
    def rollback(self, lesson_id: str, actor: str, reason: str) -> Lesson:
        """Retire a proposed or active lesson in one step."""
        reason = (reason or "").strip()
        if not reason or len(reason) > MAX_REASON_LEN:
            raise LessonInvalid(
                f"a reason of 1..{MAX_REASON_LEN} characters is required"
            )
        lesson = self.get(lesson_id)
        if lesson.status == "retired":
            raise LessonConflict("the lesson is already retired")
        previous = lesson.status
        lesson.status = "retired"
        lesson.retired_at = self.now()
        lesson.retired_by = actor
        lesson.retire_reason = reason
        self.store.update(lesson)
        self._event(
            lesson.id, "rolled_back", actor, previous_status=previous, reason=reason
        )
        return lesson


def _summary(report: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "passed": bool(report.get("passed")),
        "cases": report.get("cases"),
        "matched": report.get("matched"),
        "improvements": report.get("improvements"),
        "regressions": report.get("regressions"),
    }
