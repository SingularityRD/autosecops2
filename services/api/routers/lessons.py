"""Lessons from analyst corrections: propose, replay, promote, roll back (W3.11).

    GET  /api/lessons                    findings.read         list (?status=)
    GET  /api/lessons/{id}               findings.read         one lesson
    GET  /api/lessons/{id}/events        findings.read         its audit trail
    POST /api/lessons                    findings.write        propose
    POST /api/lessons/{id}/replay        findings.write        dry-run replay
    POST /api/lessons/{id}/promote       ai_decisions.approve  replay, then activate
    POST /api/lessons/{id}/rollback      findings.write        retire in one step

Parked here rather than in core/lessons/ because replay drives evalkit, which
builds the daemon's own triage prompt (services.daemon): core must not import
that. The actor of every write is the signed-in user, never a body field.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from core.auth.permissions import require_permission
from core.lessons.model import DEFAULT_EXPIRY_DAYS, MAX_EXPIRY_DAYS, Lesson
from core.lessons.service import (
    LessonConflict,
    LessonInvalid,
    LessonNotFound,
    LessonService,
    ReplayUnavailable,
)
from core.lessons.store import LessonStore, SqlLessonStore
from core.routing import Auth, RouterMeta, UnitOfWorkSession
from core.storage.models import User

logger = logging.getLogger(__name__)

router = APIRouter()

ROUTER_META = RouterMeta(prefix="/api/lessons", tags=["lessons"], auth=Auth.REQUIRED)

_READ = require_permission("findings.read")
_WRITE = require_permission("findings.write")
_APPROVE = require_permission("ai_decisions.approve")


class LessonScope(BaseModel):
    data_source: Optional[str] = Field(default=None, max_length=255)
    rule_name: Optional[str] = Field(default=None, max_length=255)
    mitre_technique: Optional[str] = Field(default=None, max_length=255)
    hostnames: Optional[List[str]] = None
    usernames: Optional[List[str]] = None
    src_ips: Optional[List[str]] = None
    file_hashes: Optional[List[str]] = None
    max_severity: Literal["low", "medium", "high"] = "medium"

    model_config = {"extra": "forbid"}


class LessonResponse(BaseModel):
    id: str
    lesson: str
    effect: str
    applies_to: Dict[str, Any]
    category: Optional[str] = None
    status: Literal["proposed", "active", "retired"]
    provenance: Literal["analyst", "adversary_text", "system"]
    provenance_detail: Dict[str, Any]
    source_kind: str
    source_id: Optional[str] = None
    created_by: str
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    expired: bool
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    replay: Optional[Dict[str, Any]] = None
    replay_passed: bool
    replayed_at: Optional[str] = None
    retired_at: Optional[str] = None
    retired_by: Optional[str] = None
    retire_reason: Optional[str] = None


class LessonsResponse(BaseModel):
    lessons: List[LessonResponse]


class LessonEventResponse(BaseModel):
    id: Optional[int] = None
    lesson_id: str
    action: str
    actor: str
    at: str
    detail: Dict[str, Any]


class LessonEventsResponse(BaseModel):
    events: List[LessonEventResponse]


class ProposeLessonRequest(BaseModel):
    lesson: str = Field(min_length=1, max_length=4000)
    effect: Literal["benign_hint", "escalate"]
    applies_to: LessonScope
    category: Optional[
        Literal["phishing", "malware", "identity", "network", "cloud", "other"]
    ] = None
    source_kind: Literal["analyst_override", "manual"] = "analyst_override"
    source_id: Optional[str] = Field(default=None, max_length=255)
    expires_in_days: int = Field(default=DEFAULT_EXPIRY_DAYS, ge=1, le=MAX_EXPIRY_DAYS)


class ReplayResultResponse(BaseModel):
    lesson: LessonResponse
    replay: Dict[str, Any]
    promoted: Optional[bool] = None


class RollbackRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


def _actor(user: User) -> str:
    return user.username or user.user_id


def _store(session) -> LessonStore:
    return SqlLessonStore(session)


def _baseline():
    """Imported on use: the harness pulls in the daemon's prompt builder."""
    from evalkit.lessons import baseline

    return baseline()


def _source_alert(session, finding_id: str) -> Optional[Dict[str, Any]]:
    """The finding a correction was made on, as the fields provenance reads."""
    from core.storage.models import Finding

    row = session.query(Finding).filter(Finding.finding_id == finding_id).first()
    if row is None:
        return None
    return {
        "finding_id": row.finding_id,
        "external_id": row.external_id,
        "data_source": row.data_source,
        "severity": row.severity,
        "title": row.title,
        "description": row.description,
        "entity_context": row.entity_context or {},
        "mitre_predictions": {
            p.technique_id: p.confidence for p in (row.mitre_prediction_rows or [])
        },
    }


def _service(session) -> LessonService:
    return LessonService(_store(session), _baseline)


def _out(service: LessonService, lesson: Lesson) -> Dict[str, Any]:
    return lesson.to_dict(now=service.now())


def _get(service: LessonService, lesson_id: str) -> Lesson:
    try:
        return service.get(lesson_id)
    except LessonNotFound:
        raise HTTPException(status_code=404, detail="Lesson not found") from None


def _raise(exc: Exception):
    if isinstance(exc, LessonNotFound):
        raise HTTPException(status_code=404, detail="Lesson not found") from None
    if isinstance(exc, LessonInvalid):
        raise HTTPException(status_code=422, detail=str(exc)) from None
    if isinstance(exc, LessonConflict):
        raise HTTPException(status_code=409, detail=str(exc)) from None
    if isinstance(exc, ReplayUnavailable):
        logger.warning("lesson replay unavailable: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from None
    raise exc


@router.get("", response_model=LessonsResponse)
def list_lessons(
    session: UnitOfWorkSession,
    status: Optional[Literal["proposed", "active", "retired"]] = Query(None),
    _user: User = Depends(_READ),
) -> Dict[str, Any]:
    service = _service(session)
    return {"lessons": [_out(service, x) for x in service.list(status)]}


@router.get("/{lesson_id}", response_model=LessonResponse)
def get_lesson(
    lesson_id: str, session: UnitOfWorkSession, _user: User = Depends(_READ)
) -> Dict[str, Any]:
    service = _service(session)
    return _out(service, _get(service, lesson_id))


@router.get("/{lesson_id}/events", response_model=LessonEventsResponse)
def list_lesson_events(
    lesson_id: str, session: UnitOfWorkSession, _user: User = Depends(_READ)
) -> Dict[str, Any]:
    service = _service(session)
    _get(service, lesson_id)
    return {"events": [e.to_dict() for e in service.events(lesson_id)]}


@router.post("", response_model=LessonResponse)
def propose_lesson(
    body: ProposeLessonRequest,
    session: UnitOfWorkSession,
    user: User = Depends(_WRITE),
) -> Dict[str, Any]:
    """Propose a lesson. It does nothing until promoted.

    When ``source_id`` names a finding, the scope and text are traced against
    that finding's free text; a lesson built from it is tagged
    ``adversary_text`` and can never be promoted.
    """
    source_alert = None
    if body.source_id:
        source_alert = _source_alert(session, body.source_id)
        if source_alert is None and body.source_kind == "analyst_override":
            raise HTTPException(status_code=422, detail="source finding not found")
    service = _service(session)
    try:
        lesson = service.propose(
            lesson_text=body.lesson,
            effect=body.effect,
            applies_to=body.applies_to.model_dump(exclude_none=True),
            category=body.category,
            source_kind=body.source_kind,
            source_id=body.source_id,
            expires_in_days=body.expires_in_days,
            actor=_actor(user),
            source_alert=source_alert,
        )
    except (LessonInvalid, LessonConflict) as exc:
        _raise(exc)
    return _out(service, lesson)


@router.post("/{lesson_id}/replay", response_model=ReplayResultResponse)
def replay_lesson(
    lesson_id: str, session: UnitOfWorkSession, user: User = Depends(_WRITE)
) -> Dict[str, Any]:
    """Replay over labelled historical alerts; the status does not change."""
    service = _service(session)
    _get(service, lesson_id)
    try:
        lesson, report = service.run_replay(lesson_id, _actor(user))
    except (LessonConflict, ReplayUnavailable) as exc:
        _raise(exc)
    return {"lesson": _out(service, lesson), "replay": report}


@router.post(
    "/{lesson_id}/promote",
    response_model=ReplayResultResponse,
    responses={409: {"description": "Replay failed or the lesson cannot be promoted"}},
)
def promote_lesson(
    lesson_id: str, session: UnitOfWorkSession, user: User = Depends(_APPROVE)
):
    """Replay now; activate only if no historical verdict got worse.

    A failed replay answers 409 with the report. It is returned rather than
    raised so the refusal's audit row is committed.
    """
    service = _service(session)
    _get(service, lesson_id)
    try:
        lesson, report, promoted = service.promote(lesson_id, _actor(user))
    except (LessonConflict, ReplayUnavailable) as exc:
        _raise(exc)
    body = {"lesson": _out(service, lesson), "replay": report, "promoted": promoted}
    if not promoted:
        return JSONResponse(
            status_code=409,
            content={"detail": "; ".join(report["reasons"]) or "replay failed", **body},
        )
    return body


@router.post("/{lesson_id}/rollback", response_model=LessonResponse)
def rollback_lesson(
    lesson_id: str,
    body: RollbackRequest,
    session: UnitOfWorkSession,
    user: User = Depends(_WRITE),
) -> Dict[str, Any]:
    """Retire a proposed or active lesson. It stops applying at once."""
    service = _service(session)
    _get(service, lesson_id)
    try:
        lesson = service.rollback(lesson_id, _actor(user), body.reason)
    except (LessonInvalid, LessonConflict) as exc:
        _raise(exc)
    return _out(service, lesson)
