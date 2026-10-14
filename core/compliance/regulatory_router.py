"""Regulatory notification clocks and report drafts on a case.

    GET  /api/cases/{case_id}/regulatory/clocks   cases.read   clocks, instants, chain
    GET  /api/cases/{case_id}/regulatory/events   cases.read   start-instant history
    POST /api/cases/{case_id}/regulatory/events   cases.write  set / change / clear an instant
    GET  /api/cases/{case_id}/regulatory/drafts   cases.read   drafts generated so far
    POST /api/cases/{case_id}/regulatory/drafts   cases.write  generate a draft from the pack

The actor of every write is the signed-in user, never a field of the body.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from core.auth.permissions import require_permission
from core.compliance.clocks import evaluate
from core.compliance.evidence import EvidencePack, read_citable
from core.compliance.regulatory_drafts import KINDS, DraftCitationError, generate_draft
from core.compliance.regulatory_service import (
    ClockStore,
    InstantRefused,
    RegulatoryService,
    SqlClockStore,
    fold_instants,
)
from core.routing import Auth, RouterMeta, UnitOfWorkSession
from core.storage.models import User

logger = logging.getLogger(__name__)

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/cases",
    tags=["regulatory"],
    auth=Auth.REQUIRED,
)

_READ = require_permission("cases.read")
_WRITE = require_permission("cases.write")


class ClockStatusResponse(BaseModel):
    key: str
    regime: str
    label: str
    state: Literal["not_started", "running", "overdue", "met", "met_late"]
    due_at: Optional[str] = None
    bound_to: Optional[str] = None
    started_at: Optional[str] = None
    met_at: Optional[str] = None
    met_by: str
    waiting_for: Optional[str] = None
    remaining_seconds: Optional[int] = None
    overdue: bool


class InstantSourceResponse(BaseModel):
    value: Optional[str] = None
    actor: str
    recorded_at: Optional[str] = None
    seq: int
    reason: Optional[str] = None


class ChainResponse(BaseModel):
    ok: bool
    broken_at: Optional[int] = None
    why: Optional[str] = None
    rows: Optional[int] = None
    # True when the last row was also checked against the stored chain head, so
    # a deleted tail would show; False when the store keeps no head (W0.11).
    anchored: Optional[bool] = None


class RegulatoryStatusResponse(BaseModel):
    case_id: str
    now: str
    timezone: str
    durations: Dict[str, Dict[str, int]]
    instants: Dict[str, Dict[str, InstantSourceResponse]]
    clocks: List[ClockStatusResponse]
    chain: ChainResponse
    events: int


class ClockEventResponse(BaseModel):
    seq: int
    regime: str
    instant: str
    value: Optional[str] = None
    previous_value: Optional[str] = None
    actor: str
    reason: Optional[str] = None
    recorded_at: str
    prev_hash: str
    row_hash: str


class ClockEventsResponse(BaseModel):
    events: List[ClockEventResponse]
    chain: ChainResponse


class RecordInstantRequest(BaseModel):
    regime: Literal["dora", "nis2"]
    instant: str = Field(min_length=1, max_length=40)
    # null clears the instant (needs a reason when one was recorded).
    value: Optional[datetime] = None
    reason: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("value")
    @classmethod
    def _aware(cls, value: Optional[datetime]) -> Optional[datetime]:
        if value is not None and value.tzinfo is None:
            raise ValueError("the instant must carry a UTC offset")
        return value


class RecordInstantResponse(BaseModel):
    changed: bool
    event: Optional[ClockEventResponse] = None
    status: RegulatoryStatusResponse


class DraftLine(BaseModel):
    text: str
    cites: List[str]


class DraftSection(BaseModel):
    heading: str
    lines: List[DraftLine]


class DraftResponse(BaseModel):
    draft_id: str
    case_id: str
    regime: str
    kind: str
    title: str
    generator: Literal["template", "llm"]
    fallback_reason: Optional[str] = None
    sections: List[DraftSection]
    to_complete: List[str]
    cited_ids: List[str]
    pack_digest: str
    pack_size: int
    created_by: str
    created_at: str
    markdown: str


class DraftsResponse(BaseModel):
    drafts: List[DraftResponse]


class GenerateDraftRequest(BaseModel):
    regime: Literal["dora", "nis2"]
    kind: Literal["initial", "intermediate", "final", "early_warning", "notification"]


def _actor(user: User) -> str:
    return user.username or user.user_id


def _store(session) -> ClockStore:
    return SqlClockStore(session)


def _service(session) -> RegulatoryService:
    return RegulatoryService(_store(session))


def _evidence_pack(session, case_id: str, events) -> EvidencePack:
    """The case's citable index, built by the evidence pack's reader (W3.7)."""
    pack = read_citable(session, case_id, events)
    if pack is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return pack


def _require_case(service: RegulatoryService, case_id: str) -> None:
    if not service.store.case_exists(case_id):
        raise HTTPException(status_code=404, detail="Case not found")


@router.get(
    "/{case_id}/regulatory/clocks",
    response_model=RegulatoryStatusResponse,
)
def get_regulatory_clocks(
    case_id: str, session: UnitOfWorkSession, _user: User = Depends(_READ)
) -> Dict[str, Any]:
    """Every DORA and NIS2 clock: due_at, remaining seconds, overdue, and what binds it."""
    service = _service(session)
    _require_case(service, case_id)
    return service.status(case_id)


@router.get(
    "/{case_id}/regulatory/events",
    response_model=ClockEventsResponse,
)
def list_regulatory_events(
    case_id: str, session: UnitOfWorkSession, _user: User = Depends(_READ)
) -> Dict[str, Any]:
    """The append-only history of start instants, oldest first, with its chain check."""
    service = _service(session)
    _require_case(service, case_id)
    return {
        "events": [e.to_dict() for e in service.events(case_id)],
        "chain": service.verify_chain(case_id),
    }


@router.post(
    "/{case_id}/regulatory/events",
    response_model=RecordInstantResponse,
)
def record_regulatory_instant(
    case_id: str,
    body: RecordInstantRequest,
    session: UnitOfWorkSession,
    user: User = Depends(_WRITE),
) -> Dict[str, Any]:
    """Set, change or clear one start instant. A change or clear needs a reason."""
    service = _service(session)
    _require_case(service, case_id)
    try:
        event = service.record_instant(
            case_id,
            body.regime,
            body.instant,
            body.value,
            actor=_actor(user),
            reason=body.reason,
        )
    except InstantRefused as refused:
        raise HTTPException(status_code=422, detail=str(refused)) from None
    return {
        "changed": event is not None,
        "event": event.to_dict() if event else None,
        "status": service.status(case_id),
    }


@router.get(
    "/{case_id}/regulatory/drafts",
    response_model=DraftsResponse,
)
def list_regulatory_drafts(
    case_id: str, session: UnitOfWorkSession, _user: User = Depends(_READ)
) -> Dict[str, Any]:
    service = _service(session)
    _require_case(service, case_id)
    return {"drafts": service.store.drafts(case_id)}


@router.post(
    "/{case_id}/regulatory/drafts",
    response_model=DraftResponse,
)
def generate_regulatory_draft(
    case_id: str,
    body: GenerateDraftRequest,
    session: UnitOfWorkSession,
    user: User = Depends(_WRITE),
) -> Dict[str, Any]:
    """Draft a report from the case's evidence pack; every line cites a pack item.

    Deterministic template only: no model is called from this route.
    """
    if body.kind not in KINDS[body.regime]:
        raise HTTPException(
            status_code=422, detail=f"{body.regime} has no {body.kind} report"
        )
    service = _service(session)
    _require_case(service, case_id)
    events = service.events(case_id)
    pack = _evidence_pack(session, case_id, events)
    clocks = evaluate(fold_instants(events), service.config(), service.now())
    try:
        draft = generate_draft(
            pack, body.regime, body.kind, clocks, events, _actor(user), service.now()
        )
    except DraftCitationError as exc:  # the template cites the pack; this is a bug
        logger.error(
            "regulatory draft for %s failed its citation check: %s", case_id, exc
        )
        raise HTTPException(
            status_code=500, detail="The draft could not be built"
        ) from None
    service.store.add_draft(draft)
    service.store.audit(
        case_id,
        f"regulatory.draft.{body.regime}.{body.kind}",
        None,
        draft["draft_id"],
        f"Generated {draft['title']} draft ({len(draft['cited_ids'])} cited items)",
        _actor(user),
    )
    return draft
