"""Data-subject requests (KVKK art. 11, 13): register, search, export (W0.48).

All routes need ``settings.write``: a lookup of one person's data across the
platform is an administrative act, and each is recorded against its request.
The identifier travels in the request body, never in a URL or a query string,
so it does not land in access logs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.auth.permissions import permission_gate, require_permission
from core.compliance import data_subject
from core.routing import Auth, RouterMeta, UnitOfWorkSession
from core.storage.models import User

router = APIRouter(dependencies=[permission_gate("settings.write")])

ROUTER_META = RouterMeta(
    prefix="/api/compliance/data-subject",
    tags=["compliance"],
    auth=Auth.REQUIRED,
)

_admin = require_permission("settings.write")

Kind = Literal["access", "rectification", "erasure", "objection", "other"]


class RegisterBody(BaseModel):
    identifier: str = Field(..., min_length=3, max_length=320)
    kind: Kind
    received_at: Optional[datetime] = None
    reference: Optional[str] = Field(None, max_length=200)


class LookupBody(BaseModel):
    identifier: str = Field(..., min_length=3, max_length=320)


class CloseBody(BaseModel):
    outcome: str = Field(..., min_length=1, max_length=2000)


class RequestView(BaseModel):
    request_id: str
    kind: str
    state: str
    identifier_hint: str
    reference: Optional[str] = None
    received_at: Optional[str] = None
    due_at: Optional[str] = None
    registered_at: Optional[str] = None
    registered_by: Optional[str] = None
    closed_at: Optional[str] = None
    outcome: Optional[str] = None
    overdue: bool = False
    days_left: Optional[int] = None


class RequestsView(BaseModel):
    requests: List[RequestView]


class SourceResult(BaseModel):
    count: int
    items: List[Any]
    truncated: bool


class LookupView(BaseModel):
    request_id: str
    results: Dict[str, SourceResult]
    generated_at: Optional[str] = None
    note: Optional[str] = None


def _actor(user: User) -> str:
    return user.username or user.user_id


def _naive(value: Optional[datetime]) -> Optional[datetime]:
    if value is not None and value.tzinfo is not None:
        from datetime import timezone

        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


@router.post("/requests", response_model=RequestView, status_code=201)
def register_request(
    body: RegisterBody, session: UnitOfWorkSession, user: User = Depends(_admin)
) -> Dict[str, Any]:
    """Register a request; it is due 30 days after it was received."""
    try:
        request = data_subject.register(
            session,
            identifier=body.identifier,
            kind=body.kind,
            received_at=_naive(body.received_at),
            reference=body.reference,
            actor=_actor(user),
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return data_subject.with_clock(request)


@router.get("/requests", response_model=RequestsView)
def list_requests(session: UnitOfWorkSession) -> Dict[str, Any]:
    return {"requests": data_subject.list_requests(session)}


def _lookup(fn, session, request_id: str, body: LookupBody, user: User):
    try:
        return fn(session, request_id, body.identifier, actor=_actor(user))
    except data_subject.RequestNotFound:
        raise HTTPException(404, "No such request") from None
    except data_subject.RequestClosed:
        raise HTTPException(409, "The request is closed") from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@router.post("/requests/{request_id}/search", response_model=LookupView)
def search_request(
    request_id: str,
    body: LookupBody,
    session: UnitOfWorkSession,
    user: User = Depends(_admin),
) -> Dict[str, Any]:
    """Where the identifier appears: counts and ids per source."""
    return _lookup(data_subject.search, session, request_id, body, user)


@router.post("/requests/{request_id}/export", response_model=LookupView)
def export_request(
    request_id: str,
    body: LookupBody,
    session: UnitOfWorkSession,
    user: User = Depends(_admin),
) -> Dict[str, Any]:
    """The matching records, for the reply to the data subject."""
    return _lookup(data_subject.export, session, request_id, body, user)


@router.post("/requests/{request_id}/close", response_model=RequestView)
def close_request(
    request_id: str,
    body: CloseBody,
    session: UnitOfWorkSession,
    user: User = Depends(_admin),
) -> Dict[str, Any]:
    try:
        closed = data_subject.close(
            session, request_id, outcome=body.outcome, actor=_actor(user)
        )
    except data_subject.RequestNotFound:
        raise HTTPException(404, "No such request") from None
    except data_subject.RequestClosed:
        raise HTTPException(409, "The request is already closed") from None
    return data_subject.with_clock(closed)
