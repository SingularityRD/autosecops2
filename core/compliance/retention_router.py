"""Admin API for data retention, legal holds and destruction reports (KVKK).

Reads need ``settings.read``; every change, a purge and the agent-ledger
archive export need ``settings.write``. A purge defaults to a dry run.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from core.auth.permissions import permission_gate, require_permission
from core.compliance import retention
from core.routing import Auth, RouterMeta, UnitOfWorkSession
from core.storage.models import User
from core.time import utcnow

router = APIRouter(dependencies=[permission_gate("settings.read")])

ROUTER_META = RouterMeta(
    prefix="/api/compliance/retention",
    tags=["compliance"],
    auth=Auth.REQUIRED,
)

_admin = require_permission("settings.write")


class PolicyBody(BaseModel):
    retain_days: int = Field(..., gt=0, le=36500)
    method: Optional[Literal["delete", "anonymise", "archive"]] = None
    legal_hold: bool = False


class LegalHoldBody(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)


class PurgeBody(BaseModel):
    dry_run: bool = True
    data_classes: Optional[List[str]] = None
    batch_size: int = Field(500, ge=1, le=retention.MAX_BATCH_SIZE)
    max_batches: int = Field(20, ge=1, le=retention.MAX_BATCHES)


@router.get("/classes")
def list_classes():
    """Every data class a policy can name, and how it can be destroyed."""
    return {"classes": [dc.as_dict() for dc in retention.DATA_CLASSES.values()]}


@router.get("/policies")
def list_policies(session: UnitOfWorkSession):
    return {"policies": retention.list_policies(session)}


@router.put("/policies/{data_class}")
def put_policy(
    data_class: str,
    body: PolicyBody,
    session: UnitOfWorkSession,
    user: User = Depends(_admin),
):
    try:
        return retention.set_policy(
            session,
            data_class,
            retain_days=body.retain_days,
            method=body.method,
            legal_hold=body.legal_hold,
            actor=user.username,
        )
    except retention.RetentionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/policies/{data_class}")
def delete_policy(
    data_class: str, session: UnitOfWorkSession, user: User = Depends(_admin)
):
    if not retention.delete_policy(session, data_class, actor=user.username):
        raise HTTPException(status_code=404, detail="No policy for that data class")
    return {"deleted": data_class}


@router.get("/legal-holds")
def list_legal_holds(session: UnitOfWorkSession):
    holds = retention.list_legal_holds(session)
    return {"cases": [{"case_id": k, **v} for k, v in sorted(holds.items())]}


@router.put("/legal-holds/cases/{case_id}")
def put_legal_hold(
    case_id: str,
    body: LegalHoldBody,
    session: UnitOfWorkSession,
    user: User = Depends(_admin),
):
    try:
        return retention.set_legal_hold(
            session, case_id, reason=body.reason, actor=user.username
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="Case not found")


@router.delete("/legal-holds/cases/{case_id}")
def delete_legal_hold(
    case_id: str,
    session: UnitOfWorkSession,
    user: User = Depends(_admin),
    reason: Optional[str] = Query(None, max_length=1000),
):
    if not retention.release_legal_hold(
        session, case_id, actor=user.username, reason=reason
    ):
        raise HTTPException(status_code=404, detail="Case is not under legal hold")
    return {"released": case_id}


@router.post("/purge")
def purge(body: PurgeBody, user: User = Depends(_admin)):
    """Run the policies now. ``dry_run`` (the default) changes nothing."""
    try:
        return retention.run_purge(
            dry_run=body.dry_run,
            actor=user.username,
            data_classes=body.data_classes,
            batch_size=body.batch_size,
            max_batches=body.max_batches,
        )
    except retention.RetentionBusy:
        raise HTTPException(status_code=409, detail="A retention purge is running")
    except retention.RetentionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/reports")
def destruction_report(
    session: UnitOfWorkSession,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    format: Literal["json", "markdown"] = "json",
):
    """The periodic destruction report (default: the last 180 days)."""
    until = _naive_utc(until) or utcnow()
    since = _naive_utc(since) or until - timedelta(days=180)
    if since >= until:
        raise HTTPException(status_code=400, detail="since must be before until")
    report = retention.build_destruction_report(session, since=since, until=until)
    if format == "markdown":
        return PlainTextResponse(
            retention.render_markdown(report),
            media_type="text/markdown; charset=utf-8",
        )
    return report


@router.get("/agent-ledger/archive")
def agent_ledger_archive(
    session: UnitOfWorkSession,
    before: datetime,
    limit_runs: int = Query(100, ge=1, le=1000),
    user: User = Depends(_admin),
):
    """Step 1 of archive-then-truncate: chain-verified runs, read only."""
    return retention.export_agent_ledger_archive(
        session, before=_naive_utc(before), limit_runs=limit_runs, actor=user.username
    )


def _naive_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None or value.tzinfo is None:
        return value
    return (value - value.utcoffset()).replace(tzinfo=None)
