"""Segregation of duties and the two-person rule's role condition (W3.2).

``GET /api/response/segregation``         the report (JSON)
``GET /api/response/segregation/export``  the same, as a CSV or JSON download
``GET /api/response/four-eyes``           four-eyes and distinct-role action classes
``PUT /api/response/four-eyes/{type}``    turn the distinct-role condition on/off

The report names people and their roles, so reading it takes ``users.read``.
Changing the condition changes who may release an identity action, so it
takes ``settings.write`` and a reason; it changes the ``response.policy``
system config row under a row lock (``policy_store``), with its
``config_audit_log`` row in the same transaction.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from pydantic import BaseModel, Field

from core.auth.current_user import get_current_user
from core.auth.permissions import permission_gate
from core.deps import provide_approvals
from core.response import segregation
from core.response.approval_service import ActionType, ApprovalService
from core.response.policy import PolicyConfig
from core.routing import Auth, RouterMeta
from core.storage.connection import get_db_manager
from core.storage.models import User
from core.time import utcnow

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/response",
    tags=["response"],
    auth=Auth.REQUIRED,
)

_READ = [permission_gate("users.read")]
_WRITE = [permission_gate("settings.write")]

_ACTION_TYPES = frozenset(t.value for t in ActionType) - {
    ActionType.WORKFLOW_PHASE.value
}


class SegregationRow(BaseModel):
    action_id: str
    action_type: str
    target: Optional[str] = None
    status: str
    created_at: Optional[str] = None
    proposed_by: Optional[str] = None
    proposed_role: Optional[str] = None
    approved_by: Optional[str] = None
    approved_role: Optional[str] = None
    second_approver: Optional[str] = None
    second_role: Optional[str] = None
    executed_by: Optional[str] = None
    executed_at: Optional[str] = None
    # executed | failed | claimed (dispatched, outcome unrecorded) | refused | null
    execution: Optional[str] = None
    reverse_of: Optional[str] = None
    four_eyes: bool = False
    distinct_role: bool = False
    role_source: Optional[str] = None
    violations: list[str] = Field(default_factory=list)


class SegregationSummary(BaseModel):
    total: int
    with_violations: int
    by_kind: dict[str, int]


class SegregationPolicy(BaseModel):
    four_eyes_types: list[str]
    distinct_role_types: list[str]


class SegregationReport(BaseModel):
    since: Optional[str] = None
    until: Optional[str] = None
    action_type: Optional[str] = None
    policy: SegregationPolicy
    summary: SegregationSummary
    rows: list[SegregationRow] = Field(default_factory=list)


class FourEyesConfig(BaseModel):
    four_eyes_types: list[str]
    distinct_role_types: list[str]


class DistinctRoleUpdate(BaseModel):
    distinct_role: bool
    reason: str = Field(..., min_length=1, max_length=2000)


def _report(
    service: ApprovalService,
    since: Optional[datetime],
    until: Optional[datetime],
    action_type: Optional[str],
    violations_only: bool,
    limit: int,
) -> dict[str, Any]:
    policy = service.policy_config()
    if policy.degraded:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The response policy could not be read",
        )
    with get_db_manager().session_scope() as session:
        return segregation.build_report(
            session,
            policy,
            since=since,
            until=until,
            action_type=action_type,
            violations_only=violations_only,
            limit=limit,
        )


@router.get("/segregation", dependencies=_READ, response_model=SegregationReport)
def get_segregation(
    since: Optional[datetime] = Query(None, description="Actions created at or after"),
    until: Optional[datetime] = Query(None, description="Actions created before"),
    action_type: Optional[str] = Query(None),
    violations_only: bool = Query(False),
    limit: int = Query(1000, ge=1, le=5000),
    service: ApprovalService = Depends(provide_approvals),
) -> dict[str, Any]:
    """Who proposed, approved and executed each action, in which role, and violations."""
    return _report(service, since, until, action_type, violations_only, limit)


@router.get("/segregation/export", dependencies=_READ)
def export_segregation(
    format: Literal["csv", "json"] = Query("csv"),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    action_type: Optional[str] = Query(None),
    violations_only: bool = Query(False),
    limit: int = Query(5000, ge=1, le=5000),
    service: ApprovalService = Depends(provide_approvals),
) -> Response:
    """The report as a download (CSV cells cannot start a spreadsheet formula)."""
    report = _report(service, since, until, action_type, violations_only, limit)
    stamp = re.sub(r"[^0-9T]", "", utcnow().isoformat(timespec="seconds"))
    if format == "json":
        body = json.dumps(report, indent=2)
        media = "application/json"
    else:
        body = segregation.to_csv(report)
        media = "text/csv; charset=utf-8"
    return Response(
        content=body,
        media_type=media,
        headers={
            "Content-Disposition": (
                f'attachment; filename="segregation-of-duties-{stamp}.{format}"'
            )
        },
    )


@router.get("/four-eyes", dependencies=_READ, response_model=FourEyesConfig)
def get_four_eyes(
    service: ApprovalService = Depends(provide_approvals),
) -> dict[str, Any]:
    """The action classes under the two-person rule and its distinct-role condition."""
    policy = service.policy_config()
    return {
        "four_eyes_types": sorted(policy.four_eyes_types),
        "distinct_role_types": sorted(policy.distinct_role_types),
    }


@router.put(
    "/four-eyes/{action_type}", dependencies=_WRITE, response_model=FourEyesConfig
)
def put_distinct_role(
    action_type: str,
    body: DistinctRoleUpdate,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Require (or stop requiring) a second approver of a different role.

    Turning it on also puts the class under the two-person rule. Turning it off
    leaves the two-person rule as it was.
    """
    from core.response.policy_store import update_policy

    if action_type not in _ACTION_TYPES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown action type {action_type!r}"
        )
    if not body.reason.strip():
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "A reason is required"
        )

    def change(raw: dict[str, Any]) -> dict[str, Any]:
        # Under the row lock (W0.36): a concurrent policy edit is not lost.
        distinct = set(raw.get("distinct_role_types") or [])
        if body.distinct_role:
            distinct.add(action_type)
        else:
            distinct.discard(action_type)
        raw["distinct_role_types"] = sorted(distinct)
        return raw

    try:
        raw, _version, _written = update_policy(
            current_user.username, body.reason.strip(), change
        )
    except Exception:  # noqa: BLE001
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The response policy could not be saved",
        ) from None
    policy = PolicyConfig.from_mapping(raw)
    return {
        "four_eyes_types": sorted(policy.four_eyes_types),
        "distinct_role_types": sorted(policy.distinct_role_types),
    }
