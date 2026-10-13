"""Autonomy tiers API: /api/autonomy (W3.1).

Reading the tiers and their audit takes ``settings.read``. Changing a tier, or
running the circuit breaker by hand, takes ``settings.write``. Only a person
raises a tier: a service account is refused (403) before the controller is
asked, the MCP credential never authenticates this API, and no agent or MCP
tool reaches ``AutonomyController.set_tier``. Raising also needs an evidence
link, and ``autonomous`` a QA bound that holds (409 when it does not).
"""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from core.auth.current_user import get_current_user
from core.auth.permissions import permission_gate
from core.autonomy.controller import AutonomyController, PromotionRefused
from core.autonomy.tiers import ANY_CATEGORY, AUTONOMOUS_ELIGIBLE
from core.routing import Auth, RouterMeta
from core.storage.models import User

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/autonomy",
    tags=["autonomy"],
    auth=Auth.REQUIRED,
)

_READ = [permission_gate("settings.read")]
_WRITE = [permission_gate("settings.write")]

TierValue = Literal["watch", "suggest", "approve", "autonomous"]


def provide_autonomy() -> AutonomyController:
    return AutonomyController()


class TierEntryModel(BaseModel):
    category: str
    action_type: str
    tier: str
    min_confidence: Optional[float] = None
    max_ttl_seconds: Optional[int] = None
    updated_by: Optional[str] = None
    updated_at: Optional[str] = None
    explicit: bool = False
    eligible: bool = False


class BoundModel(BaseModel):
    category: str
    reviewed: int = 0
    misses: int = 0
    fn_upper_bound: Optional[float] = None
    holds: bool = False
    readable: bool = True
    reason: str = ""


class AutonomyMatrix(BaseModel):
    default_tier: str
    tiers: list[str]
    categories: list[str]
    action_classes: list[str]
    eligible: list[str]
    max_ttl_seconds: int
    fn_bound_target: float
    fn_bound_min_reviews: int
    bounds_readable: bool
    bounds: dict[str, BoundModel] = Field(default_factory=dict)
    entries: list[TierEntryModel] = Field(default_factory=list)


class TierUpdate(BaseModel):
    tier: TierValue
    reason: str = Field(..., min_length=1, max_length=2000)
    evidence_url: Optional[str] = Field(
        default=None,
        max_length=2000,
        description="Link to the evidence (Scorecard, eval run) a raise rests on.",
    )
    min_confidence: Optional[float] = Field(default=None, ge=0, le=1)
    max_ttl_seconds: Optional[int] = Field(default=None, gt=0)


class AutonomyDemotion(BaseModel):
    category: str
    action_type: str
    from_tier: str = Field(alias="from")
    to_tier: str = Field(alias="to")
    reason: str

    model_config = {"populate_by_name": True}


class AutonomyCheckResult(BaseModel):
    demoted: list[AutonomyDemotion] = Field(default_factory=list)


class AutonomyAuditEntry(BaseModel):
    id: int
    key: str
    action: str
    old_value: Optional[dict[str, Any]] = None
    new_value: Optional[dict[str, Any]] = None
    changed_by: str
    reason: Optional[str] = None
    at: Optional[str] = None


class AutonomyAuditList(BaseModel):
    entries: list[AutonomyAuditEntry] = Field(default_factory=list)


@router.get("/tiers", dependencies=_READ, response_model=AutonomyMatrix)
def get_tiers(
    controller: AutonomyController = Depends(provide_autonomy),
) -> dict[str, Any]:
    """Every (category, action class) with its tier, and each category's QA bound."""
    return controller.matrix()


@router.put(
    "/tiers/{category}/{action_type}",
    dependencies=_WRITE,
    response_model=TierEntryModel,
)
def put_tier(
    category: str,
    action_type: str,
    body: TierUpdate,
    controller: AutonomyController = Depends(provide_autonomy),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Set one tier. Raising needs a person and an evidence link."""
    if getattr(current_user, "service_account", False):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "A service account cannot change autonomy tiers",
        )
    try:
        entry = controller.set_tier(
            category=category,
            action_type=action_type,
            tier=body.tier,
            actor=current_user.username,
            actor_is_human=True,
            reason=body.reason,
            evidence_url=body.evidence_url,
            min_confidence=body.min_confidence,
            max_ttl_seconds=body.max_ttl_seconds,
        )
    except PromotionRefused as e:
        code = {
            "actor": status.HTTP_403_FORBIDDEN,
            "bound": status.HTTP_409_CONFLICT,
        }.get(e.code, status.HTTP_422_UNPROCESSABLE_ENTITY)
        raise HTTPException(code, str(e))
    row = entry.as_dict()
    row["eligible"] = (
        entry.action_type in AUTONOMOUS_ELIGIBLE and entry.category != ANY_CATEGORY
    )
    return row


@router.post("/check", dependencies=_WRITE, response_model=AutonomyCheckResult)
def run_check(
    controller: AutonomyController = Depends(provide_autonomy),
) -> dict[str, Any]:
    """Run the circuit breaker now: demote tiers whose QA bound broke."""
    return {"demoted": controller.check_all()}


@router.get("/audit", dependencies=_READ, response_model=AutonomyAuditList)
def get_audit(
    limit: int = Query(100, ge=1, le=500),
    controller: AutonomyController = Depends(provide_autonomy),
) -> dict[str, Any]:
    """Tier changes and demotions, newest first."""
    return {"entries": controller.audit(limit)}
