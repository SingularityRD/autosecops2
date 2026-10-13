"""Response actions API (W2.4): undo an executed action.

``POST /api/response/actions/{action_id}/revert`` reverses an executed,
reversible action through its executor, verifies the reversal, and records it
on the approval audit path: a reverse row in ``approval_actions`` whose
``reverse_of`` is the original, and ``reversed_at`` on the original. It needs
the permission that releases response actions, and a reason.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from core.auth.current_user import get_current_user
from core.auth.permissions import permission_gate
from core.deps import provide_response
from core.response.autonomous_response_service import AutonomousResponseService
from core.routing import Auth, RouterMeta
from core.storage.models import User

router = APIRouter()
logger = logging.getLogger(__name__)

ROUTER_META = RouterMeta(
    prefix="/api/response",
    tags=["response"],
    auth=Auth.REQUIRED,
)

_DECIDE = [permission_gate("ai_decisions.approve")]


class RevertRequest(BaseModel):
    reason: str = Field(
        ..., min_length=1, max_length=2000, description="Why the action is undone."
    )

    @field_validator("reason")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("reason must not be blank")
        return value.strip()


class RevertResponse(BaseModel):
    action_id: str
    reverse_action_id: Optional[str] = None
    outcome: str
    verify_status: Optional[str] = None
    reversed_at: Optional[str] = None
    message: str = ""


@router.post(
    "/actions/{action_id}/revert",
    dependencies=_DECIDE,
    response_model=RevertResponse,
)
def revert_action(
    action_id: str,
    request: RevertRequest,
    service: AutonomousResponseService = Depends(provide_response),
    current_user: User = Depends(get_current_user),
):
    """Reverse an executed reversible action, then verify it is undone.

    404: no such action. 409: it is not executed, already reversed, a reverse
    row itself, irreversible, or has no executor. 502: the executor's reverse
    (or its verify) failed; the failed reverse row is kept for the record.
    Sync on purpose: the executor speaks to the vendor synchronously.
    """
    outcome = service.reverse_action(
        action_id, actor=current_user.username, reason=request.reason
    )
    kind = outcome.get("outcome")
    if kind == "not_found":
        raise HTTPException(status_code=404, detail=f"Action not found: {action_id}")
    if kind == "conflict":
        raise HTTPException(status_code=409, detail=outcome.get("message", "conflict"))
    if kind == "failed":
        raise HTTPException(
            status_code=502,
            detail={
                "message": "The reversal did not take effect",
                "reverse_action_id": outcome.get("reverse_action_id"),
                "verify_status": outcome.get("verify_status"),
            },
        )
    return RevertResponse(
        action_id=action_id,
        reverse_action_id=outcome.get("reverse_action_id"),
        outcome=str(kind),
        verify_status=outcome.get("verify_status"),
        reversed_at=outcome.get("reversed_at"),
        message=str(outcome.get("message") or ""),
    )
