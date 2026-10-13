"""Hidden canary alerts, admin surface (``/api/quality/canaries``, W1.5).

Every route needs ``settings.write`` *and* the Admin role (``settings.write``
alone also admits Managers): which alerts are canaries is exactly what analysts
must not be able to look up, and switching them on is an admin decision. ``PUT /settings`` is the only way to enable them and is recorded in
``config_audit_log`` under the admin who made the change.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from core.auth.current_user import get_current_user
from core.auth.permissions import permission_gate
from core.config import get_settings
from core.quality.canary import (
    MAX_PER_DAY,
    MAX_SCORE_AFTER_H,
    MIN_PER_DAY,
    MIN_SCORE_AFTER_H,
    CanarySettings,
    canary_summary,
    read_canary_settings,
    write_canary_settings,
)
from core.routing import Auth, RouterMeta
from core.storage.models import User

ADMIN_PERMISSION = "settings.write"
# The seeded Admin role (06_auth_tables.sql) and the legacy one that
# scripts/migrate_schema.py seeds on a create_all-only database.
ADMIN_ROLE_IDS = frozenset({"role-admin", "admin"})


def _dev_mode() -> bool:
    return bool(get_settings().dev_mode)


def require_admin(user: User = Depends(get_current_user)) -> User:
    """403 unless the signed-in user has the Admin role. DEV_MODE passes, as
    it does for every permission check."""
    if _dev_mode():
        return user
    if (getattr(user, "role_id", None) or "") not in ADMIN_ROLE_IDS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: Admin role required",
        )
    return user


router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/quality/canaries",
    tags=["quality"],
    auth=Auth.REQUIRED,
    extra_dependencies=(permission_gate(ADMIN_PERMISSION), Depends(require_admin)),
)


class CanarySettingsBody(BaseModel):
    enabled: bool
    per_day: int = Field(1, ge=MIN_PER_DAY, le=MAX_PER_DAY)
    score_after_hours: int = Field(24, ge=MIN_SCORE_AFTER_H, le=MAX_SCORE_AFTER_H)
    reason: Optional[str] = Field(
        None, max_length=500, description="Recorded in the config audit log."
    )


@router.get("")
def get_canary_summary(
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """Catch rate overall, by category and by signal, and the latest canaries."""
    return canary_summary(limit=limit)


@router.get("/settings")
def get_canary_settings() -> Dict[str, Any]:
    return asdict(read_canary_settings())


@router.put("/settings")
def put_canary_settings(
    body: CanarySettingsBody,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    settings = CanarySettings(
        enabled=body.enabled,
        per_day=body.per_day,
        score_after_hours=body.score_after_hours,
    )
    if not write_canary_settings(
        settings, user_id=str(current_user.user_id), reason=body.reason
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to store the canary setting",
        )
    return asdict(settings)
