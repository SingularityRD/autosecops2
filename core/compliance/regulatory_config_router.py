"""The tenant's regulatory clock settings: time zone and durations.

    GET /api/compliance/regulatory-clocks/config   settings.read
    PUT /api/compliance/regulatory-clocks/config   settings.write

PUT replaces the settings; ``durations`` holds only the keys that differ from
the defaults (DORA 4h / 24h / 72h / 1 month, NIS2 24h / 72h / 1 month). Every
change writes a ``config_audit_log`` row naming the signed-in user.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from core.auth.permissions import require_permission
from core.compliance.clocks import ClockConfigError
from core.compliance.regulatory_service import RegulatoryService, SqlClockStore
from core.routing import Auth, RouterMeta, UnitOfWorkSession
from core.storage.models import User

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/compliance/regulatory-clocks",
    tags=["regulatory"],
    auth=Auth.REQUIRED,
)


class DurationModel(BaseModel):
    hours: int = 0
    months: int = 0


class RegulatoryConfigResponse(BaseModel):
    timezone: str
    durations: Dict[str, DurationModel]
    defaults: Dict[str, DurationModel]


class RegulatoryConfigUpdate(BaseModel):
    timezone: str = Field(min_length=1, max_length=64)
    durations: Dict[str, DurationModel] = Field(default_factory=dict)


@router.get("/config", response_model=RegulatoryConfigResponse)
def get_regulatory_config(
    session: UnitOfWorkSession,
    _user: User = Depends(require_permission("settings.read")),
) -> Dict[str, Any]:
    return RegulatoryService(SqlClockStore(session)).config().to_dict()


@router.put("/config", response_model=RegulatoryConfigResponse)
def put_regulatory_config(
    body: RegulatoryConfigUpdate,
    session: UnitOfWorkSession,
    user: User = Depends(require_permission("settings.write")),
) -> Dict[str, Any]:
    service = RegulatoryService(SqlClockStore(session))
    try:
        config = service.set_config(
            body.timezone,
            {k: v.model_dump() for k, v in body.durations.items()},
            actor=user.username or user.user_id,
        )
    except ClockConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return config.to_dict()
