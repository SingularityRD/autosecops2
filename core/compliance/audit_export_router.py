"""Admin API for the audit stream export (``/api/compliance/audit-export``).

Console-only, outside ``/api/v1``. Reading the config and status needs
``settings.read``; changing it, or sending a test event, needs
``settings.write`` because it decides where the audit trail (and a credential)
is sent. Secrets are write-only: they go to the secrets manager under names
derived from the destination, and reads only say whether one is set.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, ValidationError

from core.auth.permissions import permission_gate, require_permission
from core.compliance.audit_export import (
    AuditExportConfig,
    AuditExportService,
    secret_name,
)
from core.routing import Auth, RouterMeta
from core.secrets_manager import delete_secret, get_secret, set_secret
from core.storage.models import User

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/compliance/audit-export",
    tags=["compliance"],
    auth=Auth.REQUIRED,
)

_READ = [permission_gate("settings.read")]
_WRITE = [permission_gate("settings.write")]


class DestinationSecrets(BaseModel):
    token: Optional[str] = Field(None, min_length=1, max_length=8192)
    client_key_pem: Optional[str] = Field(None, min_length=1, max_length=65536)
    clear_token: bool = False
    clear_client_key: bool = False


class ConfigUpdate(BaseModel):
    config: dict
    secrets: dict[str, DestinationSecrets] = Field(default_factory=dict)


class TestRequest(BaseModel):
    destination: str = Field(..., max_length=32)


def _service(request: Request) -> AuditExportService:
    service = getattr(request.app.state, "audit_export", None)
    if service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit export is not available in this process",
        )
    return service


def _view(cfg: AuditExportConfig) -> dict:
    out = cfg.model_dump(mode="json")
    for dest in out["destinations"]:
        dest["has_token"] = bool(get_secret(secret_name(dest["name"], "TOKEN")))
        dest["has_client_key"] = bool(
            get_secret(secret_name(dest["name"], "CLIENT_KEY"))
        )
    return out


@router.get("/config", dependencies=_READ)
def get_config(request: Request):
    """The stored configuration (never a secret's value)."""
    service = _service(request)
    try:
        cfg = service.load_config()
    except ValidationError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stored audit export configuration is invalid; PUT a new one",
        )
    return _view(cfg)


@router.put("/config")
def put_config(
    body: ConfigUpdate,
    request: Request,
    user: User = Depends(require_permission("settings.write")),
):
    """Validate and store the configuration, and any destination secrets."""
    service = _service(request)
    try:
        cfg = AuditExportConfig.model_validate(body.config)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=[
                {"loc": e["loc"], "msg": e["msg"]}
                for e in exc.errors(include_url=False, include_input=False)
            ],
        )
    names = {d.name for d in cfg.destinations}
    unknown = sorted(set(body.secrets) - names)
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"secrets for unknown destinations: {', '.join(unknown)}",
        )
    for name, secret in body.secrets.items():
        for kind, value, clear in (
            ("TOKEN", secret.token, secret.clear_token),
            ("CLIENT_KEY", secret.client_key_pem, secret.clear_client_key),
        ):
            if value and not set_secret(secret_name(name, kind), value):
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Could not store a destination secret",
                )
            if clear and not value:
                delete_secret(secret_name(name, kind))
    try:
        service.save_config(cfg, actor=user.username)
    except RuntimeError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not save the audit export configuration",
        )
    return _view(cfg)


@router.get("/status", dependencies=_READ)
def get_status(request: Request):
    """Whether this process exports, per-destination metrics and cursors."""
    return _service(request).status()


@router.post("/test", dependencies=_WRITE)
async def send_test(body: TestRequest, request: Request):
    """Send one synthetic event to a configured destination."""
    return await _service(request).test_destination(body.destination)
