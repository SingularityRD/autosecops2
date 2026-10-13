"""Outbound webhook endpoints: admin CRUD, test send, delivery history.

Mounted at ``/api/webhook-endpoints``, deliberately not under ``/api/webhooks/``:
that prefix is CSRF-exempt for inbound third-party receivers (which sign their
own requests), and a cookie-authenticated management API must not inherit the
exemption. Inbound receivers stay in their own modules with
``Auth.PUBLIC_WEBHOOK``.

Every route needs ``settings.write``: an endpoint is an egress target and a
signing secret, the same class of setting as an integration credential.

Queued deliveries are sent by the daemon (``core.cases.case_automation_service``);
the only request this router sends itself is the explicit test call.
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError

from core.auth.current_user import get_current_user
from core.auth.permissions import permission_gate
from core.integrations import outbound_webhooks as hooks
from core.platform.url_safety import UnresolvableHostError, UrlSafetyError
from core.routing import Auth, RouterMeta
from core.storage.models import User

logger = logging.getLogger(__name__)

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/webhook-endpoints",
    tags=["webhooks"],
    auth=Auth.REQUIRED,
    extra_dependencies=(permission_gate("settings.write"),),
)


class EndpointCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=1, max_length=hooks.MAX_URL_LENGTH)
    event_types: List[str] = Field(
        default_factory=list,
        description="Subscribed event types; empty means every type.",
    )
    enabled: bool = True
    secret: Optional[str] = Field(
        default=None,
        min_length=16,
        max_length=512,
        description="HMAC signing secret. Omit to have one generated.",
    )


class EndpointUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    url: Optional[str] = Field(
        default=None, min_length=1, max_length=hooks.MAX_URL_LENGTH
    )
    event_types: Optional[List[str]] = None
    enabled: Optional[bool] = None
    secret: Optional[str] = Field(default=None, min_length=16, max_length=512)


class EndpointOut(BaseModel):
    id: str
    tenant_id: str
    name: str
    url: str
    event_types: List[str]
    enabled: bool
    has_secret: bool
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class EndpointCreated(EndpointOut):
    secret: Optional[str] = Field(
        default=None,
        description="The generated signing secret. Shown once; store it now.",
    )


class EndpointList(BaseModel):
    endpoints: List[EndpointOut]
    event_types: List[str]


class DeliveryOut(BaseModel):
    id: int
    endpoint_id: str
    event_type: str
    event_id: str
    status: str
    attempts: int
    next_attempt_at: Optional[str] = None
    last_attempt_at: Optional[str] = None
    response_status: Optional[int] = None
    last_error: Optional[str] = None
    created_at: Optional[str] = None
    delivered_at: Optional[str] = None


class DeliveryList(BaseModel):
    deliveries: List[DeliveryOut]


class TestSendResult(BaseModel):
    delivered: bool
    outcome: str
    status_code: Optional[int] = None
    error: Optional[str] = None


class DeleteResult(BaseModel):
    deleted: bool


_REFUSED = (
    "url resolves to a private, loopback, link-local or metadata address; "
    "an administrator can allow a private network with WEBHOOK_ALLOWED_CIDRS"
)


def _unprocessable(exc: Exception) -> HTTPException:
    if isinstance(exc, UnresolvableHostError):
        return HTTPException(422, "url host does not resolve")
    if isinstance(exc, UrlSafetyError):
        return HTTPException(422, _REFUSED)
    # WebhookError messages are written for the caller.
    return HTTPException(422, str(exc))


def _conflict() -> HTTPException:
    return HTTPException(409, "an endpoint with this name already exists")


def _secret_store_down() -> HTTPException:
    return HTTPException(503, "the secrets store could not save the secret")


def _get_or_404(endpoint_id: UUID) -> dict:
    endpoint = hooks.get_endpoint(str(endpoint_id))
    if endpoint is None:
        raise HTTPException(404, "webhook endpoint not found")
    return endpoint


@router.get("", response_model=EndpointList)
def list_endpoints():
    return {
        "endpoints": [hooks.public_endpoint(e) for e in hooks.list_endpoints()],
        "event_types": sorted(hooks.SUBSCRIBABLE_EVENT_TYPES),
    }


@router.post("", response_model=EndpointCreated, status_code=status.HTTP_201_CREATED)
def create_endpoint(data: EndpointCreate, user: User = Depends(get_current_user)):
    try:
        endpoint, generated = hooks.create_endpoint(
            name=data.name,
            url=data.url,
            event_types=data.event_types,
            enabled=data.enabled,
            secret=data.secret,
            created_by=getattr(user, "username", None),
        )
    except (hooks.WebhookError, UrlSafetyError) as exc:
        raise _unprocessable(exc) from exc
    except hooks.WebhookConflict as exc:
        raise _conflict() from exc
    except hooks.SecretStoreError as exc:
        raise _secret_store_down() from exc
    return {**hooks.public_endpoint(endpoint), "secret": generated}


@router.get("/{endpoint_id}", response_model=EndpointOut)
def get_endpoint(endpoint_id: UUID):
    return hooks.public_endpoint(_get_or_404(endpoint_id))


@router.patch("/{endpoint_id}", response_model=EndpointOut)
def update_endpoint(endpoint_id: UUID, data: EndpointUpdate):
    try:
        endpoint = hooks.update_endpoint(
            str(endpoint_id),
            name=data.name,
            url=data.url,
            event_types=data.event_types,
            enabled=data.enabled,
            secret=data.secret,
        )
    except hooks.WebhookNotFound as exc:
        raise HTTPException(404, "webhook endpoint not found") from exc
    except (hooks.WebhookError, UrlSafetyError) as exc:
        raise _unprocessable(exc) from exc
    except hooks.WebhookConflict as exc:
        raise _conflict() from exc
    except hooks.SecretStoreError as exc:
        raise _secret_store_down() from exc
    return hooks.public_endpoint(endpoint)


@router.delete("/{endpoint_id}", response_model=DeleteResult)
def delete_endpoint(endpoint_id: UUID):
    try:
        deleted = hooks.delete_endpoint(str(endpoint_id))
    except IntegrityError as exc:
        raise HTTPException(
            409, "an alert route still sends to this endpoint; remove it first"
        ) from exc
    if not deleted:
        raise HTTPException(404, "webhook endpoint not found")
    return {"deleted": True}


@router.post("/{endpoint_id}/test", response_model=TestSendResult)
async def test_endpoint(endpoint_id: UUID):
    """Send a signed ``webhook.test`` event now and report what happened."""
    endpoint = await asyncio.to_thread(_get_or_404, endpoint_id)
    result = await hooks.WebhookSender().send_test(endpoint)
    return {
        "delivered": result.delivered,
        "outcome": result.outcome,
        "status_code": result.status_code,
        "error": result.error,
    }


@router.get("/{endpoint_id}/deliveries", response_model=DeliveryList)
def list_deliveries(
    endpoint_id: UUID,
    limit: int = Query(50, ge=1, le=500),
    delivery_status: Optional[str] = Query(
        None, alias="status", pattern="^(pending|delivered|failed|dead)$"
    ),
):
    _get_or_404(endpoint_id)
    return {
        "deliveries": hooks.list_deliveries(
            str(endpoint_id), limit=limit, status=delivery_status
        )
    }


@router.post(
    "/{endpoint_id}/deliveries/{delivery_id}/retry", response_model=DeliveryOut
)
def retry_delivery(endpoint_id: UUID, delivery_id: int):
    """Requeue a failed or dead delivery; the daemon sends it on its next pass."""
    delivery = hooks.requeue_delivery(str(endpoint_id), delivery_id)
    if delivery is None:
        raise HTTPException(404, "no failed or dead delivery with this id")
    return delivery
