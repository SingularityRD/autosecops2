"""Outbound webhooks: signed, retried, SSRF-guarded event delivery.

Tables (SQL-owned, ``infra/database/init/47_webhooks_alert_routes.sql``):

- ``webhook_endpoints``: where to send. ``secret_ref`` names the HMAC signing
  secret in the secrets manager; the secret itself never reaches the database.
- ``webhook_deliveries``: one event owed to one endpoint. Unique on
  ``(endpoint_id, event_id)``, so emitting the same event twice is one delivery.

Life of a delivery::

    enqueue_event()            -> pending (next_attempt_at = now)
    WebhookSender.deliver_due()
        2xx                    -> delivered
        network/408/429/5xx    -> pending, next_attempt_at = now + backoff
                                  (dead once WEBHOOK_MAX_ATTEMPTS is reached)
        3xx / other 4xx / refused target / missing secret / disabled endpoint
                               -> failed (permanent; an admin may requeue it)

Signature (see ``docs/outbound-webhooks.md`` for the receiver side)::

    X-AutoSecOps-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>

SSRF: every address the target host resolves to must be public, or inside an
admin-configured ``WEBHOOK_ALLOWED_CIDRS`` network; the cloud-metadata address is
refused regardless. The connection is then pinned to exactly the checked
addresses (a resolver that answers only with them), redirects are not followed
and environment proxies are ignored, so neither DNS rebinding nor a 30x can move
the request somewhere the check did not see.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets as _token
import socket
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from core.config import get_settings
from core.platform.url_safety import (
    UnresolvableHostError,
    UrlSafetyError,
    parse_networks,
    resolve_allowed_addresses,
)
from core.secrets import delete_secret, get_secret, set_secret
from core.storage.unit_of_work import unit_of_work

logger = logging.getLogger(__name__)

SIGNATURE_HEADER = "X-AutoSecOps-Signature"
EVENT_HEADER = "X-AutoSecOps-Event"
EVENT_ID_HEADER = "X-AutoSecOps-Event-Id"
DELIVERY_HEADER = "X-AutoSecOps-Delivery"
USER_AGENT = "AutoSecOps-Webhooks/1"

DEFAULT_TENANT = "default"

# Event types an endpoint may subscribe to. An endpoint with an empty list gets
# every one of them. ``webhook.test`` is sent only by the test-send call.
SUBSCRIBABLE_EVENT_TYPES = frozenset({"case.sla_warning", "case.stale_case"})
TEST_EVENT_TYPE = "webhook.test"

SIGNATURE_TOLERANCE_SECONDS = 300
BACKOFF_BASE_SECONDS = 30
BACKOFF_MAX_SECONDS = 3600
REQUEST_TIMEOUT_SECONDS = 10
# A claimed delivery is pushed this far into the future before it is sent, so a
# second sender (or a crash mid-send) cannot pick it up again straight away.
# It must outlast a whole pass: a claimed batch of 50 at concurrency 5 with a
# 10 s timeout can take ~100 s before its last request finishes.
CLAIM_LEASE_SECONDS = 300
MAX_URL_LENGTH = 2048
SECRET_REF_PREFIX = "WEBHOOK_SECRET_"

DELIVERED = "delivered"
PENDING = "pending"
FAILED = "failed"
DEAD = "dead"


class WebhookError(ValueError):
    """A caller-facing problem with a webhook request (bad URL, event type...)."""


class WebhookNotFound(LookupError):
    pass


class WebhookConflict(Exception):
    pass


class SecretStoreError(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --- signing -----------------------------------------------------------------


def compute_signature(secret: str, body: bytes, timestamp: int) -> str:
    message = str(int(timestamp)).encode("ascii") + b"." + body
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def signature_header(secret: str, body: bytes, timestamp: int) -> str:
    return f"t={int(timestamp)},v1={compute_signature(secret, body, timestamp)}"


def verify_signature(
    secret: str,
    header: Optional[str],
    body: bytes,
    *,
    tolerance: int = SIGNATURE_TOLERANCE_SECONDS,
    now: Optional[float] = None,
) -> bool:
    """Reference receiver check: right secret, unmodified body, fresh timestamp.

    Several ``v1=`` entries are accepted (any one may match), so a sender can
    sign with an old and a new secret during a rotation. Replay protection
    beyond the time window is the receiver's: remember the ``id`` field of the
    verified body for at least ``tolerance`` seconds and drop repeats. Not the
    ``X-AutoSecOps-Event-Id`` header: headers are outside the signature, so a
    replayed request can carry any header value.
    """
    if not header:
        return False
    timestamp: Optional[int] = None
    candidates: List[str] = []
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                return False
        elif key == "v1" and value:
            candidates.append(value)
    if timestamp is None or not candidates:
        return False
    current = time.time() if now is None else now
    if abs(current - timestamp) > tolerance:
        return False
    expected = compute_signature(secret, body, timestamp)
    return any(hmac.compare_digest(expected, c) for c in candidates)


def encode_body(payload: Dict[str, Any]) -> bytes:
    """Deterministic JSON, so every retry signs and sends the same bytes."""
    return json.dumps(
        payload, separators=(",", ":"), sort_keys=True, default=str
    ).encode("utf-8")


def build_payload(
    event_type: str,
    event_id: str,
    data: Dict[str, Any],
    *,
    tenant_id: str = DEFAULT_TENANT,
    created_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    return {
        "id": event_id,
        "type": event_type,
        "created_at": (created_at or utc_now()).isoformat(),
        "tenant_id": tenant_id,
        "data": data,
    }


def backoff_seconds(attempts: int) -> int:
    """Delay after the ``attempts``-th failed attempt: 30s, 60s, 120s ... 1h."""
    exponent = max(attempts - 1, 0)
    return int(min(BACKOFF_BASE_SECONDS * (2**exponent), BACKOFF_MAX_SECONDS))


def new_secret() -> str:
    return "whsec_" + _token.token_urlsafe(32)


# --- target checks -------------------------------------------------------------


def validate_url(url: str) -> str:
    """Syntax check for a target URL. Returns it stripped; raises WebhookError."""
    url = (url or "").strip()
    if not url:
        raise WebhookError("url is required")
    if len(url) > MAX_URL_LENGTH:
        raise WebhookError("url is too long")
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError as exc:
        raise WebhookError("url is not valid") from exc
    if parts.scheme not in ("http", "https"):
        raise WebhookError("url scheme must be http or https")
    if not parts.hostname:
        raise WebhookError("url is missing a host")
    if parts.username or parts.password:
        raise WebhookError("url must not include credentials")
    if parts.fragment:
        raise WebhookError("url must not include a fragment")
    return url


def configured_networks() -> tuple:
    """``WEBHOOK_ALLOWED_CIDRS`` parsed; a malformed value allows nothing."""
    raw = get_settings().webhook_allowed_cidrs
    try:
        return parse_networks(raw)
    except ValueError:
        logger.error(
            "WEBHOOK_ALLOWED_CIDRS is not a list of CIDRs; no private targets allowed"
        )
        return ()


def resolve_target(url: str, allowed_networks: Optional[Iterable] = None) -> List[str]:
    """Check ``url`` and return the addresses a request to it may connect to.

    Raises ``WebhookError`` for a bad URL, ``UrlSafetyError`` for a refused
    address and ``UnresolvableHostError`` when the host does not resolve.
    """
    parts = urlsplit(validate_url(url))
    port = parts.port or (443 if parts.scheme == "https" else 80)
    networks = configured_networks() if allowed_networks is None else allowed_networks
    return resolve_allowed_addresses(parts.hostname, port, allowed_networks=networks)


class PinnedResolver(AbstractResolver):
    """Answers for one host with the addresses already checked, and nothing else."""

    def __init__(self, host: str, addresses: Sequence[str]):
        self._host = host.lower()
        self._addresses = list(addresses)

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host.lower() != self._host:
            raise OSError(f"unpinned host {host}")
        return [
            {
                "hostname": host,
                "host": addr,
                "port": port,
                "family": socket.AF_INET6 if ":" in addr else socket.AF_INET,
                "proto": 0,
                "flags": socket.AI_NUMERICHOST,
            }
            for addr in self._addresses
        ]

    async def close(self) -> None:
        return None


# --- sending -------------------------------------------------------------------


@dataclass(frozen=True)
class SendResult:
    """``outcome``: ``delivered``, ``retry`` (transient) or ``failed`` (permanent)."""

    outcome: str
    status_code: Optional[int] = None
    error: Optional[str] = None

    @property
    def delivered(self) -> bool:
        return self.outcome == DELIVERED


def classify_status(status: int) -> SendResult:
    if 200 <= status < 300:
        return SendResult(DELIVERED, status)
    if status in (408, 429) or status >= 500:
        return SendResult("retry", status, f"HTTP {status}")
    if 300 <= status < 400:
        return SendResult(FAILED, status, f"HTTP {status}: redirects are not followed")
    return SendResult(FAILED, status, f"HTTP {status}")


async def send_signed(
    url: str,
    *,
    secret: str,
    event_type: str,
    event_id: str,
    delivery_id: str,
    payload: Dict[str, Any],
    allowed_networks: Optional[Iterable] = None,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
    now: Optional[Callable[[], float]] = None,
) -> SendResult:
    """POST one signed event to ``url``. Never raises for a delivery problem."""
    try:
        parts = urlsplit(validate_url(url))
        addresses = await asyncio.to_thread(resolve_target, url, allowed_networks)
    except UnresolvableHostError:
        return SendResult("retry", error="could not resolve host")
    except UrlSafetyError as exc:
        return SendResult(FAILED, error=f"target refused: {exc}")
    except WebhookError as exc:
        return SendResult(FAILED, error=f"invalid url: {exc}")

    body = encode_body(payload)
    timestamp = int((now or time.time)())
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        SIGNATURE_HEADER: signature_header(secret, body, timestamp),
        EVENT_HEADER: event_type,
        EVENT_ID_HEADER: event_id,
        DELIVERY_HEADER: delivery_id,
    }
    connector = aiohttp.TCPConnector(
        resolver=PinnedResolver(parts.hostname, addresses),
        use_dns_cache=False,
        force_close=True,
    )
    try:
        # trust_env=False: an HTTP(S)_PROXY from the environment would make the
        # proxy, not the pinned address, the thing we connect to.
        async with aiohttp.ClientSession(
            connector=connector,
            trust_env=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as session:
            async with session.post(
                url, data=body, headers=headers, allow_redirects=False
            ) as response:
                return classify_status(response.status)
    except asyncio.TimeoutError:
        return SendResult("retry", error="timed out")
    except aiohttp.ClientError as exc:
        return SendResult("retry", error=f"connection failed: {type(exc).__name__}")
    except OSError as exc:
        return SendResult("retry", error=f"connection failed: {type(exc).__name__}")


# --- endpoints (store) ---------------------------------------------------------

_ENDPOINT_COLUMNS = (
    "id, tenant_id, name, url, secret_ref, event_types, enabled, created_by, "
    "created_at, updated_at"
)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def _endpoint(row) -> Dict[str, Any]:
    m = row._mapping
    return {
        "id": str(m["id"]),
        "tenant_id": m["tenant_id"],
        "name": m["name"],
        "url": m["url"],
        "secret_ref": m["secret_ref"],
        "event_types": list(m["event_types"] or []),
        "enabled": bool(m["enabled"]),
        "created_by": m["created_by"],
        "created_at": _iso(m["created_at"]),
        "updated_at": _iso(m["updated_at"]),
    }


def public_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """The endpoint as an API answer: whether it has a secret, never which."""
    out = {k: v for k, v in endpoint.items() if k != "secret_ref"}
    out["has_secret"] = bool(endpoint.get("secret_ref"))
    return out


def validate_event_types(event_types: Iterable[str]) -> List[str]:
    cleaned = sorted({(t or "").strip() for t in event_types})
    unknown = [t for t in cleaned if t not in SUBSCRIBABLE_EVENT_TYPES]
    if unknown:
        raise WebhookError(
            "unknown event type(s): "
            + ", ".join(unknown)
            + "; known: "
            + ", ".join(sorted(SUBSCRIBABLE_EVENT_TYPES))
        )
    return cleaned


def list_endpoints(
    tenant_id: str = DEFAULT_TENANT, session: Optional[Session] = None
) -> List[Dict[str, Any]]:
    with unit_of_work(session) as s:
        rows = s.execute(
            text(
                f"SELECT {_ENDPOINT_COLUMNS} FROM webhook_endpoints "
                "WHERE tenant_id = :t ORDER BY name"
            ),
            {"t": tenant_id},
        ).fetchall()
        return [_endpoint(r) for r in rows]


def get_endpoint(
    endpoint_id: str,
    tenant_id: str = DEFAULT_TENANT,
    session: Optional[Session] = None,
) -> Optional[Dict[str, Any]]:
    with unit_of_work(session) as s:
        row = s.execute(
            text(
                f"SELECT {_ENDPOINT_COLUMNS} FROM webhook_endpoints "
                "WHERE tenant_id = :t AND id = CAST(:id AS uuid)"
            ),
            {"t": tenant_id, "id": str(endpoint_id)},
        ).first()
        return _endpoint(row) if row else None


def _name_taken(s: Session, tenant_id: str, name: str, exclude_id=None) -> bool:
    sql = "SELECT 1 FROM webhook_endpoints WHERE tenant_id = :t AND name = :n"
    params: Dict[str, Any] = {"t": tenant_id, "n": name}
    if exclude_id is not None:
        sql += " AND id <> CAST(:id AS uuid)"
        params["id"] = str(exclude_id)
    return s.execute(text(sql), params).first() is not None


def create_endpoint(
    *,
    name: str,
    url: str,
    event_types: Iterable[str] = (),
    enabled: bool = True,
    secret: Optional[str] = None,
    created_by: Optional[str] = None,
    tenant_id: str = DEFAULT_TENANT,
    check_target: bool = True,
) -> tuple[Dict[str, Any], Optional[str]]:
    """Create an endpoint; returns it and the secret if one was generated.

    The secret goes to the secrets manager under a name derived from the new
    endpoint's id, and only that name is stored. A generated secret is returned
    once, here, and cannot be read back through the API afterwards.
    """
    name = (name or "").strip()
    if not name:
        raise WebhookError("name is required")
    url = validate_url(url)
    types = validate_event_types(event_types)
    if check_target:
        resolve_target(url)

    endpoint_id = uuid.uuid4()
    secret_ref = f"{SECRET_REF_PREFIX}{endpoint_id.hex.upper()}"
    generated = None if secret else new_secret()
    with unit_of_work() as s:
        if _name_taken(s, tenant_id, name):
            raise WebhookConflict(f"an endpoint named {name!r} already exists")
        if not set_secret(secret_ref, secret or generated):
            raise SecretStoreError("could not store the signing secret")
        try:
            row = s.execute(
                text(
                    "INSERT INTO webhook_endpoints "
                    "(id, tenant_id, name, url, secret_ref, event_types, enabled, created_by) "
                    "VALUES (CAST(:id AS uuid), :t, :n, :u, :ref, :types, :en, :by) "
                    f"RETURNING {_ENDPOINT_COLUMNS}"
                ),
                {
                    "id": str(endpoint_id),
                    "t": tenant_id,
                    "n": name,
                    "u": url,
                    "ref": secret_ref,
                    "types": types,
                    "en": bool(enabled),
                    "by": created_by,
                },
            ).first()
            s.flush()
        except IntegrityError as exc:
            # Lost a race with a concurrent create of the same name.
            delete_secret(secret_ref)
            raise WebhookConflict(f"an endpoint named {name!r} already exists") from exc
        except Exception:
            delete_secret(secret_ref)
            raise
        return _endpoint(row), generated


def update_endpoint(
    endpoint_id: str,
    *,
    tenant_id: str = DEFAULT_TENANT,
    name: Optional[str] = None,
    url: Optional[str] = None,
    event_types: Optional[Iterable[str]] = None,
    enabled: Optional[bool] = None,
    secret: Optional[str] = None,
    check_target: bool = True,
) -> Dict[str, Any]:
    sets: List[str] = []
    params: Dict[str, Any] = {"t": tenant_id, "id": str(endpoint_id)}
    if name is not None:
        name = name.strip()
        if not name:
            raise WebhookError("name must not be empty")
        sets.append("name = :n")
        params["n"] = name
    if url is not None:
        url = validate_url(url)
        if check_target:
            resolve_target(url)
        sets.append("url = :u")
        params["u"] = url
    if event_types is not None:
        sets.append("event_types = :types")
        params["types"] = validate_event_types(event_types)
    if enabled is not None:
        sets.append("enabled = :en")
        params["en"] = bool(enabled)

    with unit_of_work() as s:
        current = get_endpoint(endpoint_id, tenant_id, session=s)
        if current is None:
            raise WebhookNotFound(str(endpoint_id))
        if name is not None and _name_taken(s, tenant_id, name, exclude_id=endpoint_id):
            raise WebhookConflict(f"an endpoint named {name!r} already exists")
        if secret is not None:
            ref = current["secret_ref"] or (
                f"{SECRET_REF_PREFIX}{uuid.UUID(current['id']).hex.upper()}"
            )
            if not set_secret(ref, secret):
                raise SecretStoreError("could not store the signing secret")
            if ref != current["secret_ref"]:
                sets.append("secret_ref = :ref")
                params["ref"] = ref
        if not sets:
            return current
        sets.append("updated_at = now()")
        row = s.execute(
            text(
                f"UPDATE webhook_endpoints SET {', '.join(sets)} "
                "WHERE tenant_id = :t AND id = CAST(:id AS uuid) "
                f"RETURNING {_ENDPOINT_COLUMNS}"
            ),
            params,
        ).first()
        return _endpoint(row)


def delete_endpoint(endpoint_id: str, tenant_id: str = DEFAULT_TENANT) -> bool:
    """Delete an endpoint, its deliveries (cascade) and its secret.

    An alert route still sending to it makes the delete fail with the
    database's IntegrityError (``ON DELETE RESTRICT``).
    """
    with unit_of_work() as s:
        row = s.execute(
            text(
                "DELETE FROM webhook_endpoints "
                "WHERE tenant_id = :t AND id = CAST(:id AS uuid) RETURNING secret_ref"
            ),
            {"t": tenant_id, "id": str(endpoint_id)},
        ).first()
        if row is None:
            return False
        s.flush()
        secret_ref = row._mapping["secret_ref"]
    if secret_ref:
        delete_secret(secret_ref)
    return True


# --- deliveries (store) --------------------------------------------------------


def enqueue_event(
    event_type: str,
    event_id: str,
    data: Dict[str, Any],
    *,
    tenant_id: str = DEFAULT_TENANT,
    session: Optional[Session] = None,
    now: Optional[datetime] = None,
) -> int:
    """Owe ``event`` to every enabled endpoint subscribed to ``event_type``.

    Idempotent per endpoint and event id: a second call for the same event adds
    nothing. Returns the number of deliveries newly queued.
    """
    created = now or utc_now()
    payload = build_payload(
        event_type, event_id, data, tenant_id=tenant_id, created_at=created
    )
    with unit_of_work(session) as s:
        result = s.execute(
            text(
                "INSERT INTO webhook_deliveries "
                "(tenant_id, endpoint_id, event_type, event_id, payload, next_attempt_at) "
                "SELECT e.tenant_id, e.id, :type, :eid, CAST(:payload AS jsonb), :now "
                "FROM webhook_endpoints e "
                "WHERE e.tenant_id = :t AND e.enabled "
                "AND (cardinality(e.event_types) = 0 OR :type = ANY(e.event_types)) "
                "ON CONFLICT (endpoint_id, event_id) DO NOTHING"
            ),
            {
                "t": tenant_id,
                "type": event_type,
                "eid": event_id,
                "payload": json.dumps(payload, default=str),
                "now": created,
            },
        )
        return int(result.rowcount or 0)


_DELIVERY_COLUMNS = (
    "d.id, d.tenant_id, d.endpoint_id, d.event_type, d.event_id, d.status, "
    "d.attempts, d.next_attempt_at, d.last_attempt_at, d.response_status, "
    "d.last_error, d.created_at, d.delivered_at"
)


def _delivery(row) -> Dict[str, Any]:
    m = row._mapping
    return {
        "id": int(m["id"]),
        "endpoint_id": str(m["endpoint_id"]),
        "event_type": m["event_type"],
        "event_id": m["event_id"],
        "status": m["status"],
        "attempts": int(m["attempts"]),
        "next_attempt_at": _iso(m["next_attempt_at"]),
        "last_attempt_at": _iso(m["last_attempt_at"]),
        "response_status": m["response_status"],
        "last_error": m["last_error"],
        "created_at": _iso(m["created_at"]),
        "delivered_at": _iso(m["delivered_at"]),
    }


def claim_due_deliveries(
    limit: int = 50, now: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    """Take up to ``limit`` due deliveries and lease them for one attempt.

    ``SKIP LOCKED`` keeps two senders off the same rows; moving
    ``next_attempt_at`` forward by the lease keeps them off once this
    transaction commits, without holding a lock across the HTTP call.
    """
    current = now or utc_now()
    with unit_of_work() as s:
        rows = s.execute(
            text(
                f"SELECT {_DELIVERY_COLUMNS}, d.payload, e.url, e.secret_ref, e.enabled "
                "FROM webhook_deliveries d "
                "JOIN webhook_endpoints e "
                "  ON e.tenant_id = d.tenant_id AND e.id = d.endpoint_id "
                "WHERE d.status = 'pending' AND d.next_attempt_at <= :now "
                "ORDER BY d.next_attempt_at, d.id "
                "LIMIT :limit "
                "FOR UPDATE OF d SKIP LOCKED"
            ),
            {"now": current, "limit": int(limit)},
        ).fetchall()
        if not rows:
            return []
        ids = [int(r._mapping["id"]) for r in rows]
        lease = current + timedelta(seconds=CLAIM_LEASE_SECONDS)
        s.execute(
            text(
                "UPDATE webhook_deliveries SET next_attempt_at = :lease "
                "WHERE id = ANY(:ids)"
            ),
            {"lease": lease, "ids": ids},
        )
        claimed = []
        for r in rows:
            item = _delivery(r)
            m = r._mapping
            item.update(
                payload=m["payload"],
                url=m["url"],
                secret_ref=m["secret_ref"],
                endpoint_enabled=bool(m["enabled"]),
                # The claim's token: record_attempt only writes while the row
                # still carries this lease (see there).
                lease=lease,
            )
            claimed.append(item)
        return claimed


def record_attempt(
    delivery: Dict[str, Any],
    result: SendResult,
    *,
    max_attempts: int,
    now: Optional[datetime] = None,
) -> str:
    """Write one attempt's outcome; returns the delivery's new status.

    The update only applies while the row is still the one this sender claimed:
    pending, same attempt count, and still carrying this claim's lease in
    ``next_attempt_at``. Every later claim sets a strictly later lease (a row is
    only re-claimable once its lease has passed), and every recorded outcome or
    requeue moves ``next_attempt_at`` too, so a stale claim never matches again.
    If the lease ran out and another sender took the delivery over, or an admin
    requeued it meanwhile (which resets ``attempts`` to 0, so the attempt count
    alone would match again), the stale outcome is dropped instead of
    overwriting newer state, whichever of the two results arrives first.
    """
    current = now or utc_now()
    attempts = int(delivery["attempts"]) + 1
    if result.outcome == DELIVERED:
        status, next_at = DELIVERED, current
    elif result.outcome == FAILED:
        status, next_at = FAILED, current
    elif attempts >= max_attempts:
        status, next_at = DEAD, current
    else:
        status = PENDING
        next_at = current + timedelta(seconds=backoff_seconds(attempts))
    with unit_of_work() as s:
        updated = s.execute(
            text(
                "UPDATE webhook_deliveries SET status = :status, attempts = :attempts, "
                "next_attempt_at = :next_at, last_attempt_at = :now, "
                "response_status = :code, last_error = :error, "
                "delivered_at = CASE WHEN :status = 'delivered' THEN :now ELSE delivered_at END "
                "WHERE id = :id AND status = 'pending' AND attempts = :previous "
                "AND next_attempt_at = :lease"
            ),
            {
                "status": status,
                "attempts": attempts,
                "next_at": next_at,
                "now": current,
                "code": result.status_code,
                "error": (result.error or None) and result.error[:500],
                "id": int(delivery["id"]),
                "previous": attempts - 1,
                "lease": delivery["lease"],
            },
        )
        if not updated.rowcount:
            logger.warning(
                "Webhook delivery %s changed while it was being sent; "
                "outcome %s not recorded",
                delivery["id"],
                status,
            )
    return status


def list_deliveries(
    endpoint_id: str,
    *,
    tenant_id: str = DEFAULT_TENANT,
    limit: int = 50,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    sql = (
        f"SELECT {_DELIVERY_COLUMNS} FROM webhook_deliveries d "
        "WHERE d.tenant_id = :t AND d.endpoint_id = CAST(:e AS uuid)"
    )
    params: Dict[str, Any] = {"t": tenant_id, "e": str(endpoint_id), "limit": limit}
    if status:
        sql += " AND d.status = :status"
        params["status"] = status
    sql += " ORDER BY d.created_at DESC, d.id DESC LIMIT :limit"
    with unit_of_work() as s:
        return [_delivery(r) for r in s.execute(text(sql), params).fetchall()]


def requeue_delivery(
    endpoint_id: str,
    delivery_id: int,
    *,
    tenant_id: str = DEFAULT_TENANT,
    now: Optional[datetime] = None,
) -> Optional[Dict[str, Any]]:
    """Put a failed or dead delivery back in the queue with fresh attempts."""
    with unit_of_work() as s:
        row = s.execute(
            text(
                "UPDATE webhook_deliveries d SET status = 'pending', attempts = 0, "
                "next_attempt_at = :now, last_error = NULL "
                "WHERE d.tenant_id = :t AND d.endpoint_id = CAST(:e AS uuid) "
                "AND d.id = :id AND d.status IN ('failed', 'dead') "
                f"RETURNING {_DELIVERY_COLUMNS}"
            ),
            {
                "t": tenant_id,
                "e": str(endpoint_id),
                "id": int(delivery_id),
                "now": now or utc_now(),
            },
        ).first()
        return _delivery(row) if row else None


# --- the sender --------------------------------------------------------------


class WebhookSender:
    """Drains due deliveries. Runs in the daemon (see CaseAutomationService)."""

    def __init__(
        self,
        *,
        max_attempts: Optional[int] = None,
        allowed_networks: Optional[Iterable] = None,
        concurrency: int = 5,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ):
        self._max_attempts = max_attempts
        self._allowed_networks = (
            tuple(allowed_networks) if allowed_networks is not None else None
        )
        self._concurrency = max(1, concurrency)
        self._timeout = timeout

    @property
    def max_attempts(self) -> int:
        if self._max_attempts is not None:
            return max(1, self._max_attempts)
        return max(1, get_settings().webhook_max_attempts)

    def _networks(self) -> tuple:
        if self._allowed_networks is not None:
            return self._allowed_networks
        return configured_networks()

    async def attempt(self, delivery: Dict[str, Any]) -> SendResult:
        if not delivery.get("endpoint_enabled", True):
            return SendResult(FAILED, error="endpoint disabled")
        ref = delivery.get("secret_ref")
        secret = await asyncio.to_thread(get_secret, ref) if ref else None
        if not secret:
            return SendResult(FAILED, error="signing secret missing")
        payload = delivery["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        return await send_signed(
            delivery["url"],
            secret=secret,
            event_type=delivery["event_type"],
            event_id=delivery["event_id"],
            delivery_id=str(delivery["id"]),
            payload=payload,
            allowed_networks=self._networks(),
            timeout=self._timeout,
        )

    async def deliver_due(
        self, limit: int = 50, now: Optional[datetime] = None
    ) -> Dict[str, int]:
        """One pass: claim what is due, attempt each once, record outcomes."""
        claimed = await asyncio.to_thread(claim_due_deliveries, limit, now)
        counts: Dict[str, int] = {}
        if not claimed:
            return counts
        gate = asyncio.Semaphore(self._concurrency)
        max_attempts = self.max_attempts

        async def one(delivery):
            async with gate:
                result = await self.attempt(delivery)
            status = await asyncio.to_thread(
                record_attempt, delivery, result, max_attempts=max_attempts, now=now
            )
            if status in (FAILED, DEAD):
                logger.warning(
                    "Webhook delivery %s to endpoint %s is %s: %s",
                    delivery["id"],
                    delivery["endpoint_id"],
                    status,
                    result.error,
                )
            counts[status] = counts.get(status, 0) + 1

        await asyncio.gather(*(one(d) for d in claimed))
        return counts

    async def send_test(self, endpoint: Dict[str, Any]) -> SendResult:
        """Send a ``webhook.test`` event now, outside the queue."""
        ref = endpoint.get("secret_ref")
        secret = await asyncio.to_thread(get_secret, ref) if ref else None
        if not secret:
            return SendResult(FAILED, error="signing secret missing")
        event_id = f"test:{uuid.uuid4()}"
        payload = build_payload(
            TEST_EVENT_TYPE,
            event_id,
            {"endpoint_id": endpoint["id"], "message": "AutoSecOps webhook test"},
            tenant_id=endpoint.get("tenant_id") or DEFAULT_TENANT,
        )
        return await send_signed(
            endpoint["url"],
            secret=secret,
            event_type=TEST_EVENT_TYPE,
            event_id=event_id,
            delivery_id=event_id,
            payload=payload,
            allowed_networks=self._networks(),
            timeout=self._timeout,
        )
