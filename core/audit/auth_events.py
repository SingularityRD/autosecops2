"""Authentication and user-management events, kept in the chained audit log.

Login (success, failure, lockout, MFA failure), logout, SSO login, MFA and
password changes and resets, user create / update / delete / (de)activation and
role changes are written as ``case_audit_logs`` rows with
``entity_type = 'auth'``, whatever the SIEM export (WP w3.6) is set to. That
table is chained by ``audit_chain`` (W1.10), so these rows are covered by
``python -m core.audit.verify`` like every case audit row, and the export's
``auth`` source reads them back from there (``AuthAuditSource``).

Row layout (the table predates these events; no column is added):

=================  ==========================================================
``entity_type``    ``auth``
``entity_id``      the user the event is about (target, else actor), or ``-``
``field_name``     the event (``login``, ``role_change``, ...)
``action``         the outcome (``success``, ``failure``, ``locked``, ...)
``changed_by``     who did it (``anonymous`` for an unknown login identifier)
``ip_address``     client address; ``user_agent``: client user agent
``new_value``      JSON: ``id`` (stable event id), ``event``, ``outcome``,
                   ``actor_id``, ``target_id``, ``details``
``change_summary`` a one-line description
``timestamp``      when (naive UTC, like every row of the table)
=================  ==========================================================

The person's name, address and user agent live only in the columns retention
(``core/compliance/retention.py``) anonymises, not in ``new_value``.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

AUTH_ENTITY_TYPE = "auth"
ANONYMOUS = "anonymous"


def _cap(value: Any, n: int) -> Optional[str]:
    if value is None or value == "":
        return None
    return str(value)[:n]


def describe(
    event: str,
    outcome: str,
    actor: Optional[str],
    target: Optional[str],
    actor_id: Optional[str],
) -> str:
    message = f"{event.replace('_', ' ')} {outcome}" + (
        f" for {actor}" if actor else ""
    )
    if target and target != actor_id:
        message += f" (target {target})"
    return message


def build_row(record: dict):
    """The ``CaseAuditLog`` for one auth record (``audit_export.auth_record``)."""
    from core.storage.models import CaseAuditLog

    event = str(record.get("action") or "unknown")
    outcome = str(record.get("outcome") or "success")
    actor, actor_id = record.get("actor"), record.get("actor_id")
    target = record.get("target_id")
    ts = record.get("ts")
    when = (
        datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if ts
        else datetime.now(timezone.utc)
    )
    if when.tzinfo is not None:
        when = when.astimezone(timezone.utc).replace(tzinfo=None)
    body = {
        "id": str(record.get("id") or uuid.uuid4()),
        "event": event,
        "outcome": outcome,
        "actor_id": actor_id,
        "target_id": target,
        "details": record.get("details") or {},
    }
    return CaseAuditLog(
        entity_type=AUTH_ENTITY_TYPE,
        entity_id=_cap(target or actor_id, 100) or "-",
        action=outcome[:20],
        field_name=event[:100],
        old_value=None,
        new_value=json.dumps(body, separators=(",", ":"), default=str, sort_keys=True),
        change_summary=describe(event, outcome, actor, target, actor_id),
        changed_by=_cap(actor, 100) or ANONYMOUS,
        user_agent=_cap(record.get("user_agent"), 200),
        ip_address=_cap(record.get("src_ip"), 45),
        timestamp=when,
    )


def persist(record: dict, session: Optional[Session] = None) -> bool:
    """Write one auth record. Never raises.

    With ``session`` the row joins the caller's transaction, so it commits or
    rolls back with the change it describes (user create / update / delete).
    Without one it is committed on its own, so a refused login is recorded
    even though the request fails. A failure is logged at ERROR.
    """
    from core.storage.unit_of_work import unit_of_work

    try:
        row = build_row(record)
        if session is not None:
            session.add(row)
            return True
        with unit_of_work() as own:
            own.add(row)
        return True
    except Exception as exc:  # noqa: BLE001 - auditing must not break login
        logger.error(
            "Could not record the auth event %s (%s): %s",
            record.get("action"),
            record.get("outcome"),
            type(exc).__name__,
        )
        return False


def record_from_row(row: dict) -> dict:
    """The auth record (``audit_export.auth_record`` shape) of a stored row."""
    try:
        body = json.loads(row.get("new_value") or "{}")
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    changed_by = row.get("changed_by")
    return {
        "id": body.get("id") or f"row-{row.get('audit_id')}",
        "ts": row["timestamp"],
        "action": body.get("event") or row.get("field_name") or "unknown",
        "outcome": body.get("outcome") or row.get("action") or "success",
        "actor": None if changed_by in (None, ANONYMOUS) else changed_by,
        "actor_id": body.get("actor_id"),
        "target_id": body.get("target_id"),
        "src_ip": row.get("ip_address"),
        "user_agent": row.get("user_agent"),
        "details": body.get("details") or {},
    }
