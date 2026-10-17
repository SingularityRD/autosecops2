"""Data-subject requests (KVKK art. 11 and 13): register, find, export (W0.48).

A request is registered first (who asked, what kind, when it was received); it
is due 30 days later (art. 13/2). Every search and export names its request, so
the audit trail says why a person's data was looked up. Requests live in
``config_audit_log`` (``config_type = "data_subject_request"``), append-only: a
state change is a new row and the newest row of a request is its state.

The identifier (an e-mail address, user name, IP address or host name) is not
stored: the register keeps its SHA-256 and a masked hint, so the register is not
itself a second copy of the personal data.

Search reads findings (title, description, entity_context), cases (title,
description, notes, assignee), case comments (author, content) and users
(user name, e-mail, full name). It is a case-insensitive substring match: the
results are candidates for the person handling the request, not a decision.
Erasure (W0.59, K2: ``erase``): for an open ``erasure`` request, every
case-insensitive occurrence of the identifier in the text of findings (title,
description, entity_context, ai_enrichment), cases (title, description, notes,
timeline) and case comments is replaced with ``[erased]``. Rows tied to a case
under legal hold, and every row of a data class under a class-wide hold, are
left as they are and counted. User accounts are not changed here (deactivate
or delete them in user management), and nothing chained is touched: the
hash-chained ledgers and the audit logs are kept for the legal obligation they
serve and leave through the retention tools (``core/compliance/retention.py``).
The request records what was erased, per source, without the identifier.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.audit.config_changes import record_change
from core.storage.models import ConfigAuditLog
from core.time import utcnow

CONFIG_TYPE = "data_subject_request"
DUE_DAYS = 30
KINDS = ("access", "rectification", "erasure", "objection", "other")
STATES = ("open", "closed")
# Rows per source a search returns; the counts are exact.
MAX_ROWS = 200
MIN_IDENTIFIER = 3


class RequestNotFound(LookupError):
    pass


class RequestClosed(ValueError):
    pass


def identifier_hash(identifier: str) -> str:
    return hashlib.sha256(identifier.strip().lower().encode("utf-8")).hexdigest()


def masked(identifier: str) -> str:
    """``a***@corp.example`` / ``1***`` : enough to tell requests apart."""
    value = identifier.strip()
    if "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}"
    return f"{value[:1]}***"


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def register(
    session: Session,
    *,
    identifier: str,
    kind: str,
    received_at: Optional[datetime],
    reference: Optional[str],
    actor: str,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    if len(identifier.strip()) < MIN_IDENTIFIER:
        raise ValueError(f"identifier must be at least {MIN_IDENTIFIER} characters")
    now = now or utcnow()
    received = received_at or now
    request = {
        "request_id": f"dsr-{uuid.uuid4().hex[:12]}",
        "kind": kind,
        "state": "open",
        "identifier_sha256": identifier_hash(identifier),
        "identifier_hint": masked(identifier),
        "reference": (reference or "")[:200] or None,
        "received_at": _iso(received),
        "due_at": _iso(received + timedelta(days=DUE_DAYS)),
        "registered_at": _iso(now),
        "registered_by": actor,
        "closed_at": None,
        "outcome": None,
    }
    record_change(
        session,
        config_type=CONFIG_TYPE,
        config_key=request["request_id"],
        action="create",
        old=None,
        new=request,
        actor=actor,
        reason=f"data subject request ({kind})",
    )
    return request


def _rows(session: Session, request_id: Optional[str] = None) -> List[ConfigAuditLog]:
    query = session.query(ConfigAuditLog).filter(
        ConfigAuditLog.config_type == CONFIG_TYPE
    )
    if request_id:
        query = query.filter(ConfigAuditLog.config_key == request_id)
    return query.order_by(ConfigAuditLog.id).all()


def _states(session: Session, request_id: Optional[str] = None) -> Dict[str, dict]:
    latest: Dict[str, dict] = {}
    for row in _rows(session, request_id):
        if row.action in ("create", "update") and isinstance(row.new_value, dict):
            latest[row.config_key] = dict(row.new_value)
    return latest


def get(session: Session, request_id: str) -> Dict[str, Any]:
    state = _states(session, request_id).get(request_id)
    if state is None:
        raise RequestNotFound(request_id)
    return state


def with_clock(
    request: Dict[str, Any], now: Optional[datetime] = None
) -> Dict[str, Any]:
    now = now or utcnow()
    out = dict(request)
    due = datetime.fromisoformat(request["due_at"]) if request.get("due_at") else None
    out["overdue"] = bool(due and request.get("state") == "open" and now > due)
    out["days_left"] = (
        (due - now).days if due and request.get("state") == "open" else None
    )
    return out


def list_requests(
    session: Session, now: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    requests = [with_clock(r, now) for r in _states(session).values()]
    return sorted(requests, key=lambda r: r.get("received_at") or "", reverse=True)


def close(
    session: Session,
    request_id: str,
    *,
    outcome: str,
    actor: str,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    old = get(session, request_id)
    if old.get("state") == "closed":
        raise RequestClosed(request_id)
    new = {
        **old,
        "state": "closed",
        "closed_at": _iso(now or utcnow()),
        "outcome": outcome[:2000],
    }
    record_change(
        session,
        config_type=CONFIG_TYPE,
        config_key=request_id,
        action="update",
        old=old,
        new=new,
        actor=actor,
        reason="data subject request closed",
    )
    return new


def _check(request: Dict[str, Any], identifier: str) -> None:
    if request.get("state") != "open":
        raise RequestClosed(request["request_id"])
    if identifier_hash(identifier) != request.get("identifier_sha256"):
        raise ValueError("identifier does not match the request")


def _like(identifier: str) -> str:
    escaped = (
        identifier.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    )
    return f"%{escaped}%"


# (source, count/select SQL over :p, the columns returned)
_SOURCES = (
    (
        "findings",
        "FROM findings WHERE title ILIKE :p OR description ILIKE :p"
        " OR CAST(entity_context AS TEXT) ILIKE :p",
        "finding_id, data_source, title, description, entity_context, timestamp, created_at",
        "finding_id",
    ),
    (
        "cases",
        "FROM cases WHERE title ILIKE :p OR description ILIKE :p"
        " OR CAST(notes AS TEXT) ILIKE :p OR assignee ILIKE :p",
        "case_id, title, description, status, assignee, created_at",
        "case_id",
    ),
    (
        "case_comments",
        "FROM case_comments WHERE author ILIKE :p OR content ILIKE :p",
        "comment_id, case_id, author, content, created_at",
        "comment_id",
    ),
    (
        "users",
        "FROM users WHERE username ILIKE :p OR email ILIKE :p OR full_name ILIKE :p",
        "user_id, username, email, full_name, created_at",
        "user_id",
    ),
)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _search(session: Session, identifier: str, full: bool) -> Dict[str, Any]:
    params = {"p": _like(identifier)}
    found: Dict[str, Any] = {}
    for source, where, columns, key in _SOURCES:
        # Fixed SQL per source; the identifier is only ever a bound parameter.
        count = session.execute(
            text(f"SELECT count(*) {where}"), params
        ).scalar()  # nosec B608
        select = columns if full else key
        rows = session.execute(
            text(
                f"SELECT {select} {where} ORDER BY {key} LIMIT {MAX_ROWS}"
            ),  # nosec B608
            params,
        ).mappings()
        items = [{k: _jsonable(v) for k, v in row.items()} for row in rows]
        found[source] = {
            "count": int(count or 0),
            "items": items if full else [item[key] for item in items],
            "truncated": int(count or 0) > MAX_ROWS,
        }
    return found


def search(
    session: Session, request_id: str, identifier: str, *, actor: str
) -> Dict[str, Any]:
    """Where the identifier appears (ids only), recorded against the request."""
    request = get(session, request_id)
    _check(request, identifier)
    found = _search(session, identifier, full=False)
    _record_lookup(session, request, "search", found, actor)
    return {"request_id": request_id, "results": found}


def export(
    session: Session, request_id: str, identifier: str, *, actor: str
) -> Dict[str, Any]:
    """The matching records themselves, for the reply to the person (art. 11)."""
    request = get(session, request_id)
    _check(request, identifier)
    found = _search(session, identifier, full=True)
    _record_lookup(session, request, "export", found, actor)
    return {
        "request_id": request_id,
        "generated_at": _iso(utcnow()),
        "note": (
            "Records that contain the identifier as text. A match is a candidate: "
            "review each before it is sent to the data subject."
        ),
        "results": found,
    }


def _record_lookup(
    session: Session,
    request: Dict[str, Any],
    what: str,
    found: Dict[str, Any],
    actor: str,
) -> None:
    record_change(
        session,
        config_type=CONFIG_TYPE,
        config_key=request["request_id"],
        action=what,
        old=None,
        new={"counts": {k: v["count"] for k, v in found.items()}},
        actor=actor,
        reason=f"data subject request {what}",
    )


ERASED = "[erased]"

# (source, table, key, text columns, JSON columns, how a row finds its cases)
_ERASE_SOURCES = (
    (
        "findings",
        "findings",
        "finding_id",
        ("title", "description"),
        ("entity_context", "ai_enrichment"),
        "SELECT case_id FROM case_findings WHERE finding_id = :k",
    ),
    (
        "cases",
        "cases",
        "case_id",
        ("title", "description"),
        ("notes", "timeline"),
        "SELECT :k AS case_id",
    ),
    (
        "case_comments",
        "case_comments",
        "comment_id",
        ("content",),
        (),
        "SELECT case_id FROM case_comments WHERE comment_id = :k",
    ),
)
# The retention data class whose class-wide legal hold covers each source.
_HOLD_CLASS = {"findings": "findings", "cases": "cases", "case_comments": "cases"}


def _redact(value: Any, pattern: "re.Pattern[str]") -> Any:
    """``value`` with every match replaced, walking JSON structures."""
    if isinstance(value, str):
        return pattern.sub(ERASED, value)
    if isinstance(value, list):
        return [_redact(v, pattern) for v in value]
    if isinstance(value, dict):
        return {
            _redact(k, pattern) if isinstance(k, str) else k: _redact(v, pattern)
            for k, v in value.items()
        }
    return value


def _class_held(session: Session, data_class: str) -> bool:
    if (
        session.execute(text("SELECT to_regclass('retention_policies')")).scalar()
        is None
    ):
        return False
    row = session.execute(
        text(
            "SELECT legal_hold FROM retention_policies"
            " WHERE tenant_id = 'default' AND data_class = :c"
        ),
        {"c": data_class},
    ).scalar()
    return bool(row)


def erase(
    session: Session,
    request_id: str,
    identifier: str,
    *,
    actor: str,
    confirm: bool,
) -> Dict[str, Any]:
    """Replace the identifier with ``[erased]`` where erasure is allowed."""
    from core.compliance.retention import list_legal_holds

    request = get(session, request_id)
    _check(request, identifier)
    if request.get("kind") != "erasure":
        raise ValueError("only an erasure request can erase")
    if not confirm:
        raise ValueError("confirm must be true: erasure cannot be undone")
    pattern = re.compile(re.escape(identifier.strip()), re.IGNORECASE)
    held_cases = set(list_legal_holds(session))
    params = {"p": _like(identifier)}
    results: Dict[str, Dict[str, int]] = {}
    for source, table, key, texts, jsons, cases_sql in _ERASE_SOURCES:
        columns = texts + jsons
        where = " OR ".join(
            [f"{c} ILIKE :p" for c in texts]
            + [f"CAST({c} AS TEXT) ILIKE :p" for c in jsons]
        )
        # Fixed SQL per source; the identifier is only ever a bound parameter.
        rows = (
            session.execute(
                text(
                    f"SELECT {key}, {', '.join(columns)} FROM {table} WHERE {where}"
                ),  # nosec B608
                params,
            )
            .mappings()
            .all()
        )
        counts = {"matched": len(rows), "erased": 0, "held": 0}
        class_held = _class_held(session, _HOLD_CLASS[source])
        for row in rows:
            cases = {
                c
                for c in session.execute(text(cases_sql), {"k": row[key]}).scalars()
                if c
            }
            if class_held or cases & held_cases:
                counts["held"] += 1
                continue
            new = {c: _redact(row[c], pattern) for c in columns}
            sets = [f"{c} = :{c}" for c in texts] + [
                f"{c} = CAST(:{c} AS jsonb)" for c in jsons
            ]
            values = {c: new[c] for c in texts}
            values.update(
                {c: None if new[c] is None else json.dumps(new[c]) for c in jsons}
            )
            session.execute(
                text(
                    f"UPDATE {table} SET {', '.join(sets)} WHERE {key} = :k"
                ),  # nosec B608
                {**values, "k": row[key]},
            )
            counts["erased"] += 1
        results[source] = counts
    users = session.execute(
        text(
            "SELECT count(*) FROM users WHERE username ILIKE :p OR email ILIKE :p"
            " OR full_name ILIKE :p"
        ),
        params,
    ).scalar()
    outcome = {
        "results": results,
        "user_accounts_matched": int(users or 0),
        "not_erased_here": (
            "user accounts (user management); chained ledgers and audit logs "
            "(kept for their legal obligation; the retention tools remove them)"
        ),
    }
    record_change(
        session,
        config_type=CONFIG_TYPE,
        config_key=request_id,
        action="erase",
        old=None,
        new=outcome,
        actor=actor,
        reason="data subject request erasure",
    )
    return {"request_id": request_id, **outcome}
