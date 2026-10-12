"""Keeping canary findings out of metrics, exports and egress (W1.5).

A canary is a replayed known-malicious alert that the daemon pushes through the
normal ingest path to see whether the AI and the analysts catch it
(``core.quality.canary``). The finding it becomes carries no visible mark: the
only record that it is a canary is its row in ``canary_injections``
(``infra/database/init/46_eval_qa_canary.sql``), keyed by ``finding_id``.

Everything that counts findings for a customer (analytics, case dashboards, AI
decision stats) or sends them anywhere (findings export, IOC CSV/STIX/JSON,
Jira, and any webhook or SIEM write-back) filters through this module, so the
rule lives in one place:

- ``not_canary_finding(session, column)``: a WHERE clause keeping the rows whose
  ``finding_id`` is not a canary's.
- ``not_canary_case(session, column)``: keeps a case unless every finding it
  links is a canary (a case made of canaries only exists because someone caught
  one; a mixed case is real work and stays).
- ``canary_finding_ids`` / ``is_canary_finding`` / ``drop_canaries``: the same
  test for code that holds dicts or ORM rows rather than a query.

The table is SQL-owned (no ORM model, so ``create_all`` never builds it). An
install that has not applied the init file has no canaries, so every helper
here treats a missing table as "nothing to exclude" instead of failing the
caller's query. Storage tier: imports nothing from a capability domain.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Iterable, List, Optional, Set

from sqlalchemy import (
    Column,
    MetaData,
    String,
    Table,
    and_,
    exists,
    not_,
    select,
    text,
    true,
)
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import Session

from core.storage.models.base import case_findings
from core.storage.unit_of_work import unit_of_work

logger = logging.getLogger(__name__)

# Core Table, not an ORM model, on its own MetaData: create_all and the schema
# drift check must keep ignoring it (the init SQL owns it).
_metadata = MetaData()
canary_injections = Table(
    "canary_injections",
    _metadata,
    Column("id", UUID(as_uuid=False), primary_key=True),
    Column("tenant_id", String, nullable=False),
    Column("marker", String, nullable=False),
    Column("canary_kind", String, nullable=False),
    Column("expected_verdict", String, nullable=False),
    Column("expected_category", String),
    Column("payload", JSONB, nullable=False),
    Column("injected_at", TIMESTAMP(timezone=True), nullable=False),
    Column("finding_id", String),
    Column("observed_verdict", String),
    Column("observed_at", TIMESTAMP(timezone=True)),
    Column("outcome", String, nullable=False),
    Column("error", String),
)

# Engine URLs on which the table has been seen. Only presence is cached: a
# table appears once (the init file runs) and is never dropped, while an absent
# one may be created at any time, so absence is re-checked on every call.
_present_on: Set[str] = set()
_present_lock = threading.Lock()


def _bind_key(session: Session) -> str:
    try:
        return str(session.get_bind().url)
    except Exception:  # noqa: BLE001
        return ""


def canary_table_present(session: Session) -> bool:
    """Whether ``canary_injections`` exists in the session's database."""
    key = _bind_key(session)
    with _present_lock:
        if key and key in _present_on:
            return True
    found = (
        session.execute(text("SELECT to_regclass('canary_injections')")).scalar()
        is not None
    )
    if found and key:
        with _present_lock:
            _present_on.add(key)
    return found


def forget_table_presence() -> None:
    """Drop the presence cache (tests that create the table mid-process)."""
    with _present_lock:
        _present_on.clear()


def _is_canary(column: Any):
    return exists().where(canary_injections.c.finding_id == column)


def not_canary_finding(session: Session, column: Any):
    """WHERE clause: ``column`` (a finding_id) is not a canary's finding."""
    if not canary_table_present(session):
        return true()
    return not_(_is_canary(column))


def not_canary_case(session: Session, column: Any):
    """WHERE clause: the case ``column`` names is not made of canaries only.

    Excluded when it links at least one canary finding and no other finding.
    A case with no findings, or with any real finding, stays.
    """
    if not canary_table_present(session):
        return true()
    cf = case_findings.alias("canary_cf")
    cf_real = case_findings.alias("canary_cf_real")
    has_canary = exists(
        select(cf.c.finding_id).where(
            cf.c.case_id == column, _is_canary(cf.c.finding_id)
        )
    )
    has_real = exists(
        select(cf_real.c.finding_id).where(
            cf_real.c.case_id == column, not_(_is_canary(cf_real.c.finding_id))
        )
    )
    return not_(and_(has_canary, not_(has_real)))


def canary_finding_ids(session: Optional[Session] = None) -> Set[str]:
    """Every finding_id that is a canary's; empty when the table is absent."""
    with unit_of_work(session) as s:
        if not canary_table_present(s):
            return set()
        rows = s.execute(
            select(canary_injections.c.finding_id).where(
                canary_injections.c.finding_id.isnot(None)
            )
        )
        return {r[0] for r in rows}


def is_canary_finding(
    finding_id: Optional[str], session: Optional[Session] = None
) -> bool:
    """Whether ``finding_id`` is a canary's finding.

    Raises when the lookup fails; callers that gate egress or response on it
    decide which way to fail.
    """
    if not finding_id:
        return False
    with unit_of_work(session) as s:
        if not canary_table_present(s):
            return False
        return bool(s.execute(select(_is_canary(finding_id))).scalar())


def drop_canaries(
    items: Iterable[Any], session: Optional[Session] = None, key: str = "finding_id"
) -> List[Any]:
    """``items`` (dicts or objects with ``key``) without the canaries' findings."""
    items = list(items)
    if not items:
        return items
    ids = canary_finding_ids(session)
    if not ids:
        return items

    def _id(item: Any) -> Any:
        return item.get(key) if isinstance(item, dict) else getattr(item, key, None)

    return [item for item in items if _id(item) not in ids]


def _entity_values(value: Any, out: Set[str]) -> None:
    if isinstance(value, dict):
        for v in value.values():
            _entity_values(v, out)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _entity_values(v, out)
    elif isinstance(value, str) and value.strip():
        out.add(value.strip().lower())


def case_canary_profile(case_id: str, session: Optional[Session] = None) -> dict:
    """What a case's exports must leave out.

    ``only_canaries``: every finding the case links is a canary's (and it links
    at least one). ``entity_values``: lower-cased entity values (IPs, hosts,
    users, hashes, domains) of the canaries the case links, for dropping the
    IOCs that came from them out of a mixed case's export.
    """
    with unit_of_work(session) as s:
        if not canary_table_present(s):
            return {"only_canaries": False, "entity_values": set()}
        linked = [
            r[0]
            for r in s.execute(
                select(case_findings.c.finding_id).where(
                    case_findings.c.case_id == case_id
                )
            )
        ]
        if not linked:
            return {"only_canaries": False, "entity_values": set()}
        rows = s.execute(
            select(canary_injections.c.finding_id, canary_injections.c.payload).where(
                canary_injections.c.finding_id.in_(linked)
            )
        ).all()
    values: Set[str] = set()
    for _fid, payload in rows:
        alert = (payload or {}).get("alert") or {}
        _entity_values(alert.get("entity_context") or {}, values)
    canary_ids = {r[0] for r in rows}
    return {
        "only_canaries": bool(canary_ids) and set(linked) <= canary_ids,
        "entity_values": values,
    }
