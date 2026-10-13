"""A case's evidence, read once and in one shape (W3.7).

Two consumers:

* :func:`read_citable` builds the citable index the regulatory drafts (W3.8)
  cite: the case, its findings, its ``case_evidence`` rows, its
  ``case_audit_logs`` rows and its regulatory clock events, each with a stable
  id (``case:<id>``, ``finding:<id>``, ``evidence:<id>``, ``audit:<id>``,
  ``clock:<seq>``) and one ``digest`` over all of them.
* :func:`collect_case_record` reads everything the signed evidence pack
  (``core/compliance/evidence_bundle.py``) carries: the above plus the case's
  response actions with their full before/after state and verification, the
  agent ledger of the case's runs (with the hash chain, so it can be recomputed
  offline), AI verdict provenance and, when W1.10's ``audit_chain`` is
  installed, the chain rows of the case's audit and approval rows.

Read-only. Two optional neighbours are used only when present: the canary
exclusion of W1.5 (``core.storage.canary_exclusion``) drops canary findings,
and the audit chain of W1.10 (``core.audit.chain``) supplies the chain rows.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from sqlalchemy import bindparam
from sqlalchemy import inspect as sa_inspect
from sqlalchemy import or_, text
from sqlalchemy.orm import Session

from core.compliance.regulatory_service import ClockEvent

logger = logging.getLogger(__name__)

LINE_CHARS = 300


# -- the citable index (moved here from regulatory_drafts, unchanged) --------


@dataclass(frozen=True)
class EvidenceItem:
    id: str
    kind: str
    title: str
    at: Optional[str] = None
    detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "at": self.at,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class EvidencePack:
    case_id: str
    items: tuple

    @property
    def ids(self) -> frozenset:
        return frozenset(i.id for i in self.items)

    def of_kind(self, kind: str) -> List[EvidenceItem]:
        return [i for i in self.items if i.kind == kind]

    @property
    def digest(self) -> str:
        return citable_digest([i.to_dict() for i in self.items])


def citable_digest(items: List[Mapping[str, Any]]) -> str:
    """sha256 of the items in a fixed JSON form; the verifier recomputes it."""
    body = json.dumps(items, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _clip(value: Any, limit: int = LINE_CHARS) -> str:
    text_value = " ".join(str(value or "").split())
    return text_value if len(text_value) <= limit else text_value[: limit - 1] + "…"


def _at(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return str(value)


def _get(obj: Any, name: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


def build_evidence_pack(
    case: Any,
    findings: Iterable[Any] = (),
    evidence: Iterable[Any] = (),
    audits: Iterable[Any] = (),
    clock_events: Iterable[ClockEvent] = (),
) -> EvidencePack:
    """Everything a draft may cite, from rows the case already holds.

    Accepts ORM objects or dicts (``CaseSchema.dump`` output), so it reuses the
    existing case readers: ``Case.findings``, ``CaseEvidenceService.get_case_evidence``
    and ``case_records_service.list_case_audit``.
    """
    case_id = str(_get(case, "case_id"))
    items: List[EvidenceItem] = [
        EvidenceItem(
            id=f"case:{case_id}",
            kind="case",
            title=_clip(_get(case, "title")),
            at=_at(_get(case, "created_at")),
            detail=_clip(
                f"priority {_get(case, 'priority') or '—'}, status {_get(case, 'status') or '—'}. "
                f"{_get(case, 'description') or ''}"
            ),
        )
    ]
    for f in findings:
        fid = _get(f, "finding_id")
        if not fid:
            continue
        items.append(
            EvidenceItem(
                id=f"finding:{fid}",
                kind="finding",
                title=_clip(_get(f, "title") or _get(f, "description") or fid),
                at=_at(_get(f, "timestamp") or _get(f, "created_at")),
                detail=_clip(
                    f"severity {_get(f, 'severity') or '—'}, source {_get(f, 'data_source') or '—'}"
                ),
            )
        )
    for e in evidence:
        eid = _get(e, "evidence_id")
        if eid is None:
            continue
        sha = _get(e, "file_hash_sha256")
        items.append(
            EvidenceItem(
                id=f"evidence:{eid}",
                kind="evidence",
                title=_clip(_get(e, "name") or f"evidence {eid}"),
                at=_at(_get(e, "collected_at")),
                detail=_clip(
                    f"{_get(e, 'evidence_type') or 'evidence'} collected by "
                    f"{_get(e, 'collected_by') or '—'}"
                    + (f", sha256 {sha}" if sha else "")
                ),
            )
        )
    for a in audits:
        aid = _get(a, "audit_id")
        if aid is None:
            continue
        items.append(
            EvidenceItem(
                id=f"audit:{aid}",
                kind="audit",
                title=_clip(
                    _get(a, "change_summary")
                    or f"{_get(a, 'action')} {_get(a, 'field_name') or ''}".strip()
                ),
                at=_at(_get(a, "timestamp")),
                detail=_clip(f"by {_get(a, 'changed_by') or '—'}"),
            )
        )
    for ev in clock_events:
        items.append(
            EvidenceItem(
                id=f"clock:{ev.seq}",
                kind="clock",
                title=f"{ev.regime.upper()} {ev.instant} = {_at(ev.value) or 'cleared'}",
                at=_at(ev.recorded_at),
                detail=_clip(
                    f"recorded by {ev.actor}"
                    + (f"; reason: {ev.reason}" if ev.reason else "")
                ),
            )
        )
    return EvidencePack(case_id=case_id, items=tuple(items))


# -- optional neighbours ------------------------------------------------------


def _optional(module: str, name: str) -> Optional[Any]:
    """``module.name`` when that module is installed, else None (W1.5, W1.10)."""
    try:
        return getattr(importlib.import_module(module), name)
    except (ImportError, AttributeError):
        return None


def drop_canary_findings(
    session: Session, findings: List[Any]
) -> Tuple[List[Any], int, str]:
    """``findings`` without canaries, how many were dropped, and whether it ran.

    The status is ``applied`` when W1.5's exclusion helper is installed,
    ``unavailable`` when it is not (nothing can be a canary then).
    """
    drop: Optional[Callable[..., List[Any]]] = _optional(
        "core.storage.canary_exclusion", "drop_canaries"
    )
    if drop is None:
        return list(findings), 0, "unavailable"
    kept = list(drop(findings, session=session))
    return kept, len(findings) - len(kept), "applied"


# -- reading --------------------------------------------------------------------


def jsonable(value: Any) -> Any:
    """A JSON-safe copy: datetimes in UTC ISO 8601, Decimals as floats."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, datetime):
        return _at(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, Mapping):
        return {str(k): jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(v) for v in value]
    return str(value)


def row_dict(obj: Any) -> Dict[str, Any]:
    """Every mapped column of an ORM row, JSON-safe."""
    if isinstance(obj, Mapping):
        return jsonable(dict(obj))
    mapper = sa_inspect(obj).mapper
    return {attr.key: jsonable(getattr(obj, attr.key)) for attr in mapper.column_attrs}


def _case_row(session: Session, case_id: str) -> Any:
    from core.storage.models import Case

    return session.query(Case).filter(Case.case_id == case_id).first()


def _case_evidence(session: Session, case_id: str) -> List[Any]:
    from core.cases.case_evidence_service import CaseEvidenceService

    return list(CaseEvidenceService().get_case_evidence(case_id, session=session))


def _case_audits(session: Session, case_id: str) -> List[Any]:
    from core.cases import case_records_service

    return list(case_records_service.list_case_audit(session, case_id))


def read_citable(
    session: Session, case_id: str, clock_events: Iterable[ClockEvent] = ()
) -> Optional[EvidencePack]:
    """The citable index of ``case_id`` (what W3.8 drafts cite), or None."""
    case = _case_row(session, case_id)
    if case is None:
        return None
    findings, _, _ = drop_canary_findings(session, list(case.findings or []))
    return build_evidence_pack(
        case,
        findings=findings,
        evidence=_case_evidence(session, case_id),
        audits=_case_audits(session, case_id),
        clock_events=clock_events,
    )


@dataclass
class CaseRecord:
    """Everything the evidence pack carries for one case, as read."""

    case: Any
    findings: List[Any]
    evidence: List[Any]
    audits: List[Any]
    actions: List[Dict[str, Any]]
    ledger: List[Dict[str, Any]]
    ai: Dict[str, Any]
    clock_events: List[ClockEvent]
    clock_status: str
    audit_chain: Optional[List[Dict[str, Any]]]
    excluded_canaries: int = 0
    canary_exclusion: str = "unavailable"
    notes: List[str] = field(default_factory=list)

    @property
    def case_id(self) -> str:
        return str(self.case.case_id)

    def citable(self) -> EvidencePack:
        return build_evidence_pack(
            self.case,
            findings=self.findings,
            evidence=self.evidence,
            audits=self.audits,
            clock_events=self.clock_events,
        )


def _savepoint(session: Session, what: str, read: Callable[[], Any], notes: List[str]):
    """``read()`` inside a savepoint; None and a note when it fails.

    A missing optional table (an install without the ledger or the clock SQL)
    must not abort the request's transaction or the export.
    """
    try:
        with session.begin_nested():
            return read()
    except Exception as exc:  # noqa: BLE001 -- reported in the pack, not raised
        logger.warning("evidence pack: %s unavailable: %s", what, exc)
        notes.append(f"{what} unavailable: {type(exc).__name__}")
        return None


def _actions(session: Session, case_id: str) -> List[Dict[str, Any]]:
    """The case's response actions, with full before/after state."""
    from core.response.action_timeline import case_action_timeline
    from core.storage.models import ApprovalAction

    timeline = case_action_timeline(session, case_id)
    items = list(timeline.get("actions") or [])
    ids = [item["action_id"] for item in items]
    raw: Dict[str, Any] = {}
    if ids:
        for row in session.query(ApprovalAction).filter(
            ApprovalAction.action_id.in_(ids)
        ):
            raw[row.action_id] = row
    out = []
    for item in items:
        row = raw.get(item["action_id"])
        entry = dict(jsonable(item))
        if row is not None:
            entry["before_state"] = jsonable(row.before_state)
            entry["after_state"] = jsonable(row.after_state)
            entry["execution_result"] = jsonable(row.execution_result)
            entry["parameters"] = jsonable(row.parameters)
            entry["evidence"] = jsonable(row.evidence)
            entry["description"] = row.description
            entry["reason_full"] = row.reason
        out.append(entry)
    if timeline.get("truncated"):
        out.append({"truncated": True})
    return out


def _run_ids(session: Session, case_id: str) -> Tuple[List[str], List[Any], List[Any]]:
    from core.agents.projections import run_id_for
    from core.cases import case_records_service

    investigations = case_records_service.list_case_investigations(session, case_id)
    runs = case_records_service.list_case_runs(session, case_id)
    ids: List[str] = []
    for inv in investigations:
        ids.append(run_id_for(inv.investigation_id))
    for run in runs:
        try:
            ids.append(str(uuid.UUID(str(run.run_id))))
        except ValueError:
            continue
    seen = set()
    ordered = [i for i in ids if not (i in seen or seen.add(i))]
    return ordered, investigations, runs


_LEDGER_SQL = text(
    "SELECT seq, ts, run_kind, kind, prev_hash, event_hash, "
    "CAST(payload AS text) AS payload_text "
    "FROM agent_events WHERE run_id = CAST(:run_id AS uuid) ORDER BY seq"
)


def _ledger(session: Session, run_ids: List[str], notes: List[str]) -> List[Dict]:
    """Each run's events, whole, with the stored hashes and the hashed text.

    ``payload_text`` is ``CAST(payload AS text)``, the exact text the INSERT
    trigger hashed (31_agent_ledger_hash_chain.sql), so the chain can be
    recomputed from the pack alone.
    """
    out: List[Dict[str, Any]] = []
    for run_id in run_ids:
        rows = _savepoint(
            session,
            f"ledger run {run_id}",
            lambda r=run_id: session.execute(_LEDGER_SQL, {"run_id": r}).all(),
            notes,
        )
        if rows is None:
            out.append({"run_id": run_id, "status": "unavailable", "events": []})
            continue
        out.append(
            {
                "run_id": run_id,
                "status": "read" if rows else "not_found",
                "events": [
                    {
                        "seq": int(r.seq),
                        "ts": _at(r.ts),
                        "run_kind": r.run_kind,
                        "kind": r.kind,
                        "prev_hash": r.prev_hash,
                        "event_hash": r.event_hash,
                        "payload_text": r.payload_text,
                    }
                    for r in rows
                ],
            }
        )
    return out


def _ai_provenance(
    session: Session,
    case_id: str,
    findings: List[Any],
    investigations: List[Any],
    runs: List[Any],
) -> Dict[str, Any]:
    from core.storage.models import AIDecisionLog

    finding_ids = [f.finding_id for f in findings]
    verdicts = []
    for f in findings:
        enrichment = f.ai_enrichment if isinstance(f.ai_enrichment, dict) else {}
        verdicts.append(
            {
                "finding_id": f.finding_id,
                "ai_triage": jsonable(enrichment.get("ai_triage")),
                "ai_triage_error": jsonable(enrichment.get("ai_triage_error")),
            }
        )
    cond = AIDecisionLog.case_id == case_id
    if finding_ids:
        cond = or_(cond, AIDecisionLog.finding_id.in_(finding_ids))
    decisions = (
        session.query(AIDecisionLog)
        .filter(cond)
        .order_by(AIDecisionLog.timestamp, AIDecisionLog.id)
        .all()
    )
    return {
        "finding_verdicts": verdicts,
        "decisions": [row_dict(d) for d in decisions],
        "investigations": [row_dict(i) for i in investigations],
        "workflow_runs": [row_dict(r) for r in runs],
    }


def _clock_events(
    session: Session, case_id: str, notes: List[str]
) -> Tuple[List[ClockEvent], str]:
    from core.compliance.regulatory_service import SqlClockStore

    events = _savepoint(
        session,
        "regulatory clock events",
        lambda: SqlClockStore(session).events(case_id),
        notes,
    )
    if events is None:
        return [], "unavailable"
    return list(events), "read"


def _audit_chain(
    session: Session,
    audit_ids: List[Any],
    action_ids: List[str],
    notes: List[str],
) -> Optional[List[Dict[str, Any]]]:
    """W1.10's chain rows for these audit and approval rows, or None if absent."""
    canonical = _optional("core.audit.chain", "CANONICAL_SQL")
    if canonical is None:
        return None
    present = session.execute(text("SELECT to_regclass('audit_chain')")).scalar()
    if present is None:
        return None
    keys = [str(a) for a in audit_ids]
    sql = text(
        "SELECT seq, source_table, source_id, event, prev_hash, event_hash, "
        f"{canonical} AS canonical FROM audit_chain "
        "WHERE (source_table = 'case_audit_logs' AND source_id IN :audits) "
        "OR (source_table = 'approval_actions' AND source_id IN :actions) "
        "ORDER BY seq"
    ).bindparams(
        bindparam("audits", expanding=True), bindparam("actions", expanding=True)
    )
    rows = _savepoint(
        session,
        "audit chain",
        lambda: session.execute(
            sql, {"audits": keys or [""], "actions": action_ids or [""]}
        ).all(),
        notes,
    )
    if rows is None:
        return None
    return [
        {
            "seq": int(r.seq),
            "source_table": r.source_table,
            "source_id": r.source_id,
            "event": r.event,
            "prev_hash": r.prev_hash,
            "event_hash": r.event_hash,
            "canonical": r.canonical,
        }
        for r in rows
    ]


def collect_case_record(session: Session, case_id: str) -> Optional[CaseRecord]:
    """Read everything the evidence pack carries for ``case_id``; None if absent."""
    case = _case_row(session, case_id)
    if case is None:
        return None
    notes: List[str] = []
    findings, excluded, canary_status = drop_canary_findings(
        session, list(case.findings or [])
    )
    # Same readers, same order as read_citable: the pack's citable digest is
    # then the pack_digest of a draft generated from the same rows.
    evidence = _case_evidence(session, case_id)
    audits = _case_audits(session, case_id)
    actions = _actions(session, case_id)
    run_ids, investigations, runs = _run_ids(session, case_id)
    ledger = _ledger(session, run_ids, notes)
    ai = _ai_provenance(session, case_id, findings, investigations, runs)
    clock_events, clock_status = _clock_events(session, case_id, notes)
    chain = _audit_chain(
        session,
        [a.audit_id for a in audits],
        [a["action_id"] for a in actions if "action_id" in a],
        notes,
    )
    return CaseRecord(
        case=case,
        findings=findings,
        evidence=evidence,
        audits=audits,
        actions=actions,
        ledger=ledger,
        ai=ai,
        clock_events=clock_events,
        clock_status=clock_status,
        audit_chain=chain,
        excluded_canaries=excluded,
        canary_exclusion=canary_status,
        notes=notes,
    )
