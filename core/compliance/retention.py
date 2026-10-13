"""Data retention and periodic destruction (KVKK "periyodik imha").

Each data class has a policy row in ``retention_policies`` (tenant ``default``):
how many days it is kept and whether the whole class is under legal hold. The
destruction method per class (``delete`` or ``anonymise``) and the per-case
legal holds live in ``system_config`` (``retention.methods``,
``retention.legal_holds``) so this needs no schema change.

A purge run walks every class that has a policy, in batches, each batch its own
transaction. A class with no policy is never touched. Rows tied to a case under
legal hold, or to a case that is still open, are skipped in every class. A real
run writes one ``config_audit_log`` row (``config_type='retention'``,
``action='purge'``) carrying the counts, the policy each class ran under and
the actor; a dry run changes nothing at all, not even the audit log. The
periodic destruction report is built from those audit rows.

Hash-chained tables are never written here. ``agent_events`` (the agent
ledger) is the ``agent_ledger`` class: the purge reports it as excluded and how
many whole runs are past the retention period, and
:func:`export_agent_ledger_archive` hands out a chain-verified archive of them.
Removing archived runs is a documented manual step for the database owner
(``RETENTION.md``); ``vigil_app`` cannot DELETE from that table anyway. The
W1.10 ``audit_chain`` and ``audit_checkpoints`` tables are likewise read-only
for this module and not a data class at all.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.storage.models import ConfigAuditLog, SystemConfig
from core.time import utcnow

logger = logging.getLogger(__name__)

TENANT = "default"
AUDIT_CONFIG_TYPE = "retention"
METHODS_KEY = "retention.methods"
HOLDS_KEY = "retention.legal_holds"
ANON = "[anonymised]"
ANON_TAG = "retention-anonymised"
CLOSED_CASE_STATUSES = ("resolved", "closed")
SYSTEM_ACTOR = "system"
# config_audit_log.action is VARCHAR(20); every action written here must fit.
LEDGER_ARCHIVE_ACTION = "ledger_archive_exp"
AUDIT_ACTIONS = (
    "purge",
    "policy_set",
    "policy_delete",
    "legal_hold_set",
    "legal_hold_release",
    LEDGER_ARCHIVE_ACTION,
)

DELETE = "delete"
ANONYMISE = "anonymise"
METHODS = (DELETE, ANONYMISE)

# Append-only, hash-chained tables. Nothing in this module writes to them; the
# W3.5 spec's AC6 greps this file to keep it that way.
CHAINED_TABLES = ("agent_events", "audit_chain", "audit_checkpoints")

# pg_advisory_lock key for "a purge is running" (arbitrary, fixed).
_RUN_LOCK_KEY = 0x5245_5445_4E54  # "RETENT"
# Transaction-level advisory lock guarding "what is protected". Every purge
# batch takes it shared and then reads the legal holds and its policy in the
# same transaction; set_legal_hold / set_policy / delete_policy take it
# exclusive. So a hold committed before a batch starts is always seen by it, and
# a hold being set waits at most for the batch in flight, never a whole run.
_HOLD_LOCK_KEY = 0x5245_5445_484C  # "RETEHL"

# Tables a DELETE of a findings / cases row cascades into (ON DELETE CASCADE),
# and the column on each that ties the child row to a case, or None. A finding
# or case is only deleted when none of these ties reach a held or open case
# (cases also keep regulatory records, see _cases_select). A cascading child
# not listed here makes the class refuse to delete (status "error"), so a new
# FK cannot silently widen what a purge destroys.
FINDING_CASCADE_CHILDREN: Dict[str, Optional[str]] = {
    "case_findings": "case_id",
    "ai_decision_logs": "case_id",
    "sketch_mappings": "case_id",
    "finding_mitre_predictions": None,
}
CASE_CASCADE_CHILDREN = frozenset(
    {
        "ai_decision_logs",
        "case_attachments",
        "case_closure_info",
        "case_comments",
        "case_escalations",
        "case_evidence",
        "case_findings",
        "case_iocs",
        "case_metrics",
        "case_notifications",
        "case_relationships",
        "case_slas",
        "case_tasks",
        "case_watchers",
        "sketch_mappings",
        # W3.8 regulatory records: cases that have any are never deleted here.
        "regulatory_clock_events",
        "regulatory_report_drafts",
    }
)
REGULATORY_TABLES = ("regulatory_clock_events", "regulatory_report_drafts")

MAX_BATCH_SIZE = 10_000
MAX_BATCHES = 1_000


class RetentionError(ValueError):
    """A request the retention layer refuses (unknown class, bad method...)."""


class RetentionBusy(RuntimeError):
    """Another purge run holds the run lock."""


# --- data classes ------------------------------------------------------------


@dataclass(frozen=True)
class DataClass:
    """One class of data a policy can name."""

    name: str
    label: str  # Turkish, for the destruction report
    tables: Tuple[str, ...]
    methods: Tuple[str, ...]
    default_method: str
    age_column: str
    chained: bool = False
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "data_class": self.name,
            "label": self.label,
            "tables": list(self.tables),
            "methods": list(self.methods),
            "default_method": self.default_method,
            "age_column": self.age_column,
            "chained": self.chained,
            "note": self.note,
        }


DATA_CLASSES: Dict[str, DataClass] = {
    c.name: c
    for c in (
        DataClass(
            "findings",
            "Bulgular",
            ("findings",),
            METHODS,
            DELETE,
            "findings.created_at",
            note="Açık veya yasal saklamadaki bir vakaya bağlı bulgular atlanır.",
        ),
        DataClass(
            "raw_events",
            "Ham olaylar (bulgulara gömülü kaynak kaydı)",
            ("findings.entity_context.source_evidence",),
            (DELETE,),
            DELETE,
            "findings.created_at",
            note="Bulgu satırı kalır; yalnızca ham kaynak kaydı çıkarılır.",
        ),
        DataClass(
            "cases",
            "Vakalar",
            ("cases", "case_comments"),
            METHODS,
            DELETE,
            "cases.updated_at",
            note="Yalnızca resolved/closed vakalar; silme kanıt dosyalarını da siler.",
        ),
        DataClass(
            "case_evidence",
            "Vaka kanıtları ve ekleri",
            ("case_evidence", "case_attachments"),
            METHODS,
            DELETE,
            "created_at",
            note="Anonimleştirme dosyayı siler, özetleri (hash, gözetim zinciri) tutar.",
        ),
        DataClass(
            "chat_conversations",
            "Sohbet geçmişi",
            ("conversations", "chat_messages"),
            METHODS,
            DELETE,
            "coalesce(last_message_at, updated_at)",
        ),
        DataClass(
            "llm_logs",
            "LLM istem/yanıt kayıtları",
            ("llm_interaction_logs",),
            METHODS,
            DELETE,
            "created_at",
            note="Anonimleştirme içerikleri siler, token/maliyet sayılarını tutar.",
        ),
        DataClass(
            "agent_ledger",
            "Ajan defteri (hash zincirli)",
            ("agent_events",),
            (),
            "archive",
            "max(ts) per run",
            chained=True,
            note="Otomatik imha edilmez: arşivle-sonra-kes prosedürü (RETENTION.md).",
        ),
        DataClass(
            "audit_logs",
            "Denetim kayıtları",
            ("case_audit_logs", "config_audit_log"),
            METHODS,
            DELETE,
            "timestamp",
            note="İmha tutanağı kayıtları (config_type='retention') hiç işlenmez.",
        ),
        DataClass(
            "uploads",
            "Yüklenen dosyalar (öksüz kanıt deposu dosyaları)",
            ("<evidence store>",),
            (DELETE,),
            DELETE,
            "file mtime",
            note="Hiçbir kanıt/ek satırının göstermediği dosyalar.",
        ),
    )
}


def get_data_class(name: str) -> DataClass:
    try:
        return DATA_CLASSES[name]
    except KeyError:
        raise RetentionError(f"unknown data class: {name}") from None


# --- audit -------------------------------------------------------------------


def _audit(
    session: Session,
    action: str,
    key: str,
    actor: str,
    *,
    old: Optional[dict] = None,
    new: Optional[dict] = None,
    reason: Optional[str] = None,
) -> None:
    if action not in AUDIT_ACTIONS or len(action) > 20:
        raise ValueError(f"not a retention audit action: {action}")
    session.add(
        ConfigAuditLog(
            config_type=AUDIT_CONFIG_TYPE,
            config_key=key[:200],
            action=action,
            old_value=old,
            new_value=new,
            changed_by=(actor or SYSTEM_ACTOR)[:100],
            change_reason=reason,
        )
    )


# --- policies, methods, holds ------------------------------------------------


def _config_value(session: Session, key: str, *, lock: bool = False) -> dict:
    query = session.query(SystemConfig).filter(SystemConfig.key == key)
    if lock:
        query = query.with_for_update()
    row = query.first()
    return dict(row.value) if row and isinstance(row.value, dict) else {}


def _set_config_value(
    session: Session, key: str, value: dict, actor: str, description: str
) -> None:
    row = session.query(SystemConfig).filter(SystemConfig.key == key).first()
    if row is None:
        session.add(
            SystemConfig(
                key=key,
                value=value,
                description=description,
                config_type=AUDIT_CONFIG_TYPE,
                updated_by=actor,
            )
        )
    else:
        row.value = value  # a new dict, so the JSONB column is marked dirty
        row.updated_by = actor
    session.flush()


def get_methods(session: Session) -> Dict[str, str]:
    """Method per data class: the stored choice, else the class default."""
    stored = _config_value(session, METHODS_KEY)
    out = {}
    for name, dc in DATA_CLASSES.items():
        method = stored.get(name)
        out[name] = method if method in dc.methods else dc.default_method
    return out


def list_policies(session: Session) -> List[Dict[str, Any]]:
    """Every policy row for the tenant, with the method that would apply."""
    methods = get_methods(session)
    rows = session.execute(
        text(
            "SELECT data_class, retain_days, legal_hold, updated_by, updated_at "
            "FROM retention_policies WHERE tenant_id = :t ORDER BY data_class"
        ),
        {"t": TENANT},
    ).mappings()
    out = []
    for row in rows:
        known = row["data_class"] in DATA_CLASSES
        out.append(
            {
                "data_class": row["data_class"],
                "retain_days": row["retain_days"],
                "legal_hold": row["legal_hold"],
                "method": methods.get(row["data_class"]),
                "known": known,
                "updated_by": row["updated_by"],
                "updated_at": _iso(row["updated_at"]),
            }
        )
    return out


def set_policy(
    session: Session,
    data_class: str,
    *,
    retain_days: int,
    method: Optional[str],
    legal_hold: bool,
    actor: str,
) -> Dict[str, Any]:
    """Create or replace one class's policy, and record the change."""
    dc = get_data_class(data_class)
    _lock_holds(session, exclusive=True)
    if not isinstance(retain_days, int) or retain_days <= 0:
        raise RetentionError("retain_days must be a positive integer")
    if dc.chained:
        if method not in (None, dc.default_method):
            raise RetentionError(
                f"{data_class} is hash-chained: it is archived, never purged"
            )
    elif method is not None and method not in dc.methods:
        raise RetentionError(
            f"{data_class} supports {', '.join(dc.methods)}, not {method}"
        )
    old = _policy_row(session, data_class)
    session.execute(
        text(
            "INSERT INTO retention_policies "
            "(tenant_id, data_class, retain_days, legal_hold, updated_by, updated_at) "
            "VALUES (:t, :c, :d, :h, :by, now()) "
            "ON CONFLICT (tenant_id, data_class) DO UPDATE SET "
            "retain_days = EXCLUDED.retain_days, legal_hold = EXCLUDED.legal_hold, "
            "updated_by = EXCLUDED.updated_by, updated_at = now()"
        ),
        {"t": TENANT, "c": data_class, "d": retain_days, "h": legal_hold, "by": actor},
    )
    old_method = get_methods(session)[data_class]
    if method is not None and not dc.chained:
        methods = _config_value(session, METHODS_KEY, lock=True)
        methods[data_class] = method
        _set_config_value(
            session, METHODS_KEY, methods, actor, "Retention method per data class"
        )
    new = {
        "retain_days": retain_days,
        "legal_hold": legal_hold,
        "method": get_methods(session)[data_class],
    }
    old_value = dict(old, method=old_method) if old else None
    _audit(session, "policy_set", f"policy:{data_class}", actor, old=old_value, new=new)
    return dict(new, data_class=data_class)


def delete_policy(session: Session, data_class: str, *, actor: str) -> bool:
    """Remove a policy: the class is then never purged."""
    _lock_holds(session, exclusive=True)
    old = _policy_row(session, data_class)
    if old is None:
        return False
    session.execute(
        text("DELETE FROM retention_policies WHERE tenant_id = :t AND data_class = :c"),
        {"t": TENANT, "c": data_class},
    )
    _audit(session, "policy_delete", f"policy:{data_class}", actor, old=old)
    return True


def _policy_row(session: Session, data_class: str) -> Optional[Dict[str, Any]]:
    row = (
        session.execute(
            text(
                "SELECT retain_days, legal_hold FROM retention_policies "
                "WHERE tenant_id = :t AND data_class = :c"
            ),
            {"t": TENANT, "c": data_class},
        )
        .mappings()
        .first()
    )
    return dict(row) if row else None


def _lock_holds(session: Session, *, exclusive: bool) -> None:
    """Take the transaction-level hold lock (see ``_HOLD_LOCK_KEY``)."""
    fn = "pg_advisory_xact_lock" if exclusive else "pg_advisory_xact_lock_shared"
    session.execute(text(f"SELECT {fn}(:k)"), {"k": _HOLD_LOCK_KEY})


def list_legal_holds(session: Session) -> Dict[str, Dict[str, Any]]:
    """Case id -> {reason, set_by, set_at} for every case under legal hold."""
    cases = _config_value(session, HOLDS_KEY).get("cases") or {}
    return {k: dict(v) for k, v in cases.items() if isinstance(v, dict)}


def held_case_ids(session: Session) -> List[str]:
    return sorted(list_legal_holds(session))


def set_legal_hold(
    session: Session, case_id: str, *, reason: str, actor: str
) -> Dict[str, Any]:
    """Put a case (and what hangs off it) under legal hold.

    Takes the hold lock exclusive first, so it waits for a purge batch in
    flight and every later batch sees the hold.
    """
    _lock_holds(session, exclusive=True)
    exists = session.execute(
        text("SELECT 1 FROM cases WHERE case_id = :c"), {"c": case_id}
    ).first()
    if not exists:
        raise LookupError(case_id)
    value = _config_value(session, HOLDS_KEY, lock=True)
    cases = dict(value.get("cases") or {})
    hold = {"reason": reason, "set_by": actor, "set_at": _iso(utcnow())}
    previous = cases.get(case_id)
    cases[case_id] = hold
    _set_config_value(
        session, HOLDS_KEY, {**value, "cases": cases}, actor, "Legal holds"
    )
    _audit(
        session,
        "legal_hold_set",
        f"legal_hold:case:{case_id}",
        actor,
        old=previous,
        new=hold,
        reason=reason,
    )
    return dict(hold, case_id=case_id)


def release_legal_hold(
    session: Session, case_id: str, *, actor: str, reason: Optional[str] = None
) -> bool:
    value = _config_value(session, HOLDS_KEY, lock=True)
    cases = dict(value.get("cases") or {})
    previous = cases.pop(case_id, None)
    if previous is None:
        return False
    _set_config_value(
        session, HOLDS_KEY, {**value, "cases": cases}, actor, "Legal holds"
    )
    _audit(
        session,
        "legal_hold_release",
        f"legal_hold:case:{case_id}",
        actor,
        old=previous,
        reason=reason,
    )
    return True


# --- per-class batch handlers ------------------------------------------------
#
# select(session, ctx, method, limit, lock) -> ids eligible now, oldest first.
# apply(session, ctx, method, ids) -> files to unlink once the batch commits.
# Every select excludes rows tied to a held case, and rows already anonymised
# when the method is anonymise, so a run always makes progress.

_HELD = "CAST(:held AS text[])"
_SKIP = " FOR UPDATE SKIP LOCKED"

_OPEN = "c.status NOT IN ('resolved', 'closed')"


def _case_id_protected(col: str) -> str:
    """SQL: the case named by ``col`` is held, or exists and is still open.

    ``col`` may name a case that no longer exists (conversations, audit rows
    carry a bare id): then only a hold protects it. The subquery's own alias
    (``pc``) keeps it from capturing an outer ``c``.
    """
    return (
        f"({col} = ANY({_HELD}) OR EXISTS (SELECT 1 FROM cases pc "
        f"WHERE pc.case_id = {col} "
        "AND pc.status NOT IN ('resolved', 'closed')))"
    )


# A finding is protected while any case tied to it -- through case_findings or
# through a row a DELETE of the finding would cascade into -- is held or open.
_FINDING_PROTECTED = (
    "EXISTS (SELECT 1 FROM ("
    + " UNION ALL ".join(
        f"SELECT k.{col} AS case_id FROM {table} k WHERE k.finding_id = f.finding_id"
        for table, col in FINDING_CASCADE_CHILDREN.items()
        if col
    )
    + ") linked WHERE "
    + _case_id_protected("linked.case_id")
    + ")"
)
# Rows owned by a case: protected while that case is held or still open.
_CASE_PROTECTED = "(c.case_id = ANY(" + _HELD + ") OR " + _OPEN + ")"


@dataclass
class _Ctx:
    cutoff: datetime
    now: datetime
    held: List[str]
    evidence_root: Optional[Path]

    def params(self, **extra: Any) -> Dict[str, Any]:
        return {"cutoff": self.cutoff, "held": self.held, "anon": ANON, **extra}


def _ids(session: Session, sql: str, ctx: _Ctx, limit: int, lock: bool) -> List:
    sql = sql + " LIMIT :limit" + (_SKIP if lock else "")
    return [r[0] for r in session.execute(text(sql), ctx.params(limit=limit))]


def _findings_select(session, ctx, method, limit, lock):
    sql = (
        "SELECT f.finding_id FROM findings f WHERE f.created_at < :cutoff "
        "AND NOT " + _FINDING_PROTECTED
    )
    if method == ANONYMISE:
        sql += (
            " AND (f.entity_context IS NULL "
            "OR NOT (f.entity_context ? 'retention_anonymised_at'))"
        )
    sql += " ORDER BY f.created_at, f.finding_id"
    return _ids(session, sql, ctx, limit, lock)


def _findings_apply(session, ctx, method, ids):
    if method == DELETE:
        session.execute(
            text("DELETE FROM findings WHERE finding_id = ANY(CAST(:ids AS text[]))"),
            {"ids": ids},
        )
    else:
        # ai_enrichment stays non-NULL so the unrated sweep does not re-triage it.
        session.execute(
            text(
                "UPDATE findings SET title = :anon, description = NULL, "
                "evidence_links = NULL, external_id = NULL, "
                "ai_enrichment = jsonb_build_object('retention_anonymised', true), "
                "entity_context = jsonb_build_object("
                "'retention_anonymised_at', CAST(:at AS text)), "
                "updated_at = :now "
                "WHERE finding_id = ANY(CAST(:ids AS text[]))"
            ),
            {"anon": ANON, "at": _iso(ctx.now), "now": ctx.now, "ids": ids},
        )
    return []


def _raw_select(session, ctx, method, limit, lock):
    sql = (
        "SELECT f.finding_id FROM findings f WHERE f.created_at < :cutoff "
        "AND f.entity_context ? 'source_evidence' AND NOT "
        + _FINDING_PROTECTED
        + " ORDER BY f.created_at, f.finding_id"
    )
    return _ids(session, sql, ctx, limit, lock)


def _raw_apply(session, ctx, method, ids):
    session.execute(
        text(
            "UPDATE findings SET entity_context = entity_context - 'source_evidence' "
            "WHERE finding_id = ANY(CAST(:ids AS text[]))"
        ),
        {"ids": ids},
    )
    return []


def _cases_select(session, ctx, method, limit, lock):
    sql = (
        "SELECT c.case_id FROM cases c WHERE c.updated_at < :cutoff "
        "AND c.status IN ('resolved', 'closed') "
        "AND NOT (c.case_id = ANY(" + _HELD + "))"
    )
    if method == ANONYMISE:
        sql += (
            " AND NOT (CAST(:tag AS varchar) = ANY("
            "coalesce(c.tags, CAST(ARRAY[] AS varchar[]))))"
        )
    else:
        # A case's DELETE cascades into case_relationships rows on both ends:
        # keep it while the case on the other end is held or open.
        sql += (
            " AND NOT EXISTS (SELECT 1 FROM case_relationships r "
            "WHERE (r.case_id = c.case_id OR r.related_case_id = c.case_id) AND "
            + _case_id_protected(
                "CASE WHEN r.case_id = c.case_id "
                "THEN r.related_case_id ELSE r.case_id END"
            )
            + ")"
        )
        # DORA/NIS2 clock history and report drafts are regulatory records
        # that would cascade away with the case: such cases are never deleted
        # by a purge (anonymising leaves those rows alone).
        for table in REGULATORY_TABLES:
            if _table_exists(session, table):
                sql += (
                    f" AND NOT EXISTS (SELECT 1 FROM {table} rg "
                    "WHERE rg.case_id = c.case_id)"
                )
    sql += " ORDER BY c.updated_at, c.case_id LIMIT :limit" + (_SKIP if lock else "")
    return [
        r[0] for r in session.execute(text(sql), ctx.params(limit=limit, tag=ANON_TAG))
    ]


def _case_files(session, case_ids) -> List[str]:
    rows = session.execute(
        text(
            "SELECT file_path FROM case_evidence "
            "WHERE case_id = ANY(CAST(:ids AS text[])) AND file_path IS NOT NULL "
            "UNION ALL SELECT file_path FROM case_attachments "
            "WHERE case_id = ANY(CAST(:ids AS text[])) AND file_path <> ''"
        ),
        {"ids": case_ids},
    )
    return [r[0] for r in rows if r[0]]


def _cases_apply(session, ctx, method, ids):
    if method == DELETE:
        files = _case_files(session, ids)
        # Evidence, attachments, comments, closure info... cascade at the FK.
        session.execute(
            text("DELETE FROM cases WHERE case_id = ANY(CAST(:ids AS text[]))"),
            {"ids": ids},
        )
        return files
    session.execute(
        text(
            "UPDATE cases SET title = :anon, description = '', assignee = NULL, "
            "notes = CAST('[]' AS jsonb), timeline = CAST('[]' AS jsonb), "
            "activities = CAST('[]' AS jsonb), "
            "resolution_steps = CAST('[]' AS jsonb), "
            "tags = ARRAY[CAST(:tag AS varchar)], updated_at = :now "
            "WHERE case_id = ANY(CAST(:ids AS text[]))"
        ),
        {"anon": ANON, "tag": ANON_TAG, "now": ctx.now, "ids": ids},
    )
    session.execute(
        text(
            "UPDATE case_comments SET content = :anon, author = :anon, "
            "mentions = NULL WHERE case_id = ANY(CAST(:ids AS text[]))"
        ),
        {"anon": ANON, "ids": ids},
    )
    return []


def _evidence_select(session, ctx, method, limit, lock):
    """``("e", id)`` from case_evidence first, then ``("a", id)`` attachments."""
    out: List[Tuple[str, int]] = []
    marker = (
        " AND NOT (CAST(:tag AS varchar) = ANY("
        "coalesce({t}.tags, CAST(ARRAY[] AS varchar[]))))"
        if method == ANONYMISE
        else ""
    )
    for kind, table, pk, alias in (
        ("e", "case_evidence", "evidence_id", "e"),
        ("a", "case_attachments", "attachment_id", "a"),
    ):
        room = limit - len(out)
        if room <= 0:
            break
        sql = (
            f"SELECT {alias}.{pk} FROM {table} {alias} "
            f"JOIN cases c ON c.case_id = {alias}.case_id "
            f"WHERE {alias}.created_at < :cutoff AND NOT {_CASE_PROTECTED}"
            + marker.format(t=alias)
            + f" ORDER BY {alias}.created_at, {alias}.{pk} LIMIT :limit"
            + (f" FOR UPDATE OF {alias} SKIP LOCKED" if lock else "")
        )
        rows = session.execute(text(sql), ctx.params(limit=room, tag=ANON_TAG))
        out.extend((kind, r[0]) for r in rows)
    return out


def _evidence_apply(session, ctx, method, ids):
    evidence = [i for k, i in ids if k == "e"]
    attachments = [i for k, i in ids if k == "a"]
    files = [
        r[0]
        for r in session.execute(
            text(
                "SELECT file_path FROM case_evidence "
                "WHERE evidence_id = ANY(CAST(:e AS int[])) AND file_path IS NOT NULL "
                "UNION ALL SELECT file_path FROM case_attachments "
                "WHERE attachment_id = ANY(CAST(:a AS int[])) AND file_path <> ''"
            ),
            {"e": evidence, "a": attachments},
        )
        if r[0]
    ]
    if method == DELETE:
        session.execute(
            text(
                "DELETE FROM case_evidence WHERE evidence_id = ANY(CAST(:e AS int[]))"
            ),
            {"e": evidence},
        )
        session.execute(
            text(
                "DELETE FROM case_attachments "
                "WHERE attachment_id = ANY(CAST(:a AS int[]))"
            ),
            {"a": attachments},
        )
        return files
    custody = json.dumps(
        [{"action": "retention_anonymised", "at": _iso(ctx.now), "by": SYSTEM_ACTOR}]
    )
    # Hashes and custody stay: they prove what existed without holding it.
    session.execute(
        text(
            "UPDATE case_evidence SET name = :anon, description = NULL, "
            "file_path = NULL, analysis_results = NULL, source = NULL, "
            "collected_by = :anon, tags = ARRAY[CAST(:tag AS varchar)], "
            "chain_of_custody = coalesce(chain_of_custody, CAST('[]' AS jsonb)) "
            "|| CAST(:custody AS jsonb), updated_at = :now "
            "WHERE evidence_id = ANY(CAST(:e AS int[]))"
        ),
        {
            "anon": ANON,
            "tag": ANON_TAG,
            "custody": custody,
            "now": ctx.now,
            "e": evidence,
        },
    )
    session.execute(
        text(
            "UPDATE case_attachments SET filename = :anon, file_path = '', "
            "description = NULL, uploaded_by = :anon, scan_details = NULL, "
            "tags = ARRAY[CAST(:tag AS varchar)] "
            "WHERE attachment_id = ANY(CAST(:a AS int[]))"
        ),
        {"anon": ANON, "tag": ANON_TAG, "a": attachments},
    )
    return files


def _chat_select(session, ctx, method, limit, lock):
    sql = (
        "SELECT cv.id FROM conversations cv "
        "WHERE coalesce(cv.last_message_at, cv.updated_at) < :cutoff "
        "AND (cv.case_id IS NULL OR NOT " + _case_id_protected("cv.case_id") + ")"
    )
    if method == ANONYMISE:
        sql += " AND cv.title IS DISTINCT FROM :anon"
    sql += " ORDER BY coalesce(cv.last_message_at, cv.updated_at), cv.id"
    return _ids(session, sql, ctx, limit, lock)


def _chat_apply(session, ctx, method, ids):
    if method == DELETE:
        session.execute(
            text(
                "DELETE FROM chat_messages WHERE conversation_id = ANY(CAST(:ids AS text[]))"
            ),
            {"ids": ids},
        )
        session.execute(
            text("DELETE FROM conversations WHERE id = ANY(CAST(:ids AS text[]))"),
            {"ids": ids},
        )
        return []
    session.execute(
        text(
            "UPDATE chat_messages SET content = :anon, thinking = NULL, "
            "tool_calls = CAST('[]' AS jsonb) WHERE conversation_id = ANY(CAST(:ids AS text[]))"
        ),
        {"anon": ANON, "ids": ids},
    )
    session.execute(
        text(
            "UPDATE conversations SET title = :anon, user_id = NULL, "
            "page_context = NULL, updated_at = :now "
            "WHERE id = ANY(CAST(:ids AS text[]))"
        ),
        {"anon": ANON, "now": ctx.now, "ids": ids},
    )
    return []


def _llm_select(session, ctx, method, limit, lock):
    sql = (
        "SELECT l.id FROM llm_interaction_logs l WHERE l.created_at < :cutoff "
        # Agent investigations of a held or open case...
        "AND NOT EXISTS (SELECT 1 FROM investigations i "
        "WHERE i.investigation_id = l.investigation_id AND i.case_id IS NOT NULL "
        "AND " + _case_id_protected("i.case_id") + ") "
        # ...and chat turns: session_id is the conversation id.
        "AND NOT EXISTS (SELECT 1 FROM conversations cv "
        "WHERE cv.id = l.session_id AND cv.case_id IS NOT NULL "
        "AND " + _case_id_protected("cv.case_id") + ")"
    )
    if method == ANONYMISE:
        sql += " AND l.response_content IS DISTINCT FROM :anon"
    sql += " ORDER BY l.created_at, l.id"
    return _ids(session, sql, ctx, limit, lock)


def _llm_apply(session, ctx, method, ids):
    if method == DELETE:
        session.execute(
            text(
                "DELETE FROM llm_interaction_logs WHERE id = ANY(CAST(:ids AS int[]))"
            ),
            {"ids": ids},
        )
        return []
    # Token counts and cost stay: they are billing, not personal data.
    session.execute(
        text(
            "UPDATE llm_interaction_logs SET request_messages = CAST('[]' AS jsonb), "
            "system_prompt = NULL, thinking_content = NULL, response_content = :anon, "
            "tool_calls = CAST('[]' AS jsonb), tool_results = CAST('[]' AS jsonb), "
            "error = NULL WHERE id = ANY(CAST(:ids AS int[]))"
        ),
        {"anon": ANON, "ids": ids},
    )
    return []


def _audit_select(session, ctx, method, limit, lock):
    """``("c", id)`` case_audit_logs, then ``("g", id)`` config_audit_log."""
    marker = " AND {t}.changed_by <> :anon" if method == ANONYMISE else ""
    out: List[Tuple[str, int]] = []
    queries = (
        (
            "c",
            "SELECT x.audit_id FROM case_audit_logs x WHERE x.timestamp < :cutoff "
            "AND NOT (x.entity_type = 'case' AND "
            + _case_id_protected("x.entity_id")
            + ")"
            + marker.format(t="x")
            + " ORDER BY x.timestamp, x.audit_id",
        ),
        (
            "g",
            # The destruction record itself is never destroyed by a purge.
            "SELECT x.id FROM config_audit_log x WHERE x.timestamp < :cutoff "
            "AND x.config_type <> :rt"
            + marker.format(t="x")
            + " ORDER BY x.timestamp, x.id",
        ),
    )
    for kind, sql in queries:
        room = limit - len(out)
        if room <= 0:
            break
        sql += " LIMIT :limit" + (_SKIP if lock else "")
        rows = session.execute(text(sql), ctx.params(limit=room, rt=AUDIT_CONFIG_TYPE))
        out.extend((kind, r[0]) for r in rows)
    return out


def _audit_apply(session, ctx, method, ids):
    case_ids = [i for k, i in ids if k == "c"]
    config_ids = [i for k, i in ids if k == "g"]
    if method == DELETE:
        session.execute(
            text("DELETE FROM case_audit_logs WHERE audit_id = ANY(CAST(:c AS int[]))"),
            {"c": case_ids},
        )
        session.execute(
            text(
                "DELETE FROM config_audit_log WHERE id = ANY(CAST(:g AS int[])) "
                "AND config_type <> :rt"
            ),
            {"g": config_ids, "rt": AUDIT_CONFIG_TYPE},
        )
        return []
    session.execute(
        text(
            "UPDATE case_audit_logs SET changed_by = :anon, ip_address = NULL, "
            "user_agent = NULL WHERE audit_id = ANY(CAST(:c AS int[]))"
        ),
        {"anon": ANON, "c": case_ids},
    )
    session.execute(
        text(
            "UPDATE config_audit_log SET changed_by = :anon "
            "WHERE id = ANY(CAST(:g AS int[])) AND config_type <> :rt"
        ),
        {"anon": ANON, "g": config_ids, "rt": AUDIT_CONFIG_TYPE},
    )
    return []


def _uploads_select(session, ctx, method, limit, lock):
    """Evidence-store files no evidence/attachment row points at, past cutoff."""
    root = ctx.evidence_root
    if root is None or not root.is_dir():
        return []
    referenced = {
        os.path.normpath(r[0])
        for r in session.execute(
            text(
                "SELECT file_path FROM case_evidence WHERE file_path IS NOT NULL "
                "UNION SELECT file_path FROM case_attachments WHERE file_path <> ''"
            )
        )
        if r[0]
    }
    held = set(ctx.held)
    cutoff_ts = _epoch(ctx.cutoff)
    found: List[Tuple[float, str]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        top = rel_dir.split(os.sep, 1)[0]
        if top in held:  # attachments live under <case_id>/
            dirnames[:] = []
            continue
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                continue
            rel = os.path.normpath(os.path.relpath(full, root))
            if rel in referenced:
                continue
            try:
                mtime = os.stat(full).st_mtime
            except OSError:
                continue
            if mtime < cutoff_ts:
                found.append((mtime, rel))
    found.sort()
    return [rel for _, rel in found[:limit]]


def _uploads_apply(session, ctx, method, ids):
    return list(ids)


_Select = Callable[[Session, _Ctx, str, int, bool], List]
_Apply = Callable[[Session, _Ctx, str, List], List[str]]

HANDLERS: Dict[str, Tuple[_Select, _Apply]] = {
    "findings": (_findings_select, _findings_apply),
    "raw_events": (_raw_select, _raw_apply),
    "cases": (_cases_select, _cases_apply),
    "case_evidence": (_evidence_select, _evidence_apply),
    "chat_conversations": (_chat_select, _chat_apply),
    "llm_logs": (_llm_select, _llm_apply),
    "audit_logs": (_audit_select, _audit_apply),
    "uploads": (_uploads_select, _uploads_apply),
}


def _ledger_archive_candidates(session: Session, cutoff: datetime) -> int:
    """Whole agent runs whose last event is older than cutoff (read only)."""
    if not _table_exists(session, "agent_events"):
        return 0
    row = session.execute(
        text(
            "SELECT count(*) FROM (SELECT run_id FROM agent_events "
            "GROUP BY run_id HAVING max(ts) < :cutoff) runs"
        ),
        {"cutoff": cutoff},
    ).first()
    return int(row[0]) if row else 0


# --- the purge run -----------------------------------------------------------


def _default_evidence_root() -> Optional[Path]:
    try:
        from core.cases.case_evidence_service import CaseEvidenceService

        return Path(os.path.realpath(CaseEvidenceService().storage_path))
    except Exception:  # noqa: BLE001 - uploads are skipped, the rest still runs
        logger.warning("Evidence store unavailable; uploads class skipped")
        return None


def _unlink_all(root: Optional[Path], rel_paths: Sequence[str]) -> int:
    """Remove evidence-store files; only paths that resolve inside ``root``."""
    if root is None:
        return 0
    real_root = os.path.realpath(root)
    removed = 0
    for rel in rel_paths:
        full = os.path.realpath(os.path.join(real_root, rel))
        if not full.startswith(real_root + os.sep):
            logger.warning("Retention skipped a path outside the evidence store")
            continue
        try:
            os.unlink(full)
            removed += 1
        except FileNotFoundError:
            continue
        except OSError as exc:
            # Left behind as an orphan; the uploads class sweeps it later.
            logger.warning("Retention could not remove a file: %s", type(exc).__name__)
    return removed


@contextmanager
def _run_lock() -> Iterator[None]:
    """Hold a session-level advisory lock for the whole run, or refuse."""
    from core.storage.connection import get_db_manager

    conn = get_db_manager().engine.connect()
    try:
        got = conn.execute(
            text("SELECT pg_try_advisory_lock(:k)"), {"k": _RUN_LOCK_KEY}
        ).scalar()
        conn.commit()
        if not got:
            raise RetentionBusy("a retention purge is already running")
        try:
            yield
        finally:
            conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _RUN_LOCK_KEY})
            conn.commit()
    finally:
        conn.close()


def run_purge(
    *,
    dry_run: bool = True,
    actor: str = SYSTEM_ACTOR,
    data_classes: Optional[Sequence[str]] = None,
    batch_size: int = 500,
    max_batches: int = 20,
    now: Optional[datetime] = None,
    evidence_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Apply every policy once; return the run report.

    ``dry_run`` counts what would be processed (up to ``batch_size *
    max_batches`` per class) and writes nothing. A real run commits each batch
    on its own and finishes with one audit row holding this report.
    """
    from core.storage.unit_of_work import unit_of_work

    if not 1 <= batch_size <= MAX_BATCH_SIZE:
        raise RetentionError(f"batch_size must be 1..{MAX_BATCH_SIZE}")
    if not 1 <= max_batches <= MAX_BATCHES:
        raise RetentionError(f"max_batches must be 1..{MAX_BATCHES}")
    wanted = list(data_classes) if data_classes is not None else None
    if wanted is not None and not wanted:
        # Omit the field to run every class; an empty list is a mistake, not "all".
        raise RetentionError("data_classes must name at least one class")
    for name in wanted or ():
        get_data_class(name)

    now = now or utcnow()
    started = utcnow()
    run_id = str(uuid.uuid4())

    with _run_lock():
        # Only for the report: every class and every batch re-reads the holds
        # and its policy under the hold lock (see _protection).
        with unit_of_work() as session:
            held = held_case_ids(session)

        if "uploads" in (wanted or DATA_CLASSES) and evidence_root is None:
            evidence_root = _default_evidence_root()

        results = []
        for name, dc in DATA_CLASSES.items():
            if wanted is not None and name not in wanted:
                continue
            results.append(
                _run_class(
                    dc,
                    now=now,
                    dry_run=dry_run,
                    batch_size=batch_size,
                    max_batches=max_batches,
                    evidence_root=evidence_root,
                )
            )

        report = {
            "run_id": run_id,
            "tenant_id": TENANT,
            "actor": actor,
            "dry_run": dry_run,
            "started_at": _iso(started),
            "finished_at": _iso(utcnow()),
            "as_of": _iso(now),
            "batch_size": batch_size,
            "max_batches": max_batches,
            "legal_hold_cases": len(held),
            "classes": results,
            "total_processed": sum(r["processed"] for r in results),
        }
        if not dry_run:
            with unit_of_work() as session:
                _audit(session, "purge", f"purge:{run_id}", actor, new=report)
    logger.info(
        "Retention purge %s: %d item(s) %s",
        run_id,
        report["total_processed"],
        "would be processed (dry run)" if dry_run else "processed",
    )
    return report


def _protection(
    session: Session, dc: DataClass
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Under the shared hold lock: this class's policy and the held case ids.

    Called at the start of every batch transaction, so a legal hold or a policy
    change committed before the batch began is always honoured by it.
    """
    _lock_holds(session, exclusive=False)
    policy = next(
        (p for p in list_policies(session) if p["data_class"] == dc.name), None
    )
    return policy, held_case_ids(session)


def _unknown_cascades(session: Session, table: str, known) -> List[str]:
    """Tables an ON DELETE CASCADE from ``table`` reaches that are not ``known``."""
    rows = session.execute(
        text(
            "SELECT DISTINCT conrelid::regclass::text FROM pg_constraint "
            "WHERE contype = 'f' AND confdeltype = 'c' "
            "AND confrelid = to_regclass(:t) AND conrelid <> confrelid"
        ),
        {"t": table},
    )
    return sorted(r[0] for r in rows if r[0].split(".")[-1] not in known)


_CASCADE_CHECK = {
    "findings": ("findings", FINDING_CASCADE_CHILDREN),
    "cases": ("cases", CASE_CASCADE_CHILDREN),
}


def _run_class(
    dc: DataClass,
    *,
    now: datetime,
    dry_run: bool,
    batch_size: int,
    max_batches: int,
    evidence_root: Optional[Path],
) -> Dict[str, Any]:
    from core.storage.unit_of_work import unit_of_work

    result: Dict[str, Any] = {
        "data_class": dc.name,
        "label": dc.label,
        "retain_days": None,
        "method": None,
        "cutoff": None,
        "status": "no_policy",
        "processed": 0,
        "batches": 0,
        "more_remaining": False,
        "files_removed": 0,
    }
    with unit_of_work() as session:
        policy, held = _protection(session, dc)
        unknown: List[str] = []
        check = _CASCADE_CHECK.get(dc.name)
        if policy is not None and check and policy["method"] == DELETE:
            unknown = _unknown_cascades(session, check[0], check[1])
    if policy is None:
        return result
    cutoff = now - timedelta(days=int(policy["retain_days"]))
    result.update(
        retain_days=policy["retain_days"], method=policy["method"], cutoff=_iso(cutoff)
    )
    if policy["legal_hold"]:
        result["status"] = "legal_hold"
        return result
    if dc.chained:
        result["status"] = "excluded_hash_chained"
        with unit_of_work() as session:
            result["archive_candidates"] = _ledger_archive_candidates(session, cutoff)
        return result
    if unknown:
        # Fail closed: a DELETE here would cascade into tables nobody vetted.
        logger.error(
            "Retention refused to delete %s: unvetted ON DELETE CASCADE into %s",
            dc.name,
            ", ".join(unknown),
        )
        result["status"] = "error"
        result["error"] = "UnvettedCascade"
        result["unvetted_cascades"] = unknown
        return result

    select, apply = HANDLERS[dc.name]
    method = policy["method"]
    try:
        if dry_run:
            cap = batch_size * max_batches
            with unit_of_work() as session:
                ctx = _Ctx(
                    cutoff=cutoff, now=now, held=held, evidence_root=evidence_root
                )
                found = select(session, ctx, method, cap + 1, False)
                session.rollback()
            result["processed"] = min(len(found), cap)
            result["more_remaining"] = len(found) > cap
            result["status"] = "dry_run"
            return result
        stopped = None
        for _ in range(max_batches):
            with unit_of_work() as session:
                # Re-read under the hold lock in the batch's own transaction.
                policy_now, held = _protection(session, dc)
                if policy_now is None or policy_now["legal_hold"]:
                    stopped = "no_policy" if policy_now is None else "legal_hold"
                    ids, files = [], []
                elif (
                    policy_now["method"] != method
                    or policy_now["retain_days"] != policy["retain_days"]
                ):
                    stopped = "policy_changed"
                    ids, files = [], []
                else:
                    ctx = _Ctx(
                        cutoff=cutoff, now=now, held=held, evidence_root=evidence_root
                    )
                    ids = select(session, ctx, method, batch_size, True)
                    files = apply(session, ctx, method, ids) if ids else []
            # Files go only once their rows are committed away.
            result["files_removed"] += _unlink_all(evidence_root, files)
            if not ids:
                break
            result["batches"] += 1
            result["processed"] += len(ids)
            if len(ids) < batch_size:
                break
        else:
            with unit_of_work() as session:
                _, held = _protection(session, dc)
                ctx = _Ctx(
                    cutoff=cutoff, now=now, held=held, evidence_root=evidence_root
                )
                result["more_remaining"] = bool(select(session, ctx, method, 1, False))
        result["status"] = "processed"
        if stopped:
            result["stopped"] = stopped
    except Exception as exc:  # noqa: BLE001 - one class failing must not stop the rest
        logger.exception("Retention purge of %s failed", dc.name)
        result["status"] = "error"
        result["error"] = type(exc).__name__
    return result


# --- periodic destruction report ----------------------------------------------


def build_destruction_report(
    session: Session, *, since: datetime, until: datetime
) -> Dict[str, Any]:
    """Aggregate the retention audit rows in ``[since, until)`` into a report."""
    rows = (
        session.query(ConfigAuditLog)
        .filter(
            ConfigAuditLog.config_type == AUDIT_CONFIG_TYPE,
            ConfigAuditLog.timestamp >= since,
            ConfigAuditLog.timestamp < until,
        )
        .order_by(ConfigAuditLog.timestamp, ConfigAuditLog.id)
        .all()
    )
    totals: Dict[str, Dict[str, Any]] = {}
    runs = []
    changes = []
    for row in rows:
        if row.action == "purge" and isinstance(row.new_value, dict):
            run = row.new_value
            runs.append(
                {
                    "run_id": run.get("run_id"),
                    "at": _iso(row.timestamp),
                    "actor": row.changed_by,
                    "total_processed": run.get("total_processed", 0),
                    "classes": [
                        {
                            k: c.get(k)
                            for k in (
                                "data_class",
                                "method",
                                "retain_days",
                                "cutoff",
                                "status",
                                "processed",
                                "more_remaining",
                                "files_removed",
                                "archive_candidates",
                            )
                            if k in c
                        }
                        for c in run.get("classes", [])
                    ],
                }
            )
            for c in run.get("classes", []):
                if not c.get("processed"):
                    continue
                key = c["data_class"]
                t = totals.setdefault(
                    key,
                    {
                        "data_class": key,
                        "label": c.get("label"),
                        "deleted": 0,
                        "anonymised": 0,
                        "files_removed": 0,
                    },
                )
                bucket = "anonymised" if c.get("method") == ANONYMISE else "deleted"
                t[bucket] += int(c["processed"])
                t["files_removed"] += int(c.get("files_removed") or 0)
        else:
            changes.append(
                {
                    "at": _iso(row.timestamp),
                    "action": row.action,
                    "key": row.config_key,
                    "actor": row.changed_by,
                    "reason": row.change_reason,
                }
            )
    holds = list_legal_holds(session)
    return {
        "title": "AutoSecOps periyodik imha tutanağı",
        "tenant_id": TENANT,
        "period": {"since": _iso(since), "until": _iso(until)},
        "generated_at": _iso(utcnow()),
        "policies": list_policies(session),
        "legal_holds": [{"case_id": k, **v} for k, v in sorted(holds.items())],
        "totals": sorted(totals.values(), key=lambda t: t["data_class"]),
        "runs": runs,
        "changes": changes,
        "excluded": [
            {"data_class": dc.name, "reason": dc.note}
            for dc in DATA_CLASSES.values()
            if dc.chained
        ],
    }


_STATUS_TR = {
    "processed": "işlendi",
    "dry_run": "kuru çalıştırma",
    "legal_hold": "yasal saklama",
    "excluded_hash_chained": "hariç (hash zinciri)",
    "no_policy": "politika yok",
    "error": "hata",
}


def render_markdown(report: Dict[str, Any]) -> str:
    """The report as Markdown, ready for a PDF converter (pandoc etc.)."""

    def cell(value: Any) -> str:
        if value is None or value == "":
            return "—"
        return str(value).replace("|", "\\|").replace("\n", " ")

    period = report["period"]
    lines = [
        f"# {report['title']}",
        "",
        f"- **Dönem:** {cell(period['since'])} — {cell(period['until'])}",
        f"- **Kiracı:** {cell(report['tenant_id'])}",
        f"- **Oluşturulma:** {cell(report['generated_at'])}",
        f"- **İmha çalıştırması sayısı:** {len(report['runs'])}",
        "",
        "> Bu tutanak AutoSecOps tarafından denetim kayıtlarından otomatik "
        "üretilmiştir. Hukuki görüş değildir.",
        "",
        "## 1. Saklama ve imha politikaları",
        "",
        "| Veri sınıfı | Saklama (gün) | Yöntem | Sınıf düzeyinde yasal saklama |",
        "|---|---|---|---|",
    ]
    for p in report["policies"]:
        lines.append(
            f"| {cell(p['data_class'])} | {cell(p['retain_days'])} | "
            f"{cell(p['method'])} | {'evet' if p['legal_hold'] else 'hayır'} |"
        )
    if not report["policies"]:
        lines.append("| — | — | — | — |")
    lines += [
        "",
        "## 2. Dönem içinde imha edilen / anonimleştirilen kayıtlar",
        "",
        "| Veri sınıfı | Silinen | Anonimleştirilen | Silinen dosya |",
        "|---|---|---|---|",
    ]
    for t in report["totals"]:
        lines.append(
            f"| {cell(t['label'] or t['data_class'])} | {t['deleted']} | "
            f"{t['anonymised']} | {t['files_removed']} |"
        )
    if not report["totals"]:
        lines.append("| — | 0 | 0 | 0 |")
    lines += [
        "",
        "## 3. İmha çalıştırmaları",
        "",
        "| Zaman | Çalıştırma | Aktör | Sınıf | Yöntem | Durum | Adet |",
        "|---|---|---|---|---|---|---|",
    ]
    for run in report["runs"]:
        for c in run["classes"]:
            if c.get("status") == "no_policy":
                continue
            lines.append(
                f"| {cell(run['at'])} | {cell(run['run_id'])} | {cell(run['actor'])} "
                f"| {cell(c.get('data_class'))} | {cell(c.get('method'))} | "
                f"{cell(_STATUS_TR.get(c.get('status'), c.get('status')))} | "
                f"{cell(c.get('processed'))} |"
            )
    lines += [
        "",
        "## 4. Yasal saklama (legal hold) altındaki vakalar",
        "",
        "| Vaka | Gerekçe | Koyan | Tarih |",
        "|---|---|---|---|",
    ]
    for h in report["legal_holds"]:
        lines.append(
            f"| {cell(h['case_id'])} | {cell(h.get('reason'))} | "
            f"{cell(h.get('set_by'))} | {cell(h.get('set_at'))} |"
        )
    if not report["legal_holds"]:
        lines.append("| — | — | — | — |")
    lines += [
        "",
        "## 5. Politika ve yasal saklama değişiklikleri",
        "",
        "| Zaman | İşlem | Anahtar | Aktör | Gerekçe |",
        "|---|---|---|---|---|",
    ]
    for ch in report["changes"]:
        lines.append(
            f"| {cell(ch['at'])} | {cell(ch['action'])} | {cell(ch['key'])} | "
            f"{cell(ch['actor'])} | {cell(ch['reason'])} |"
        )
    if not report["changes"]:
        lines.append("| — | — | — | — | — |")
    lines += ["", "## 6. Otomatik imhadan hariç tutulanlar", ""]
    for ex in report["excluded"]:
        lines.append(f"- **{ex['data_class']}**: {ex['reason']}")
    lines += [
        "",
        "## İmza",
        "",
        "| Rol | Ad Soyad | İmza | Tarih |",
        "|---|---|---|---|",
        "| Veri sorumlusu temsilcisi | | | |",
        "| İmha işlemini onaylayan | | | |",
        "",
    ]
    return "\n".join(lines)


# --- agent ledger archive (archive-then-truncate, step 1) ---------------------


def export_agent_ledger_archive(
    session: Session, *, before: datetime, limit_runs: int, actor: str
) -> Dict[str, Any]:
    """Whole agent runs whose last event is before ``before``, chain-verified.

    Read only on ``agent_events``. The hash of each event is recomputed here
    (sha256 of prev_hash || payload text, the formula of
    ``31_agent_ledger_hash_chain.sql``) so the archive proves itself. The export
    is recorded in the audit log with the archive digest, not its content.
    """
    if not 1 <= limit_runs <= 1000:
        raise RetentionError("limit_runs must be 1..1000")
    runs: List[Dict[str, Any]] = []
    if _table_exists(session, "agent_events"):
        run_ids = [
            str(r[0])
            for r in session.execute(
                text(
                    "SELECT run_id FROM agent_events GROUP BY run_id "
                    "HAVING max(ts) < :before ORDER BY max(ts), run_id LIMIT :n"
                ),
                {"before": before, "n": limit_runs},
            )
        ]
        rows = session.execute(
            text(
                "SELECT run_id, seq, ts, run_kind, kind, payload, "
                "CAST(payload AS text) AS payload_text, snapshot, schema_version, "
                "prev_hash, event_hash FROM agent_events "
                "WHERE run_id = ANY(CAST(:ids AS uuid[])) ORDER BY run_id, seq"
            ),
            {"ids": run_ids},
        ).mappings()
        by_run: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            by_run.setdefault(str(r["run_id"]), []).append(dict(r))
        for run_id in run_ids:
            events = by_run.get(run_id, [])
            ok, broken_at = verify_chain(events)
            runs.append(
                {
                    "run_id": run_id,
                    "events": len(events),
                    "chain_verified": ok,
                    "first_break_seq": broken_at,
                    "head_hash": events[-1]["event_hash"] if events else None,
                    "rows": [
                        {
                            "seq": e["seq"],
                            "ts": _iso(e["ts"]),
                            "run_kind": e["run_kind"],
                            "kind": e["kind"],
                            "payload": e["payload"],
                            "payload_text": e["payload_text"],
                            "snapshot": e["snapshot"],
                            "schema_version": e["schema_version"],
                            "prev_hash": e["prev_hash"],
                            "event_hash": e["event_hash"],
                        }
                        for e in events
                    ],
                }
            )
    body = json.dumps(runs, sort_keys=True, separators=(",", ":"), default=str)
    manifest = {
        "before": _iso(before),
        "runs": len(runs),
        "events": sum(r["events"] for r in runs),
        "all_verified": all(r["chain_verified"] for r in runs),
        "run_ids": [r["run_id"] for r in runs],
        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "exported_at": _iso(utcnow()),
    }
    _audit(
        session,
        LEDGER_ARCHIVE_ACTION,
        f"ledger_archive:{manifest['sha256'][:16]}",
        actor,
        new=manifest,
    )
    return {"manifest": manifest, "runs": runs}


def verify_chain(events: Sequence[Dict[str, Any]]) -> Tuple[bool, Optional[int]]:
    """Recompute one run's chain; (ok, seq of the first broken event)."""
    prev = ""
    for e in events:
        expected = hashlib.sha256(
            (prev + (e["payload_text"] or "")).encode("utf-8")
        ).hexdigest()
        if (e["prev_hash"] or "") != prev or e["event_hash"] != expected:
            return False, e["seq"]
        prev = e["event_hash"]
    return True, None


# --- scheduler entry point ----------------------------------------------------


def run_scheduled_purge() -> Optional[Dict[str, Any]]:
    """The daemon's periodic run: None when RETENTION_PURGE_ENABLED is off."""
    from core.config import get_settings

    settings = get_settings()
    if not settings.retention_purge_enabled:
        return None
    try:
        return run_purge(
            dry_run=settings.retention_purge_dry_run,
            actor=SYSTEM_ACTOR,
            batch_size=settings.retention_purge_batch_size,
            max_batches=settings.retention_purge_max_batches,
        )
    except RetentionBusy:
        logger.info("Retention purge skipped: another run holds the lock")
        return None


# --- helpers -----------------------------------------------------------------


def _table_exists(session: Session, name: str) -> bool:
    return bool(session.execute(text("SELECT to_regclass(:n)"), {"n": name}).scalar())


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else value


def _epoch(naive_utc: datetime) -> float:
    return naive_utc.replace(tzinfo=timezone.utc).timestamp()
