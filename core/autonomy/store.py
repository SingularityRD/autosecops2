"""Where tiers live: ``autonomy_tiers`` rows, audited in ``config_audit_log``.

``autonomy_tiers`` is SQL-owned (``48_autonomy_lessons_suppression_retention.sql``,
no ORM model), so it is read and written with plain SQL. Every change writes a
``config_audit_log`` row (``config_type = 'autonomy_tier'``) in the same
transaction: a tier change that cannot be audited does not happen.
"""

from __future__ import annotations

from typing import Any, Optional, Protocol

from sqlalchemy import text

from core.autonomy.tiers import TO_DB, TierEntry, tier_from_db
from core.storage.models import ConfigAuditLog
from core.storage.unit_of_work import unit_of_work

TENANT = "default"
AUDIT_CONFIG_TYPE = "autonomy_tier"


class TierStore(Protocol):
    def entries(self) -> list[TierEntry]: ...

    def put(
        self,
        entry: TierEntry,
        *,
        old: Optional[TierEntry],
        audit_action: str,
        actor: str,
        reason: str,
        evidence_url: Optional[str] = None,
        detail: Optional[dict[str, Any]] = None,
    ) -> None: ...

    def audit(self, limit: int = 100) -> list[dict[str, Any]]: ...


def audit_key(category: str, action_type: str) -> str:
    return f"{category}/{action_type}"


def _audit_value(entry: Optional[TierEntry]) -> Optional[dict[str, Any]]:
    if entry is None:
        return None
    return {
        "tier": entry.tier,
        "min_confidence": entry.min_confidence,
        "max_ttl_seconds": entry.max_ttl_seconds,
    }


_SELECT = text("""
    SELECT category, action_type, tier, min_confidence, max_ttl_seconds,
           updated_by, updated_at
    FROM autonomy_tiers
    WHERE tenant_id = :t
    """)

_UPSERT = text("""
    INSERT INTO autonomy_tiers
        (tenant_id, action_type, category, tier, min_confidence,
         max_ttl_seconds, updated_by, updated_at)
    VALUES (:t, :a, :c, :tier, :mc, :ttl, :by, now())
    ON CONFLICT (tenant_id, action_type, category) DO UPDATE SET
        tier = EXCLUDED.tier,
        min_confidence = EXCLUDED.min_confidence,
        max_ttl_seconds = EXCLUDED.max_ttl_seconds,
        updated_by = EXCLUDED.updated_by,
        updated_at = now()
    """)


class SqlTierStore:
    """The tenant's ``autonomy_tiers`` rows."""

    def entries(self) -> list[TierEntry]:
        with unit_of_work() as session:
            rows = session.execute(_SELECT, {"t": TENANT}).mappings().all()
        return [
            TierEntry(
                category=r["category"],
                action_type=r["action_type"],
                tier=tier_from_db(r["tier"]),
                min_confidence=(
                    float(r["min_confidence"])
                    if r["min_confidence"] is not None
                    else None
                ),
                max_ttl_seconds=(
                    int(r["max_ttl_seconds"])
                    if r["max_ttl_seconds"] is not None
                    else None
                ),
                updated_by=r["updated_by"],
                updated_at=r["updated_at"],
                explicit=True,
            )
            for r in rows
        ]

    def put(
        self,
        entry: TierEntry,
        *,
        old: Optional[TierEntry],
        audit_action: str,
        actor: str,
        reason: str,
        evidence_url: Optional[str] = None,
        detail: Optional[dict[str, Any]] = None,
    ) -> None:
        new_value = _audit_value(entry) or {}
        if evidence_url:
            new_value["evidence_url"] = evidence_url
        if detail:
            new_value["detail"] = detail
        with unit_of_work() as session:
            session.execute(
                _UPSERT,
                {
                    "t": TENANT,
                    "a": entry.action_type,
                    "c": entry.category,
                    "tier": TO_DB[entry.tier],
                    "mc": entry.min_confidence,
                    "ttl": entry.max_ttl_seconds,
                    "by": actor[:200],
                },
            )
            session.add(
                ConfigAuditLog(
                    config_type=AUDIT_CONFIG_TYPE,
                    config_key=audit_key(entry.category, entry.action_type),
                    action=audit_action,
                    old_value=_audit_value(old),
                    new_value=new_value,
                    changed_by=actor[:100],
                    change_reason=reason,
                )
            )

    def audit(self, limit: int = 100) -> list[dict[str, Any]]:
        with unit_of_work() as session:
            rows = (
                session.query(ConfigAuditLog)
                .filter(ConfigAuditLog.config_type == AUDIT_CONFIG_TYPE)
                .order_by(ConfigAuditLog.id.desc())
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": row.id,
                    "key": row.config_key,
                    "action": row.action,
                    "old_value": row.old_value,
                    "new_value": row.new_value,
                    "changed_by": row.changed_by,
                    "reason": row.change_reason,
                    "at": row.timestamp.isoformat() if row.timestamp else None,
                }
                for row in rows
            ]


__all__ = ["AUDIT_CONFIG_TYPE", "SqlTierStore", "TENANT", "TierStore", "audit_key"]
