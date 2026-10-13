"""Reads ``suppression_rules`` (infra/database/init/48_*.sql) for the alert lanes.

The table is SQL-owned (no ORM model), so this speaks plain SQL. Only enabled,
unexpired rows of one tenant are returned; the lane decision checks expiry again
against its own clock, because a cached row can outlive its ``expires_at``.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from core.lanes.alert_lanes import SuppressionRule

logger = logging.getLogger(__name__)

_SELECT = """
SELECT id, tenant_id, name, match, reason, enabled, expires_at
FROM suppression_rules
WHERE tenant_id = :tenant_id
  AND enabled
  AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at, name
"""

_HIT = """
UPDATE suppression_rules
SET hit_count = hit_count + 1, last_hit_at = now()
WHERE id = CAST(:id AS uuid) AND tenant_id = :tenant_id
"""


def _aware(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value))


def rule_from_row(row: Any) -> Optional[SuppressionRule]:
    """A row as a rule, or None when ``match`` is not a predicate document."""
    m = dict(row._mapping) if hasattr(row, "_mapping") else dict(row)
    match = m.get("match")
    if not isinstance(match, dict):
        logger.warning(
            "suppression rule %s has a non-object match; ignored", m.get("name")
        )
        return None
    return SuppressionRule(
        id=str(m["id"]),
        tenant_id=str(m.get("tenant_id") or "default"),
        name=str(m.get("name") or ""),
        match=match,
        reason=str(m.get("reason") or ""),
        enabled=bool(m.get("enabled", True)),
        expires_at=_aware(m.get("expires_at")),
    )


def _session_scope():
    from core.storage.connection import get_db_manager

    return get_db_manager().session_scope()


def load_active_rules(tenant_id: str) -> List[SuppressionRule]:
    """Enabled, unexpired rules of ``tenant_id``. Raises when the DB can't be read."""
    from sqlalchemy import text

    with _session_scope() as session:
        rows = session.execute(text(_SELECT), {"tenant_id": tenant_id}).fetchall()
    return [r for r in (rule_from_row(row) for row in rows) if r is not None]


def record_hit(rule: SuppressionRule) -> None:
    """Count a suppression; best effort, never raises."""
    from sqlalchemy import text

    try:
        with _session_scope() as session:
            session.execute(text(_HIT), {"id": rule.id, "tenant_id": rule.tenant_id})
    except Exception as exc:  # noqa: BLE001
        logger.warning("suppression hit not counted for %s: %s", rule.name, exc)


class CachedRules:
    """Per-tenant cache over a rule loader, so intake doesn't query per finding.

    A failed load keeps serving the last good rules for that tenant (or none)
    and retries on the next call after the TTL.
    """

    def __init__(
        self,
        loader: Callable[[str], Sequence[SuppressionRule]] = load_active_rules,
        ttl_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._loader = loader
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: Dict[str, Tuple[float, Tuple[SuppressionRule, ...]]] = {}

    def __call__(self, tenant_id: str) -> Tuple[SuppressionRule, ...]:
        now = self._clock()
        with self._lock:
            hit = self._cache.get(tenant_id)
        if hit is not None and now - hit[0] < self._ttl:
            return hit[1]
        try:
            rules = tuple(self._loader(tenant_id))
        except Exception as exc:  # noqa: BLE001
            logger.warning("suppression rules not read for %s: %s", tenant_id, exc)
            rules = hit[1] if hit is not None else ()
        with self._lock:
            self._cache[tenant_id] = (now, rules)
        return rules
