"""Tier names, action classes and what may ever be autonomous (W3.1).

Kept free of ``core.response`` imports: ``core.response.approval_service``
consults the controller, so the controller must not import it back. The action
class list mirrors ``core.response.approval_service.ActionType`` (minus
``workflow_phase``, a human checkpoint the tiers do not govern); a unit test
pins the two together.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from core.contracts.verdict import CATEGORIES

WATCH = "watch"
SUGGEST = "suggest"
APPROVE = "approve"
AUTONOMOUS = "autonomous"

#: Least to most autonomous.
TIERS: tuple[str, ...] = (WATCH, SUGGEST, APPROVE, AUTONOMOUS)
#: GA default for every (category, action class) nobody has configured.
DEFAULT_TIER = APPROVE

# The stored vocabulary of autonomy_tiers.tier (48_*.sql) and ours. The table
# predates the product names; ``two_person`` is the response policy's four-eyes
# rule (W2.4), which applies at any tier, so a stored two_person reads approve.
TO_DB = {
    WATCH: "off",
    SUGGEST: "recommend",
    APPROVE: "approve",
    AUTONOMOUS: "autonomous",
}
FROM_DB = {
    "off": WATCH,
    "recommend": SUGGEST,
    "approve": APPROVE,
    "two_person": APPROVE,
    "autonomous": AUTONOMOUS,
}

#: The row for every category not named (48_*.sql). Never autonomous: the
#: bound that releases autonomy is per category.
ANY_CATEGORY = "*"
TIER_CATEGORIES: tuple[str, ...] = (ANY_CATEGORY, *CATEGORIES)

#: Response action classes the tiers govern (``ActionType`` minus workflow_phase).
ACTION_CLASSES: tuple[str, ...] = (
    "isolate_host",
    "block_ip",
    "block_domain",
    "quarantine_file",
    "disable_user",
    "execute_spl_query",
    "waf_block",
    "gateway_block",
    "access_revoke",
    "revoke_sessions",
    "custom",
)

#: The only classes that may ever be autonomous: reversible by their nature,
#: undone by the TTL sweep. Everything else (access_revoke, disable_user,
#: revoke_sessions, quarantine_file, execute_spl_query, custom) is refused at
#: configuration and at every decision. The row's and the executor's
#: reversibility are checked on top of this list, never instead of it.
AUTONOMOUS_ELIGIBLE = frozenset(
    {"isolate_host", "block_ip", "block_domain", "waf_block", "gateway_block"}
)

#: The longest an autonomous change may stand before the TTL sweep undoes it.
AUTONOMOUS_MAX_TTL_SECONDS = 7 * 24 * 3600

#: The W1.6 bar autonomy is held to: the one-sided 95% Clopper-Pearson upper
#: bound on the sampled false-negative rate at or under 1%, from at least 299
#: simple-random reviews (299 clean reviews is the least that can reach 1%).
FN_BOUND_TARGET = 0.01
FN_BOUND_MIN_REVIEWS = 299


def tier_from_db(value: Optional[str]) -> str:
    """Our tier for a stored one; anything unknown reads as the default."""
    return FROM_DB.get(str(value or "").strip().lower(), DEFAULT_TIER)


def normalise_category(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in CATEGORIES else "other"


def category_of(source: Optional[Mapping[str, Any]]) -> str:
    """The alert category a finding, decision or verdict document names.

    Looks at ``category``, ``verdict_category``, ``verdict.category`` and
    ``metadata.category``; ``other`` when none names a known category.
    """
    if not source:
        return "other"
    candidates: list[Any] = [source.get("category"), source.get("verdict_category")]
    for nested in ("verdict", "metadata"):
        inner = source.get(nested)
        if isinstance(inner, Mapping):
            candidates.append(inner.get("category"))
    for value in candidates:
        text = str(value or "").strip().lower()
        if text in CATEGORIES:
            return text
    return "other"


@dataclass(frozen=True)
class TierEntry:
    """One (category, action class) setting; ``explicit`` False is the default."""

    category: str
    action_type: str
    tier: str = DEFAULT_TIER
    min_confidence: Optional[float] = None
    max_ttl_seconds: Optional[int] = None
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None
    explicit: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "action_type": self.action_type,
            "tier": self.tier,
            "min_confidence": self.min_confidence,
            "max_ttl_seconds": self.max_ttl_seconds,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "explicit": self.explicit,
        }


__all__ = [
    "ACTION_CLASSES",
    "ANY_CATEGORY",
    "APPROVE",
    "AUTONOMOUS",
    "AUTONOMOUS_ELIGIBLE",
    "AUTONOMOUS_MAX_TTL_SECONDS",
    "DEFAULT_TIER",
    "FN_BOUND_MIN_REVIEWS",
    "FN_BOUND_TARGET",
    "FROM_DB",
    "SUGGEST",
    "TIERS",
    "TIER_CATEGORIES",
    "TO_DB",
    "TierEntry",
    "WATCH",
    "category_of",
    "normalise_category",
    "tier_from_db",
]
