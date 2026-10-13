"""Autonomy controller (W3.1): how far AutoSecOps may act alone.

One tier per (alert category x action class), stored in ``autonomy_tiers``
(``48_autonomy_lessons_suppression_retention.sql``):

watch       observe only: no action row is created.
suggest     the action is recorded as a suggestion; only a person releases it.
approve     the action is queued and a person approves it (the GA default).
autonomous  a reversible action, with a ttl, runs without a person, while the
            category's sampled false-negative bound holds.

The tier only ever decides whether a person must release an action. The
response policy (``core.response.policy``) still runs on every action before
an executor sees it, whatever the tier. See ``controller`` for the rules.
"""

from core.autonomy.categories import category_of, resolve_category
from core.autonomy.controller import (
    AutonomyController,
    AutonomyDecision,
    AutonomyWatchOnly,
    PromotionRefused,
)
from core.autonomy.tiers import (
    ACTION_CLASSES,
    AUTONOMOUS_ELIGIBLE,
    DEFAULT_TIER,
    TIERS,
    TierEntry,
)

__all__ = [
    "ACTION_CLASSES",
    "AUTONOMOUS_ELIGIBLE",
    "DEFAULT_TIER",
    "TIERS",
    "AutonomyController",
    "AutonomyDecision",
    "AutonomyWatchOnly",
    "PromotionRefused",
    "TierEntry",
    "category_of",
    "resolve_category",
]
