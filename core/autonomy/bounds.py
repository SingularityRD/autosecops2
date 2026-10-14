"""The evidence autonomy stands on: W1.6's sampled false-negative bound.

A category may hold an autonomous tier only while its one-sided 95%
Clopper-Pearson upper bound on the false-negative rate of auto-closed
decisions, computed from simple-random QA reviews only (``core.quality``), is
at or under ``FN_BOUND_TARGET`` from at least ``FN_BOUND_MIN_REVIEWS`` reviews.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

from core.autonomy.tiers import FN_BOUND_MIN_REVIEWS, FN_BOUND_TARGET

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BoundStatus:
    """One category's bound and whether autonomy may stand on it.

    ``readable`` False: the bound could not be read. Autonomy is then refused
    for the decision at hand, but nothing is demoted: an unreadable table is
    not evidence that the model got worse.
    """

    category: str
    reviewed: int = 0
    misses: int = 0
    fn_upper_bound: Optional[float] = None
    holds: bool = False
    readable: bool = True
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "reviewed": self.reviewed,
            "misses": self.misses,
            "fn_upper_bound": self.fn_upper_bound,
            "holds": self.holds,
            "readable": self.readable,
            "reason": self.reason,
        }


def judge(category: str, reviewed: int, misses: int, upper: float) -> BoundStatus:
    """Whether ``upper`` from ``reviewed`` reviews meets the autonomy bar."""
    if reviewed < FN_BOUND_MIN_REVIEWS:
        return BoundStatus(
            category,
            reviewed,
            misses,
            upper,
            holds=False,
            reason=(
                f"{reviewed} simple-random reviews, at least "
                f"{FN_BOUND_MIN_REVIEWS} needed"
            ),
        )
    if not upper <= FN_BOUND_TARGET:
        return BoundStatus(
            category,
            reviewed,
            misses,
            upper,
            holds=False,
            reason=(
                f"FN upper bound {upper:.4f} exceeds {FN_BOUND_TARGET:.2%} "
                f"({misses} miss(es) in {reviewed})"
            ),
        )
    return BoundStatus(
        category,
        reviewed,
        misses,
        upper,
        holds=True,
        reason=f"FN upper bound {upper:.4f} <= {FN_BOUND_TARGET:.2%} at n={reviewed}",
    )


def read_bounds() -> dict[str, BoundStatus]:
    """Every category's bound from the QA scorecard; raises when unreadable."""
    from core.quality import sampling
    from core.storage.unit_of_work import unit_of_work

    with unit_of_work() as session:
        data = sampling.scorecard(session, target=FN_BOUND_TARGET)
    return {
        row["category"]: judge(
            row["category"],
            int(row["reviewed"]),
            int(row["misses"]),
            float(row["fn_upper_bound"]),
        )
        for row in data["categories"]
    }


BoundReader = Callable[[], dict[str, BoundStatus]]


def safe_bound(reader: BoundReader, category: str) -> BoundStatus:
    """``category``'s bound, or an unreadable status when the read fails."""
    try:
        bounds = reader()
    except Exception as e:  # noqa: BLE001
        logger.error("Cannot read the QA bound; autonomy refused: %s", e)
        return BoundStatus(
            category, holds=False, readable=False, reason="QA bound unreadable"
        )
    status = bounds.get(category)
    if status is None:
        return BoundStatus(category, holds=False, reason="no QA data for category")
    return status


__all__ = ["BoundReader", "BoundStatus", "judge", "read_bounds", "safe_bound"]
