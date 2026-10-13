"""Exact one-sided Clopper–Pearson upper bound for a binomial rate.

The Scorecard claims "the false-negative rate of auto-closed verdicts in this
category is at most p, with 95% confidence". With ``x`` misses in ``n``
simple-random reviews, the exact one-sided upper bound is the ``p`` at which
seeing ``x`` or fewer misses becomes a ``1 - confidence`` event:

    P(X <= x | n, p) = 1 - confidence

equivalently the ``confidence`` quantile of Beta(x + 1, n - x). No scipy in the
runtime, so the binomial CDF is summed exactly in log space and ``p`` is found
by bisection; the CDF is strictly decreasing in ``p``, so bisection converges to
the unique root. For ``x == 0`` this reduces to ``1 - (1 - confidence) ** (1/n)``.
"""

from __future__ import annotations

import math
from typing import Optional

#: The rate a category must stay under to meet the Scorecard target.
DEFAULT_TARGET = 0.01
DEFAULT_CONFIDENCE = 0.95

# Far below any number the Scorecard prints; 200 halvings are well past it.
_TOLERANCE = 1e-15
_MAX_ITERATIONS = 200
# reviews_needed stops looking past this many reviews and answers None.
_MAX_REVIEWS = 10_000_000


def binomial_cdf(x: int, n: int, p: float) -> float:
    """``P(X <= x)`` for ``X ~ Binomial(n, p)``, summed exactly in log space."""
    if x < 0:
        return 0.0
    if x >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    log_p = math.log(p)
    log_q = math.log1p(-p)
    log_n_fact = math.lgamma(n + 1)
    terms = [
        log_n_fact
        - math.lgamma(k + 1)
        - math.lgamma(n - k + 1)
        + k * log_p
        + (n - k) * log_q
        for k in range(x + 1)
    ]
    peak = max(terms)
    return min(1.0, math.exp(peak) * math.fsum(math.exp(t - peak) for t in terms))


def clopper_pearson_upper(
    misses: int, n: int, confidence: float = DEFAULT_CONFIDENCE
) -> float:
    """One-sided ``confidence`` upper bound on the rate behind ``misses``/``n``.

    ``n == 0`` says nothing about the rate, so the bound is 1.
    """
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be strictly between 0 and 1")
    if n < 0 or misses < 0 or misses > n:
        raise ValueError("need 0 <= misses <= n")
    if n == 0 or misses == n:
        return 1.0
    alpha = 1.0 - confidence
    lo, hi = misses / n, 1.0
    for _ in range(_MAX_ITERATIONS):
        mid = (lo + hi) / 2.0
        if binomial_cdf(misses, n, mid) > alpha:
            lo = mid
        else:
            hi = mid
        if hi - lo < _TOLERANCE:
            break
    return hi


def reviews_needed(
    misses: int,
    n: int,
    target: float = DEFAULT_TARGET,
    confidence: float = DEFAULT_CONFIDENCE,
) -> Optional[int]:
    """More reviews, all agreeing, before the bound is at or under ``target``.

    0 when it already is. ``None`` when it would take more than ten million.
    """
    if clopper_pearson_upper(misses, n, confidence) <= target:
        return 0

    def ok(m: int) -> bool:
        return clopper_pearson_upper(misses, m, confidence) <= target

    hi = max(n, 1)
    while not ok(hi):
        if hi >= _MAX_REVIEWS:
            return None
        hi = min(hi * 2, _MAX_REVIEWS)
    lo = n  # known not ok
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if ok(mid):
            hi = mid
        else:
            lo = mid
    return hi - n
