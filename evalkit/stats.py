"""Exact binomial bounds and percentiles, in pure Python (no scipy)."""

from __future__ import annotations

import math
from typing import Optional, Sequence

DEFAULT_ALPHA = 0.05  # one-sided 95%


def _log_pmf(i: int, n: int, p: float) -> float:
    return (
        math.lgamma(n + 1)
        - math.lgamma(i + 1)
        - math.lgamma(n - i + 1)
        + i * math.log(p)
        + (n - i) * math.log1p(-p)
    )


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p)."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    terms = [_log_pmf(i, n, p) for i in range(0, k + 1)]
    top = max(terms)
    return min(1.0, math.exp(top) * sum(math.exp(t - top) for t in terms))


def _bisect(f, lo: float = 0.0, hi: float = 1.0, iterations: int = 200) -> float:
    """Root of a function that is increasing on [lo, hi]."""
    for _ in range(iterations):
        mid = (lo + hi) / 2
        if f(mid) < 0:
            lo = mid
        else:
            hi = mid
        if hi - lo < 1e-12:
            break
    return (lo + hi) / 2


def cp_lower(k: int, n: int, alpha: float = DEFAULT_ALPHA) -> Optional[float]:
    """One-sided Clopper–Pearson lower bound: the p with P(X >= k | p) = alpha."""
    _check(k, n)
    if n == 0:
        return None
    if k == 0:
        return 0.0
    # P(X >= k | p) = 1 - cdf(k - 1) rises with p.
    return _bisect(lambda p: (1.0 - binom_cdf(k - 1, n, p)) - alpha)


def cp_upper(k: int, n: int, alpha: float = DEFAULT_ALPHA) -> Optional[float]:
    """One-sided Clopper–Pearson upper bound: the p with P(X <= k | p) = alpha."""
    _check(k, n)
    if n == 0:
        return None
    if k == n:
        return 1.0
    # P(X <= k | p) falls with p, so bisect on its negation.
    return _bisect(lambda p: alpha - binom_cdf(k, n, p))


def _check(k: int, n: int) -> None:
    if n < 0 or k < 0 or k > n:
        raise ValueError(f"need 0 <= k <= n, got k={k} n={n}")


def ratio(k: int, n: int) -> Optional[float]:
    return k / n if n else None


def percentile(values: Sequence[float], q: float) -> Optional[float]:
    """Linear-interpolated percentile (numpy's default), ``q`` in [0, 100]."""
    if not values:
        return None
    data = sorted(values)
    if len(data) == 1:
        return float(data[0])
    pos = (len(data) - 1) * q / 100.0
    lo = math.floor(pos)
    hi = math.ceil(pos)
    return float(data[lo] + (data[hi] - data[lo]) * (pos - lo))


def f1(precision: Optional[float], recall: Optional[float]) -> Optional[float]:
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)
