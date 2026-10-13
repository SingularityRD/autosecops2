"""Clopper–Pearson bounds and percentiles against known values."""

import math

import pytest

from evalkit.stats import binom_cdf, cp_lower, cp_upper, f1, percentile


def test_all_successes_lower_bound_is_alpha_root():
    # P(X = n | p) = p**n = alpha  ->  p = alpha ** (1/n)
    assert cp_lower(10, 10) == pytest.approx(0.05**0.1, abs=1e-9)
    assert cp_upper(10, 10) == 1.0


def test_no_successes_upper_bound_is_closed_form():
    assert cp_upper(0, 10) == pytest.approx(1 - 0.05**0.1, abs=1e-9)
    assert cp_lower(0, 10) == 0.0


def test_half_matches_textbook_interval():
    # The two-sided 90% Clopper–Pearson interval for 5/10 is (0.2224, 0.7776);
    # its ends are the one-sided 95% bounds.
    assert cp_lower(5, 10) == pytest.approx(0.22244, abs=1e-4)
    assert cp_upper(5, 10) == pytest.approx(0.77756, abs=1e-4)


@pytest.mark.parametrize("k,n", [(0, 1), (3, 7), (40, 432), (700, 720), (17, 1296)])
def test_bounds_are_symmetric_and_bracket_the_estimate(k, n):
    lo, hi = cp_lower(k, n), cp_upper(k, n)
    assert lo <= k / n <= hi
    assert cp_upper(k, n) == pytest.approx(1 - cp_lower(n - k, n), abs=1e-9)
    if 0 < k:
        # At the lower bound, P(X >= k) is exactly alpha.
        assert 1 - binom_cdf(k - 1, n, lo) == pytest.approx(0.05, abs=1e-7)
    if k < n:
        assert binom_cdf(k, n, hi) == pytest.approx(0.05, abs=1e-7)


def test_empty_sample_has_no_bound():
    assert cp_lower(0, 0) is None
    assert cp_upper(0, 0) is None


def test_invalid_counts_raise():
    with pytest.raises(ValueError):
        cp_lower(3, 2)


def test_binom_cdf_sums_to_one():
    assert binom_cdf(20, 20, 0.3) == 1.0
    total = sum(binom_cdf(i, 20, 0.3) - binom_cdf(i - 1, 20, 0.3) for i in range(0, 21))
    assert math.isclose(total, 1.0, abs_tol=1e-12)


def test_percentile_interpolates_like_numpy():
    data = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
    assert percentile(data, 50) == 55.0
    assert percentile(data, 95) == pytest.approx(95.5)
    assert percentile([7], 95) == 7.0
    assert percentile([], 50) is None


def test_f1():
    assert f1(1.0, 1.0) == 1.0
    assert f1(0.0, 0.0) == 0.0
    assert f1(None, 0.5) is None
    assert f1(0.5, 1.0) == pytest.approx(2 / 3)
