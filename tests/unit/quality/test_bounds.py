"""The Scorecard's exact one-sided Clopper-Pearson bound against known values."""

import math

import pytest

from core.quality.bounds import (
    binomial_cdf,
    clopper_pearson_upper,
    reviews_needed,
)

pytestmark = pytest.mark.unit


def test_299_clean_reviews_put_the_bound_under_one_percent():
    assert clopper_pearson_upper(0, 299) < 0.01


def test_298_clean_reviews_leave_it_over_one_percent():
    assert clopper_pearson_upper(0, 298) > 0.01


@pytest.mark.parametrize("n", [1, 10, 298, 299, 1000, 25_000])
def test_zero_misses_matches_the_closed_form(n):
    assert clopper_pearson_upper(0, n) == pytest.approx(1 - 0.05 ** (1 / n), abs=1e-12)


@pytest.mark.parametrize(
    "misses,n,expected",
    [
        # Published one-sided 95% Clopper-Pearson upper limits (Beta quantiles).
        (1, 10, 0.39416),
        (0, 10, 0.25887),
        (5, 1000, 0.010484),
        (2, 20, 0.28262),
    ],
)
def test_known_upper_limits(misses, n, expected):
    assert clopper_pearson_upper(misses, n) == pytest.approx(expected, abs=5e-5)


@pytest.mark.parametrize("misses,n", [(1, 10), (3, 300), (17, 5000)])
def test_bound_is_the_root_of_the_binomial_tail(misses, n):
    p = clopper_pearson_upper(misses, n)
    assert binomial_cdf(misses, n, p) == pytest.approx(0.05, abs=1e-9)


def test_binomial_cdf_matches_direct_sum():
    n, p = 30, 0.07
    direct = sum(math.comb(n, k) * p**k * (1 - p) ** (n - k) for k in range(4))
    assert binomial_cdf(3, n, p) == pytest.approx(direct, rel=1e-12)


def test_degenerate_inputs():
    assert clopper_pearson_upper(0, 0) == 1.0
    assert clopper_pearson_upper(5, 5) == 1.0
    with pytest.raises(ValueError):
        clopper_pearson_upper(3, 2)
    with pytest.raises(ValueError):
        clopper_pearson_upper(0, 10, confidence=1.0)


def test_other_confidence_levels():
    # 99%: 1 - 0.01**(1/n)
    assert clopper_pearson_upper(0, 100, 0.99) == pytest.approx(
        1 - 0.01**0.01, abs=1e-12
    )


def test_reviews_needed():
    assert reviews_needed(0, 0) == 299
    assert reviews_needed(0, 100) == 199
    assert reviews_needed(0, 299) == 0
    # the smallest total that meets the target, not merely one that does
    needed = reviews_needed(1, 10)
    assert (
        clopper_pearson_upper(1, 10 + needed)
        <= 0.01
        < clopper_pearson_upper(1, 9 + needed)
    )
