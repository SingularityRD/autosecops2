"""The live backend's budget cap, with a fake router (no network)."""

import asyncio
from types import SimpleNamespace

import pytest

from evalkit.backends import Budget, BudgetExceeded, LiveBackend, Rates

PROVIDER = SimpleNamespace(provider_type="anthropic", default_model="m")
PROMPT = "x" * 300  # ~101 estimated input tokens


def fake_dispatch(calls, *, input_tokens=100, output_tokens=50, fail=False, delay=0.0):
    async def dispatch(**kwargs):
        calls.append(kwargs)
        await asyncio.sleep(delay)
        if fail:
            raise RuntimeError("gateway down")
        return {
            "content": "RECOMMENDED_ACTION: dismiss",
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": 0,
        }

    return dispatch


def priced(rate_in=1e-6, rate_out=5e-6):
    return lambda model, provider_type: Rates(input=rate_in, output=rate_out)


def make(cap, calls, *, max_tokens=100, rates=None, **kw):
    return LiveBackend(
        provider=PROVIDER,
        model="m",
        budget=Budget(cap),
        dispatch=fake_dispatch(calls, **kw),
        rates=rates or priced(),
        max_tokens=max_tokens,
    )


def run(backend, n):
    async def go():
        return [await backend.complete(PROMPT) for _ in range(n)]

    return asyncio.run(go())


def test_dispatches_the_prompt_unchanged_and_prices_the_call():
    calls = []
    b = make(1.0, calls)
    [r] = run(b, 1)
    assert calls[0]["messages"] == [{"role": "user", "content": PROMPT}]
    assert calls[0]["model"] == "m" and calls[0]["max_tokens"] == 100
    assert r.cost_usd == pytest.approx(100 * 1e-6 + 50 * 5e-6)
    assert r.content and r.error is None and r.model == "anthropic/m"
    assert b.budget.spent_usd == pytest.approx(r.cost_usd)


def test_cap_is_never_exceeded():
    calls = []
    # worst case per call = 101 * 1e-6 + 100 * 5e-6 = 0.000601
    b = make(0.0025, calls)
    results = run(b, 10)
    assert b.budget.spent_usd <= 0.0025
    refused = [r for r in results if r.error and r.error.startswith("budget:")]
    assert refused and len(calls) + len(refused) == 10
    # Once refused, the call never reached the router.
    assert len(calls) == b.budget.calls


def test_concurrent_calls_respect_the_cap():
    calls = []
    # Every call is in flight at once, so each holds its worst-case reservation:
    # floor(0.002 / 0.000601) = 3 fit.
    b = make(0.002, calls, delay=0.01)

    async def go():
        return await asyncio.gather(*(b.complete(PROMPT) for _ in range(20)))

    asyncio.run(go())
    assert len(calls) == 3
    assert b.budget.spent_usd <= 0.002


def test_unpriced_model_is_refused_by_default():
    with pytest.raises(BudgetExceeded):
        make(1.0, [], rates=lambda m, p: None)


def test_unpriced_model_with_flat_charge():
    calls = []
    b = LiveBackend(
        provider=PROVIDER,
        model="m",
        budget=Budget(0.1),
        dispatch=fake_dispatch(calls),
        rates=lambda m, p: None,
        allow_unpriced=True,
        unpriced_call_usd=0.04,
    )
    results = run(b, 5)
    assert len(calls) == 2
    assert all(r.cost_usd is None for r in results)  # unpriced, never 0
    assert b.budget.spent_usd == pytest.approx(0.08)


def test_router_failure_is_an_error_and_still_charged():
    calls = []
    b = make(1.0, calls, fail=True)
    [r] = run(b, 1)
    assert r.content is None and "gateway down" in r.error
    assert b.budget.spent_usd == pytest.approx(101 * 1e-6 + 100 * 5e-6)


def test_budget_must_be_positive():
    with pytest.raises(ValueError):
        Budget(0)
