"""suppression_rules rows and the per-tenant cache in front of them."""

from __future__ import annotations

from datetime import datetime

import pytest

from core.lanes.alert_lanes import SuppressionRule
from core.lanes.suppression_store import CachedRules, rule_from_row

pytestmark = pytest.mark.unit


def test_row_becomes_rule_with_aware_expiry():
    r = rule_from_row(
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "tenant_id": "acme",
            "name": "scanner",
            "match": {"data_source": "nessus"},
            "reason": "noise",
            "enabled": True,
            "expires_at": datetime(2026, 1, 1),
        }
    )
    assert r.tenant_id == "acme"
    assert r.expires_at.tzinfo is not None


def test_non_object_match_is_skipped():
    assert rule_from_row({"id": "x", "name": "bad", "match": ["nope"]}) is None


def test_cache_reuses_within_ttl_and_keeps_last_good_on_failure():
    clock = [0.0]
    calls = []
    good = (SuppressionRule("1", "t", "n", {"a": 1}),)

    def loader(tenant):
        calls.append(tenant)
        if len(calls) > 1:
            raise RuntimeError("db down")
        return good

    cache = CachedRules(loader, ttl_seconds=30, clock=lambda: clock[0])
    assert cache("t") == good
    assert cache("t") == good and calls == ["t"]
    clock[0] = 31
    assert cache("t") == good  # failed reload serves last good
    assert calls == ["t", "t"]
    assert cache("other") == ()  # failure with nothing cached: no rules


def test_tenants_are_cached_separately():
    cache = CachedRules(lambda t: (SuppressionRule(t, t, t, {"a": 1}),), clock=lambda: 0.0)
    assert cache("a")[0].tenant_id == "a"
    assert cache("b")[0].tenant_id == "b"
