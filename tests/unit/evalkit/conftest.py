"""Shared helpers for the evalkit tests. Everything here is offline."""

import pytest

from evalkit.corpus import Case
from evalkit.runner import CaseResult


def make_case(
    *,
    case_id="c1",
    suite="test",
    verdict="malicious",
    category="malware",
    alert=None,
    **labels,
):
    alert = alert or {
        "finding_id": case_id,
        "data_source": "crowdstrike",
        "severity": "high",
        "title": "t",
        "description": "d",
        "entity_context": {"hostnames": ["WS-1"], "src_ips": ["192.0.2.1"]},
        "mitre_predictions": {"T1059": 0.9},
    }
    return Case(
        case_id=case_id,
        suite=suite,
        alert=alert,
        labels={"verdict": verdict, "category": category, **labels},
    )


def make_result(
    *,
    expected="malicious",
    actual="malicious",
    category="malware",
    actual_category=None,
    action=None,
    error=None,
    latency_ms=0,
    cost_usd=0.0,
    case=None,
    **labels,
):
    case = case or make_case(verdict=expected, category=category, **labels)
    return CaseResult(
        case=case,
        prompt_sha256="0" * 64,
        expected_verdict=expected,
        expected_category=category,
        actual_verdict=actual,
        actual_category=actual_category or category,
        confidence=0.9,
        recommended_action=action,
        raw_action=None,
        raw_category=None,
        verdict=None,
        latency_ms=latency_ms,
        cost_usd=cost_usd,
        error=error,
    )


@pytest.fixture
def case_factory():
    return make_case


@pytest.fixture
def result_factory():
    return make_result
