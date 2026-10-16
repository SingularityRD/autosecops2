"""Setup readiness tells the truth, and wizard progress is the install's (W0.33)."""

from __future__ import annotations

import pytest

from core.platform.setup_state import (
    SetupProgressWrite,
    build_readiness,
    next_progress,
    read_progress,
)

pytestmark = pytest.mark.unit

CATEGORIES = {"splunk": "SIEM", "slack": "Communications", "palo-alto": "Network Security",
              "virustotal": "Threat Intelligence"}
EXECUTORS = ["cloudflare", "microsoft-defender", "azure-ad", "palo-alto"]


def _facts(**over):
    facts = dict(
        demo_mode=False,
        enabled_integrations=[],
        categories=CATEGORIES,
        federation_sources=0,
        alerts=0,
        provider_ready=False,
        gateway_routable=False,
        executor_integrations=EXECUTORS,
        notify_route=False,
    )
    facts.update(over)
    return facts


def _items(verdict):
    return {i["id"]: i for i in verdict["items"]}


def test_an_empty_install_is_not_ready_and_says_what_is_missing():
    verdict = build_readiness(**_facts())
    assert verdict["ready"] is False
    assert verdict["missing"] == ["data", "model"]
    assert verdict["recommended_missing"] == ["executor", "notify"]
    items = _items(verdict)
    assert items["data"]["required"] and not items["data"]["ready"]
    assert "cannot act" in items["executor"]["detail"]


def test_an_install_with_an_alert_source_and_a_model_is_ready():
    verdict = build_readiness(**_facts(enabled_integrations=["splunk"], provider_ready=True))
    assert verdict["ready"] is True and verdict["missing"] == []
    assert verdict["recommended_missing"] == ["executor", "notify"]


def test_a_non_alert_integration_is_not_a_data_source():
    verdict = build_readiness(**_facts(enabled_integrations=["virustotal", "slack"]))
    assert "data" in verdict["missing"]


@pytest.mark.parametrize(
    "over",
    [{"demo_mode": True}, {"federation_sources": 1}, {"alerts": 3}],
)
def test_demo_data_collection_or_ingested_alerts_count_as_data(over):
    assert "data" not in build_readiness(**_facts(**over))["missing"]


def test_a_routable_gateway_key_is_a_model_and_an_unreachable_gateway_says_so():
    assert "model" not in build_readiness(**_facts(gateway_routable=True))["missing"]
    unreachable = _items(build_readiness(**_facts(gateway_routable=None)))["model"]
    assert not unreachable["ready"] and "could not be reached" in unreachable["detail"]


def test_an_enabled_executor_integration_and_a_notify_route_fill_the_recommended():
    verdict = build_readiness(
        **_facts(enabled_integrations=["splunk", "palo-alto"], provider_ready=True,
                 notify_route=True)
    )
    assert verdict["recommended_missing"] == []


def test_progress_reads_unstarted_and_malformed_rows_as_not_started():
    for value in (None, "x", {"furthest": 9}, {"passed": ["a"]}):
        progress = read_progress(value)
        assert progress["started"] is False and progress["status"] == "in_progress"
        assert progress["furthest"] == 1 and progress["passed"] == []


def test_completed_is_only_recorded_when_ready():
    write = SetupProgressWrite(furthest=5, passed=[1, 2, 3, 4, 5], status="completed")
    stored = next_progress(None, write, actor="ada", now="t1", ready=False)
    assert stored["status"] == "deferred" and stored["completed_at"] is None
    stored = next_progress(None, write, actor="ada", now="t1", ready=True)
    assert stored["status"] == "completed"
    assert (stored["completed_by"], stored["completed_at"]) == ("ada", "t1")
    # A later save keeps who finished it first.
    again = next_progress(stored, write, actor="bob", now="t2", ready=True)
    assert (again["completed_by"], again["completed_at"]) == ("ada", "t1")
    assert again["updated_by"] == "bob"


def test_progress_write_validates_step_numbers():
    with pytest.raises(ValueError):
        SetupProgressWrite(furthest=6)
    with pytest.raises(ValueError):
        SetupProgressWrite(passed=[0])
    assert SetupProgressWrite(passed=[3, 1, 3]).passed == [1, 3]
