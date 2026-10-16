"""Containment always waits for a person, whatever the tier (W0.32, gap T1).

The console says host isolation, disabling or locking an account and blocking
on a firewall always need a person. These tests hold the code to that for every
action id an executor exposes: a stored Autonomous row with everything else in
its favour (reversible, full confidence, a holding bound, a ttl) still decides
``approve``, and a person cannot raise one to Autonomous.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

from core.autonomy import AutonomyController, PromotionRefused
from core.autonomy.tiers import (
    ACTION_CLASSES,
    ALWAYS_HUMAN,
    APPROVE,
    AUTONOMOUS,
    AUTONOMOUS_ELIGIBLE,
    TierEntry,
)
from core.contracts.verdict import CATEGORIES
from core.response.executors.wiring import EXECUTOR_SOURCES
from tests.unit.response._autonomy import MemoryTierStore, bounds

pytestmark = pytest.mark.unit

EVIDENCE = "https://console.example/scorecard?category=network"


def _executor_action_types() -> dict[str, frozenset[str]]:
    """Every executor class in every EXECUTOR_SOURCES module -> its action ids.

    Read from the classes, not built: a factory needs credentials.
    """
    found: dict[str, frozenset[str]] = {}
    for source in EXECUTOR_SOURCES:
        module = importlib.import_module(source.module)
        for name, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ != module.__name__:
                continue
            types = getattr(cls, "action_types", None)
            if isinstance(types, frozenset) and types:
                found[f"{source.module}.{name}"] = types
    return found


EXECUTORS = _executor_action_types()
EXECUTOR_TYPES = sorted(set().union(*EXECUTORS.values()))


def _autonomous_everywhere(action_type: str) -> AutonomyController:
    store = MemoryTierStore(
        [
            TierEntry(
                category=c,
                action_type=action_type,
                tier=AUTONOMOUS,
                min_confidence=0.0,
                max_ttl_seconds=3600,
                explicit=True,
            )
            for c in CATEGORIES
        ]
    )
    return AutonomyController(store=store, bound_reader=bounds(True))


def test_every_executor_source_exposes_its_action_ids():
    modules = {key.rsplit(".", 1)[0] for key in EXECUTORS}
    assert modules == {source.module for source in EXECUTOR_SOURCES}
    assert set(EXECUTOR_TYPES) <= set(ACTION_CLASSES)


def test_the_promised_containment_is_always_human():
    # The console's wording (shared/alwaysHuman.ts) names these.
    for action_type in ("isolate_host", "disable_user", "block_ip", "waf_block"):
        assert action_type in ALWAYS_HUMAN
        assert action_type not in AUTONOMOUS_ELIGIBLE
    assert not ALWAYS_HUMAN & AUTONOMOUS_ELIGIBLE
    assert ALWAYS_HUMAN <= set(ACTION_CLASSES)


@pytest.mark.parametrize("action_type", EXECUTOR_TYPES)
def test_no_executor_action_is_autonomous_unless_eligible(action_type):
    controller = _autonomous_everywhere(action_type)
    for category in CATEGORIES:
        decision = controller.decide(
            category=category,
            action_type=action_type,
            reversibility="reversible",
            confidence=1.0,
        )
        assert decision is not None
        if action_type in AUTONOMOUS_ELIGIBLE and category != "other":
            continue
        assert decision.effective == APPROVE, (action_type, category)
        assert not decision.autonomous


@pytest.mark.parametrize("action_type", sorted(ALWAYS_HUMAN))
def test_isolation_and_other_containment_is_never_autonomous(action_type):
    controller = _autonomous_everywhere(action_type)
    for category in CATEGORIES:
        decision = controller.decide(
            category=category,
            action_type=action_type,
            reversibility="reversible",
            confidence=1.0,
        )
        assert decision.configured == AUTONOMOUS
        assert decision.effective == APPROVE
        assert any("containment" in reason for reason in decision.reasons)


@pytest.mark.parametrize("action_type", sorted(ALWAYS_HUMAN))
def test_a_person_cannot_raise_containment_to_autonomous(action_type):
    controller = AutonomyController(store=MemoryTierStore(), bound_reader=bounds(True))
    with pytest.raises(PromotionRefused, match="containment"):
        controller.set_tier(
            category="network",
            action_type=action_type,
            tier=AUTONOMOUS,
            actor="alice",
            actor_is_human=True,
            reason="Scorecard met",
            evidence_url=EVIDENCE,
            min_confidence=0.9,
            max_ttl_seconds=3600,
        )


def test_the_matrix_reports_containment_as_always_human():
    matrix = AutonomyController(
        store=MemoryTierStore(), bound_reader=bounds(True)
    ).matrix()
    assert matrix["always_human"] == sorted(ALWAYS_HUMAN)
    for entry in matrix["entries"]:
        if entry["action_type"] in ALWAYS_HUMAN:
            assert entry["eligible"] is False
