"""The autonomy controller's rules, without a database (W3.1).

Property-style: the decision is checked over the whole grid of categories,
action classes, reversibilities, confidences, stored tiers and bounds, plus a
seeded random sweep, for the invariant that matters: nothing irreversible, and
nothing outside the eligible classes, is ever autonomous.
"""

from __future__ import annotations

import itertools
import math
import random

import pytest

from core.autonomy import AutonomyController, PromotionRefused
from core.autonomy.bounds import BoundStatus, judge
from core.autonomy.categories import (
    MITRE_TECHNIQUE_CATEGORY,
    category_of,
    resolve_category,
)
from core.autonomy.controller import BREAKER_ACTOR
from core.autonomy.tiers import (
    ACTION_CLASSES,
    ANY_CATEGORY,
    APPROVE,
    AUTONOMOUS,
    AUTONOMOUS_ELIGIBLE,
    AUTONOMOUS_MAX_TTL_SECONDS,
    DEFAULT_TIER,
    FROM_DB,
    NEVER_AUTONOMOUS_CATEGORIES,
    SUGGEST,
    TIER_CATEGORIES,
    TIERS,
    TO_DB,
    TRIAGE_TO_AUTONOMY,
    WATCH,
    TierEntry,
)
from core.contracts.verdict import CATEGORIES
from core.response.approval_service import ActionType
from tests.unit.response._autonomy import MemoryTierStore, bounds

pytestmark = pytest.mark.unit

EVIDENCE = "https://console.example/scorecard?category=phishing"


def _auto(category="phishing", action_type="waf_block", ttl=3600, floor=0.5):
    return TierEntry(
        category=category,
        action_type=action_type,
        tier=AUTONOMOUS,
        min_confidence=floor,
        max_ttl_seconds=ttl,
        explicit=True,
    )


def _controller(entries=(), holds=True):
    store = MemoryTierStore(list(entries))
    return AutonomyController(store=store, bound_reader=bounds(holds)), store


class TestVocabulary:
    def test_action_classes_are_the_response_types_bar_workflow_phase(self):
        types = {t.value for t in ActionType} - {ActionType.WORKFLOW_PHASE.value}
        assert set(ACTION_CLASSES) == types

    def test_irreversible_and_identity_classes_are_not_eligible(self):
        for never in (
            "access_revoke",
            "disable_user",
            "revoke_sessions",
            "quarantine_file",
            "execute_spl_query",
            "unblock_ip",
            "unisolate_host",
            "enable_user",
            "custom",
        ):
            assert never not in AUTONOMOUS_ELIGIBLE
        assert AUTONOMOUS_ELIGIBLE <= set(ACTION_CLASSES)

    def test_stored_tier_names_round_trip(self):
        for tier in TIERS:
            assert FROM_DB[TO_DB[tier]] == tier
        assert FROM_DB["two_person"] == APPROVE

    def test_every_triage_category_has_an_explicit_mapping(self):
        # The W1.2 verdict schema's enum is the triage vocabulary.
        assert set(TRIAGE_TO_AUTONOMY) == set(CATEGORIES)
        assert set(TRIAGE_TO_AUTONOMY.values()) <= set(CATEGORIES)
        assert set(MITRE_TECHNIQUE_CATEGORY.values()) <= set(CATEGORIES)
        assert TRIAGE_TO_AUTONOMY["other"] in NEVER_AUTONOMOUS_CATEGORIES

    def test_category_of_maps_triage_categories_and_nothing_else(self):
        for triage in CATEGORIES:
            assert category_of({"category": triage}) == TRIAGE_TO_AUTONOMY[triage]
        assert category_of({"category": "Phishing"}) == "phishing"
        assert category_of({"verdict": {"category": "identity"}}) == "identity"
        assert category_of({"category": "ransomware"}) == "other"
        assert category_of({"category": "network\u200b"}) == "other"
        assert category_of(None) == "other"
        # Sender-chosen metadata is not a category source.
        assert category_of({"metadata": {"category": "cloud"}}) == "other"


class TestSensorCategories:
    """Round 5: sensor-authored fields outrank the model's category."""

    def test_sensor_mitre_outranks_the_verdict(self):
        finding = {
            "data_source": "splunk",
            "mitre_predictions": {"T1566.001": 0.9},
            "category": "network",
        }
        assert resolve_category(finding) == ("phishing", "sensor")

    def test_webhook_mitre_is_not_sensor_authored(self):
        finding = {
            "data_source": "webhook",
            "mitre_predictions": {"T1566": 0.9},
            "category": "network",
        }
        assert resolve_category(finding) == ("network", "triage")

    def test_data_source_fixes_the_category(self):
        finding = {"data_source": "aws_security_hub", "category": "phishing"}
        assert resolve_category(finding) == ("cloud", "sensor")

    def test_ambiguous_sensor_fields_take_the_verdict_only_among_them(self):
        base = {
            "data_source": "elastic",
            "mitre_predictions": {"T1566": 0.5, "T1071": 0.5},
        }
        assert category_of({**base, "category": "network"}) == "network"
        assert category_of({**base, "category": "cloud"}) == "other"

    def test_no_signal_is_other(self):
        assert resolve_category({"data_source": "splunk"}) == ("other", "none")
        assert category_of({"mitre_predictions": "garbage"}) == "other"


class TestDefaults:
    def test_ga_default_is_approve_everywhere(self):
        controller, _ = _controller()
        assert DEFAULT_TIER == APPROVE
        for category, action_type in itertools.product(CATEGORIES, ACTION_CLASSES):
            d = controller.decide(
                category=category,
                action_type=action_type,
                reversibility="reversible",
                confidence=1.0,
            )
            assert d.configured == APPROVE and d.effective == APPROVE

    def test_workflow_checkpoints_are_not_governed(self):
        controller, _ = _controller()
        assert (
            controller.decide(
                category="other",
                action_type="workflow_phase",
                reversibility="reversible",
                confidence=0.0,
            )
            is None
        )

    def test_the_star_row_applies_to_unnamed_categories(self):
        star = TierEntry(ANY_CATEGORY, "block_ip", tier=WATCH, explicit=True)
        controller, _ = _controller([star])
        d = controller.decide(
            category="malware",
            action_type="block_ip",
            reversibility="reversible",
            confidence=0.9,
        )
        assert d.effective == WATCH

    def test_an_unreadable_store_means_approve(self):
        class Broken(MemoryTierStore):
            def entries(self):
                raise RuntimeError("db down")

        controller = AutonomyController(store=Broken(), bound_reader=bounds(True))
        d = controller.decide(
            category="phishing",
            action_type="waf_block",
            reversibility="reversible",
            confidence=1.0,
        )
        assert d.effective == APPROVE


class TestAutonomousEligibility:
    def test_eligible_reversible_confident_with_a_holding_bound_is_autonomous(self):
        controller, _ = _controller([_auto()])
        d = controller.decide(
            category="phishing",
            action_type="waf_block",
            reversibility="reversible",
            confidence=0.9,
        )
        assert d.autonomous and d.ttl_seconds == 3600

    @pytest.mark.parametrize(
        "kwargs,why",
        [
            ({"reversibility": "irreversible"}, "reversibility"),
            ({"reversibility": None}, "reversibility"),
            ({"four_eyes": True}, "two approvers"),
            ({"confidence": 0.1}, "below the tier floor"),
            ({"confidence": float("nan")}, "below the tier floor"),
            ({"confidence": True}, "below the tier floor"),
            ({"confidence": 7.0}, "below the tier floor"),
        ],
    )
    def test_any_failing_condition_falls_back_to_approve(self, kwargs, why):
        controller, store = _controller([_auto()])
        args = dict(
            category="phishing",
            action_type="waf_block",
            reversibility="reversible",
            confidence=0.9,
        )
        args.update(kwargs)
        d = controller.decide(**args)
        assert d.effective == APPROVE
        assert any(why in r for r in d.reasons)
        # An ineligible action is not a broken bound: the tier stays.
        assert store.rows[("phishing", "waf_block")].tier == AUTONOMOUS

    def test_a_tier_without_a_ttl_is_never_autonomous(self):
        controller, _ = _controller([_auto(ttl=None)])
        d = controller.decide(
            category="phishing",
            action_type="waf_block",
            reversibility="reversible",
            confidence=0.9,
        )
        assert d.effective == APPROVE

    def test_a_star_row_is_never_autonomous(self):
        controller, _ = _controller([_auto(category=ANY_CATEGORY)])
        d = controller.decide(
            category="phishing",
            action_type="waf_block",
            reversibility="reversible",
            confidence=0.9,
        )
        assert d.effective == APPROVE


class TestNoPathMakesIrreversibleAutonomous:
    """Property: autonomous => eligible class, reversible, one approver, bound holds."""

    CONFIDENCES = (0.0, 0.5, 0.99, 1.0, -1.0, 2.0, float("nan"), float("inf"), True)
    REVERSIBILITIES = ("reversible", "irreversible", None, "", "REVERSIBLE")

    def _check(self, controller, category, action_type, rev, conf, four_eyes, holds):
        d = controller.decide(
            category=category,
            action_type=action_type,
            reversibility=rev,
            confidence=conf,
            four_eyes=four_eyes,
        )
        if d is None:
            assert action_type not in ACTION_CLASSES
            return
        if d.autonomous:
            assert action_type in AUTONOMOUS_ELIGIBLE
            assert rev == "reversible"
            assert not four_eyes
            assert holds
            assert isinstance(conf, float) and math.isfinite(conf)
            assert 0.0 <= conf <= 1.0
            assert d.ttl_seconds and 0 < d.ttl_seconds <= AUTONOMOUS_MAX_TTL_SECONDS
            assert d.category not in NEVER_AUTONOMOUS_CATEGORIES
            assert d.category != ANY_CATEGORY

    def test_exhaustive_grid(self):
        types = (*ACTION_CLASSES, "workflow_phase", "nuke_everything")
        for holds in (True, False):
            # Every class stored autonomous in every category, '*' included:
            # what a direct database write could leave behind.
            entries = [
                _auto(category=c, action_type=a, ttl=ttl, floor=0.0)
                for c in TIER_CATEGORIES
                for a in types
                for ttl in (3600,)
            ]
            for category, action_type, rev, conf, four_eyes in itertools.product(
                (*CATEGORIES, "*", "unknown"),
                types,
                self.REVERSIBILITIES,
                self.CONFIDENCES,
                (False, True),
            ):
                controller, _ = _controller(entries, holds=holds)
                self._check(
                    controller, category, action_type, rev, conf, four_eyes, holds
                )

    def test_random_sweep(self):
        rng = random.Random(3101)
        types = (*ACTION_CLASSES, "x")
        for _ in range(3000):
            holds = rng.random() < 0.7
            entries = [
                TierEntry(
                    category=rng.choice(TIER_CATEGORIES),
                    action_type=rng.choice(types),
                    tier=rng.choice(TIERS),
                    min_confidence=rng.choice((None, 0.0, 0.5, 1.0)),
                    max_ttl_seconds=rng.choice(
                        (None, 0, 60, 3600, AUTONOMOUS_MAX_TTL_SECONDS + 1)
                    ),
                    explicit=True,
                )
                for _ in range(rng.randint(0, 12))
            ]
            controller, _ = _controller(entries, holds=holds)
            self._check(
                controller,
                rng.choice((*CATEGORIES, "*")),
                rng.choice(types),
                rng.choice(self.REVERSIBILITIES),
                rng.choice(self.CONFIDENCES),
                rng.random() < 0.3,
                holds,
            )

    @pytest.mark.parametrize(
        "action_type", sorted(set(ACTION_CLASSES) - AUTONOMOUS_ELIGIBLE)
    )
    def test_set_tier_refuses_autonomous_for_every_ineligible_class(self, action_type):
        controller, store = _controller()
        with pytest.raises(PromotionRefused) as e:
            controller.set_tier(
                category="phishing",
                action_type=action_type,
                tier=AUTONOMOUS,
                actor="alice",
                actor_is_human=True,
                reason="try",
                evidence_url=EVIDENCE,
                min_confidence=0.5,
                max_ttl_seconds=3600,
            )
        assert e.value.code == "invalid"
        assert store.rows == {}


class TestCircuitBreaker:
    def test_a_broken_bound_demotes_the_tier_and_audits_it(self):
        controller, store = _controller([_auto()], holds=False)
        d = controller.decide(
            category="phishing",
            action_type="waf_block",
            reversibility="reversible",
            confidence=0.9,
        )
        assert d.effective == APPROVE and d.demoted
        assert store.rows[("phishing", "waf_block")].tier == APPROVE
        (row,) = store.audit_rows
        assert row["action"] == "demote"
        assert row["changed_by"] == BREAKER_ACTOR
        assert "circuit breaker" in row["reason"]

    def test_the_demotion_sticks_when_the_bound_recovers(self):
        controller, store = _controller([_auto()], holds=False)
        controller.decide(
            category="phishing",
            action_type="waf_block",
            reversibility="reversible",
            confidence=0.9,
        )
        controller.bound_reader = bounds(True)
        d = controller.decide(
            category="phishing",
            action_type="waf_block",
            reversibility="reversible",
            confidence=0.9,
        )
        assert d.configured == APPROVE and d.effective == APPROVE

    def test_an_unreadable_bound_refuses_but_does_not_demote(self):
        def broken():
            raise RuntimeError("qa_samples missing")

        store = MemoryTierStore([_auto()])
        controller = AutonomyController(store=store, bound_reader=broken)
        d = controller.decide(
            category="phishing",
            action_type="waf_block",
            reversibility="reversible",
            confidence=0.9,
        )
        assert d.effective == APPROVE and not d.demoted
        assert store.rows[("phishing", "waf_block")].tier == AUTONOMOUS
        assert controller.check_all() == []

    def test_check_all_demotes_only_the_broken_categories(self):
        def read():
            return {
                "phishing": judge("phishing", 299, 0, 0.00997),
                "malware": judge("malware", 400, 3, 0.019),
            }

        store = MemoryTierStore(
            [_auto("phishing"), _auto("malware"), _auto("identity", "block_ip")]
        )
        controller = AutonomyController(store=store, bound_reader=read)
        demoted = controller.check_all()
        assert {(d["category"], d["action_type"]) for d in demoted} == {
            ("malware", "waf_block"),
            ("identity", "block_ip"),
        }
        assert store.rows[("phishing", "waf_block")].tier == AUTONOMOUS
        assert store.rows[("malware", "waf_block")].tier == APPROVE

    def test_the_w16_bar(self):
        assert judge("phishing", 299, 0, 0.00997).holds
        assert not judge("phishing", 298, 0, 0.01).holds  # too few reviews
        assert not judge("phishing", 1000, 8, 0.0151).holds  # bound above 1%
        assert isinstance(judge("x", 0, 0, 1.0), BoundStatus)


class TestPromotion:
    def _promote(self, controller, **over):
        args = dict(
            category="phishing",
            action_type="waf_block",
            tier=AUTONOMOUS,
            actor="alice",
            actor_is_human=True,
            reason="Scorecard met for 4 weeks",
            evidence_url=EVIDENCE,
            min_confidence=0.9,
            max_ttl_seconds=3600,
        )
        args.update(over)
        return controller.set_tier(**args)

    def test_a_person_with_evidence_and_a_holding_bound_promotes(self):
        controller, store = _controller()
        entry = self._promote(controller)
        assert entry.tier == AUTONOMOUS
        (row,) = store.audit_rows
        assert row["action"] == "promote"
        assert row["new_value"]["evidence_url"] == EVIDENCE
        assert row["changed_by"] == "alice"

    def test_not_a_person_cannot_raise_any_tier(self):
        controller, store = _controller()
        for tier in (AUTONOMOUS,):
            with pytest.raises(PromotionRefused) as e:
                self._promote(controller, tier=tier, actor_is_human=False)
            assert e.value.code == "actor"
        controller2, _ = _controller(
            [TierEntry("phishing", "waf_block", WATCH, explicit=True)]
        )
        with pytest.raises(PromotionRefused) as e:
            controller2.set_tier(
                category="phishing",
                action_type="waf_block",
                tier=SUGGEST,
                actor="agent",
                actor_is_human=False,
                reason="r",
                evidence_url=EVIDENCE,
            )
        assert e.value.code == "actor"
        assert store.rows == {}

    def test_lowering_needs_no_person_or_evidence(self):
        controller, store = _controller([_auto()])
        entry = controller.set_tier(
            category="phishing",
            action_type="waf_block",
            tier=WATCH,
            actor="system:x",
            actor_is_human=False,
            reason="pause",
        )
        assert entry.tier == WATCH
        assert store.audit_rows[-1]["action"] == "demote"

    @pytest.mark.parametrize(
        "over",
        [
            {"evidence_url": None},
            {"evidence_url": "javascript:alert(1)"},
            {"evidence_url": "not a url"},
            {"evidence_url": "http://console.example/scorecard"},
            {"evidence_url": "https://"},
            {"evidence_url": "https:///path"},
            {"evidence_url": "https://console.example/score card"},
            {"evidence_url": "https://console.example/\tx"},
            {"evidence_url": "https://user@console.example/"},
            {"evidence_url": "https://console.example:99999/"},
            {"evidence_url": "//console.example/x"},
            {"evidence_url": "ftp://console.example/x"},
            {"category": "other"},
            {"category": ANY_CATEGORY},
            {"max_ttl_seconds": None},
            {"max_ttl_seconds": 0},
            {"max_ttl_seconds": AUTONOMOUS_MAX_TTL_SECONDS + 1},
            {"min_confidence": None},
            {"min_confidence": 1.5},
            {"reason": "  "},
            {"category": "ransomware"},
            {"tier": "yolo"},
        ],
    )
    def test_invalid_promotions_are_refused(self, over):
        controller, store = _controller()
        with pytest.raises(PromotionRefused) as e:
            self._promote(controller, **over)
        assert e.value.code == "invalid"
        assert store.rows == {}

    def test_a_bound_that_does_not_hold_refuses_autonomous(self):
        controller, store = _controller(holds=False)
        with pytest.raises(PromotionRefused) as e:
            self._promote(controller)
        assert e.value.code == "bound"
        assert store.rows == {}

    def test_raising_from_a_star_watch_needs_evidence(self):
        star = TierEntry(ANY_CATEGORY, "waf_block", WATCH, explicit=True)
        controller, _ = _controller([star])
        with pytest.raises(PromotionRefused):
            controller.set_tier(
                category="phishing",
                action_type="waf_block",
                tier=APPROVE,
                actor="alice",
                actor_is_human=True,
                reason="r",
            )

    def test_matrix_lists_every_pair(self):
        controller, _ = _controller([_auto()])
        m = controller.matrix()
        assert len(m["entries"]) == len(TIER_CATEGORIES) * len(ACTION_CLASSES)
        row = next(
            e
            for e in m["entries"]
            if e["category"] == "phishing" and e["action_type"] == "waf_block"
        )
        assert row["tier"] == AUTONOMOUS and row["explicit"] and row["eligible"]
        assert m["default_tier"] == APPROVE
        assert m["bounds"]["phishing"]["holds"] is True


class TestOtherIsNeverAutonomous:
    """Round 5: ``other`` (unknown, unmapped, ambiguous) is never autonomous."""

    def test_a_stored_autonomous_other_row_decides_approve(self):
        controller, _ = _controller([_auto(category="other")])
        for category in ("other", "ransomware", None, ""):
            d = controller.decide(
                category=category,
                action_type="waf_block",
                reversibility="reversible",
                confidence=1.0,
            )
            assert d.effective == APPROVE
            assert any("never autonomous" in r for r in d.reasons)

    def test_check_all_demotes_a_stored_autonomous_other_row(self):
        controller, store = _controller([_auto(category="other")])
        (demoted,) = controller.check_all()
        assert demoted["category"] == "other" and demoted["to"] == APPROVE
        assert store.rows[("other", "waf_block")].tier == APPROVE

    def test_the_matrix_marks_other_ineligible(self):
        controller, _ = _controller()
        rows = [e for e in controller.matrix()["entries"] if e["category"] == "other"]
        assert rows and not any(r["eligible"] for r in rows)
