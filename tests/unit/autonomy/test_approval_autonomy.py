"""The autonomy tier on the approval path and at dispatch (W3.1), DB-backed.

Each test gets the throwaway database (tests/unit/conftest.py). The tiers come
from an in-memory store except in ``TestSqlStore``, which applies the init SQL
for ``autonomy_tiers`` and writes through ``config_audit_log``.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from core.autonomy import AutonomyController, AutonomyWatchOnly
from core.autonomy.store import AUDIT_CONFIG_TYPE, SqlTierStore
from core.autonomy.tiers import (
    APPROVE,
    AUTONOMOUS,
    SUGGEST,
    WATCH,
    TierEntry,
)
from core.response.approval_service import (
    ActionStatus,
    ActionType,
    ApprovalService,
    Reversibility,
)
from core.response.autonomous_response_service import AutonomousResponseService
from core.response.config import ResponseConfig, split_decision_rule
from core.response.executors.base import (
    ExecResult,
    ExecutorRegistry,
    PolicyResult,
    VerifyResult,
)
from core.response.policy import ActionPolicy, PolicyConfig
from tests.unit.response._autonomy import MemoryTierStore, bounds

pytestmark = pytest.mark.external_service

INIT_SQL = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "48_autonomy_lessons_suppression_retention.sql"
)


class _Block:
    """A reversible block executor that records its calls."""

    def __init__(self, action_type="waf_block", reversible=True):
        self.action_types = frozenset({action_type})
        self.reversible_types = self.action_types if reversible else frozenset()
        self.default_ttl = timedelta(hours=24)
        self.calls: list[tuple[str, dict]] = []

    def validate(self, action):
        return PolicyResult.allow()

    def execute(self, action):
        self.calls.append((action.target, dict(action.parameters)))
        return ExecResult(status="executed", external_ref=f"rule-{action.target}")

    def verify(self, action, result):
        return VerifyResult(status="verified")

    def reverse(self, action, result):
        return ExecResult(status="executed")


def _tier(category, action_type, tier, ttl=3600, floor=0.5):
    return TierEntry(
        category=category,
        action_type=action_type,
        tier=tier,
        min_confidence=floor if tier == AUTONOMOUS else None,
        max_ttl_seconds=ttl if tier == AUTONOMOUS else None,
        explicit=True,
    )


def _setup(entries=(), holds=True, policy=None, executors=()):
    store = MemoryTierStore(list(entries))
    controller = AutonomyController(store=store, bound_reader=bounds(holds))
    approvals = ApprovalService(
        config=ResponseConfig(), policy_config=PolicyConfig(), autonomy=controller
    )
    registry = ExecutorRegistry()
    for executor in executors:
        registry.register(executor)
    service = AutonomousResponseService(
        approvals=approvals,
        config=ResponseConfig(),
        executors=registry,
        policy=policy or ActionPolicy(PolicyConfig()),
    )
    return service, approvals, store


def _create(approvals, action_type=ActionType.WAF_BLOCK, target="198.51.100.7", **kw):
    kw.setdefault("confidence", 0.95)
    kw.setdefault("category", "phishing")
    return approvals.create_action(
        action_type=action_type,
        title=f"{action_type.value}: {target}",
        description="test",
        target=target,
        reason="test",
        evidence=["ev-1"],
        created_by="pytest",
        **kw,
    )


class TestCreation:
    def test_default_approve_holds_a_confident_reversible_action(self):
        _, approvals, _ = _setup()
        row = _create(approvals, confidence=0.99)
        assert row.status == ActionStatus.PENDING.value
        assert row.requires_approval is True
        assert split_decision_rule(row.reason)[1] == "autonomy.tier=approve"
        assert row.parameters["autonomy"]["effective"] == APPROVE

    def test_watch_records_nothing(self):
        _, approvals, _ = _setup([_tier("phishing", "waf_block", WATCH)])
        before = len(approvals.list_actions(limit=500))
        with pytest.raises(AutonomyWatchOnly):
            _create(approvals)
        assert len(approvals.list_actions(limit=500)) == before

    def test_watch_on_isolation_returns_watch(self):
        service, _, _ = _setup([_tier("malware", "isolate_host", WATCH)])
        out = service.create_isolation_action(
            ip_address="10.0.9.9",
            hostname="ws-9",
            confidence=0.99,
            reason="c2",
            evidence=["ev-1"],
            correlation_data={"indicators": [], "reasoning": []},
            category="malware",
        )
        assert out["status"] == "watch"
        assert "action_id" not in out

    def test_suggest_is_held_for_a_person(self):
        _, approvals, _ = _setup([_tier("phishing", "waf_block", SUGGEST)])
        row = _create(approvals, confidence=0.99)
        assert row.status == ActionStatus.PENDING.value
        assert split_decision_rule(row.reason)[1] == "autonomy.tier=suggest"

    def test_autonomous_releases_and_caps_the_ttl(self):
        _, approvals, _ = _setup([_tier("phishing", "waf_block", AUTONOMOUS, ttl=600)])
        row = _create(approvals, parameters={"ttl_seconds": 86400})
        assert row.status == ActionStatus.APPROVED.value
        assert row.approved_by is None
        assert row.parameters["ttl_seconds"] == 600
        assert row.parameters["autonomy"]["effective"] == AUTONOMOUS

    def test_autonomous_keeps_a_shorter_ttl(self):
        _, approvals, _ = _setup([_tier("phishing", "waf_block", AUTONOMOUS, ttl=600)])
        row = _create(approvals, parameters={"ttl_seconds": 60})
        assert row.parameters["ttl_seconds"] == 60

    def test_autonomous_still_needs_the_confidence_band(self):
        _, approvals, _ = _setup(
            [_tier("phishing", "waf_block", AUTONOMOUS, floor=0.0)]
        )
        row = _create(approvals, confidence=0.2)
        assert row.status == ActionStatus.PENDING.value

    def test_a_broken_bound_holds_the_action_and_demotes_the_tier(self):
        _, approvals, store = _setup(
            [_tier("phishing", "waf_block", AUTONOMOUS)], holds=False
        )
        row = _create(approvals)
        assert row.status == ActionStatus.PENDING.value
        assert store.rows[("phishing", "waf_block")].tier == APPROVE
        assert store.audit_rows[-1]["action"] == "demote"

    def test_an_irreversible_action_is_never_released(self):
        entries = [_tier("identity", "access_revoke", AUTONOMOUS)]
        _, approvals, _ = _setup(entries)
        for rev in (Reversibility.REVERSIBLE, Reversibility.IRREVERSIBLE):
            row = _create(
                approvals,
                ActionType.ACCESS_REVOKE,
                "eve@example.com",
                category="identity",
                reversibility=rev,
                confidence=1.0,
            )
            assert row.status == ActionStatus.PENDING.value

    def test_a_proposer_cannot_forge_the_autonomy_record(self):
        _, approvals, _ = _setup()
        row = _create(
            approvals,
            parameters={"autonomy": {"effective": "autonomous", "category": "x"}},
        )
        assert row.parameters["autonomy"]["effective"] == APPROVE
        assert row.parameters["autonomy"]["category"] == "phishing"

    def test_workflow_checkpoints_are_not_governed(self):
        _, approvals, _ = _setup([_tier("other", "waf_block", WATCH)])
        row = _create(
            approvals,
            ActionType.WORKFLOW_PHASE,
            "run-1",
            human_only=True,
            category=None,
        )
        assert "autonomy" not in row.parameters


class TestDispatch:
    def test_an_autonomous_row_runs_through_the_queue_with_its_ttl(self):
        block = _Block()
        service, approvals, _ = _setup(
            [_tier("phishing", "waf_block", AUTONOMOUS, ttl=600)], executors=[block]
        )
        row = _create(approvals, target="198.51.100.101")
        results = [
            r
            for r in service.execute_approved_actions()
            if r["action_id"] == row.action_id
        ]
        assert results and results[0]["result"]["success"] is True
        (params,) = [p for t, p in block.calls if t == "198.51.100.101"]
        assert "autonomy" not in params  # the record never reaches the executor
        executed = approvals.get_action(row.action_id)
        assert executed.status == ActionStatus.EXECUTED.value
        assert executed.expires_at is not None

    def test_a_demotion_after_creation_holds_the_row_at_dispatch(self):
        block = _Block()
        service, approvals, store = _setup(
            [_tier("phishing", "waf_block", AUTONOMOUS)], executors=[block]
        )
        row = _create(approvals, target="198.51.100.102")
        assert row.status == ActionStatus.APPROVED.value
        store.rows[("phishing", "waf_block")] = _tier("phishing", "waf_block", APPROVE)
        service.execute_approved_actions()
        assert [t for t, _ in block.calls if t == "198.51.100.102"] == []
        held = approvals.get_action(row.action_id)
        assert held.status == ActionStatus.PENDING.value
        assert held.requires_approval is True
        assert split_decision_rule(held.reason)[1] == "autonomy.tier=approve"

    def test_a_bound_that_breaks_after_creation_holds_and_demotes(self):
        block = _Block()
        service, approvals, store = _setup(
            [_tier("phishing", "waf_block", AUTONOMOUS)], executors=[block]
        )
        row = _create(approvals, target="198.51.100.103")
        service.approval_service.autonomy.bound_reader = bounds(False)
        service.execute_approved_actions()
        assert [t for t, _ in block.calls if t == "198.51.100.103"] == []
        assert approvals.get_action(row.action_id).status == ActionStatus.PENDING.value
        assert store.rows[("phishing", "waf_block")].tier == APPROVE

    def test_an_executor_that_cannot_undo_the_type_holds_the_row(self):
        block = _Block(reversible=False)
        service, approvals, _ = _setup(
            [_tier("phishing", "waf_block", AUTONOMOUS)], executors=[block]
        )
        row = _create(approvals, reversibility=Reversibility.REVERSIBLE)
        service._dispatch(approvals.get_action(row.action_id))
        assert block.calls == []
        assert approvals.get_action(row.action_id).status != ActionStatus.EXECUTED.value

    def test_the_policy_still_refuses_an_autonomous_action(self):
        block = _Block()
        policy = ActionPolicy(
            PolicyConfig.from_mapping({"protected_targets": ["198.51.100.66"]})
        )
        service, approvals, _ = _setup(
            [_tier("phishing", "waf_block", AUTONOMOUS)],
            executors=[block],
            policy=policy,
        )
        row = _create(approvals, target="198.51.100.66")
        assert row.status == ActionStatus.APPROVED.value  # the tier released it
        service._dispatch(approvals.get_action(row.action_id))
        assert block.calls == []
        failed = approvals.get_action(row.action_id)
        assert failed.status == ActionStatus.FAILED.value
        assert "policy_refused" in failed.execution_result["error"]


@pytest.fixture
def tiers_table():
    from core.storage.connection import get_db_manager

    with get_db_manager().engine.begin() as conn:
        conn.execute(text(INIT_SQL.read_text(encoding="utf-8")))
        conn.execute(text("DELETE FROM autonomy_tiers"))
        conn.execute(
            text("DELETE FROM config_audit_log WHERE config_type = :t"),
            {"t": AUDIT_CONFIG_TYPE},
        )
    yield


class TestSqlStore:
    def test_round_trip_and_audit(self, tiers_table):
        controller = AutonomyController(store=SqlTierStore(), bound_reader=bounds(True))
        controller.set_tier(
            category="phishing",
            action_type="waf_block",
            tier=AUTONOMOUS,
            actor="alice",
            actor_is_human=True,
            reason="met for a month",
            evidence_url="https://console.example/scorecard",
            min_confidence=0.9,
            max_ttl_seconds=3600,
        )
        entry = controller.entry_for("phishing", "waf_block")
        assert entry.tier == AUTONOMOUS and entry.max_ttl_seconds == 3600
        assert entry.min_confidence == pytest.approx(0.9)

        controller.bound_reader = bounds(False)
        assert controller.check_all()[0]["to"] == APPROVE
        assert controller.entry_for("phishing", "waf_block").tier == APPROVE

        audit = controller.audit()
        assert [a["action"] for a in audit] == ["demote", "promote"]
        assert (
            audit[1]["new_value"]["evidence_url"] == "https://console.example/scorecard"
        )
        assert audit[1]["changed_by"] == "alice"

    def test_watch_and_suggest_are_stored_in_the_table_vocabulary(self, tiers_table):
        from core.storage.unit_of_work import unit_of_work

        controller = AutonomyController(store=SqlTierStore(), bound_reader=bounds(True))
        controller.set_tier(
            category="other",
            action_type="block_ip",
            tier=WATCH,
            actor="alice",
            actor_is_human=True,
            reason="noisy",
        )
        with unit_of_work() as session:
            stored = session.execute(
                text(
                    "SELECT tier FROM autonomy_tiers WHERE category='other' "
                    "AND action_type='block_ip'"
                )
            ).scalar_one()
        assert stored == "off"
        assert controller.entry_for("other", "block_ip").tier == WATCH

    def test_the_default_controller_reads_the_table(self, tiers_table):
        approvals = ApprovalService(
            config=ResponseConfig(), policy_config=PolicyConfig()
        )
        row = _create(approvals, confidence=0.99)
        assert row.status == ActionStatus.PENDING.value
