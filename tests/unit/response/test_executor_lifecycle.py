"""Four-eyes approval and the TTL reverse + verify lifecycle on approval_actions (W2.4).

DB-backed: each test gets a throwaway database (tests/unit/conftest.py).
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from core.response.approval_service import (
    ActionStatus,
    ActionType,
    ApprovalService,
    Reversibility,
    SecondApproverConflict,
)
from core.response.autonomous_response_service import (
    TTL_SWEEP_ACTOR,
    AutonomousResponseService,
)
from core.response.config import ResponseConfig
from core.response.executors.base import (
    ExecResult,
    ExecutorRegistry,
    PolicyResult,
    VerifyResult,
)
from core.response.policy import ActionPolicy, PolicyConfig
from core.time import utcnow

pytestmark = pytest.mark.external_service


class _Block:
    """A reversible block that remembers what is in effect."""

    def __init__(
        self, action_type="waf_block", reversible=True, ttl=timedelta(hours=1)
    ):
        self.action_types = frozenset({action_type})
        self.reversible_types = self.action_types if reversible else frozenset()
        self.default_ttl = ttl
        self.in_effect: set[str] = set()
        self.calls: list[str] = []
        self.reverse_verifies_as = None

    def validate(self, action):
        return PolicyResult.allow()

    def execute(self, action):
        self.calls.append(f"execute:{action.target}")
        self.in_effect.add(action.target)
        return ExecResult(
            status="executed",
            external_ref=f"rule-{action.target}",
            before_state={"blocked": False},
            after_state={"blocked": True},
        )

    def verify(self, action, result):
        self.calls.append(f"verify:{'reverse' if action.reverse_of else 'forward'}")
        if action.reverse_of and self.reverse_verifies_as:
            return VerifyResult(status=self.reverse_verifies_as)
        present = action.target in self.in_effect
        want = action.reverse_of is None
        return VerifyResult(status="verified" if present == want else "failed")

    def reverse(self, action, result):
        self.calls.append(f"reverse:{result.external_ref}")
        self.in_effect.discard(action.target)
        return ExecResult(
            status="executed",
            before_state=result.after_state,
            after_state=result.before_state,
        )


def _service(*executors):
    approvals = ApprovalService(config=ResponseConfig(), policy_config=PolicyConfig())
    approvals.force_manual_approval = False
    registry = ExecutorRegistry()
    for executor in executors:
        registry.register(executor)
    return AutonomousResponseService(
        approvals=approvals,
        config=ResponseConfig(),
        executors=registry,
        policy=ActionPolicy(PolicyConfig()),
    )


def _mine(results, row):
    """The database is shared by this module's tests: keep this test's rows."""
    return [r for r in results if r.get("action_id") == row.action_id]


def _create(svc: ApprovalService, action_type: ActionType, target: str, **kw):
    kw.setdefault("confidence", 0.5)
    return svc.create_action(
        action_type=action_type,
        title=f"{action_type.value}: {target}",
        description="test",
        target=target,
        reason="test",
        evidence=["ev-1"],
        created_by="pytest",
        **kw,
    )


class TestFourEyes:
    def test_two_distinct_people_approve_an_identity_action(self):
        svc = ApprovalService(config=ResponseConfig(), policy_config=PolicyConfig())
        svc.force_manual_approval = False
        # Even a confidence that would auto-approve holds it for people.
        row = _create(svc, ActionType.DISABLE_USER, "bob@example.com", confidence=0.99)
        assert row.status == ActionStatus.PENDING.value
        assert row.requires_approval is True

        first = svc.approve_action(row.action_id, "alice")
        assert first.status == ActionStatus.PENDING.value
        assert first.approved_by == "alice"

        with pytest.raises(SecondApproverConflict):
            svc.approve_action(row.action_id, "ALICE")

        second = svc.approve_action(row.action_id, "bob")
        assert second.status == ActionStatus.APPROVED.value
        assert second.approved_by == "alice"
        assert second.second_approver == "bob"

    def test_revoke_sessions_is_stored_typed_and_needs_two_people(self):
        # W2.4 verifier #6: it used to be stored as "custom", which neither
        # held it for two people at creation nor at approval.
        svc = ApprovalService(config=ResponseConfig(), policy_config=PolicyConfig())
        svc.force_manual_approval = False
        row = _create(
            svc, ActionType.REVOKE_SESSIONS, "bob@example.com", confidence=0.99
        )
        assert row.action_type == "revoke_sessions"
        assert row.status == ActionStatus.PENDING.value
        assert row.requires_approval is True
        assert svc.approve_action(row.action_id, "alice").status == "pending"
        with pytest.raises(SecondApproverConflict):
            svc.approve_action(row.action_id, "Alice ")
        assert svc.approve_action(row.action_id, "bob").second_approver == "bob"

    def test_an_ordinary_action_needs_one_approval(self):
        svc = ApprovalService(config=ResponseConfig(), policy_config=PolicyConfig())
        svc.force_manual_approval = False
        row = _create(svc, ActionType.BLOCK_IP, "203.0.113.9")
        approved = svc.approve_action(row.action_id, "alice")
        assert approved.status == ActionStatus.APPROVED.value
        assert approved.second_approver is None


class TestIrreversibleNeverAuto:
    def test_a_row_that_overstates_reversibility_is_not_executed_unapproved(self):
        revoke = _Block("access_revoke", reversible=False, ttl=None)
        service = _service(revoke)
        # The creator claims reversible with a high confidence: auto-approved.
        row = _create(
            service.approval_service,
            ActionType.ACCESS_REVOKE,
            "eve@example.com",
            confidence=0.99,
            reversibility=Reversibility.REVERSIBLE,
        )
        assert row.status == ActionStatus.APPROVED.value
        assert row.approved_by is None

        assert service.execute_approved_actions() == []
        service._dispatch(service.approval_service.get_action(row.action_id))
        assert revoke.calls == []
        failed = service.approval_service.get_action(row.action_id)
        assert failed.status == ActionStatus.FAILED.value

    def test_isolation_by_an_irreversible_executor_waits_for_a_person(self):
        edr = _Block("isolate_host", reversible=False, ttl=None)
        service = _service(edr)
        out = service.create_isolation_action(
            ip_address="10.0.7.7",
            hostname="ws-7",
            confidence=0.99,
            reason="c2",
            evidence=["ev-1"],
            correlation_data={"indicators": [], "reasoning": []},
        )
        assert out["status"] == "pending_approval"
        assert edr.calls == []
        row = service.approval_service.get_action(out["action_id"])
        assert row.reversibility == "irreversible"


class TestTtlReverseAndVerify:
    def _executed(self, service, block, target="198.51.100.20"):
        row = _create(service.approval_service, ActionType.WAF_BLOCK, target)
        service.approval_service.approve_action(row.action_id, "alice")
        results = service.execute_approved_actions()
        assert row.action_id in [r["action_id"] for r in results]
        return service.approval_service.get_action(row.action_id)

    def test_execute_records_expiry_states_and_verification(self):
        block = _Block()
        service = _service(block)
        row = self._executed(service, block)
        assert row.status == ActionStatus.EXECUTED.value
        assert row.expires_at is not None
        assert row.verify_status == "verified"
        assert row.before_state == {"blocked": False}
        assert row.after_state == {"blocked": True}
        assert row.execution_result["external_ref"] == "rule-198.51.100.20"

    def test_the_sweep_reverses_and_verifies_an_expired_action(self):
        block = _Block()
        service = _service(block)
        row = self._executed(service, block)

        assert _mine(service.sweep_expired(now=utcnow()), row) == []  # not due yet

        swept = _mine(service.sweep_expired(now=utcnow() + timedelta(hours=2)), row)
        assert [s["outcome"] for s in swept] == ["reversed"]
        assert block.calls[-2:] == [
            "reverse:rule-198.51.100.20",
            "verify:reverse",
        ]
        assert block.in_effect == set()

        original = service.approval_service.get_action(row.action_id)
        assert original.reversed_at is not None
        reverse = service.approval_service.get_action(swept[0]["reverse_action_id"])
        assert reverse.reverse_of == row.action_id
        assert reverse.status == ActionStatus.EXECUTED.value
        assert reverse.verify_status == "verified"
        assert reverse.approved_by == TTL_SWEEP_ACTOR
        assert reverse.action_type == "waf_block"

        # Done once: a later sweep finds nothing, and the reverse row is never
        # picked up as a forward action.
        assert (
            _mine(service.sweep_expired(now=utcnow() + timedelta(hours=3)), row) == []
        )
        assert swept[0]["reverse_action_id"] not in [
            r["action_id"] for r in service.execute_approved_actions()
        ]

    def test_a_reverse_that_does_not_verify_leaves_the_action_in_force(self):
        block = _Block()
        block.reverse_verifies_as = "failed"
        service = _service(block)
        row = self._executed(service, block)

        swept = _mine(service.sweep_expired(now=utcnow() + timedelta(hours=2)), row)
        assert [s["outcome"] for s in swept] == ["failed"]
        original = service.approval_service.get_action(row.action_id)
        assert original.reversed_at is None
        reverse = service.approval_service.get_action(swept[0]["reverse_action_id"])
        assert reverse.status == ActionStatus.FAILED.value
        assert reverse.verify_status == "failed"
        # Backed off: not retried on the next pass.
        assert (
            _mine(service.sweep_expired(now=utcnow() + timedelta(hours=2)), row) == []
        )

    def test_a_person_reverts_before_expiry_and_cannot_revert_twice(self):
        block = _Block()
        service = _service(block)
        row = self._executed(service, block)

        out = service.reverse_action(
            row.action_id, actor="alice", reason="false positive"
        )
        assert out["outcome"] == "reversed"
        assert out["reversed_at"] is not None
        again = service.reverse_action(row.action_id, actor="bob", reason="again")
        assert again["outcome"] == "conflict"

    def test_an_irreversible_action_cannot_be_reverted(self):
        revoke = _Block("access_revoke", reversible=False, ttl=None)
        service = _service(revoke)
        row = _create(
            service.approval_service, ActionType.ACCESS_REVOKE, "eve@example.com"
        )
        service.approval_service.approve_action(row.action_id, "alice")
        service.execute_approved_actions()
        executed = service.approval_service.get_action(row.action_id)
        assert executed.status == ActionStatus.EXECUTED.value
        assert executed.expires_at is None

        out = service.reverse_action(row.action_id, actor="alice", reason="oops")
        assert out["outcome"] == "conflict"
        assert "irreversible" in out["message"]
