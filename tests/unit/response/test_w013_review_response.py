"""W0.13 review of core/response: regression tests for the findings fixed there.

1. An agent's proposal of an undo type (unblock_ip, unisolate_host,
   enable_user) was stored as ``custom``: no executor takes ``custom``, so the
   approved row was never run and nothing said so.
2. The dispatcher read approved rows newest first, capped at 500, and then
   skipped those it can never run (workflow phases, custom, claimed rows). Once
   500 such rows were newer than it, an action approved long after it was
   proposed was never dispatched.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from core.response.approval_service import ActionType
from core.response.autonomous_response_service import AutonomousResponseService
from core.response.config import ResponseConfig
from core.response.executors.base import (
    ExecResult,
    ExecutorRegistry,
    PolicyResult,
    VerifyResult,
)
from core.response.policy import DEFAULT_UNDO_TYPES, ActionPolicy, PolicyConfig
from core.time import utcnow


class _Fake:
    def __init__(self, types_=("waf_block",)):
        self.action_types = frozenset(types_)
        self.reversible_types = frozenset(types_)
        self.default_ttl = None
        self.executed: list = []

    def validate(self, action):
        return PolicyResult.allow()

    def execute(self, action):
        self.executed.append(action)
        return ExecResult(status="executed")

    def verify(self, action, result):
        return VerifyResult(status="verified")

    def reverse(self, action, result):
        return ExecResult(status="executed")


class _Recorder:
    """Just enough approval service for propose_action."""

    def __init__(self):
        self.created: list[dict[str, Any]] = []

    def policy_config(self):
        return PolicyConfig()

    def count_executed_since(self, action_type, since):
        return 0

    def create_action(self, **kw):
        self.created.append(kw)
        return SimpleNamespace(status="pending", action_id="a-1")


def _service(approvals, *executors):
    registry = ExecutorRegistry()
    for executor in executors:
        registry.register(executor)
    return AutonomousResponseService(
        approvals=approvals,
        config=ResponseConfig(),
        executors=registry,
        policy=ActionPolicy(PolicyConfig()),
    )


@pytest.mark.unit
@pytest.mark.parametrize("undo_type", sorted(DEFAULT_UNDO_TYPES))
def test_a_proposed_undo_type_keeps_its_type(undo_type):
    approvals = _Recorder()
    service = _service(approvals, _Fake((undo_type,)))
    outcome = service.propose_action(
        action_type=undo_type,
        target="198.51.100.7" if undo_type == "unblock_ip" else "host-7",
        title="t",
        description="d",
        reason="r",
        evidence=[],
        proposed_by="agent",
    )
    assert outcome["status"] == "pending"
    assert approvals.created[0]["action_type"] is ActionType(undo_type)
    assert approvals.created[0]["action_type"] is not ActionType.CUSTOM


@pytest.mark.unit
def test_every_registered_executor_type_is_an_action_type():
    # A type an executor takes but ActionType lacks is stored as custom and
    # can never run; keep the enum in step with the executors. Each executor
    # is built from a configuration and registered, so a set of types fixed
    # per instance (Palo Alto, Entra) is checked as the registry sees it.
    from core.integrations.azure_ad.executor import build_executor as build_entra
    from core.integrations.cloudflare.executor import build_executor as build_cloudflare
    from core.integrations.microsoft_defender.executor import (
        build_executor as build_defender,
    )
    from core.integrations.palo_alto.executor import build_executor as build_palo_alto

    executors = (
        build_entra({"token_provider": lambda: "t"}, sleep=lambda _s: None),
        build_cloudflare({}),
        build_defender(
            {"tenant_id": "tid", "client_id": "cid", "client_secret": "s"},
            sleep=lambda _s: None,
        ),
        build_palo_alto(
            {"hostname": "pan.test", "api_key": "k", "verify_ssl": True},
            sleep=lambda _s: None,
        ),
    )
    known = {member.value for member in ActionType}
    registry = ExecutorRegistry()
    for executor in executors:
        types_ = frozenset(executor.action_types)
        assert types_, type(executor).__name__
        assert types_ <= known, (type(executor).__name__, sorted(types_ - known))
        registry.register(executor)
    assert registry.action_types() <= known
    for undo in DEFAULT_UNDO_TYPES:
        assert undo in registry.action_types(), undo


@pytest.mark.external_service
@pytest.mark.database
def test_an_old_approved_action_is_dispatched_behind_500_newer_rows(
    throwaway_database,
):
    import uuid

    from core.response.approval_service import ApprovalService
    from core.storage.models import ApprovalAction
    from core.storage.unit_of_work import unit_of_work

    tag = uuid.uuid4().hex[:8]
    now = utcnow()

    def row(action_id, action_type, created_at):
        return ApprovalAction(
            action_id=action_id,
            action_type=action_type,
            title="t",
            description="d",
            target="203.0.113.7",
            confidence=0.5,
            reason="r",
            evidence=[],
            created_by="pytest",
            requires_approval=True,
            status="approved",
            approved_by="alice",
            created_at=created_at,
            parameters={},
        )

    old_id = f"old-{tag}"
    with unit_of_work() as session:
        session.add(row(old_id, "waf_block", now - timedelta(days=2)))
        for i in range(501):
            session.add(
                row(f"wf-{tag}-{i}", "workflow_phase", now - timedelta(seconds=i))
            )

    executor = _Fake(("waf_block",))
    service = _service(ApprovalService(), executor)
    results = service.execute_approved_actions()

    assert old_id in [r["action_id"] for r in results]
    assert [a.target for a in executor.executed] == ["203.0.113.7"]
    assert ApprovalService().get_action(old_id).status == "executed"


# --- 3. an abandoned reversal claim no longer blocks every later reversal ---------


@pytest.mark.external_service
@pytest.mark.database
class TestAbandonedReversalClaim:
    @pytest.fixture
    def executed(self, throwaway_database):
        import uuid

        from core.storage.models import ApprovalAction
        from core.storage.unit_of_work import unit_of_work

        action_id = f"orig-{uuid.uuid4().hex[:10]}"
        with unit_of_work() as session:
            session.add(
                ApprovalAction(
                    action_id=action_id,
                    action_type="waf_block",
                    title="t",
                    description="d",
                    target="203.0.113.9",
                    confidence=0.9,
                    reason="r",
                    evidence=[],
                    created_by="pytest",
                    requires_approval=True,
                    status="executed",
                    approved_by="alice",
                    created_at=utcnow() - timedelta(days=1),
                    executed_at=utcnow() - timedelta(days=1),
                    reversibility="reversible",
                    parameters={},
                )
            )
        return action_id

    @staticmethod
    def _claim(action_id, *, age, status="pending"):
        from core.storage.models import ApprovalAction
        from core.storage.unit_of_work import unit_of_work

        claim_id = f"{action_id}-rev-old"
        with unit_of_work() as session:
            session.add(
                ApprovalAction(
                    action_id=claim_id,
                    action_type="waf_block",
                    title="Reverse",
                    description="d",
                    target="203.0.113.9",
                    confidence=0.9,
                    reason="r",
                    evidence=[action_id],
                    created_by="bob",
                    requires_approval=False,
                    status=status,
                    approved_by="bob",
                    created_at=utcnow() - age,
                    parameters={},
                    reversibility="reversible",
                    idempotency_key=f"reverse:{action_id}",
                    reverse_of=action_id,
                )
            )
        return claim_id

    def test_a_claim_in_flight_still_blocks(self, executed):
        from core.response.approval_service import ApprovalService

        self._claim(executed, age=timedelta(minutes=1))
        assert ApprovalService().begin_reversal(executed, "carol", "again") is None

    @pytest.mark.parametrize(
        "age,status",
        [(timedelta(hours=2), "pending"), (timedelta(minutes=1), "rejected")],
    )
    def test_an_abandoned_claim_is_released(self, executed, age, status):
        from core.response.approval_service import ApprovalService

        svc = ApprovalService()
        old = self._claim(executed, age=age, status=status)
        claim = svc.begin_reversal(executed, "carol", "again")
        assert claim is not None and claim.reverse_of == executed
        assert svc.get_action(old).status == "failed"

    def test_a_reversal_in_flight_is_not_an_approval(self, executed):
        from core.response.approval_service import ApprovalService

        svc = ApprovalService()
        claim = self._claim(executed, age=timedelta(days=30))
        assert svc.reject_action(claim, "no", rejected_by="mallory").status == "pending"
        row = svc.approve_action(claim, approved_by="mallory")
        assert row.status == "pending" and row.approved_by == "bob"
        assert claim not in svc.list_stale_pending(utcnow())


# --------------------------------------------------------------------------
# Round 5 fixes (verifier findings on the W0.13 response review)
# --------------------------------------------------------------------------


@pytest.mark.external_service
@pytest.mark.database
def test_the_dispatcher_lists_tier_released_rows_and_no_other_unpersoned_row(
    throwaway_database,
):
    # R5-1: the undispatched filter (requires_approval OR approved_by) dropped
    # rows the autonomy tier released (W3.1): no approver, requires_approval
    # False, autonomy.effective == autonomous. Those are listed; a row
    # released without a person any other way still is not.
    import uuid

    from core.response.approval_service import ActionStatus, ApprovalService
    from core.storage.models import ApprovalAction
    from core.storage.unit_of_work import unit_of_work

    tag = uuid.uuid4().hex[:8]
    now = utcnow()
    cases = {
        f"auto-{tag}": {"autonomy": {"effective": "autonomous", "reasons": []}},
        f"held-{tag}": {"autonomy": {"effective": "approve", "reasons": []}},
        f"conf-{tag}": {},
        f"odd-{tag}": {"autonomy": "autonomous"},
    }
    with unit_of_work() as session:
        for i, (action_id, params) in enumerate(cases.items()):
            session.add(
                ApprovalAction(
                    action_id=action_id,
                    action_type="waf_block",
                    title="t",
                    description="d",
                    target="203.0.113.8",
                    confidence=0.99,
                    reason="r",
                    evidence=[],
                    created_by="pytest",
                    requires_approval=False,
                    status="approved",
                    approved_by=None,
                    created_at=now - timedelta(seconds=10 - i),
                    parameters=params,
                )
            )
    try:
        listed = {
            a.action_id
            for a in ApprovalService().list_actions(
                status=ActionStatus.APPROVED,
                action_types={"waf_block"},
                undispatched=True,
            )
        }
    finally:
        # Approved rows left behind would be dispatched by later tests.
        with unit_of_work() as session:
            session.query(ApprovalAction).filter(
                ApprovalAction.action_id.in_(list(cases))
            ).delete(synchronize_session=False)
    assert f"auto-{tag}" in listed
    assert not ({f"held-{tag}", f"conf-{tag}", f"odd-{tag}"} & listed)


@pytest.mark.unit
def test_undo_types_are_governed_and_never_autonomous_eligible():
    # R5-1: W3.1 pins ACTION_CLASSES to ActionType; the undo types joined
    # ActionType here and are classes the tiers govern, never autonomous.
    from core.autonomy.tiers import ACTION_CLASSES, AUTONOMOUS_ELIGIBLE

    for undo in DEFAULT_UNDO_TYPES:
        assert undo in ACTION_CLASSES
        assert undo not in AUTONOMOUS_ELIGIBLE


@pytest.mark.unit
def test_defender_verify_timeout_is_capped_well_under_the_takeover_window():
    # R5-2: a reverse's verify polls while its claim is held; a claim older
    # than REVERSAL_CLAIM_STALE is taken over.
    from core.integrations.microsoft_defender.executor import (
        MAX_VERIFY_TIMEOUT_SECONDS,
        DefenderExecutorSettings,
        build_executor,
    )
    from core.response.approval_service import REVERSAL_CLAIM_STALE

    assert MAX_VERIFY_TIMEOUT_SECONDS <= REVERSAL_CLAIM_STALE.total_seconds() / 2
    with pytest.raises(ValueError):
        DefenderExecutorSettings(verify_timeout_seconds=3600)
    with pytest.raises(ValueError):
        build_executor(
            {
                "tenant_id": "t",
                "client_id": "c",
                "client_secret": "s",
                "verify_timeout_seconds": 3000,
            }
        )
    DefenderExecutorSettings(verify_timeout_seconds=MAX_VERIFY_TIMEOUT_SECONDS)


class _StateFake(_Fake):
    """A waf_block executor whose current state the test sets."""

    def __init__(self, still_in_effect: bool):
        super().__init__(("waf_block",))
        self.still_in_effect = still_in_effect
        self.reversed: list = []

    def verify(self, action, result):
        if result.status == "noop" and action.reverse_of is None:
            return VerifyResult(status="verified" if self.still_in_effect else "failed")
        return VerifyResult(status="verified")

    def reverse(self, action, result):
        self.reversed.append(action)
        return ExecResult(status="executed")


@pytest.mark.external_service
@pytest.mark.database
class TestStaleClaimTakeover:
    """R5-2: the claimant behind a stale claim may still be alive."""

    executed = TestAbandonedReversalClaim.executed
    _claim = staticmethod(TestAbandonedReversalClaim._claim)

    def test_a_superseded_claim_records_its_late_outcome(self, executed):
        from core.response.approval_service import ApprovalService

        svc = ApprovalService()
        old = self._claim(executed, age=timedelta(hours=2))
        new = svc.begin_reversal(executed, "carol", "again")
        assert new is not None and new.parameters["supersedes"] == old

        late = svc.finish_reversal(
            old, succeeded=True, result={"success": True}, verify_status="verified"
        )
        assert late is not None, "a superseded claim's outcome must not be lost"
        assert late.status == "failed"  # the key stays with the new claim
        assert late.execution_result["late_outcome"]["succeeded"] is True
        assert svc.get_action(executed).reversed_at is not None
        assert svc.get_action(new.action_id).status == "pending"

    def test_a_superseded_failure_is_recorded_without_stamping(self, executed):
        from core.response.approval_service import ApprovalService

        svc = ApprovalService()
        old = self._claim(executed, age=timedelta(hours=2))
        assert svc.begin_reversal(executed, "carol", "again") is not None
        late = svc.finish_reversal(old, succeeded=False, result={"success": False})
        assert late.execution_result["late_outcome"]["succeeded"] is False
        assert svc.get_action(executed).reversed_at is None

    @pytest.mark.parametrize("still_in_effect", [True, False])
    def test_the_takeover_checks_state_before_reversing(
        self, executed, still_in_effect
    ):
        from core.response.approval_service import ApprovalService

        old = self._claim(executed, age=timedelta(hours=2))
        executor = _StateFake(still_in_effect)
        out = _service(ApprovalService(), executor).reverse_action(
            executed, actor="ttl-sweep", reason="ttl"
        )
        assert out["outcome"] == "reversed"
        assert len(executor.reversed) == (1 if still_in_effect else 0)
        row = ApprovalService().get_action(out["reverse_action_id"])
        assert row.status == "executed"
        if not still_in_effect:
            assert row.execution_result["superseded_claim"] == old
        assert ApprovalService().get_action(executed).reversed_at is not None

    def test_no_state_check_without_a_takeover(self, executed):
        from core.response.approval_service import ApprovalService

        executor = _StateFake(still_in_effect=False)
        out = _service(ApprovalService(), executor).reverse_action(
            executed, actor="alice", reason="undo"
        )
        assert out["outcome"] == "reversed"
        assert len(executor.reversed) == 1
