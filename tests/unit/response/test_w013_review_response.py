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
    # can never run; keep the enum in step with the executors.
    from core.integrations.azure_ad.executor import EntraIdExecutor
    from core.integrations.cloudflare.executor import CloudflareExecutor
    from core.integrations.microsoft_defender.executor import DefenderIsolationExecutor
    from core.integrations.palo_alto.executor import PaloAltoExecutor

    known = {member.value for member in ActionType}
    for cls in (
        EntraIdExecutor,
        CloudflareExecutor,
        DefenderIsolationExecutor,
        PaloAltoExecutor,
    ):
        types_ = getattr(cls, "action_types", None)
        if not isinstance(types_, frozenset):  # set per instance
            continue
        assert types_ <= known, (cls.__name__, sorted(types_ - known))


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
