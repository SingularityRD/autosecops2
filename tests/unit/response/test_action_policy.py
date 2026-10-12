"""Response action policy and registry dispatch (W2.4), without a database.

The approval service is a fake here; the DB-backed lifecycle (four-eyes on the
row, TTL reverse + verify) is in test_executor_lifecycle.py.
"""

from __future__ import annotations

import sys
import types
from datetime import timedelta

import pytest

from core.response.approval_service import PendingAction
from core.response.autonomous_response_service import AutonomousResponseService
from core.response.config import ResponseConfig
from core.response.executors.base import (
    ExecResult,
    ExecutorRegistry,
    PolicyResult,
    TypedAction,
    VerifyResult,
)
from core.response.executors.wiring import (
    ExecutorSource,
    build_executor_registry,
    registry_snapshot,
)
from core.response.policy import ActionPolicy, PolicyConfig

pytestmark = pytest.mark.unit


class _Fake:
    """An executor that records what it was asked to do."""

    def __init__(self, types_, reversible=None, ttl=timedelta(hours=1)):
        self.action_types = frozenset(types_)
        self.reversible_types = frozenset(
            self.action_types if reversible is None else reversible
        )
        self.default_ttl = ttl
        self.executed: list[TypedAction] = []

    def validate(self, action):
        return PolicyResult.allow()

    def execute(self, action):
        self.executed.append(action)
        return ExecResult(
            status="executed",
            external_ref="ref-1",
            before_state={"on": False},
            after_state={"on": True},
        )

    def verify(self, action, result):
        return VerifyResult(status="verified")

    def reverse(self, action, result):
        return ExecResult(status="executed")


class _Approvals:
    def __init__(self, rows=(), executed_count=0):
        self.rows = list(rows)
        self.executed: dict[str, dict] = {}
        self.failed: dict[str, str] = {}
        self.created: list[dict] = []
        self.executed_count = executed_count

    def list_actions(self, status=None, **_):
        return self.rows

    def mark_executed(self, action_id, result, **lifecycle):
        self.executed[action_id] = {"result": result, **lifecycle}

    def mark_failed(self, action_id, error):
        self.failed[action_id] = error

    def record_verification(self, action_id, verify_status):
        self.executed[action_id]["verify_status"] = verify_status

    def count_executed_since(self, action_type, since):
        return self.executed_count

    def create_action(self, **kw):
        self.created.append(kw)
        return PendingAction(
            action_id="action-new",
            action_type=kw["action_type"].value,
            title=kw["title"],
            description=kw["description"],
            target=kw["target"],
            confidence=kw["confidence"],
            reason=kw["reason"],
            evidence=kw["evidence"],
            created_at="",
            created_by=kw["created_by"],
            requires_approval=True,
            status="pending",
        )


def _row(
    action_id="a-1",
    *,
    action_type="waf_block",
    target="203.0.113.7",
    approved_by="alice",
    second_approver=None,
    created_by="responder",
    requires_approval=True,
    parameters=None,
):
    return PendingAction(
        action_id=action_id,
        action_type=action_type,
        title="t",
        description="d",
        target=target,
        confidence=0.99,
        reason="r",
        evidence=[],
        created_at="",
        created_by=created_by,
        requires_approval=requires_approval,
        status="approved",
        approved_by=approved_by,
        second_approver=second_approver,
        parameters=parameters or {},
    )


def _service(approvals, *executors, config=None):
    registry = ExecutorRegistry()
    for executor in executors:
        registry.register(executor)
    return AutonomousResponseService(
        approvals=approvals,
        config=ResponseConfig(),
        executors=registry,
        policy=ActionPolicy(config or PolicyConfig()),
    )


def _action(**kw):
    kw.setdefault("action_type", "waf_block")
    kw.setdefault("target", "203.0.113.7")
    return TypedAction(**kw)


# --- the policy on its own ---------------------------------------------------


class TestProtectedAssets:
    def test_a_listed_target_is_refused_in_any_letter_case(self):
        policy = ActionPolicy(
            PolicyConfig.from_mapping({"protected_targets": ["DC01.corp.local"]})
        )
        verdict = policy.evaluate(
            _action(action_type="isolate_host", target="dc01.CORP.local"),
            registry=None,
        )
        assert not verdict.allowed
        assert "protected asset" in verdict.reasons[0]

    def test_a_target_tagged_domain_controller_in_config_is_refused(self):
        policy = ActionPolicy(
            PolicyConfig.from_mapping(
                {"asset_tags": {"10.0.0.10": ["Domain_Controller"]}}
            )
        )
        verdict = policy.evaluate(
            _action(action_type="isolate_host", target="10.0.0.10"), registry=None
        )
        assert not verdict.allowed
        assert "domain_controller" in verdict.reasons[0]

    def test_a_protected_hostname_in_parameters_is_refused(self):
        policy = ActionPolicy(
            PolicyConfig.from_mapping({"protected_targets": ["dc01"]})
        )
        verdict = policy.evaluate(
            _action(
                action_type="isolate_host",
                target="10.0.0.10",
                parameters={"hostname": "DC01"},
            ),
            registry=None,
        )
        assert not verdict.allowed

    def test_a_tag_on_the_action_itself_is_refused(self):
        verdict = ActionPolicy(PolicyConfig()).evaluate(
            _action(parameters={"tags": ["break_glass"]}), registry=None
        )
        assert not verdict.allowed

    def test_config_cannot_drop_the_default_protected_tags(self):
        cfg = PolicyConfig.from_mapping({"protected_tags": ["crown_jewel"]})
        assert {"domain_controller", "crown_jewel"} <= cfg.protected_tags

    def test_an_unreadable_config_refuses_everything(self):
        verdict = ActionPolicy(PolicyConfig(degraded=True)).evaluate(
            _action(), registry=None
        )
        assert not verdict.allowed


class TestTypedValidation:
    def test_a_target_naming_nothing_is_refused(self):
        verdict = ActionPolicy(PolicyConfig()).evaluate(
            _action(action_type="isolate_host", target="unknown"), registry=None
        )
        assert not verdict.allowed

    def test_an_ip_less_isolation_with_a_hostname_is_allowed(self):
        verdict = ActionPolicy(PolicyConfig()).evaluate(
            _action(
                action_type="isolate_host",
                target="unknown",
                parameters={"hostname": "ws-1"},
            ),
            registry=None,
        )
        assert verdict.allowed


class TestBlastRadius:
    def test_the_hourly_limit_refuses_the_next_action(self):
        policy = ActionPolicy(
            PolicyConfig.from_mapping({"hourly_limits": {"waf_block": 3}})
        )
        verdict = policy.evaluate(
            _action(), registry=None, recent_count=lambda _t, _since: 3
        )
        assert not verdict.allowed
        assert "blast radius" in verdict.reasons[0]

    def test_below_the_limit_is_allowed(self):
        policy = ActionPolicy(
            PolicyConfig.from_mapping({"hourly_limits": {"waf_block": 3}})
        )
        assert policy.evaluate(
            _action(), registry=None, recent_count=lambda _t, _since: 2
        ).allowed


class TestApprovalClasses:
    def test_irreversible_always_requires_approval(self):
        verdict = ActionPolicy(PolicyConfig()).evaluate(
            _action(reversibility="irreversible"), registry=None
        )
        assert verdict.allowed and verdict.requires_approval

    def test_a_type_the_registry_holds_irreversible_requires_approval(self):
        registry = ExecutorRegistry()
        registry.register(_Fake({"access_revoke"}, reversible=set()))
        verdict = ActionPolicy(PolicyConfig()).evaluate(
            _action(
                action_type="access_revoke",
                target="a@example.com",
                reversibility="irreversible",
            ),
            registry=registry,
        )
        assert verdict.allowed and verdict.requires_approval

    def test_overstating_reversibility_is_refused(self):
        registry = ExecutorRegistry()
        registry.register(_Fake({"access_revoke"}, reversible=set()))
        verdict = ActionPolicy(PolicyConfig()).evaluate(
            _action(action_type="access_revoke", target="a@example.com"),
            registry=registry,
        )
        assert not verdict.allowed

    def test_the_identity_class_needs_a_second_approver(self):
        verdict = ActionPolicy(PolicyConfig()).evaluate(
            _action(action_type="disable_user", target="bob@example.com"),
            registry=None,
        )
        assert verdict.requires_second_approver


# --- dispatch ------------------------------------------------------------------


class TestDispatchNeverBypassesPolicy:
    def test_a_model_proposed_row_on_a_protected_asset_never_reaches_the_executor(self):
        fake = _Fake({"waf_block"})
        approvals = _Approvals(
            [_row(created_by="mcp:model", target="198.51.100.1", approved_by="alice")]
        )
        service = _service(
            approvals,
            fake,
            config=PolicyConfig.from_mapping({"protected_targets": ["198.51.100.1"]}),
        )

        results = service.execute_approved_actions()

        assert fake.executed == []
        assert approvals.failed["a-1"].startswith("policy_refused: protected asset")
        assert results[0]["result"]["success"] is False

    def test_a_model_proposal_on_a_protected_asset_is_never_created(self):
        approvals = _Approvals()
        service = _service(
            approvals,
            _Fake({"isolate_host"}),
            config=PolicyConfig.from_mapping(
                {"asset_tags": {"dc01": ["domain_controller"]}}
            ),
        )
        out = service.propose_action(
            action_type="isolate_host",
            target="dc01",
            title="t",
            description="d",
            reason="model says so",
            evidence=[],
            proposed_by="agent:llm",
            confidence=1.0,
        )
        assert out["status"] == "refused"
        assert approvals.created == []

    def test_an_allowed_proposal_is_held_for_a_person(self):
        approvals = _Approvals()
        service = _service(approvals, _Fake({"isolate_host"}))
        out = service.propose_action(
            action_type="isolate_host",
            target="10.0.0.9",
            title="t",
            description="d",
            reason="r",
            evidence=[],
            proposed_by="agent:llm",
            confidence=1.0,
        )
        assert out["status"] == "pending"
        assert approvals.created[0]["human_only"] is True

    def test_the_blast_radius_stops_dispatch(self):
        fake = _Fake({"waf_block"})
        approvals = _Approvals([_row()], executed_count=1000)
        service = _service(approvals, fake)
        service.execute_approved_actions()
        assert fake.executed == []
        assert "blast radius" in approvals.failed["a-1"]

    def test_an_irreversible_action_no_person_approved_is_refused(self):
        fake = _Fake({"access_revoke"}, reversible=set())
        approvals = _Approvals()
        service = _service(approvals, fake)
        row = _row(
            action_type="access_revoke",
            target="a@example.com",
            approved_by=None,
            requires_approval=False,
        )
        service._dispatch(row)
        assert fake.executed == []
        assert "irreversible" in approvals.failed["a-1"]

    @pytest.mark.parametrize("second", [None, "ALICE", " alice "])
    def test_four_eyes_without_a_distinct_second_approver_is_refused(self, second):
        fake = _Fake({"disable_user"})
        approvals = _Approvals(
            [
                _row(
                    action_type="disable_user",
                    target="bob@example.com",
                    approved_by="alice",
                    second_approver=second,
                )
            ]
        )
        _service(approvals, fake).execute_approved_actions()
        assert fake.executed == []
        assert "second approver" in approvals.failed["a-1"]

    def test_four_eyes_with_a_distinct_second_approver_runs(self):
        fake = _Fake({"disable_user"})
        approvals = _Approvals(
            [
                _row(
                    action_type="disable_user",
                    target="bob@example.com",
                    approved_by="alice",
                    second_approver="carol",
                )
            ]
        )
        _service(approvals, fake).execute_approved_actions()
        assert len(fake.executed) == 1
        assert approvals.executed["a-1"]["verify_status"] == "verified"

    def test_an_executed_reversible_action_gets_its_expiry_and_states(self):
        fake = _Fake({"waf_block"}, ttl=timedelta(hours=24))
        approvals = _Approvals([_row(parameters={"ttl_seconds": 600})])
        _service(approvals, fake).execute_approved_actions()
        record = approvals.executed["a-1"]
        assert record["expires_at"] - record["executed_at"] == timedelta(seconds=600)
        assert record["before_state"] == {"on": False}
        assert record["after_state"] == {"on": True}
        assert record["result"]["external_ref"] == "ref-1"

    def test_an_irreversible_action_never_expires(self):
        fake = _Fake({"access_revoke"}, reversible=set())
        approvals = _Approvals(
            [_row(action_type="access_revoke", target="a@example.com")]
        )
        _service(approvals, fake).execute_approved_actions()
        assert approvals.executed["a-1"]["expires_at"] is None

    def test_isolate_host_without_an_executor_is_recorded_failed(self):
        approvals = _Approvals([_row(action_type="isolate_host", target="10.0.0.5")])
        results = _service(approvals).execute_approved_actions()
        assert results[0]["result"]["error"] == "unsupported_action_type"
        assert approvals.failed["a-1"] == "unsupported_action_type"

    def test_another_type_without_an_executor_is_left_alone(self):
        approvals = _Approvals([_row(action_type="quarantine_file", target="f")])
        assert _service(approvals).execute_approved_actions() == []
        assert approvals.failed == {} and approvals.executed == {}

    def test_a_reverse_row_is_never_run_forward(self):
        fake = _Fake({"waf_block"})
        row = _row()
        row.reverse_of = "a-0"
        _service(_Approvals([row]), fake).execute_approved_actions()
        assert fake.executed == []


# --- the registry ----------------------------------------------------------------


def test_registry_snapshot():
    """What a default build registers with every optional integration off.

    Cloudflare is always registered: it reads its settings per call. A change
    here is a change to which actions can run and which can be undone.
    """
    registry = build_executor_registry(
        enabled=lambda _id: False, config_for=lambda _id: {}
    )
    assert registry_snapshot(registry) == {
        "access_revoke": {
            "executor": "CloudflareExecutor",
            "reversibility": "irreversible",
            "default_ttl_seconds": 86400,
        },
        "gateway_block": {
            "executor": "CloudflareExecutor",
            "reversibility": "reversible",
            "default_ttl_seconds": 86400,
        },
        "waf_block": {
            "executor": "CloudflareExecutor",
            "reversibility": "reversible",
            "default_ttl_seconds": 86400,
        },
    }


def test_a_new_executor_plugs_in_by_naming_its_module(monkeypatch):
    module = types.ModuleType("_w24_fake_executor")
    module.build_executor = lambda config: _Fake(
        {"isolate_host"}, reversible={"isolate_host"}
    )
    monkeypatch.setitem(sys.modules, "_w24_fake_executor", module)
    broken = types.ModuleType("_w24_broken_executor")

    def _boom(config):
        raise RuntimeError("bad config")

    broken.build_executor = _boom
    monkeypatch.setitem(sys.modules, "_w24_broken_executor", broken)

    registry = build_executor_registry(
        [
            ExecutorSource("edr", "_w24_fake_executor"),
            ExecutorSource("off", "_w24_fake_executor"),
            ExecutorSource("broken", "_w24_broken_executor"),
            ExecutorSource("missing", "core.integrations._w24_absent.executor"),
            ExecutorSource("dup", "_w24_fake_executor", always=True),
        ],
        enabled=lambda i: i != "off",
        config_for=lambda _id: {},
    )
    # The duplicate claim on isolate_host is refused; the first one stands.
    assert registry.action_types() == frozenset({"isolate_host"})
    assert registry.reversibility_of("isolate_host") == "reversible"
