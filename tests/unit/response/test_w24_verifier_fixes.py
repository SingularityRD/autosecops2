"""Regressions for the W2.4 verifier findings (docs/wp/FIXES.md, section W2.4).

One test (or parametrised family) per finding, without a database:

1. a ttl that cannot become an expiry stops the action before it runs, and
   one failing row neither stays approved nor stops the queue;
2. protected-asset matching survives every spelling of a protected name,
   address or range, in the target or in any identifier parameter;
3. a model's parameters cannot point Cloudflare at something other than the
   target the approver saw;
4. the registry wiring uses descriptor ids and resolved (secret) config, so
   the Entra executor actually registers;
5. a reverse does not re-resolve the target through executor.validate;
6. revoke_sessions is a typed, four-eyes action;
7. the Cloudflare MCP tools are gated by the W1.7 tool-effects table.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from core.integrations.cloudflare import executor as cf_executor
from core.integrations.cloudflare.executor import CloudflareExecutor
from core.response.approval_service import ActionType, PendingAction
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
    EXECUTOR_SOURCES,
    build_executor_registry,
    resolved_integration_config,
)
from core.response.policy import MAX_TTL, ActionPolicy, PolicyConfig

pytestmark = pytest.mark.unit


# --- fakes -------------------------------------------------------------------


class _Fake:
    def __init__(self, types_=("waf_block",), ttl=timedelta(hours=1), deny=None):
        self.action_types = frozenset(types_)
        self.reversible_types = frozenset(types_)
        self.default_ttl = ttl
        self.deny = deny
        self.executed: list[TypedAction] = []
        self.reversed: list[tuple[TypedAction, ExecResult]] = []
        self.validated: list[TypedAction] = []

    def validate(self, action):
        self.validated.append(action)
        if self.deny:
            return PolicyResult.deny(self.deny)
        return PolicyResult.allow()

    def execute(self, action):
        self.executed.append(action)
        return ExecResult(
            status="executed",
            external_ref="machine-123",
            before_state={"on": False},
            after_state={"on": True},
        )

    def verify(self, action, result):
        return VerifyResult(status="verified")

    def reverse(self, action, result):
        self.reversed.append((action, result))
        return ExecResult(status="executed", external_ref=result.external_ref)


def _row(action_id="a-1", **kw):
    base: dict[str, Any] = dict(
        action_id=action_id,
        action_type="waf_block",
        title="t",
        description="d",
        target="203.0.113.7",
        confidence=0.99,
        reason="r",
        evidence=[],
        created_at="",
        created_by="responder",
        requires_approval=True,
        status="approved",
        approved_by="alice",
        parameters={},
    )
    base.update(kw)
    return PendingAction(**base)


class _Approvals:
    def __init__(self, rows=(), *, explode_on=None):
        self.rows = {r.action_id: r for r in rows}
        self.executed: dict[str, dict] = {}
        self.failed: dict[str, str] = {}
        self.created: list[dict] = []
        self.explode_on = explode_on
        self.reversals: list[dict] = []

    def list_actions(self, status=None, **_):
        return list(self.rows.values())

    def get_action(self, action_id):
        return self.rows.get(action_id)

    def claim_execution(self, action_id):
        return action_id not in self.executed and action_id not in self.failed

    def mark_executed(self, action_id, result, **lifecycle):
        if action_id == self.explode_on:
            raise RuntimeError("db went away")
        self.executed[action_id] = {"result": result, **lifecycle}
        return self.executed[action_id]

    def mark_failed(self, action_id, error):
        self.failed[action_id] = error

    def record_verification(self, action_id, verify_status):
        self.executed[action_id]["verify_status"] = verify_status

    def count_executed_since(self, action_type, since):
        return 0

    def create_action(self, **kw):
        self.created.append(kw)
        return _row("action-new", status="pending", action_type=kw["action_type"].value)

    def begin_reversal(self, original_id, actor, reason):
        return _row(f"rev-{original_id}", reverse_of=original_id)

    def finish_reversal(self, reverse_id, **kw):
        self.reversals.append({"reverse_id": reverse_id, **kw})
        return _row(reverse_id)


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


# --- 1. ttl overflow -----------------------------------------------------------


class TestTtl:
    @pytest.mark.parametrize(
        "ttl", [1e12, 10**30, "1e400", float("inf"), float("nan"), True, "abc", -5, 0]
    )
    def test_an_unusable_ttl_is_refused_before_the_executor_runs(self, ttl):
        executor = _Fake()
        approvals = _Approvals([_row(parameters={"ttl_seconds": ttl})])
        results = _service(approvals, executor).execute_approved_actions()
        assert executor.executed == []
        assert "a-1" in approvals.failed
        assert approvals.failed["a-1"].startswith("policy_refused: invalid action")
        assert results[0]["result"]["success"] is False

    def test_the_maximum_ttl_is_accepted_and_recorded(self):
        executor = _Fake()
        approvals = _Approvals(
            [_row(parameters={"ttl_seconds": MAX_TTL.total_seconds()})]
        )
        _service(approvals, executor).execute_approved_actions()
        done = approvals.executed["a-1"]
        assert done["expires_at"] - done["executed_at"] == MAX_TTL

    def test_a_failing_row_is_marked_failed_and_the_queue_continues(self):
        executor = _Fake()
        approvals = _Approvals(
            [_row("a-1"), _row("a-2", target="203.0.113.8")], explode_on="a-1"
        )
        results = _service(approvals, executor).execute_approved_actions()
        assert approvals.failed["a-1"].startswith("dispatch error")
        assert "a-2" in approvals.executed
        assert [r["action_id"] for r in results] == ["a-1", "a-2"]

    def test_a_proposal_with_an_unusable_ttl_is_never_created(self):
        approvals = _Approvals()
        out = _service(approvals, _Fake()).propose_action(
            action_type="waf_block",
            target="203.0.113.7",
            title="t",
            description="d",
            reason="r",
            evidence=[],
            proposed_by="agent:orchestrator",
            parameters={"ttl_seconds": 1e12},
        )
        assert out["status"] == "refused"
        assert approvals.created == []


# --- 2. protected-asset normalisation -------------------------------------------

_PROTECTED = PolicyConfig.from_mapping(
    {
        "protected_targets": ["dc01", "10.0.0.5", "fd00:1::/64"],
        "asset_tags": {"fs01": ["domain_controller"], "192.0.2.0/28": ["tier0"]},
    }
)


def _refused(**kw) -> bool:
    kw.setdefault("action_type", "isolate_host")
    action = TypedAction(**kw)
    return not ActionPolicy(_PROTECTED).evaluate(action, registry=None).allowed


class TestProtectedMatching:
    @pytest.mark.parametrize(
        "target",
        [
            "dc01",
            "dc01.corp.local",
            "DC01.CORP.LOCAL.",
            "dc01.",
            "CORP\\dc01",
            " Dc01 ",
            "host:dc01.corp.local",
            "fs01.corp.local",  # tagged by short name
            "10.0.0.5",
            "10.0.0.5/32",
            "::ffff:10.0.0.5",
            "10.0.0.0/24",  # contains the protected address
            "fd00:1::7",
            "192.0.2.3",  # inside a tagged range
        ],
    )
    def test_every_spelling_of_a_protected_target_is_refused(self, target):
        assert _refused(target=target)

    @pytest.mark.parametrize(
        "target", ["10.0.0.0/8", "0.0.0.0/0", "::/0", "2001:db8::/32", "10.1.0.0/23"]
    )
    def test_a_too_broad_range_is_refused_whatever_it_holds(self, target):
        assert _refused(target=target, action_type="waf_block")

    @pytest.mark.parametrize(
        "parameters",
        [
            {"hostname": "DC01.corp.local."},
            {"host": "CORP\\dc01"},
            {"ip": "::ffff:10.0.0.5"},
            {"domain": "dc01.corp.local"},
            {"ips": ["198.51.100.1", "10.0.0.5"]},
        ],
    )
    def test_a_protected_identifier_in_parameters_is_refused(self, parameters):
        assert _refused(target="198.51.100.9", parameters=parameters)

    @pytest.mark.parametrize(
        "target", ["198.51.100.9", "web01.corp.local", "10.0.0.6", "192.0.2.16"]
    )
    def test_unprotected_targets_still_pass(self, target):
        assert not _refused(target=target)


# --- 3. parameters cannot override the approved target ---------------------------


class _Calls:
    def __init__(self):
        self.calls: list[dict] = []

    def waf(self, **kw):
        self.calls.append(kw)
        return {"success": True, "rule_id": "r-1"}


@pytest.fixture
def cloudflare(monkeypatch):
    calls = _Calls()
    monkeypatch.setattr(cf_executor.cf, "_waf_block_ip", calls.waf)
    return CloudflareExecutor(settings=lambda: (True, {"api_token": "t"})), calls


class TestCloudflareTarget:
    @pytest.mark.parametrize(
        "action_type,target,parameters",
        [
            ("waf_block", "203.0.113.7", {"ip": "198.51.100.1"}),
            ("gateway_block", "evil.example", {"domain": "corp.example"}),
            ("access_revoke", "mallory@example.com", {"email": "ceo@example.com"}),
            ("waf_block", "203.0.113.7", {"mode": "whitelist"}),
            ("waf_block", "203.0.113.7", {"mode": "allow"}),
            ("waf_block", "203.0.113.7", {"account_id": "someone-elses"}),
            ("gateway_block", "evil.example", {"rule_name": "x" * 500}),
        ],
    )
    def test_a_parameter_that_changes_the_effect_is_refused(
        self, cloudflare, action_type, target, parameters
    ):
        executor, _ = cloudflare
        action = TypedAction(
            action_type=action_type, target=target, parameters=parameters
        )
        assert not executor.validate(action).allowed

    def test_the_same_subject_in_another_form_is_allowed(self, cloudflare):
        executor, _ = cloudflare
        action = TypedAction(
            action_type="waf_block",
            target="203.0.113.7",
            parameters={"ip": "203.0.113.7/32", "mode": "challenge", "reason": "r"},
        )
        assert executor.validate(action).allowed

    def test_execute_sends_the_target_not_the_parameter(self, cloudflare):
        executor, calls = cloudflare
        action = TypedAction(
            action_type="waf_block",
            target="203.0.113.7",
            parameters={"ip": "203.0.113.7/32"},
        )
        assert executor.execute(action).status == "executed"
        assert calls.calls[0]["ip"] == "203.0.113.7"

    def test_the_dispatcher_refuses_a_divergent_parameter(self, cloudflare):
        executor, calls = cloudflare
        approvals = _Approvals([_row(parameters={"ip": "198.51.100.1"})])
        _service(approvals, executor).execute_approved_actions()
        assert calls.calls == []
        assert "differs from the target" in approvals.failed["a-1"]


# --- 4. wiring: descriptor ids, resolved secrets, Entra registers ----------------


def test_executor_sources_use_descriptor_ids():
    from core.integrations._base.descriptor import get_descriptor

    ids = {s.integration_id for s in EXECUTOR_SOURCES}
    assert {"microsoft-defender", "azure-ad", "palo-alto", "cloudflare"} <= ids
    for source in EXECUTOR_SOURCES:
        assert get_descriptor(source.integration_id) is not None, source


def _secret_store(monkeypatch, stored, secrets):
    import core.config
    import core.integrations._base.config as base_config

    monkeypatch.setattr(
        core.config, "get_integration_config", lambda i: dict(stored.get(i, {}))
    )
    monkeypatch.setattr(
        base_config, "get_integration_config", lambda i: dict(stored.get(i, {}))
    )
    monkeypatch.setattr(base_config, "get_secret", lambda key: secrets.get(key))


def test_entra_registers_with_its_client_secret_from_the_secret_store(monkeypatch):
    from core.integrations.integration_secrets import secret_fields_for

    secret_key = secret_fields_for("azure-ad")["client_secret"]
    # The stored JSON never holds the secret; only the secret store does.
    _secret_store(
        monkeypatch,
        {
            "azure-ad": {
                "tenant_id": "t-1",
                "client_id": "c-1",
                "protected_users": ["breakglass@corp.example"],
            }
        },
        {secret_key: "s3cret"},
    )
    config = resolved_integration_config("azure-ad")
    assert config["client_secret"] == "s3cret"
    assert config["protected_users"] == ["breakglass@corp.example"]

    registry = build_executor_registry(enabled=lambda i: i == "azure-ad")
    entra = registry.get("disable_user")
    assert type(entra).__name__ == "EntraIdExecutor"
    assert registry.get("revoke_sessions") is entra
    assert registry.reversibility_of("disable_user") == "reversible"
    assert registry.reversibility_of("revoke_sessions") == "irreversible"


def test_entra_without_its_secret_is_left_out_not_fatal(monkeypatch):
    _secret_store(
        monkeypatch, {"azure-ad": {"tenant_id": "t-1", "client_id": "c-1"}}, {}
    )
    registry = build_executor_registry(enabled=lambda i: i == "azure-ad")
    assert registry.get("disable_user") is None
    assert registry.get("waf_block") is not None  # Cloudflare is unaffected


def test_cloudflare_reads_its_api_token_from_the_secret_store(monkeypatch):
    from core.integrations.integration_secrets import secret_fields_for

    _secret_store(
        monkeypatch,
        {"cloudflare": {"account_id": "acc-1"}},
        {secret_fields_for("cloudflare")["api_token"]: "cf-token"},
    )
    monkeypatch.setattr("core.config.is_integration_enabled", lambda i: True)
    enabled, cfg = cf_executor._live_settings()
    assert enabled and cfg["api_token"] == "cf-token" and cfg["account_id"] == "acc-1"


# --- 5. reverse does not re-resolve the target -----------------------------------


def test_a_reverse_uses_the_recorded_identity_not_a_fresh_lookup():
    # The executor now refuses the name (the host was renamed): the reverse of
    # what it did must still run, on the recorded machine id.
    executor = _Fake(("isolate_host",), deny="no machine named web01")
    original = _row(
        action_type="isolate_host",
        target="web01",
        status="executed",
        execution_result={"status": "executed", "external_ref": "machine-123"},
        before_state={"isolated": False},
        after_state={"isolated": True},
    )
    approvals = _Approvals([original])
    out = _service(approvals, executor).reverse_action(
        "a-1", actor="alice", reason="false positive"
    )
    assert out["outcome"] == "reversed"
    assert executor.validated == []
    action, result = executor.reversed[0]
    assert action.reverse_of == "a-1"
    assert result.external_ref == "machine-123"


def test_a_reverse_ignores_a_bad_stored_ttl():
    executor = _Fake()
    original = _row(
        status="executed",
        parameters={"ttl_seconds": 1e12},
        execution_result={"status": "executed", "external_ref": "r-1"},
    )
    out = _service(_Approvals([original]), executor).reverse_action(
        "a-1", actor="system:ttl-sweep", reason="ttl"
    )
    assert out["outcome"] == "reversed"


# --- 6. revoke_sessions is typed and four-eyes ----------------------------------


def test_revoke_sessions_is_an_action_type_and_proposals_keep_it():
    assert ActionType("revoke_sessions") is ActionType.REVOKE_SESSIONS
    assert PolicyConfig().needs_second_approver("revoke_sessions")
    approvals = _Approvals()
    out = _service(approvals).propose_action(
        action_type="revoke_sessions",
        target="bob@example.com",
        title="t",
        description="d",
        reason="r",
        evidence=[],
        proposed_by="agent:orchestrator",
    )
    assert out["status"] == "pending"
    assert out["requires_second_approver"] is True
    assert approvals.created[0]["action_type"] is ActionType.REVOKE_SESSIONS


# --- 7. Cloudflare MCP tools are gated --------------------------------------------


def test_every_mutating_cloudflare_tool_is_gated():
    from core.llm.tool_effects import integration_tool_names, is_gated

    names = set(integration_tool_names("cloudflare"))
    mutating = {
        "cf_waf_block_ip",
        "cf_waf_unblock_ip",
        "cf_gateway_block_domain",
        "cf_access_revoke_session",
    }
    assert mutating <= names
    for tool in mutating:
        assert is_gated(f"cloudflare_{tool}"), tool
    for tool in names - mutating:
        assert tool.startswith("cf_lookup_"), tool
