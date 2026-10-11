"""The executor protocol (core/response/executors/base.py): contract only."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from pydantic import ValidationError

from core.response.executors import base
from core.response.executors.base import (
    ExecResult,
    Executor,
    ExecutorConflict,
    ExecutorRegistry,
    PolicyResult,
    TypedAction,
    UnknownActionType,
    VerifyResult,
    derive_idempotency_key,
)
from core.storage.models import ApprovalAction

pytestmark = pytest.mark.unit


class FakeFirewall:
    action_types = frozenset({"block_ip", "allow_ip"})
    reversible_types = frozenset({"block_ip"})
    default_ttl = timedelta(hours=1)

    def __init__(self):
        self.blocked: set[str] = set()

    def validate(self, action):
        if action.target.startswith("10."):
            return PolicyResult.deny("internal address")
        return PolicyResult.allow()

    def execute(self, action):
        before = {"blocked": action.target in self.blocked}
        if before["blocked"]:
            return ExecResult(status="noop", before_state=before, after_state=before)
        self.blocked.add(action.target)
        return ExecResult(
            status="executed", before_state=before, after_state={"blocked": True}
        )

    def verify(self, action, result):
        return VerifyResult(
            status="verified" if action.target in self.blocked else "failed"
        )

    def reverse(self, action, result):
        if not (result.before_state or {}).get("blocked"):
            self.blocked.discard(action.target)
        return ExecResult(status="executed", after_state=result.before_state)


def test_a_conforming_class_is_an_executor():
    assert isinstance(FakeFirewall(), Executor)
    assert not isinstance(object(), Executor)


def test_no_module_level_registry_and_a_new_one_is_empty():
    # Injected, not ambient (test_no_ambient_state); no executors exist yet.
    assert not hasattr(base, "registry")
    assert ExecutorRegistry().action_types() == frozenset()


def test_lifecycle_against_a_fake_executor():
    reg = ExecutorRegistry()
    fw = reg.register(FakeFirewall())
    action = TypedAction(action_type="block_ip", target="203.0.113.7")
    assert reg.validate(action).allowed
    first = fw.execute(action)
    assert first.ok and first.status == "executed"
    assert fw.execute(action).status == "noop"
    assert fw.verify(action, first).verified
    undo = TypedAction(
        action_type="block_ip", target="203.0.113.7", reverse_of="action-1"
    )
    assert reg.validate(undo).allowed
    assert fw.reverse(undo, first).ok
    assert fw.verify(action, first).status == "failed"


def test_registry_refuses_overlap_unknown_and_malformed():
    reg = ExecutorRegistry()
    reg.register(FakeFirewall())
    with pytest.raises(ExecutorConflict, match="already registered"):
        reg.register(FakeFirewall())
    with pytest.raises(UnknownActionType):
        reg.for_type("isolate_host")
    assert reg.get("isolate_host") is None

    class Stray(FakeFirewall):
        action_types = frozenset({"x"})
        reversible_types = frozenset({"y"})

    with pytest.raises(ExecutorConflict, match="reversible types"):
        ExecutorRegistry().register(Stray())

    class Empty(FakeFirewall):
        action_types = frozenset()
        reversible_types = frozenset()

    with pytest.raises(ExecutorConflict, match="no action types"):
        ExecutorRegistry().register(Empty())

    class BadTtl(FakeFirewall):
        default_ttl = timedelta(0)

    with pytest.raises(ExecutorConflict, match="default_ttl"):
        ExecutorRegistry().register(BadTtl())

    with pytest.raises(ExecutorConflict, match="does not implement"):
        ExecutorRegistry().register(object())  # type: ignore[arg-type]


def test_unregister_frees_the_types():
    reg = ExecutorRegistry()
    fw = reg.register(FakeFirewall())
    reg.unregister(fw)
    assert reg.action_types() == frozenset()
    reg.register(FakeFirewall())


def test_registry_validate_guards_reversibility():
    reg = ExecutorRegistry()
    reg.register(FakeFirewall())
    assert reg.reversibility_of("block_ip") == "reversible"
    assert reg.reversibility_of("allow_ip") == "irreversible"

    # Overstating reversibility would let it auto-approve.
    overstated = reg.validate(TypedAction(action_type="allow_ip", target="1.2.3.4"))
    assert not overstated.allowed and "irreversible" in overstated.reasons[0]

    honest = reg.validate(
        TypedAction(
            action_type="allow_ip", target="1.2.3.4", reversibility="irreversible"
        )
    )
    assert honest.allowed and honest.requires_approval

    no_undo = reg.validate(
        TypedAction(
            action_type="allow_ip",
            target="1.2.3.4",
            reversibility="irreversible",
            reverse_of="a",
        )
    )
    assert not no_undo.allowed

    assert not reg.validate(TypedAction(action_type="nope", target="x")).allowed
    denied = reg.validate(TypedAction(action_type="block_ip", target="10.0.0.1"))
    assert denied.reasons == ("internal address",)


def test_idempotency_key_is_derived_and_stable():
    a = TypedAction(
        action_type="block_ip", target="1.2.3.4", parameters={"b": 1, "a": 2}
    )
    b = TypedAction(
        action_type="block_ip", target="1.2.3.4", parameters={"a": 2, "b": 1}
    )
    c = TypedAction(action_type="block_ip", target="1.2.3.4", parameters={"a": 3})
    assert a.idempotency_key == b.idempotency_key != c.idempotency_key
    assert a.idempotency_key == derive_idempotency_key(
        "block_ip", "1.2.3.4", {"a": 2, "b": 1}
    )
    assert (
        TypedAction(action_type="t", target="x", idempotency_key="mine").idempotency_key
        == "mine"
    )


def test_typed_action_is_strict_and_frozen():
    with pytest.raises(ValidationError):
        TypedAction(action_type="t", target="x", surprise=1)
    with pytest.raises(ValidationError):
        TypedAction(action_type="t", target="x", reversibility="maybe")
    with pytest.raises(ValidationError):
        TypedAction(action_type="t", target="x", ttl=timedelta(0))
    with pytest.raises(ValidationError):
        TypedAction(action_type="x" * 41, target="x")
    a = TypedAction(action_type="t", target="x")
    with pytest.raises(ValidationError):
        a.target = "y"
    assert a.tenant_id == "default"


def test_to_approval_columns_names_real_approval_actions_columns():
    executed = datetime(2026, 10, 12, 12, 0, 0)
    a = TypedAction(action_type="block_ip", target="1.2.3.4")
    cols = a.to_approval_columns(executed_at=executed, default_ttl=timedelta(hours=1))
    assert set(cols) <= set(ApprovalAction.__table__.columns.keys())
    assert cols["expires_at"] == executed + timedelta(hours=1)
    assert cols["reversibility"] == "reversible"
    assert cols["idempotency_key"] == a.idempotency_key
    own = TypedAction(
        action_type="block_ip", target="1.2.3.4", ttl=timedelta(minutes=5)
    )
    assert own.to_approval_columns(
        executed_at=executed, default_ttl=timedelta(hours=1)
    )["expires_at"] == executed + timedelta(minutes=5)
    assert a.to_approval_columns()["expires_at"] is None
    assert a.to_approval_columns(executed_at=executed)["expires_at"] is None


def test_verify_status_values_match_the_column_check():
    from typing import get_args

    sql = (
        base.__file__.rsplit("/core/", 1)[0]
        + "/infra/database/init/49_approval_action_lifecycle.sql"
    )
    text = open(sql, encoding="utf-8").read()
    for value in get_args(base.VerifyStatus):
        assert f"'{value}'" in text


def test_results_must_say_why_they_failed():
    with pytest.raises(ValidationError):
        ExecResult(status="failed")
    with pytest.raises(ValidationError):
        PolicyResult(allowed=False)
    failed = ExecResult(status="failed", error="api 500", external_ref="r1")
    assert not failed.ok
    assert failed.to_execution_result() == {
        "success": False,
        "status": "failed",
        "message": "",
        "external_ref": "r1",
        "error": "api 500",
    }
    assert ExecResult(status="noop").ok
    assert not VerifyResult(status="unknown").verified
