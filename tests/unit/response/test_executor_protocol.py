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


def test_idempotency_key_without_parameters_matches_the_legacy_format():
    # autonomous_response_service.py writes f"{ActionType.ISOLATE_HOST.value}:{target_key}"
    # with target_key the IP; an executor's isolate_host on that IP must land
    # on the same approval_actions row, not a second one.
    from core.response.approval_service import ActionType

    ip = "203.0.113.7"
    legacy = f"{ActionType.ISOLATE_HOST.value}:{ip}"
    assert derive_idempotency_key(ActionType.ISOLATE_HOST.value, ip, {}) == legacy
    assert (
        TypedAction(
            action_type=ActionType.ISOLATE_HOST.value, target=ip
        ).idempotency_key
        == legacy
    )


def test_idempotency_key_with_parameters_appends_a_digest():
    import hashlib
    import json

    params = {"duration": 3600, "scope": ["inbound", "outbound"]}
    key = derive_idempotency_key("block_ip", "1.2.3.4", params)
    digest = hashlib.sha256(
        json.dumps(params, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    assert key == f"block_ip:1.2.3.4:{digest}"
    assert key != derive_idempotency_key("block_ip", "1.2.3.4", {})
    assert key != derive_idempotency_key("block_ip", "1.2.3.4", {"duration": 86400})
    # The frozen form a TypedAction holds keys the same as the plain dict.
    assert (
        TypedAction(
            action_type="block_ip", target="1.2.3.4", parameters=params
        ).idempotency_key
        == key
    )


def test_parameters_are_deeply_immutable():
    source = {"duration": 60, "ports": [22, 443], "meta": {"why": "scan"}}
    a = TypedAction(action_type="block_ip", target="1.2.3.4", parameters=source)
    key = a.idempotency_key
    # Mutating what was passed in does not reach the action.
    source["duration"] = 86400
    source["ports"].append(80)
    source["meta"]["why"] = "other"
    assert a.parameters["duration"] == 60
    # Nor can the action's own copy be changed.
    with pytest.raises(TypeError):
        a.parameters["duration"] = 86400  # type: ignore[index]
    with pytest.raises(TypeError):
        a.parameters["meta"]["why"] = "other"  # type: ignore[index]
    with pytest.raises(AttributeError):
        a.parameters["ports"].append(80)  # type: ignore[union-attr]
    assert (
        a.idempotency_key
        == key
        == derive_idempotency_key(
            "block_ip",
            "1.2.3.4",
            {"duration": 60, "ports": [22, 443], "meta": {"why": "scan"}},
        )
    )
    # What leaves the action is plain JSON-shaped data again.
    plain = {"duration": 60, "ports": [22, 443], "meta": {"why": "scan"}}
    assert a.to_approval_columns()["parameters"] == plain
    assert a.model_dump()["parameters"] == plain
    assert type(a.to_approval_columns()["parameters"]["meta"]) is dict


def test_registry_snapshots_what_an_executor_declared():
    reg = ExecutorRegistry()
    fw = FakeFirewall()
    fw.action_types = {"block_ip", "allow_ip"}  # mutable on purpose
    fw.reversible_types = {"block_ip"}
    reg.register(fw)

    # Growing the executor's sets after registration changes nothing.
    fw.reversible_types.add("allow_ip")
    fw.action_types.add("wipe_host")
    fw.reversible_types = frozenset({"block_ip", "allow_ip", "wipe_host"})
    assert reg.reversibility_of("allow_ip") == "irreversible"
    assert reg.get("wipe_host") is None
    assert reg.action_types() == frozenset({"block_ip", "allow_ip"})
    overstated = reg.validate(TypedAction(action_type="allow_ip", target="1.2.3.4"))
    assert not overstated.allowed
    no_undo = reg.validate(
        TypedAction(
            action_type="allow_ip",
            target="1.2.3.4",
            reversibility="irreversible",
            reverse_of="a",
        )
    )
    assert not no_undo.allowed
    honest = reg.validate(
        TypedAction(
            action_type="allow_ip", target="1.2.3.4", reversibility="irreversible"
        )
    )
    assert honest.allowed and honest.requires_approval

    # Shrinking them does not take reversibility away either: the registry's
    # answer is the one it gave at registration.
    fw.reversible_types = frozenset()
    assert reg.reversibility_of("block_ip") == "reversible"
    with pytest.raises(UnknownActionType):
        reg.reversibility_of("wipe_host")


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
