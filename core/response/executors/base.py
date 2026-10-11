"""The executor protocol (W0.5): how a response action is checked, run,
confirmed and undone.

Contract only. No executor exists yet, and
``core/response/autonomous_response_service.py`` does not consult this module;
the work packages that write executors (EDR isolation, IdP disable, firewall
block, ...) implement ``Executor`` and register into an ``ExecutorRegistry``.
There is deliberately no module-level registry instance
(tests/unit/_ratchets/test_no_ambient_state.py): the work package that wires
executors in builds one in the services/api/main.py lifespan, onto app.state,
and hands it out through a core/deps.py provider.

One action, one lifecycle, all on the ``approval_actions`` row:

=============  =====================================================
step           approval_actions columns it writes
=============  =====================================================
validate       nothing; a refused action is never created
(approve)      status, approved_by/at, second_approver
execute        status, executed_at, execution_result,
               before_state, after_state, expires_at
verify         verified_at, verify_status
reverse        a new row with reverse_of = the original action_id;
               reversed_at on the original
=============  =====================================================

``reversibility`` and ``idempotency_key`` are the existing columns from
``infra/database/init/30_approval_action_reversibility.sql``: a
``TypedAction`` carries both, and ``to_approval_columns`` maps it onto them.
The lifecycle columns come from ``49_approval_action_lifecycle.sql``.

Calls are synchronous like the rest of ``core.response``; an executor that
speaks to an async client runs it to completion inside the call.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Literal, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

Reversibility = Literal["reversible", "irreversible"]
ExecStatus = Literal["executed", "noop", "failed"]
# Same values as the approval_actions.verify_status CHECK constraint.
VerifyStatus = Literal["verified", "failed", "unknown"]

_FROZEN = ConfigDict(extra="forbid", frozen=True)


def derive_idempotency_key(
    action_type: str, target: str, parameters: dict[str, Any]
) -> str:
    """A stable key for "the same action on the same target".

    approval_actions keeps idempotency_key unique among non-failed rows, so two
    requests to isolate one host become one row. Parameters are part of the
    key: blocking an IP for an hour and for a day are different actions.
    """
    canonical = json.dumps(
        {"action_type": action_type, "target": target, "parameters": parameters},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"{action_type}:{hashlib.sha256(canonical.encode()).hexdigest()[:32]}"


class TypedAction(BaseModel):
    """A response action as an executor receives it.

    ``action_type`` names the executor; ``target`` is what it acts on (host,
    IP, user, ...). ``ttl`` of None means the executor's ``default_ttl``; an
    executor whose ``default_ttl`` is None makes permanent changes.
    ``reverse_of`` is set on the action that undoes another: same action_type
    and target, reverse_of = the original's action_id.
    """

    model_config = _FROZEN

    action_type: str = Field(
        min_length=1, max_length=40
    )  # approval_actions.action_type VARCHAR(40)
    target: str = Field(min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)
    reversibility: Reversibility = "reversible"
    idempotency_key: Optional[str] = None
    ttl: Optional[timedelta] = None
    reverse_of: Optional[str] = Field(default=None, max_length=80)
    action_id: Optional[str] = Field(default=None, max_length=80)
    tenant_id: str = Field(default="default", min_length=1)
    requested_by: str = Field(default="system", min_length=1, max_length=100)

    @model_validator(mode="after")
    def _fill_key(self) -> "TypedAction":
        if not self.idempotency_key:
            object.__setattr__(
                self,
                "idempotency_key",
                derive_idempotency_key(self.action_type, self.target, self.parameters),
            )
        if self.ttl is not None and self.ttl <= timedelta(0):
            raise ValueError("ttl must be positive; use None for the executor default")
        return self

    def to_approval_columns(
        self,
        *,
        executed_at: Optional[datetime] = None,
        default_ttl: Optional[timedelta] = None,
    ) -> dict[str, Any]:
        """The approval_actions columns this action sets.

        ``expires_at`` is only known once the action has run: executed_at plus
        the action's ttl, else the executor's default_ttl, else None (permanent).
        """
        ttl = self.ttl if self.ttl is not None else default_ttl
        expires_at = (
            executed_at + ttl if (executed_at is not None and ttl is not None) else None
        )
        return {
            "action_type": self.action_type,
            "target": self.target,
            "parameters": dict(self.parameters),
            "reversibility": self.reversibility,
            "idempotency_key": self.idempotency_key,
            "reverse_of": self.reverse_of,
            "expires_at": expires_at,
        }


class PolicyResult(BaseModel):
    """Whether an executor will take an action, before anyone approves it.

    ``allowed=False`` carries at least one reason. ``requires_approval`` and
    ``requires_second_approver`` can only tighten what the approval gate and
    autonomy tier decide; an executor cannot waive approval.
    """

    model_config = _FROZEN

    allowed: bool
    reasons: tuple[str, ...] = ()
    requires_approval: bool = False
    requires_second_approver: bool = False

    @model_validator(mode="after")
    def _refusal_says_why(self) -> "PolicyResult":
        if not self.allowed and not self.reasons:
            raise ValueError("a refused action must give a reason")
        return self

    @classmethod
    def allow(cls, **kw: Any) -> "PolicyResult":
        return cls(allowed=True, **kw)

    @classmethod
    def deny(cls, *reasons: str) -> "PolicyResult":
        return cls(allowed=False, reasons=tuple(reasons))


class ExecResult(BaseModel):
    """What execute (or reverse) did.

    ``noop`` means the target was already in the requested state (the host was
    already isolated): success, nothing changed. ``before_state`` and
    ``after_state`` are what the executor observed around the change; reverse
    restores ``before_state``, so an executor that cannot capture it must not
    list the action type as reversible.
    """

    model_config = _FROZEN

    status: ExecStatus
    message: str = ""
    before_state: Optional[dict[str, Any]] = None
    after_state: Optional[dict[str, Any]] = None
    external_ref: Optional[str] = None
    error: Optional[str] = None

    @model_validator(mode="after")
    def _failure_says_why(self) -> "ExecResult":
        if self.status == "failed" and not self.error:
            raise ValueError("a failed execution must carry an error")
        return self

    @property
    def ok(self) -> bool:
        return self.status != "failed"

    def to_execution_result(self) -> dict[str, Any]:
        """approval_actions.execution_result, in the shape existing rows use."""
        out: dict[str, Any] = {
            "success": self.ok,
            "status": self.status,
            "message": self.message,
        }
        if self.external_ref is not None:
            out["external_ref"] = self.external_ref
        if self.error is not None:
            out["error"] = self.error
        return out


class VerifyResult(BaseModel):
    """Whether the effect execute claimed is observable on the target.

    ``unknown`` is not ``failed``: the executor could not look (API down), so
    nothing should be retried or reversed on its account.
    """

    model_config = _FROZEN

    status: VerifyStatus
    observed: Optional[dict[str, Any]] = None
    message: str = ""

    @property
    def verified(self) -> bool:
        return self.status == "verified"


@runtime_checkable
class Executor(Protocol):
    """One integration's response actions.

    action_types
        Every ``TypedAction.action_type`` this executor takes.
    reversible_types
        The subset ``reverse`` can undo. An action type outside it is
        irreversible and always needs a human.
    default_ttl
        How long a change stands before it is reversed, when the action names
        no ttl. None: changes are permanent until someone reverses them.

    validate must not touch the target. execute must be idempotent for a
    given ``idempotency_key`` (return ``noop`` rather than act twice). reverse
    receives the original action and its ExecResult and returns the result of
    undoing it.
    """

    action_types: frozenset[str]
    reversible_types: frozenset[str]
    default_ttl: Optional[timedelta]

    def validate(self, action: TypedAction) -> PolicyResult: ...

    def execute(self, action: TypedAction) -> ExecResult: ...

    def verify(self, action: TypedAction, result: ExecResult) -> VerifyResult: ...

    def reverse(self, action: TypedAction, result: ExecResult) -> ExecResult: ...


class UnknownActionType(LookupError):
    """No executor is registered for the action type."""


class ExecutorConflict(ValueError):
    """An executor claims a type another already has, or is malformed."""


class ExecutorRegistry:
    """Action type -> the one executor that performs it."""

    def __init__(self) -> None:
        self._by_type: dict[str, Executor] = {}

    def register(self, executor: Executor) -> Executor:
        if not isinstance(executor, Executor):
            raise ExecutorConflict(f"{executor!r} does not implement Executor")
        types = frozenset(executor.action_types)
        if not types:
            raise ExecutorConflict(f"{executor!r} declares no action types")
        stray = frozenset(executor.reversible_types) - types
        if stray:
            raise ExecutorConflict(
                f"{executor!r} lists reversible types it does not execute: {sorted(stray)}"
            )
        taken = sorted(t for t in types if t in self._by_type)
        if taken:
            raise ExecutorConflict(f"action types already registered: {taken}")
        ttl = executor.default_ttl
        if ttl is not None and ttl <= timedelta(0):
            raise ExecutorConflict(f"{executor!r} default_ttl must be positive or None")
        for t in types:
            self._by_type[t] = executor
        return executor

    def unregister(self, executor: Executor) -> None:
        for t in [t for t, e in self._by_type.items() if e is executor]:
            del self._by_type[t]

    def for_type(self, action_type: str) -> Executor:
        try:
            return self._by_type[action_type]
        except KeyError:
            raise UnknownActionType(action_type) from None

    def get(self, action_type: str) -> Optional[Executor]:
        return self._by_type.get(action_type)

    def action_types(self) -> frozenset[str]:
        return frozenset(self._by_type)

    def reversibility_of(self, action_type: str) -> Reversibility:
        executor = self.for_type(action_type)
        return (
            "reversible" if action_type in executor.reversible_types else "irreversible"
        )

    def validate(self, action: TypedAction) -> PolicyResult:
        """The executor's verdict on the action, plus the registry's own checks.

        An action that calls itself reversible when its executor cannot undo it
        is refused: approval_actions.reversibility gates auto-approval, so
        overstating it would let an irreversible change skip a human.
        """
        executor = self.get(action.action_type)
        if executor is None:
            return PolicyResult.deny(
                f"no executor for action type {action.action_type!r}"
            )
        if (
            action.reversibility == "reversible"
            and self.reversibility_of(action.action_type) == "irreversible"
        ):
            return PolicyResult.deny(
                f"{action.action_type!r} cannot be reversed by its executor; mark it irreversible"
            )
        if (
            action.reverse_of is not None
            and action.action_type not in executor.reversible_types
        ):
            return PolicyResult.deny(f"{action.action_type!r} has no reverse")
        result = executor.validate(action)
        if (
            action.reversibility == "irreversible"
            and result.allowed
            and not result.requires_approval
        ):
            result = result.model_copy(update={"requires_approval": True})
        return result


__all__ = [
    "ExecResult",
    "ExecStatus",
    "Executor",
    "ExecutorConflict",
    "ExecutorRegistry",
    "PolicyResult",
    "Reversibility",
    "TypedAction",
    "UnknownActionType",
    "VerifyResult",
    "VerifyStatus",
    "derive_idempotency_key",
]
