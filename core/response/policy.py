"""Response action policy (W2.4): what may run, however it was proposed.

Every action an executor takes passes ``ActionPolicy.evaluate`` first, in the
dispatcher (``AutonomousResponseService``), whoever created the row: an
analyst, the correlation path, an agent, or a model through MCP. Agent and
model proposals are also screened when they are created, so a refused proposal
never becomes a row (W0.5: "a refused action is never created"). Screening at
creation is the early answer; the dispatcher's check is the one nothing skips.

The rules, in order:

typed validation
    ``TypedAction`` (pydantic) already holds the shape. Here: an action whose
    target and identifier parameters all name nothing (``unknown``, ``none``,
    blank) is refused.
protected assets
    A target, or any identifier in its parameters (hostname, ip, email, ...),
    listed in ``protected_targets`` or carrying a protected tag is refused,
    always: no approval, autonomy tier or confidence releases it. Tags come
    from the config (``asset_tags``: target -> tags) and from the action's own
    ``parameters["tags"]`` / ``parameters["asset_tags"]``. The config is the
    one that matters: a proposer can omit a tag, not remove one.
blast radius
    At most ``hourly_limits[type]`` (else ``default_hourly_limit``) actions of
    one type executed per rolling hour.
executor
    ``ExecutorRegistry.validate``: an executor exists for the type, the action
    does not overstate its reversibility, and the executor's own checks.
approval
    Irreversible actions always require approval and are never auto-approved.
    Types in ``four_eyes_types`` need a second approver distinct from the first
    (compared case-insensitively); ``ApprovalService.approve_action`` enforces
    it and the dispatcher refuses a row that lacks one.

Configuration is the system config row ``response.policy`` (JSON, keys as in
``PolicyConfig.from_mapping``), read at each decision. A failed read is not
"no protected assets": the policy is then ``degraded`` and refuses everything.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any, Optional

from core.response.executors.base import ExecutorRegistry, PolicyResult, TypedAction

logger = logging.getLogger(__name__)

POLICY_CONFIG_KEY = "response.policy"

DEFAULT_PROTECTED_TAGS = frozenset(
    {
        "domain_controller",
        "protected",
        "break_glass",
        "tier0",
        "critical_infrastructure",
    }
)
# The identity class: taking an account away from a person needs two people.
DEFAULT_FOUR_EYES_TYPES = frozenset({"disable_user", "revoke_sessions"})
DEFAULT_HOURLY_LIMIT = 20
DEFAULT_HOURLY_LIMITS: Mapping[str, int] = MappingProxyType(
    {"isolate_host": 10, "disable_user": 10, "revoke_sessions": 10}
)
BLAST_RADIUS_WINDOW = timedelta(hours=1)

# Parameters that name the same thing the target does, in another form.
_IDENTIFIER_PARAMS = (
    "hostname",
    "host",
    "ip",
    "ip_address",
    "email",
    "upn",
    "user",
    "username",
    "domain",
    "machine_id",
)
_EMPTY_TARGETS = frozenset({"", "unknown", "none", "null", "n/a"})


def _norm(value: Any) -> str:
    return str(value).strip().casefold()


def _norm_set(values: Any) -> frozenset[str]:
    if values is None:
        return frozenset()
    if isinstance(values, str):
        values = [values]
    return frozenset(_norm(v) for v in values if str(v).strip())


@dataclass(frozen=True)
class PolicyConfig:
    """What the policy protects and limits. All names compare case-insensitively."""

    protected_targets: frozenset[str] = frozenset()
    protected_tags: frozenset[str] = DEFAULT_PROTECTED_TAGS
    asset_tags: Mapping[str, frozenset[str]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    hourly_limits: Mapping[str, int] = DEFAULT_HOURLY_LIMITS
    default_hourly_limit: int = DEFAULT_HOURLY_LIMIT
    four_eyes_types: frozenset[str] = DEFAULT_FOUR_EYES_TYPES
    # Set when the stored config could not be read: refuse everything.
    degraded: bool = False

    @classmethod
    def from_mapping(cls, raw: Optional[Mapping[str, Any]]) -> "PolicyConfig":
        """Build from the stored JSON. Missing keys keep their defaults.

        ``protected_tags`` and ``four_eyes_types`` add to the defaults rather
        than replace them: a config row cannot unprotect a domain controller.
        """
        raw = raw or {}
        limits = dict(DEFAULT_HOURLY_LIMITS)
        for key, value in (raw.get("hourly_limits") or {}).items():
            limits[_norm(key)] = int(value)
        asset_tags = {
            _norm(target): _norm_set(tags)
            for target, tags in (raw.get("asset_tags") or {}).items()
        }
        return cls(
            protected_targets=_norm_set(raw.get("protected_targets")),
            protected_tags=DEFAULT_PROTECTED_TAGS
            | _norm_set(raw.get("protected_tags")),
            asset_tags=MappingProxyType(asset_tags),
            hourly_limits=MappingProxyType(limits),
            default_hourly_limit=int(
                raw.get("default_hourly_limit", DEFAULT_HOURLY_LIMIT)
            ),
            four_eyes_types=DEFAULT_FOUR_EYES_TYPES
            | _norm_set(raw.get("four_eyes_types")),
        )

    @classmethod
    def load(cls) -> "PolicyConfig":
        """The stored config; ``degraded`` when it cannot be read."""
        try:
            from core.storage.config_service import get_config_service

            raw = get_config_service().read_system_config(POLICY_CONFIG_KEY)
            return cls.from_mapping(raw)
        except Exception as e:  # noqa: BLE001
            logger.error("Cannot read the response policy; refusing actions: %s", e)
            return cls(degraded=True)

    def limit_for(self, action_type: str) -> int:
        return int(
            self.hourly_limits.get(_norm(action_type), self.default_hourly_limit)
        )

    def needs_second_approver(self, action_type: str) -> bool:
        return _norm(action_type) in self.four_eyes_types


def _identifiers(action: TypedAction) -> set[str]:
    found = {_norm(action.target)}
    for name in _IDENTIFIER_PARAMS:
        value = action.parameters.get(name)
        if isinstance(value, str) and value.strip():
            found.add(_norm(value))
    return found


def _declared_tags(action: TypedAction) -> frozenset[str]:
    tags: set[str] = set()
    for name in ("tags", "asset_tags"):
        value = action.parameters.get(name)
        if isinstance(value, str):
            tags |= _norm_set(value)
        elif isinstance(value, Iterable) and not isinstance(value, Mapping):
            tags |= _norm_set(list(value))
    return frozenset(tags)


# Executed actions of a type since a moment.
RecentCount = Callable[[str, datetime], int]


class ActionPolicy:
    """The checks every action passes before an executor sees it."""

    def __init__(
        self,
        config: Optional[PolicyConfig] = None,
        *,
        config_loader: Callable[[], PolicyConfig] = PolicyConfig.load,
    ) -> None:
        # Injected config is fixed; otherwise it is read at each decision so a
        # change in Settings applies without a restart.
        self._config = config
        self._config_loader = config_loader

    @property
    def config(self) -> PolicyConfig:
        return self._config if self._config is not None else self._config_loader()

    def protected_reason(
        self, action: TypedAction, config: Optional[PolicyConfig] = None
    ) -> Optional[str]:
        cfg = config or self.config
        ids = _identifiers(action)
        hit = sorted(ids & cfg.protected_targets)
        if hit:
            return f"protected asset: {hit[0]} is listed in protected_targets"
        tags: set[str] = set(_declared_tags(action))
        for ident in ids:
            tags |= cfg.asset_tags.get(ident, frozenset())
        hit = sorted(tags & cfg.protected_tags)
        if hit:
            return f"protected asset: {action.target} is tagged {hit[0]}"
        return None

    def evaluate(
        self,
        action: TypedAction,
        *,
        registry: Optional[ExecutorRegistry],
        recent_count: Optional[RecentCount] = None,
        now: Optional[datetime] = None,
    ) -> PolicyResult:
        """The verdict on ``action``.

        ``registry`` None skips the executor's checks: used only to screen a
        proposal in a process with no executors (the MCP server). The
        dispatcher always passes its registry. ``recent_count`` None skips the
        blast-radius check, likewise only for screening.
        """
        cfg = self.config
        if cfg.degraded:
            return PolicyResult.deny("response policy configuration unavailable")
        if not (_identifiers(action) - _EMPTY_TARGETS):
            return PolicyResult.deny(f"target {action.target!r} names nothing")

        protected = self.protected_reason(action, cfg)
        if protected:
            return PolicyResult.deny(protected)

        if recent_count is not None and action.reverse_of is None:
            from core.time import utcnow

            since = (now or utcnow()) - BLAST_RADIUS_WINDOW
            limit = cfg.limit_for(action.action_type)
            done = recent_count(action.action_type, since)
            if done >= limit:
                return PolicyResult.deny(
                    f"blast radius: {done} {action.action_type} action(s) in the "
                    f"last hour, limit {limit}"
                )

        requires_approval = action.reversibility == "irreversible"
        if registry is not None:
            verdict = registry.validate(action)
            if not verdict.allowed:
                return verdict
            requires_approval = requires_approval or verdict.requires_approval
            second = verdict.requires_second_approver
            if registry.get(action.action_type) is not None and (
                registry.reversibility_of(action.action_type) == "irreversible"
            ):
                requires_approval = True
        else:
            second = False

        return PolicyResult.allow(
            requires_approval=requires_approval,
            requires_second_approver=second
            or cfg.needs_second_approver(action.action_type),
        )


__all__ = [
    "ActionPolicy",
    "BLAST_RADIUS_WINDOW",
    "DEFAULT_FOUR_EYES_TYPES",
    "DEFAULT_PROTECTED_TAGS",
    "POLICY_CONFIG_KEY",
    "PolicyConfig",
    "RecentCount",
]
