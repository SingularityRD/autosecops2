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
    Names are compared normalised (``identify``): host names case-folded,
    without a trailing dot or a ``DOMAIN\\`` prefix, and by short name (first
    label) as well as in full; addresses through ``ipaddress`` (IPv4-mapped
    IPv6 is the IPv4 it maps) and refused when they overlap a protected address
    or range. A range broader than /24 (IPv4) or /64 (IPv6), /0 included, is
    refused whatever it holds.
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
    it and the dispatcher refuses a row that lacks one. Types in
    ``distinct_role_types`` (W3.2) also need the second approver to hold a
    different role from the first, enforced at approval.

Configuration is the system config row ``response.policy`` (JSON, keys as in
``PolicyConfig.from_mapping``), read at each decision. A failed read is not
"no protected assets": the policy is then ``degraded`` and refuses everything.
"""

from __future__ import annotations

import ipaddress
import logging
import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any, Optional, Union

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

# Parameters that name the same thing the target does, in another form. Every
# one is checked against the protected set, not only the target: an executor
# may act on a parameter, and a proposer chooses the parameters.
_IDENTIFIER_PARAMS = (
    "hostname",
    "host",
    "fqdn",
    "computer_name",
    "computer_dns_name",
    "device_name",
    "machine",
    "machine_id",
    "device_id",
    "ip",
    "ip_address",
    "ips",
    "address",
    "cidr",
    "network",
    "email",
    "upn",
    "user",
    "username",
    "user_principal_name",
    "domain",
    "target",
    "subject",
)
_EMPTY_TARGETS = frozenset({"", "unknown", "none", "null", "n/a"})

# The narrowest network a single action may name. Anything broader is not a
# response to one host; it is an outage. /0 is the extreme case.
MIN_IPV4_PREFIX = 24
MIN_IPV6_PREFIX = 64

# The longest a reversible change may stand before it is undone. A ttl beyond
# it is refused, not clamped: the approver saw the number.
MAX_TTL = timedelta(days=30)

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def ttl_from_parameters(parameters: Mapping[str, Any]) -> Optional[timedelta]:
    """``parameters["ttl_seconds"]`` as a ttl; None when absent.

    Raises ``ValueError`` for anything that is not a positive, finite number of
    seconds no longer than ``MAX_TTL``. A ttl that cannot be turned into an
    expiry must stop the action before it runs: afterwards there is no
    ``expires_at`` to record and the row would be executed again.
    """
    raw = parameters.get("ttl_seconds")
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError("ttl_seconds must be a number of seconds")
    try:
        seconds = float(raw)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("ttl_seconds must be a number of seconds") from None
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("ttl_seconds must be a positive number of seconds")
    if seconds > MAX_TTL.total_seconds():
        raise ValueError(
            f"ttl_seconds {seconds:g} exceeds the maximum of "
            f"{int(MAX_TTL.total_seconds())} ({MAX_TTL.days} days)"
        )
    return timedelta(seconds=seconds)


def _norm(value: Any) -> str:
    return str(value).strip().casefold()


def _norm_set(values: Any) -> frozenset[str]:
    if values is None:
        return frozenset()
    if isinstance(values, str):
        values = [values]
    return frozenset(_norm(v) for v in values if str(v).strip())


def _as_network(value: str) -> Optional[IPNetwork]:
    """``value`` as a network (a bare address is a /32 or /128), canonical.

    IPv4-mapped IPv6 (``::ffff:10.0.0.5``) becomes the IPv4 it maps; a scope
    id (``fe80::1%eth0``) is dropped.
    """
    text = value.strip().strip("[]")
    if "%" in text:
        text = text.split("%", 1)[0]
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    if isinstance(net, ipaddress.IPv6Network):
        mapped = net.network_address.ipv4_mapped
        if mapped is not None and net.prefixlen >= 96:
            return ipaddress.ip_network(f"{mapped}/{net.prefixlen - 96}", strict=False)
    return net


def _too_broad(net: IPNetwork) -> bool:
    floor = MIN_IPV4_PREFIX if net.version == 4 else MIN_IPV6_PREFIX
    return net.prefixlen < floor


@dataclass(frozen=True)
class Identifier:
    """One name an action carries, in every form it is compared in.

    ``name`` is the canonical full name (host names lower-case, no trailing
    dot, no ``DOMAIN\\`` prefix; addresses in canonical text form). ``short``
    is a host name's first label (``dc01`` for ``dc01.corp.local``), so a
    protected short name matches any qualification of it and the reverse.
    ``network`` is set for addresses and CIDRs.
    """

    raw: str
    name: str
    short: Optional[str] = None
    network: Optional[IPNetwork] = None


def identify(value: Any) -> Optional[Identifier]:
    """``value`` normalised for protected-asset matching; None when blank."""
    raw = str(value).strip()
    if not raw:
        return None
    text = raw.casefold()
    if text.startswith("host:"):
        text = text[len("host:") :].strip()
    net = _as_network(text)
    if net is not None:
        name = (
            str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
        )
        return Identifier(raw=raw, name=name, network=net)
    if "\\" in text:
        # CORP\\dc01 -> dc01 (NetBIOS domain prefix).
        text = text.rsplit("\\", 1)[1].strip()
    text = text.rstrip(".")
    if not text:
        return None
    if "@" in text:
        # A mailbox / UPN: compared whole, never by its first label.
        return Identifier(raw=raw, name=text)
    short = text.split(".", 1)[0] or None
    return Identifier(raw=raw, name=text, short=short)


def _param_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return [str(value)]
    if isinstance(value, Iterable) and not isinstance(value, Mapping):
        return [str(v) for v in value if isinstance(v, (str, int)) and str(v).strip()]
    return []


class ProtectedSet:
    """The protected names and networks, normalised once per config."""

    def __init__(self, entries: Iterable[str]) -> None:
        self.names: set[str] = set()
        self.shorts: set[str] = set()
        self.networks: list[IPNetwork] = []
        for entry in entries:
            ident = identify(entry)
            if ident is None:
                continue
            if ident.network is not None:
                self.networks.append(ident.network)
            else:
                self.names.add(ident.name)
                if ident.short:
                    self.shorts.add(ident.short)

    def match(self, ident: Identifier) -> Optional[str]:
        """The protected entry ``ident`` names or overlaps, if any."""
        if ident.network is not None:
            for net in self.networks:
                if net.version == ident.network.version and net.overlaps(ident.network):
                    return str(net)
            return None
        if ident.name in self.names:
            return ident.name
        if ident.short and ident.short in self.shorts:
            return ident.short
        return None


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
    # Four-eyes types whose second approver must also hold a different role
    # from the first (W3.2). Opt-in per action class; every type listed here is
    # a four-eyes type too.
    distinct_role_types: frozenset[str] = frozenset()
    # Set when the stored config could not be read: refuse everything.
    degraded: bool = False

    @classmethod
    def from_mapping(cls, raw: Optional[Mapping[str, Any]]) -> "PolicyConfig":
        """Build from the stored JSON. Missing keys keep their defaults.

        ``protected_tags`` and ``four_eyes_types`` add to the defaults rather
        than replace them: a config row cannot unprotect a domain controller.
        ``distinct_role_types`` (W3.2) are added to ``four_eyes_types``: a
        second approver of another role presupposes a second approver.
        """
        raw = raw or {}
        limits = dict(DEFAULT_HOURLY_LIMITS)
        for key, value in (raw.get("hourly_limits") or {}).items():
            limits[_norm(key)] = int(value)
        asset_tags: dict[str, frozenset[str]] = {}
        for target, tags in (raw.get("asset_tags") or {}).items():
            ident = identify(target)
            if ident is None:
                continue
            key = ident.name
            asset_tags[key] = asset_tags.get(key, frozenset()) | _norm_set(tags)
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
            | _norm_set(raw.get("four_eyes_types"))
            | _norm_set(raw.get("distinct_role_types")),
            distinct_role_types=_norm_set(raw.get("distinct_role_types")),
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

    def needs_distinct_role(self, action_type: str) -> bool:
        """Whether the second approver must hold a role the first does not (W3.2)."""
        return _norm(action_type) in self.distinct_role_types


def _identifiers(action: TypedAction) -> list[Identifier]:
    """The target and every identifier parameter, normalised."""
    values = [action.target]
    for name in _IDENTIFIER_PARAMS:
        values.extend(_param_values(action.parameters.get(name)))
    found: list[Identifier] = []
    for value in values:
        ident = identify(value)
        if ident is not None:
            found.append(ident)
    return found


def _names_something(action: TypedAction) -> bool:
    return any(ident.name not in _EMPTY_TARGETS for ident in _identifiers(action))


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
        """Why ``action`` touches a protected asset, or None.

        Every identifier is compared normalised (see ``identify``): a host by
        its full name and by its short name, an address or CIDR by overlap
        with any protected address or range. A range broader than /24 (IPv4)
        or /64 (IPv6) is refused outright.
        """
        cfg = config or self.config
        idents = _identifiers(action)
        for ident in idents:
            if ident.network is not None and _too_broad(ident.network):
                return (
                    f"protected asset: {ident.raw} is too broad a range "
                    f"(narrowest allowed /{MIN_IPV4_PREFIX} IPv4, "
                    f"/{MIN_IPV6_PREFIX} IPv6)"
                )
        protected = ProtectedSet(cfg.protected_targets)
        for ident in idents:
            hit = protected.match(ident)
            if hit:
                return (
                    f"protected asset: {ident.raw} matches {hit} in protected_targets"
                )

        tags: set[str] = set(_declared_tags(action))
        tagged = [
            (entry, tag_set)
            for entry, tag_set in cfg.asset_tags.items()
            if tag_set & cfg.protected_tags
        ]
        for entry, tag_set in tagged:
            one = ProtectedSet([entry])
            if any(one.match(ident) for ident in idents):
                tags |= tag_set
        hit_tags = sorted(tags & cfg.protected_tags)
        if hit_tags:
            return f"protected asset: {action.target} is tagged {hit_tags[0]}"
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
        if not _names_something(action):
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
    "MAX_TTL",
    "MIN_IPV4_PREFIX",
    "MIN_IPV6_PREFIX",
    "ActionPolicy",
    "Identifier",
    "ProtectedSet",
    "identify",
    "ttl_from_parameters",
    "BLAST_RADIUS_WINDOW",
    "DEFAULT_FOUR_EYES_TYPES",
    "DEFAULT_PROTECTED_TAGS",
    "POLICY_CONFIG_KEY",
    "PolicyConfig",
    "RecentCount",
]
