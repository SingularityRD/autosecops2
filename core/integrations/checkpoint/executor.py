"""Check Point response executor: block an IP through the gateway's feed (W0.60).

``block_ip`` adds the IP to the block list served at
``/api/feeds/checkpoint/blocklist`` (``core/integrations/checkpoint/feed.py``);
the Check Point gateway polls it as a Generic Data Center object that a drop
rule references, so no policy install is needed per block. ``unblock_ip``
removes it; the ttl (default 24 hours) bounds it on the list and the TTL sweep
reverses it. Nothing is sent to the firewall from here.

The lifecycle and the target checks are those of the Palo Alto executor. The
block takes effect when the gateway next polls (its refresh interval), which
``verify`` cannot see: it confirms the list, and the message says so.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Callable, Iterable, Mapping
from datetime import timedelta
from typing import Any, Optional, Union

from core.integrations.checkpoint import feed
from core.integrations.palo_alto.executor import _host_address
from core.response.executors.base import (
    ExecResult,
    PolicyResult,
    TypedAction,
    VerifyResult,
)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

BLOCK_IP = "block_ip"
UNBLOCK_IP = "unblock_ip"
DEFAULT_TTL_SECONDS = 24 * 60 * 60
MAX_TTL_SECONDS = 30 * 24 * 60 * 60
_MIN_ALLOWED_PREFIX = {4: 8, 6: 32}
ACTOR = "checkpoint-executor"


class CheckPointConfigError(ValueError):
    pass


def _cidrs(value: Any, name: str) -> tuple[IPNetwork, ...]:
    if value is None or value == "":
        return ()
    items = (
        [p for p in str(value).replace(",", " ").split() if p]
        if isinstance(value, str)
        else list(value)
    )
    out = []
    for item in items:
        try:
            out.append(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            raise CheckPointConfigError(f"{name}: {item!r} is not a CIDR") from None
    return tuple(out)


def _default_session_scope():
    from core.storage.unit_of_work import unit_of_work

    return unit_of_work()


class CheckPointFeedExecutor:
    """``Executor`` for ``block_ip`` / ``unblock_ip`` via the polled block list."""

    action_types: frozenset[str] = frozenset({BLOCK_IP, UNBLOCK_IP})
    reversible_types: frozenset[str] = frozenset({BLOCK_IP, UNBLOCK_IP})

    def __init__(
        self,
        *,
        default_ttl: timedelta = timedelta(seconds=DEFAULT_TTL_SECONDS),
        protected_cidrs: Iterable[IPNetwork] = (),
        allowed_internal_cidrs: Iterable[IPNetwork] = (),
        session_scope: Callable[[], Any] = _default_session_scope,
    ) -> None:
        seconds = default_ttl.total_seconds()
        if not (0 < seconds <= MAX_TTL_SECONDS):
            raise CheckPointConfigError(
                f"default TTL must be between 1 second and {MAX_TTL_SECONDS} seconds"
            )
        allowed = tuple(allowed_internal_cidrs)
        for net in allowed:
            if net.prefixlen < _MIN_ALLOWED_PREFIX[net.version]:
                raise CheckPointConfigError(
                    f"allowed_internal_cidrs entry {net} is broader than "
                    f"/{_MIN_ALLOWED_PREFIX[net.version]}"
                )
        self.default_ttl: Optional[timedelta] = default_ttl
        self.protected_cidrs = tuple(protected_cidrs)
        self.allowed_internal_cidrs = allowed
        self._scope = session_scope

    def __repr__(self) -> str:
        return "CheckPointFeedExecutor()"

    # ------------------------------------------------------------------ #
    # validate
    # ------------------------------------------------------------------ #

    def _ttl(self, action: TypedAction) -> timedelta:
        ttl = action.ttl if action.ttl is not None else self.default_ttl
        assert ttl is not None
        return timedelta(seconds=max(1, math.ceil(ttl.total_seconds())))

    @staticmethod
    def _wants_listed(action: TypedAction) -> bool:
        forward = action.action_type == BLOCK_IP
        return forward if action.reverse_of is None else not forward

    def _refusals(self, action: TypedAction) -> tuple[list[str], bool]:
        if action.action_type not in self.action_types:
            return [
                f"checkpoint executor does not handle {action.action_type!r}"
            ], False
        try:
            ip = _host_address(action.target)
        except ValueError as exc:
            return [str(exc)], False
        if not self._wants_listed(action):
            return [], False
        return self._block_refusals(ip, action)

    def _block_refusals(
        self, ip: IPAddress, action: TypedAction
    ) -> tuple[list[str], bool]:
        reasons: list[str] = []
        needs_human = False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return [
                f"{ip} is an IPv4-mapped IPv6 address; block {ip.ipv4_mapped} instead"
            ], False
        if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            reasons.append(
                f"{ip} is a loopback/link-local/multicast/unspecified address"
            )
        elif ip.is_reserved:
            reasons.append(f"{ip} is in a reserved range")
        elif not ip.is_global:
            if any(ip in net for net in self.allowed_internal_cidrs):
                needs_human = True
            else:
                reasons.append(
                    f"{ip} is a private/internal address; add its range to "
                    "allowed_internal_cidrs to permit blocking it"
                )
        for net in self.protected_cidrs:
            if ip.version == net.version and ip in net:
                reasons.append(f"{ip} is in protected range {net}")
                break
        ttl = action.ttl if action.ttl is not None else self.default_ttl
        if ttl is not None and ttl.total_seconds() > MAX_TTL_SECONDS:
            reasons.append(f"ttl {ttl} exceeds the 30-day maximum")
        return reasons, needs_human

    def validate(self, action: TypedAction) -> PolicyResult:
        reasons, needs_human = self._refusals(action)
        if reasons:
            return PolicyResult.deny(*reasons)
        return PolicyResult.allow(requires_approval=needs_human)

    # ------------------------------------------------------------------ #
    # execute / reverse / verify
    # ------------------------------------------------------------------ #

    @staticmethod
    def _state(ip: IPAddress, listed: bool) -> dict[str, Any]:
        return {"ip": str(ip), "feed": feed.FEED_KEY, "listed": listed}

    @staticmethod
    def _ref(ip: IPAddress) -> str:
        return f"checkpoint:feed:{ip}"

    def _apply(
        self, ip: IPAddress, want: bool, action: TypedAction, verb: str
    ) -> ExecResult:
        try:
            with self._scope() as session:
                before = self._state(ip, feed.contains(session, str(ip)))
                if before["listed"] == want:
                    state = "on" if want else "not on"
                    return ExecResult(
                        status="noop",
                        message=f"{verb}: {ip} already {state} the block list",
                        before_state=before,
                        after_state=before,
                        external_ref=self._ref(ip),
                    )
                if want:
                    feed.add(
                        session,
                        str(ip),
                        ttl=self._ttl(action),
                        action_id=action.action_id,
                        actor=ACTOR,
                    )
                else:
                    feed.remove(session, str(ip), actor=ACTOR)
                after = self._state(ip, feed.contains(session, str(ip)))
        except feed.FeedFull as exc:
            return ExecResult(
                status="failed", message=f"{verb}: refused", error=str(exc)
            )
        except Exception as exc:  # noqa: BLE001 - the store is unavailable
            return ExecResult(
                status="failed",
                message=f"{verb}: the block list could not be updated",
                error=type(exc).__name__,
                external_ref=self._ref(ip),
            )
        message = (
            f"{verb}: {ip} on the block list; the gateway drops it from its next poll"
            if want
            else f"{verb}: {ip} off the block list from the gateway's next poll"
        )
        return ExecResult(
            status="executed",
            message=message,
            before_state=before,
            after_state=after,
            external_ref=self._ref(ip),
        )

    def execute(self, action: TypedAction) -> ExecResult:
        reasons, _ = self._refusals(action)
        if reasons:
            return ExecResult(
                status="failed", message="refused by validate", error="; ".join(reasons)
            )
        ip = _host_address(action.target)
        verb = (
            action.action_type
            if action.reverse_of is None
            else f"reverse {action.action_type}"
        )
        return self._apply(ip, self._wants_listed(action), action, verb)

    def reverse(self, action: TypedAction, result: ExecResult) -> ExecResult:
        if action.action_type not in self.action_types:
            return ExecResult(
                status="failed",
                message="reverse refused",
                error=f"checkpoint executor does not handle {action.action_type!r}",
            )
        try:
            ip = _host_address(action.target)
        except ValueError as exc:
            return ExecResult(
                status="failed", message="reverse refused", error=str(exc)
            )
        verb = f"reverse {action.action_type}"
        nothing = ExecResult(
            status="noop",
            message=f"{verb}: the original action changed nothing; nothing to undo",
            external_ref=self._ref(ip),
        )
        before = result.before_state
        if result.status == "noop" or (result.status == "failed" and not before):
            return nothing
        if before is None or "listed" not in before:
            return ExecResult(
                status="failed",
                message="reverse refused",
                error="the original result carries no before_state to restore",
            )
        want = bool(before["listed"])
        if want == (action.action_type == BLOCK_IP):
            return nothing
        if want:
            reasons, _ = self._block_refusals(ip, action)
            if reasons:
                return ExecResult(
                    status="failed",
                    message="reverse refused by validate",
                    error="; ".join(reasons),
                    external_ref=self._ref(ip),
                )
        return self._apply(ip, want, action, verb)

    def verify(self, action: TypedAction, result: ExecResult) -> VerifyResult:
        if action.action_type not in self.action_types:
            return VerifyResult(
                status="unknown",
                message=f"checkpoint executor does not handle {action.action_type!r}",
            )
        try:
            ip = _host_address(action.target)
        except ValueError as exc:
            return VerifyResult(status="unknown", message=str(exc))
        if result.status == "noop" and result.after_state is None:
            return VerifyResult(
                status="verified", message=result.message or "nothing to undo"
            )
        try:
            with self._scope() as session:
                observed = self._state(ip, feed.contains(session, str(ip)))
        except Exception as exc:  # noqa: BLE001
            return VerifyResult(
                status="unknown",
                message=f"could not read the block list: {type(exc).__name__}",
            )
        want = self._wants_listed(action)
        if observed["listed"] == want:
            state = "on" if want else "off"
            return VerifyResult(
                status="verified",
                observed=observed,
                message=f"{ip} is {state} the block list (the gateway follows on its next poll)",
            )
        return VerifyResult(
            status="failed",
            observed=observed,
            message=f"expected {ip} {'on' if want else 'off'} the block list",
        )


def _ttl_from_config(config: Mapping[str, Any]) -> timedelta:
    raw = config.get("default_ttl_seconds")
    if raw is None or raw == "":
        return timedelta(seconds=DEFAULT_TTL_SECONDS)
    if isinstance(raw, bool) or (isinstance(raw, float) and not raw.is_integer()):
        raise CheckPointConfigError(f"default_ttl_seconds {raw!r} is not an integer")
    try:
        return timedelta(seconds=int(raw))
    except (TypeError, ValueError):
        raise CheckPointConfigError(
            f"default_ttl_seconds {raw!r} is not an integer"
        ) from None


def build_executor(config: Mapping[str, Any]) -> CheckPointFeedExecutor:
    """A ``CheckPointFeedExecutor`` from the integration config.

    ``feed_token`` is required: without it the gateway cannot read the list,
    so a block would never take effect. Optional: ``default_ttl_seconds``,
    ``protected_cidrs``, ``allowed_internal_cidrs``.
    """
    if not config.get("feed_token"):
        raise CheckPointConfigError("Check Point not configured (feed_token required)")
    return CheckPointFeedExecutor(
        default_ttl=_ttl_from_config(config),
        protected_cidrs=_cidrs(config.get("protected_cidrs"), "protected_cidrs"),
        allowed_internal_cidrs=_cidrs(
            config.get("allowed_internal_cidrs"), "allowed_internal_cidrs"
        ),
    )


__all__ = ["BLOCK_IP", "UNBLOCK_IP", "CheckPointFeedExecutor", "build_executor"]
