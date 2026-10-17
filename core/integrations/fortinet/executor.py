"""FortiGate response executor: block an IP through an address group (W0.57).

``block_ip`` does not edit a firewall policy. It creates an address object
``autosecops-<ip>`` and adds it to an address group (``autosecops-block``, or
``autosecops-block6`` for IPv6) that an operator has referenced once from a
deny policy; FortiOS applies CMDB changes at once, with no commit. Members are
added and removed one at a time through the group's ``member`` child table, so
two actions never overwrite each other's list. ``unblock_ip`` removes the
member and the object. The firewall-side setup is in ``EXECUTOR.md``.

FortiOS has no expiry on an address-group member, so the block lasts until it
is reversed: the action's ttl (default 24 hours) sets ``expires_at`` and the
daemon's TTL sweep reverses it then (``AutonomousResponseService.sweep_expired``).

Lifecycle and validation rules are those of the Palo Alto executor
(``core/integrations/palo_alto/executor.py``): validate never calls the
firewall; execute reads the membership first and answers ``noop`` when the
requested state holds; verify re-reads it; reverse restores ``before_state``.
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
import time
from collections.abc import Callable, Iterable, Mapping
from datetime import timedelta
from typing import Any, Optional, Union

from core.integrations.fortinet.client import (
    FortiApiError,
    FortiConfigError,
    FortiConnection,
    path_name,
)
from core.integrations.palo_alto.executor import _host_address
from core.response.executors.base import (
    ExecResult,
    PolicyResult,
    TypedAction,
    VerifyResult,
)

logger = logging.getLogger(__name__)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

BLOCK_IP = "block_ip"
UNBLOCK_IP = "unblock_ip"

DEFAULT_GROUP = "autosecops-block"
DEFAULT_GROUP6 = "autosecops-block6"
ADDRESS_PREFIX = "autosecops-"
DEFAULT_TTL_SECONDS = 24 * 60 * 60
MAX_TTL_SECONDS = 30 * 24 * 60 * 60
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BACKOFF_SECONDS = 0.5

_MIN_ALLOWED_PREFIX = {4: 8, 6: 32}
# FortiOS object names: up to 79 characters.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,78}$")


def _cidrs(value: Any, name: str) -> tuple[IPNetwork, ...]:
    if value is None or value == "":
        return ()
    items: Iterable[Any]
    if isinstance(value, str):
        items = [p for p in re.split(r"[,\s]+", value) if p]
    else:
        items = value
    out: list[IPNetwork] = []
    for item in items:
        try:
            out.append(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            raise FortiConfigError(f"{name}: {item!r} is not a CIDR") from None
    return tuple(out)


class FortiGateExecutor:
    """``Executor`` for ``block_ip`` / ``unblock_ip`` via an address group."""

    action_types: frozenset[str] = frozenset({BLOCK_IP, UNBLOCK_IP})
    reversible_types: frozenset[str] = frozenset({BLOCK_IP, UNBLOCK_IP})

    def __init__(
        self,
        connection: FortiConnection,
        *,
        group: str = DEFAULT_GROUP,
        group6: str = DEFAULT_GROUP6,
        default_ttl: timedelta = timedelta(seconds=DEFAULT_TTL_SECONDS),
        protected_cidrs: Iterable[IPNetwork] = (),
        allowed_internal_cidrs: Iterable[IPNetwork] = (),
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        for label, value in (("group", group), ("group6", group6)):
            if not _NAME_RE.match(value or ""):
                raise FortiConfigError(f"{label} {value!r} is not a valid object name")
        seconds = default_ttl.total_seconds()
        if not (0 < seconds <= MAX_TTL_SECONDS):
            raise FortiConfigError(
                f"default TTL must be between 1 second and {MAX_TTL_SECONDS} seconds"
            )
        allowed = tuple(allowed_internal_cidrs)
        for net in allowed:
            if net.prefixlen < _MIN_ALLOWED_PREFIX[net.version]:
                raise FortiConfigError(
                    f"allowed_internal_cidrs entry {net} is broader than "
                    f"/{_MIN_ALLOWED_PREFIX[net.version]}"
                )
        protected = list(protected_cidrs)
        try:
            mgmt = ipaddress.ip_address(connection.host.strip("[]"))
            protected.append(ipaddress.ip_network(mgmt))
        except ValueError:
            pass
        self.connection = connection
        self.group = group
        self.group6 = group6
        self.default_ttl: Optional[timedelta] = default_ttl
        self.protected_cidrs: tuple[IPNetwork, ...] = tuple(protected)
        self.allowed_internal_cidrs: tuple[IPNetwork, ...] = allowed
        self.max_attempts = max(1, int(max_attempts))
        self.backoff_seconds = max(0.0, float(backoff_seconds))
        self._sleep = sleep

    def __repr__(self) -> str:
        return f"FortiGateExecutor(host={self.connection.host!r}, group={self.group!r})"

    # ------------------------------------------------------------------ #
    # validate
    # ------------------------------------------------------------------ #

    def _ttl_seconds(self, action: TypedAction) -> int:
        ttl = action.ttl if action.ttl is not None else self.default_ttl
        assert ttl is not None
        return max(1, math.ceil(ttl.total_seconds()))

    @staticmethod
    def _wants_member(action: TypedAction) -> bool:
        forward = action.action_type == BLOCK_IP
        return forward if action.reverse_of is None else not forward

    def _refusals(self, action: TypedAction) -> tuple[list[str], bool]:
        if action.action_type not in self.action_types:
            return [f"fortigate executor does not handle {action.action_type!r}"], False
        try:
            ip = _host_address(action.target)
        except ValueError as exc:
            return [str(exc)], False
        if not self._wants_member(action):
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
    # firewall calls
    # ------------------------------------------------------------------ #

    def _call(self, method: str, path: str, body: Optional[Mapping[str, Any]] = None):
        return self.connection.call(
            method,
            path,
            body,
            attempts=self.max_attempts,
            backoff_seconds=self.backoff_seconds,
            sleep=self._sleep,
        )

    @staticmethod
    def address_name(ip: IPAddress) -> str:
        # IPv6 colons become dashes; a compressed IPv6 form holds no dash, so
        # the name still identifies one address.
        return f"{ADDRESS_PREFIX}{str(ip).replace(':', '-')}"

    def _group_for(self, ip: IPAddress) -> tuple[str, str, str]:
        """(group, group table, address table) for ``ip``'s family."""
        if ip.version == 6:
            return self.group6, "cmdb/firewall/addrgrp6", "cmdb/firewall/address6"
        return self.group, "cmdb/firewall/addrgrp", "cmdb/firewall/address"

    def members(self, ip: IPAddress) -> list[str]:
        """The names in ``ip``'s block group (sorted)."""
        group, grp_table, _ = self._group_for(ip)
        payload = self._call("GET", f"{grp_table}/{path_name(group)}")
        results = payload.get("results") or []
        if isinstance(results, dict):
            results = [results]
        names: set[str] = set()
        for entry in results:
            for member in entry.get("member") or []:
                name = member.get("name") if isinstance(member, dict) else None
                if name:
                    names.add(str(name))
        return sorted(names)

    def _address_exists(self, ip: IPAddress) -> bool:
        _, _, addr_table = self._group_for(ip)
        try:
            self._call("GET", f"{addr_table}/{path_name(self.address_name(ip))}")
        except FortiApiError as exc:
            if exc.not_found:
                return False
            raise
        return True

    def _create_address(self, ip: IPAddress) -> None:
        _, _, addr_table = self._group_for(ip)
        body: dict[str, Any] = {
            "name": self.address_name(ip),
            "comment": "Created by AutoSecOps block_ip",
        }
        if ip.version == 6:
            body["ip6"] = f"{ip}/128"
        else:
            body["type"] = "ipmask"
            body["subnet"] = f"{ip}/32"
        try:
            self._call("POST", addr_table, body)
        except FortiApiError as exc:
            if not exc.exists:
                raise

    def _delete_address(self, ip: IPAddress) -> None:
        """Best effort: an object still referenced elsewhere stays."""
        _, _, addr_table = self._group_for(ip)
        try:
            self._call("DELETE", f"{addr_table}/{path_name(self.address_name(ip))}")
        except FortiApiError as exc:
            if not exc.not_found:
                logger.warning(
                    "fortigate: left address %s in place: %s",
                    self.address_name(ip),
                    exc.message,
                )

    def _add_member(self, ip: IPAddress) -> None:
        group, grp_table, _ = self._group_for(ip)
        try:
            self._call(
                "POST",
                f"{grp_table}/{path_name(group)}/member",
                {"name": self.address_name(ip)},
            )
        except FortiApiError as exc:
            if not exc.exists:
                raise

    def _remove_member(self, ip: IPAddress) -> None:
        group, grp_table, _ = self._group_for(ip)
        try:
            self._call(
                "DELETE",
                f"{grp_table}/{path_name(group)}/member/{path_name(self.address_name(ip))}",
            )
        except FortiApiError as exc:
            if not exc.not_found:
                raise

    def _state(self, ip: IPAddress, members: list[str]) -> dict[str, Any]:
        group, _, _ = self._group_for(ip)
        address = self.address_name(ip)
        return {
            "ip": str(ip),
            "group": group,
            "address": address,
            "member": address in members,
        }

    def _external_ref(self, ip: IPAddress) -> str:
        group, _, _ = self._group_for(ip)
        return f"fortigate:{self.connection.host}:{self.connection.vdom}:{group}:{ip}"

    # ------------------------------------------------------------------ #
    # execute / reverse
    # ------------------------------------------------------------------ #

    def _apply(self, ip: IPAddress, want_member: bool, verb: str) -> ExecResult:
        ref = self._external_ref(ip)
        group, _, _ = self._group_for(ip)
        try:
            before = self._state(ip, self.members(ip))
        except FortiApiError as exc:
            hint = (
                f"; create address group {group} and a deny policy that uses it"
                if exc.not_found
                else ""
            )
            return ExecResult(
                status="failed",
                message=f"{verb}: could not read address group {group}{hint}",
                error=exc.message,
                external_ref=ref,
            )
        if before["member"] == want_member:
            state = "in" if want_member else "not in"
            return ExecResult(
                status="noop",
                message=f"{verb}: {ip} already {state} {group}",
                before_state=before,
                after_state=before,
                external_ref=ref,
            )
        try:
            if want_member:
                if not self._address_exists(ip):
                    self._create_address(ip)
                self._add_member(ip)
            else:
                self._remove_member(ip)
                self._delete_address(ip)
        except FortiApiError as exc:
            return ExecResult(
                status="failed",
                message=f"{verb}: the firewall refused the change for {ip}",
                before_state=before,
                error=exc.message,
                external_ref=ref,
            )
        try:
            after: Optional[dict[str, Any]] = self._state(ip, self.members(ip))
        except FortiApiError as exc:
            logger.warning(
                "fortigate %s %s applied but re-read failed: %s", verb, ip, exc.message
            )
            after = None
        message = (
            f"{verb}: added {ip} to {group}"
            if want_member
            else f"{verb}: removed {ip} from {group}"
        )
        logger.info("fortigate %s", message)
        return ExecResult(
            status="executed",
            message=message,
            before_state=before,
            after_state=after,
            external_ref=ref,
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
        return self._apply(ip, self._wants_member(action), verb)

    def reverse(self, action: TypedAction, result: ExecResult) -> ExecResult:
        """Undo ``result``, restoring its ``before_state``.

        A ``noop`` changed nothing, so its reverse changes nothing. Re-adding
        an IP that an unblock removed is a block, held to every block check.
        """
        if action.action_type not in self.action_types:
            return ExecResult(
                status="failed",
                message="reverse refused",
                error=f"fortigate executor does not handle {action.action_type!r}",
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
            external_ref=self._external_ref(ip),
        )
        if result.status == "noop":
            return nothing
        before = result.before_state
        if before is None or "member" not in before:
            if result.status == "failed":
                return nothing
            return ExecResult(
                status="failed",
                message="reverse refused",
                error="the original result carries no before_state to restore",
            )
        want = bool(before["member"])
        if want == (action.action_type == BLOCK_IP):
            return nothing
        if want:
            reasons, _ = self._block_refusals(ip, action)
            if reasons:
                return ExecResult(
                    status="failed",
                    message="reverse refused by validate",
                    error="; ".join(reasons),
                    external_ref=self._external_ref(ip),
                )
        return self._apply(ip, want, verb)

    # ------------------------------------------------------------------ #
    # verify
    # ------------------------------------------------------------------ #

    def verify(self, action: TypedAction, result: ExecResult) -> VerifyResult:
        if action.action_type not in self.action_types:
            return VerifyResult(
                status="unknown",
                message=f"fortigate executor does not handle {action.action_type!r}",
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
            observed = self._state(ip, self.members(ip))
        except FortiApiError as exc:
            return VerifyResult(
                status="unknown",
                message=f"could not read the address group: {exc.message}",
            )
        want = self._wants_member(action)
        if observed["member"] == want:
            state = "in" if want else "not in"
            return VerifyResult(
                status="verified",
                observed=observed,
                message=f"{ip} is {state} {observed['group']}",
            )
        expected = "in" if want else "out of"
        return VerifyResult(
            status="failed",
            observed=observed,
            message=f"expected {ip} {expected} {observed['group']}",
        )


def _ttl_from_config(config: Mapping[str, Any]) -> timedelta:
    raw = config.get("default_ttl_seconds")
    if raw is None or raw == "":
        return timedelta(seconds=DEFAULT_TTL_SECONDS)
    if isinstance(raw, bool) or (isinstance(raw, float) and not raw.is_integer()):
        raise FortiConfigError(f"default_ttl_seconds {raw!r} is not an integer")
    try:
        return timedelta(seconds=int(raw))
    except (TypeError, ValueError):
        raise FortiConfigError(
            f"default_ttl_seconds {raw!r} is not an integer"
        ) from None


def build_executor(
    config: Mapping[str, Any], *, sleep: Callable[[float], None] = time.sleep
) -> FortiGateExecutor:
    """A ``FortiGateExecutor`` from the integration config.

    Connection keys are those of the ``fortigate`` descriptor (``hostname``,
    ``api_token``, ``vdom``, ``verify_ssl``, ``ca_cert_path``) plus optional
    ``timeout``. Executor keys, all optional: ``group``, ``group6``,
    ``default_ttl_seconds``, ``protected_cidrs``, ``allowed_internal_cidrs``,
    ``max_attempts``, ``backoff_seconds``.
    """
    connection = FortiConnection.from_config(config)
    max_attempts = config.get("max_attempts")
    backoff = config.get("backoff_seconds")
    return FortiGateExecutor(
        connection,
        group=str(config.get("group") or DEFAULT_GROUP),
        group6=str(config.get("group6") or DEFAULT_GROUP6),
        default_ttl=_ttl_from_config(config),
        protected_cidrs=_cidrs(config.get("protected_cidrs"), "protected_cidrs"),
        allowed_internal_cidrs=_cidrs(
            config.get("allowed_internal_cidrs"), "allowed_internal_cidrs"
        ),
        max_attempts=int(max_attempts) if max_attempts else DEFAULT_MAX_ATTEMPTS,
        backoff_seconds=(
            float(backoff)
            if backoff is not None and backoff != ""
            else DEFAULT_BACKOFF_SECONDS
        ),
        sleep=sleep,
    )


__all__ = [
    "BLOCK_IP",
    "DEFAULT_GROUP",
    "DEFAULT_GROUP6",
    "FortiGateExecutor",
    "UNBLOCK_IP",
    "build_executor",
]
