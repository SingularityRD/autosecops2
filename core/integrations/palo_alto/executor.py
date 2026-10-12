"""Palo Alto firewall response executor: block an IP by tagging it.

``block_ip`` does not edit a security rule or an address object (both need a
commit and both outlive a mistake). It registers the IP with a tag through the
PAN-OS User-ID API; a Dynamic Address Group matching that tag, referenced by a
deny rule configured once by an operator, does the blocking. Registration
takes effect without a commit, carries a ``timeout`` so the firewall itself
drops the tag when the TTL runs out, and ``unregister`` undoes it exactly.
The firewall-side configuration is in ``EXECUTOR.md`` next to this file.

Lifecycle (``core/response/executors/base.py``):

validate  parses the target and refuses anything that is not a single,
          public (or explicitly allowed internal) host address outside the
          protected ranges; it never calls the firewall.
execute   reads the IP's registered tags (before_state), returns ``noop`` when
          the requested state already holds, otherwise registers/unregisters
          and reads the tags again (after_state).
verify    reads the registered tags and compares with what the action wants.
reverse   restores before_state: unregisters a tag this action added, and
          leaves alone a tag that was already there.

Not wired into any registry here; ``build_executor(config)`` builds one.
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
from xml.sax.saxutils import quoteattr

from core.integrations.palo_alto.client import (
    PanApiError,
    PanConfigError,
    PanConnection,
)
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

DEFAULT_TAG = "autosecops-block"
DEFAULT_TTL_SECONDS = 24 * 60 * 60
# PAN-OS accepts a registered-tag timeout of at most 30 days (0 = never, which
# this executor does not use: every block expires).
MAX_TTL_SECONDS = 30 * 24 * 60 * 60
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BACKOFF_SECONDS = 0.5

# An allow-list entry for internal targets broader than this would let
# validate wave through most of an internal network.
_MIN_ALLOWED_PREFIX = {4: 8, 6: 32}

# PAN-OS tag names: up to 127 characters; keep to a conservative alphabet so a
# tag never needs escaping anywhere it is shown.
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")

# Register/unregister answers that mean the requested state already holds:
# a retried request whose first attempt landed, or a TTL that expired between
# the read and the write.
_ALREADY_REGISTERED = ("already exists", "already registered")
_NOT_REGISTERED = ("does not exist", "not registered", "not found", "doesn't exist")


def _cidrs(value: Any, name: str) -> tuple[IPNetwork, ...]:
    """A list (or comma/whitespace-separated string) of CIDRs, strictly parsed."""
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
            raise PanConfigError(f"{name}: {item!r} is not a CIDR") from None
    return tuple(out)


def _host_address(target: str) -> IPAddress:
    """``target`` as one host address; a bare IP, or an IP with a host prefix.

    Raises ValueError with an operator-readable reason otherwise.
    """
    text = str(target).strip()
    if not text:
        raise ValueError("target is empty")
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise ValueError(f"target {target!r} is not an IP address") from None
        if net.num_addresses != 1:
            raise ValueError(
                f"target {target!r} is a range of {net.num_addresses} addresses; "
                "only a single host can be blocked"
            )
        return net.network_address
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        raise ValueError(f"target {target!r} is not an IP address") from None


class PaloAltoExecutor:
    """``Executor`` for ``block_ip`` / ``unblock_ip`` via DAG tag registration."""

    action_types: frozenset[str] = frozenset({BLOCK_IP, UNBLOCK_IP})
    reversible_types: frozenset[str] = frozenset({BLOCK_IP, UNBLOCK_IP})

    def __init__(
        self,
        connection: PanConnection,
        *,
        tag: str = DEFAULT_TAG,
        default_ttl: timedelta = timedelta(seconds=DEFAULT_TTL_SECONDS),
        protected_cidrs: Iterable[IPNetwork] = (),
        allowed_internal_cidrs: Iterable[IPNetwork] = (),
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not _TAG_RE.match(tag or ""):
            raise PanConfigError(f"tag {tag!r} is not a valid PAN-OS tag name")
        seconds = default_ttl.total_seconds()
        if not (0 < seconds <= MAX_TTL_SECONDS):
            raise PanConfigError(
                f"default TTL must be between 1 second and {MAX_TTL_SECONDS} seconds"
            )
        allowed = tuple(allowed_internal_cidrs)
        for net in allowed:
            if net.prefixlen < _MIN_ALLOWED_PREFIX[net.version]:
                raise PanConfigError(
                    f"allowed_internal_cidrs entry {net} is broader than "
                    f"/{_MIN_ALLOWED_PREFIX[net.version]}"
                )
        protected = list(protected_cidrs)
        # The firewall's own management address, when configured as an IP.
        try:
            mgmt = ipaddress.ip_address(connection.host.strip("[]"))
            protected.append(ipaddress.ip_network(mgmt))
        except ValueError:
            pass
        self.connection = connection
        self.tag = tag
        self.default_ttl: Optional[timedelta] = default_ttl
        self.protected_cidrs: tuple[IPNetwork, ...] = tuple(protected)
        self.allowed_internal_cidrs: tuple[IPNetwork, ...] = allowed
        self.max_attempts = max(1, int(max_attempts))
        self.backoff_seconds = max(0.0, float(backoff_seconds))
        self._sleep = sleep

    def __repr__(self) -> str:
        return f"PaloAltoExecutor(host={self.connection.host!r}, tag={self.tag!r})"

    # ------------------------------------------------------------------ #
    # validate
    # ------------------------------------------------------------------ #

    def _ttl_seconds(self, action: TypedAction) -> int:
        ttl = action.ttl if action.ttl is not None else self.default_ttl
        assert ttl is not None
        return max(1, math.ceil(ttl.total_seconds()))

    def _refusals(self, action: TypedAction) -> tuple[list[str], bool]:
        """Why ``action`` must not run, and whether it needs a human anyway."""
        if action.action_type not in self.action_types:
            return [f"palo-alto executor does not handle {action.action_type!r}"], False
        try:
            ip = _host_address(action.target)
        except ValueError as exc:
            return [str(exc)], False
        if action.action_type == UNBLOCK_IP:
            # Removing our tag cannot cut anyone off; any single host will do.
            return [], False

        reasons: list[str] = []
        needs_human = False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            reasons.append(
                f"{ip} is an IPv4-mapped IPv6 address; block {ip.ipv4_mapped} instead"
            )
            return reasons, False
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
            reasons.append(
                f"ttl {ttl} exceeds the PAN-OS registered-tag maximum of 30 days"
            )
        return reasons, needs_human

    def validate(self, action: TypedAction) -> PolicyResult:
        reasons, needs_human = self._refusals(action)
        if reasons:
            return PolicyResult.deny(*reasons)
        return PolicyResult.allow(requires_approval=needs_human)

    # ------------------------------------------------------------------ #
    # firewall calls
    # ------------------------------------------------------------------ #

    def _call(self, fields: Mapping[str, Any]):
        params = dict(fields)
        if self.connection.vsys:
            params.setdefault("vsys", self.connection.vsys)
        return self.connection.call(
            "POST",
            params,
            attempts=self.max_attempts,
            backoff_seconds=self.backoff_seconds,
            sleep=self._sleep,
        )

    def registered_tags(self, ip: IPAddress) -> list[str]:
        """The tags the firewall has registered on ``ip`` (sorted)."""
        cmd = (
            "<show><object><registered-ip><ip>"
            f"{ip}"
            "</ip></registered-ip></object></show>"
        )
        root = self._call({"type": "op", "cmd": cmd})
        tags: set[str] = set()
        for entry in root.iter("entry"):
            raw = entry.get("ip")
            if raw is None:
                continue
            try:
                if _host_address(raw) != ip:
                    continue
            except ValueError:
                continue
            for member in entry.iter("member"):
                if member.text and member.text.strip():
                    tags.add(member.text.strip())
        return sorted(tags)

    def _uid_message(self, verb: str, ip: IPAddress, timeout: Optional[int]) -> str:
        attr = f" timeout={quoteattr(str(timeout))}" if timeout is not None else ""
        return (
            "<uid-message><version>2.0</version><type>update</type><payload>"
            f"<{verb}><entry ip={quoteattr(str(ip))}><tag>"
            f"<member{attr}>{self.tag}</member>"
            f"</tag></entry></{verb}>"
            "</payload></uid-message>"
        )

    def _register(self, ip: IPAddress, timeout: int) -> None:
        try:
            self._call(
                {"type": "user-id", "cmd": self._uid_message("register", ip, timeout)}
            )
        except PanApiError as exc:
            if any(m in exc.message.lower() for m in _ALREADY_REGISTERED):
                return
            raise

    def _unregister(self, ip: IPAddress) -> None:
        try:
            self._call(
                {"type": "user-id", "cmd": self._uid_message("unregister", ip, None)}
            )
        except PanApiError as exc:
            if any(m in exc.message.lower() for m in _NOT_REGISTERED):
                return
            raise

    def _state(self, ip: IPAddress, tags: list[str]) -> dict[str, Any]:
        return {
            "ip": str(ip),
            "tag": self.tag,
            "registered": self.tag in tags,
            "tags": list(tags),
        }

    def _external_ref(self, ip: IPAddress) -> str:
        return f"palo-alto:{self.connection.host}:{self.tag}:{ip}"

    # ------------------------------------------------------------------ #
    # execute / reverse
    # ------------------------------------------------------------------ #

    def _apply(
        self, ip: IPAddress, want_registered: bool, ttl_seconds: int, verb: str
    ) -> ExecResult:
        """Bring ``ip``'s tag registration to ``want_registered``."""
        ref = self._external_ref(ip)
        try:
            before_tags = self.registered_tags(ip)
        except PanApiError as exc:
            return ExecResult(
                status="failed",
                message=f"{verb}: could not read the current registration of {ip}",
                error=exc.message,
                external_ref=ref,
            )
        before = self._state(ip, before_tags)
        if before["registered"] == want_registered:
            state = "registered" if want_registered else "not registered"
            return ExecResult(
                status="noop",
                message=f"{verb}: {ip} already {state} with tag {self.tag}",
                before_state=before,
                after_state=before,
                external_ref=ref,
            )
        try:
            if want_registered:
                self._register(ip, ttl_seconds)
            else:
                self._unregister(ip)
        except PanApiError as exc:
            return ExecResult(
                status="failed",
                message=f"{verb}: the firewall refused the change for {ip}",
                before_state=before,
                error=exc.message,
                external_ref=ref,
            )
        try:
            after: Optional[dict[str, Any]] = self._state(ip, self.registered_tags(ip))
        except PanApiError as exc:
            logger.warning(
                "palo-alto %s %s applied but re-read failed: %s", verb, ip, exc.message
            )
            after = None
        if want_registered:
            message = f"{verb}: registered {ip} with tag {self.tag} for {ttl_seconds}s"
        else:
            message = f"{verb}: unregistered tag {self.tag} from {ip}"
        logger.info("palo-alto %s", message)
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
                status="failed",
                message="refused by validate",
                error="; ".join(reasons),
            )
        ip = _host_address(action.target)
        want = action.action_type == BLOCK_IP
        return self._apply(ip, want, self._ttl_seconds(action), action.action_type)

    def reverse(self, action: TypedAction, result: ExecResult) -> ExecResult:
        """Restore ``result.before_state``.

        A block that found the tag already registered (noop) leaves it; a
        block that added it removes it. An unblock re-registers with the
        action's ttl (else the default), since the remaining lifetime of the
        removed registration is not known.
        """
        if action.action_type not in self.action_types:
            return ExecResult(
                status="failed",
                message="reverse refused",
                error=f"palo-alto executor does not handle {action.action_type!r}",
            )
        try:
            ip = _host_address(action.target)
        except ValueError as exc:
            return ExecResult(
                status="failed", message="reverse refused", error=str(exc)
            )
        before = result.before_state
        if before is None or "registered" not in before:
            if result.status == "failed":
                # execute failed before it could read the firewall, so it
                # changed nothing.
                return ExecResult(
                    status="noop",
                    message=f"reverse {action.action_type}: the original action changed nothing",
                    external_ref=self._external_ref(ip),
                )
            return ExecResult(
                status="failed",
                message="reverse refused",
                error="the original result carries no before_state to restore",
            )
        want = bool(before["registered"])
        return self._apply(
            ip, want, self._ttl_seconds(action), f"reverse {action.action_type}"
        )

    # ------------------------------------------------------------------ #
    # verify
    # ------------------------------------------------------------------ #

    def verify(self, action: TypedAction, result: ExecResult) -> VerifyResult:
        if action.action_type not in self.action_types:
            return VerifyResult(
                status="unknown",
                message=f"palo-alto executor does not handle {action.action_type!r}",
            )
        try:
            ip = _host_address(action.target)
        except ValueError as exc:
            return VerifyResult(status="unknown", message=str(exc))
        try:
            tags = self.registered_tags(ip)
        except PanApiError as exc:
            return VerifyResult(
                status="unknown",
                message=f"could not read registered tags: {exc.message}",
            )
        observed = self._state(ip, tags)
        want = action.action_type == BLOCK_IP
        if observed["registered"] == want:
            state = "registered" if want else "not registered"
            return VerifyResult(
                status="verified",
                observed=observed,
                message=f"{ip} is {state} with tag {self.tag}",
            )
        expected = "registered" if want else "absent"
        return VerifyResult(
            status="failed",
            observed=observed,
            message=f"expected tag {self.tag} {expected} on {ip}; firewall has {tags}",
        )


def _ttl_from_config(config: Mapping[str, Any]) -> timedelta:
    raw = config.get("default_ttl_seconds")
    if raw is None or raw == "":
        return timedelta(seconds=DEFAULT_TTL_SECONDS)
    try:
        seconds = int(raw)
    except (TypeError, ValueError):
        raise PanConfigError(f"default_ttl_seconds {raw!r} is not an integer") from None
    return timedelta(seconds=seconds)


def build_executor(
    config: Mapping[str, Any], *, sleep: Callable[[float], None] = time.sleep
) -> PaloAltoExecutor:
    """A ``PaloAltoExecutor`` from the integration config.

    Connection keys are those of the ``palo-alto`` descriptor (``hostname``,
    ``api_key``, ``verify_ssl``, ``ca_cert_path``) plus optional ``vsys`` and
    ``timeout``. Executor keys, all optional: ``tag``, ``default_ttl_seconds``,
    ``protected_cidrs``, ``allowed_internal_cidrs``, ``max_attempts``,
    ``backoff_seconds``. Raises ``PanConfigError`` (a ValueError) on a config
    that cannot be used.
    """
    connection = PanConnection.from_config(config)
    max_attempts = config.get("max_attempts")
    backoff = config.get("backoff_seconds")
    return PaloAltoExecutor(
        connection,
        tag=str(config.get("tag") or DEFAULT_TAG),
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
    "DEFAULT_TAG",
    "DEFAULT_TTL_SECONDS",
    "MAX_TTL_SECONDS",
    "PaloAltoExecutor",
    "UNBLOCK_IP",
    "build_executor",
]
