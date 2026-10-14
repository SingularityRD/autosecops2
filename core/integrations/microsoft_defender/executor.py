"""Microsoft Defender for Endpoint host isolation as a response executor (W2.5).

Implements ``core.response.executors.base.Executor`` for two action types:

``isolate_host``
    ``POST /machines/{id}/isolate`` with ``IsolationType`` Full (default) or
    Selective. Reversed by unisolating.
``unisolate_host``
    ``POST /machines/{id}/unisolate``. Reversed by isolating again with the
    isolation type observed before.

The target is a hostname / FQDN (``computerDnsName``), an IP address
(``lastIpAddress``) or a 40-hex MDE machine id, and must resolve to exactly one
machine; an ambiguous or unknown target is refused at validate. MDE has no
isolation flag on the machine entity, so the isolation state is read from the
machine's latest Isolate / Unisolate machine action that did not fail.

No registry wiring here: ``build_executor(config)`` returns an executor, and
the work package that owns the ``ExecutorRegistry`` registers it.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx

from core.integrations._base.aad_token import TokenError
from core.integrations._base.config import resolve
from core.integrations.microsoft_defender.client import (
    API_BASE,
    ISOLATION_TYPES,
    MDEApiError,
    MDEClient,
    acquire_token,
    check_api_base,
    odata_quote,
)
from core.integrations.microsoft_defender.descriptor import MICROSOFT_DEFENDER
from core.response.executors.base import (
    ExecResult,
    PolicyResult,
    TypedAction,
    VerifyResult,
)

logger = logging.getLogger(__name__)

ISOLATE = "isolate_host"
UNISOLATE = "unisolate_host"

_MACHINE_ID = re.compile(r"^[0-9a-fA-F]{40}$")
# A DNS name: labels of letters, digits and hyphens (underscores tolerated, as
# Windows NetBIOS names carry them). Anything else never reaches an OData filter.
_HOSTNAME = re.compile(
    r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_-]{1,63})*\.?$"
)

# machineAction.status values (learn.microsoft.com/defender-endpoint/api/machineaction).
_PENDING = frozenset({"Pending", "InProgress"})
_TERMINAL_BAD = frozenset({"Failed", "Cancelled", "TimeOut"})
_MAX_COMMENT = 1000
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# What a 400 from isolate/unisolate says when the machine already has an
# action of that kind in flight.
_ALREADY_PENDING_CODES = frozenset({"ActiveRequestAlreadyExists"})


def _created_at(action: Mapping[str, Any]) -> datetime:
    """When a machine action was created, for ordering; unparseable sorts first.

    MDE writes 7 fractional digits (``2026-10-12T08:00:00.1234567Z``), which a
    plain string sort misorders against a timestamp with fewer digits.
    """
    raw = action.get("creationDateTimeUtc") or action.get("lastUpdateDateTimeUtc")
    try:
        parsed = datetime.fromisoformat(str(raw))
    except (TypeError, ValueError):
        return _EPOCH
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class TargetError(Exception):
    """The target did not resolve to exactly one machine. ``str()`` says why."""


#: The longest verify may poll. A reverse's verify runs while its claim is
#: held; a claim older than REVERSAL_CLAIM_STALE (1h, approval_service) is
#: taken over, so the poll must end well inside that window.
MAX_VERIFY_TIMEOUT_SECONDS = 900.0


@dataclass(frozen=True)
class DefenderExecutorSettings:
    """Executor options. Credentials are not here: they come from a provider.

    ``isolation_ttl`` is the executor's ``default_ttl``: None (the default)
    means an isolation stands until someone reverses it.
    """

    api_base: str = API_BASE
    isolation_ttl: Optional[timedelta] = None
    default_isolation_type: str = "Full"
    verify_timeout_seconds: float = 300.0
    poll_interval_seconds: float = 10.0
    max_retries: int = 3
    backoff_base_seconds: float = 1.0
    require_approval: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "api_base", check_api_base(self.api_base))
        if self.default_isolation_type not in ISOLATION_TYPES:
            raise ValueError(f"default_isolation_type must be one of {ISOLATION_TYPES}")
        if self.isolation_ttl is not None and self.isolation_ttl <= timedelta(0):
            raise ValueError("isolation_ttl must be positive or None")
        if self.verify_timeout_seconds < 0 or self.poll_interval_seconds <= 0:
            raise ValueError("verify timeout must be >= 0 and poll interval > 0")
        if self.verify_timeout_seconds > MAX_VERIFY_TIMEOUT_SECONDS:
            raise ValueError(
                "verify_timeout_seconds must be at most "
                f"{MAX_VERIFY_TIMEOUT_SECONDS:.0f} (a reversal claim is taken "
                "over after an hour)"
            )


class DefenderIsolationExecutor:
    """``isolate_host`` / ``unisolate_host`` through Microsoft Defender for Endpoint."""

    action_types = frozenset({ISOLATE, UNISOLATE})
    reversible_types = frozenset({ISOLATE, UNISOLATE})

    def __init__(
        self,
        client: MDEClient,
        settings: Optional[DefenderExecutorSettings] = None,
        *,
        configured: Callable[[], bool] = lambda: True,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self.settings = settings or DefenderExecutorSettings()
        self.default_ttl: Optional[timedelta] = self.settings.isolation_ttl
        self._configured = configured
        self._sleep = sleep
        self._clock = clock

    def __repr__(self) -> str:
        return "DefenderIsolationExecutor()"

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------ resolving

    def _resolve(self, target: str) -> dict[str, Any]:
        """The one machine ``target`` names, or ``TargetError``.

        API failures propagate as ``MDEApiError`` / ``TokenError``.
        """
        target = target.strip()
        if _MACHINE_ID.match(target):
            try:
                machine = self._client.get_machine(target.lower())
            except MDEApiError as exc:
                if exc.status == 404:
                    raise TargetError(f"no MDE machine with id {target}") from None
                raise
            if not machine.get("id"):
                raise TargetError(f"no MDE machine with id {target}")
            return machine

        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            ip = None
        if ip is not None:
            candidates, more = self._client.find_machines(
                f"lastIpAddress eq {odata_quote(str(ip))}"
            )
            matches = [m for m in candidates if m.get("lastIpAddress") == str(ip)]
        elif _HOSTNAME.match(target):
            name = target.rstrip(".").lower()
            if "." in name:
                odata = f"computerDnsName eq {odata_quote(name)}"
            else:
                # A short name is the first DNS label: it matches ``host`` and
                # ``host.<domain>``, never ``host2`` or ``host-old``.
                odata = (
                    f"computerDnsName eq {odata_quote(name)} or "
                    f"startswith(computerDnsName,{odata_quote(name + '.')})"
                )
            candidates, more = self._client.find_machines(odata)
            matches = [
                m
                for m in candidates
                if (dns := str(m.get("computerDnsName") or "").lower().rstrip("."))
                == name
                or ("." not in name and dns.split(".", 1)[0] == name)
            ]
        else:
            raise TargetError(
                "target must be a hostname, an IP address or a 40-hex MDE machine id"
            )

        if more:
            # Not every match was seen, so "exactly one" cannot be established.
            raise TargetError(
                f"{target!r} matches more MDE machines than one page returns; "
                "name the machine id instead"
            )
        if not matches:
            raise TargetError(f"no MDE machine matches {target!r}")
        if len(matches) > 1:
            ids = ", ".join(sorted(str(m.get("id")) for m in matches)[:10])
            raise TargetError(
                f"{target!r} matches {len(matches)} MDE machines ({ids}); "
                "name the machine id instead"
            )
        return matches[0]

    # ---------------------------------------------------------------- state

    def _isolation_state(self, machine_id: str) -> dict[str, Any]:
        """The isolation state the latest live Isolate/Unisolate action implies."""
        actions = self._client.list_isolation_actions(machine_id)
        live = [a for a in actions if a.get("status") not in _TERMINAL_BAD]
        live.sort(key=_created_at)
        if not live:
            return {
                "isolated": False,
                "isolation_state": "not_isolated",
                "isolation_type": None,
                "last_action_id": None,
                "last_action_status": None,
            }
        last = live[-1]
        isolate = last.get("type") == "Isolate"
        pending = last.get("status") in _PENDING
        if isolate:
            state = "isolating" if pending else "isolated"
        else:
            state = "unisolating" if pending else "not_isolated"
        return {
            "isolated": isolate,
            "isolation_state": state,
            # The machineAction entity does not echo IsolationType; it is kept
            # from our own parameters where we know it.
            "isolation_type": last.get("isolationType"),
            "last_action_id": last.get("id"),
            "last_action_status": last.get("status"),
        }

    def _capture(self, machine: Mapping[str, Any]) -> dict[str, Any]:
        """Machine health plus isolation state, as stored in before/after_state."""
        machine_id = str(machine.get("id"))
        state = {
            "machine_id": machine_id,
            "computer_dns_name": machine.get("computerDnsName"),
            "health_status": machine.get("healthStatus"),
            "onboarding_status": machine.get("onboardingStatus"),
            "last_seen": machine.get("lastSeen"),
            "last_ip_address": machine.get("lastIpAddress"),
            "os_platform": machine.get("osPlatform"),
        }
        state.update(self._isolation_state(machine_id))
        return state

    # ------------------------------------------------------------- validate

    def validate(self, action: TypedAction) -> PolicyResult:
        """Refuse what cannot be done safely. Reads MDE; changes nothing."""
        if action.action_type not in self.action_types:
            return PolicyResult.deny(
                f"Defender executor does not take {action.action_type!r}"
            )
        isolation_type = action.parameters.get("isolation_type")
        if isolation_type is not None and (
            action.action_type != ISOLATE or isolation_type not in ISOLATION_TYPES
        ):
            return PolicyResult.deny(
                f"isolation_type must be one of {ISOLATION_TYPES} and only on {ISOLATE}"
            )
        comment = action.parameters.get("comment")
        if comment is not None and not isinstance(comment, str):
            return PolicyResult.deny("comment must be a string")
        if not self._configured():
            return PolicyResult.deny("Microsoft Defender is not configured")
        if action.reverse_of is not None:
            # A reverse works from the machine id recorded in the original's
            # before_state, not the target string: re-resolving the name here
            # would refuse the undo of a host renamed or re-addressed since.
            return PolicyResult.allow(requires_approval=self.settings.require_approval)
        try:
            self._resolve(action.target)
        except TargetError as exc:
            return PolicyResult.deny(str(exc))
        except (MDEApiError, TokenError) as exc:
            return PolicyResult.deny(f"could not resolve the target in MDE: {exc}")
        return PolicyResult.allow(requires_approval=self.settings.require_approval)

    # -------------------------------------------------------------- execute

    def _comment(self, action: TypedAction, verb: str) -> str:
        given = action.parameters.get("comment")
        text = (
            given
            if isinstance(given, str) and given.strip()
            else (
                f"AutoSecOps {verb} (action {action.action_id or action.idempotency_key}, "
                f"requested by {action.requested_by})"
            )
        )
        return text[:_MAX_COMMENT]

    def _apply(
        self,
        before: dict[str, Any],
        *,
        isolate: bool,
        isolation_type: str,
        comment: str,
    ) -> ExecResult:
        """Drive the machine to ``isolate``, idempotently, from ``before``."""
        machine_id = before["machine_id"]
        verb = "isolat" if isolate else "unisolat"
        state = before["isolation_state"]
        if before["isolated"] == isolate:
            pending = state in ("isolating", "unisolating")
            return ExecResult(
                status="noop",
                message=(
                    f"machine {machine_id} is already {verb}{'ing' if pending else 'ed'}"
                ),
                before_state=before,
                after_state=before,
                external_ref=before.get("last_action_id") if pending else None,
            )

        try:
            if isolate:
                response = self._client.isolate(machine_id, comment, isolation_type)
            else:
                response = self._client.unisolate(machine_id, comment)
        except MDEApiError as exc:
            return self._settle_rejected_post(before, exc, isolate=isolate, verb=verb)

        action_id = response.get("id")
        status = response.get("status") or "Pending"
        after = {
            **before,
            "isolated": isolate,
            "isolation_state": (
                ("isolating" if isolate else "unisolating")
                if status in _PENDING
                else ("isolated" if isolate else "not_isolated")
            ),
            "isolation_type": isolation_type if isolate else None,
            "last_action_id": action_id,
            "last_action_status": status,
        }
        logger.info(
            "MDE %sion requested for machine %s (machine action %s)",
            verb,
            machine_id,
            action_id,
        )
        return ExecResult(
            status="executed",
            message=f"{verb}ion requested for machine {machine_id}",
            before_state=before,
            after_state=after,
            external_ref=action_id,
        )

    def _settle_rejected_post(
        self,
        before: dict[str, Any],
        exc: MDEApiError,
        *,
        isolate: bool,
        verb: str,
    ) -> ExecResult:
        """What a POST that raised actually did, from MDE's machine actions.

        A timeout, a 5xx after retries or a 400 can each hide a request MDE
        accepted (a retried POST that landed the first time answers
        ``ActiveRequestAlreadyExists``). Reporting ``failed`` then would leave
        a host isolated with nothing scheduled to undo it, so the machine's
        actions are re-read: a live action in our direction newer than the one
        ``before`` saw is ours, and the result is ``executed`` with it as
        ``external_ref`` for verify to follow. Only a re-read that confirms no
        such action gives ``failed``. If the re-read itself fails after an
        ambiguous error (transport, 429, 5xx) the outcome is unknown: it is
        reported ``executed`` with ``outcome: unknown`` and no external_ref,
        so verify re-checks the state and reverse / TTL expiry can still undo
        it; a definite rejection (other 4xx) stays ``failed``.
        """
        machine_id = before["machine_id"]
        try:
            now = self._isolation_state(machine_id)
        except (MDEApiError, TokenError) as reread:
            if exc.retryable:
                logger.warning(
                    "MDE %sion of machine %s: outcome unknown (%s; re-read: %s)",
                    verb,
                    machine_id,
                    exc,
                    reread,
                )
                return ExecResult(
                    status="executed",
                    message=(
                        f"{verb}ion of machine {machine_id} may or may not have "
                        "been accepted; state could not be re-read"
                    ),
                    before_state=before,
                    after_state={
                        **before,
                        "isolated": isolate,
                        "isolation_state": "unknown",
                        "outcome": "unknown",
                        "error": str(exc),
                    },
                    error=str(exc),
                )
            return ExecResult(
                status="failed",
                message=f"{verb}ion of machine {machine_id} was not accepted",
                before_state=before,
                error=str(exc),
            )

        landed = (
            now["isolated"] == isolate
            and now.get("last_action_id")
            and now.get("last_action_id") != before.get("last_action_id")
        )
        if landed:
            logger.info(
                "MDE %sion of machine %s answered %s but machine action %s exists",
                verb,
                machine_id,
                exc,
                now.get("last_action_id"),
            )
            return ExecResult(
                status="executed",
                message=(
                    f"{verb}ion of machine {machine_id} is in machine action "
                    f"{now.get('last_action_id')} (the request answered: {exc})"
                ),
                before_state=before,
                after_state={**before, **now},
                external_ref=now.get("last_action_id"),
            )
        return ExecResult(
            status="failed",
            message=f"{verb}ion of machine {machine_id} was not accepted",
            before_state=before,
            after_state={**before, **now},
            error=str(exc),
        )

    def execute(self, action: TypedAction) -> ExecResult:
        if action.action_type not in self.action_types:
            return ExecResult(
                status="failed", error=f"unsupported action type {action.action_type!r}"
            )
        isolate = action.action_type == ISOLATE
        isolation_type = str(
            action.parameters.get("isolation_type")
            or self.settings.default_isolation_type
        )
        try:
            machine = self._resolve(action.target)
            before = self._capture(machine)
        except TargetError as exc:
            return ExecResult(status="failed", error=str(exc))
        except (MDEApiError, TokenError) as exc:
            return ExecResult(
                status="failed", error=f"could not read machine state: {exc}"
            )
        return self._apply(
            before,
            isolate=isolate,
            isolation_type=isolation_type,
            comment=self._comment(action, "isolate" if isolate else "unisolate"),
        )

    # --------------------------------------------------------------- verify

    def verify(self, action: TypedAction, result: ExecResult) -> VerifyResult:
        """Poll the machine action until it settles, or the timeout says unknown."""
        if result.status == "failed":
            return VerifyResult(status="failed", message="execution failed")
        want_isolated = (result.after_state or {}).get("isolated")
        if want_isolated is None:
            want_isolated = action.action_type == ISOLATE
        machine_id = (result.after_state or result.before_state or {}).get("machine_id")

        if not result.external_ref:
            # A settled noop: confirm the state still holds.
            if not machine_id:
                return VerifyResult(status="unknown", message="no machine id recorded")
            try:
                now = self._isolation_state(machine_id)
            except (MDEApiError, TokenError) as exc:
                return VerifyResult(status="unknown", message=str(exc))
            ok = now["isolated"] == want_isolated and now["isolation_state"] in (
                "isolated",
                "not_isolated",
            )
            return VerifyResult(
                status="verified" if ok else "failed",
                observed=now,
                message="state holds" if ok else "state changed since execution",
            )

        deadline = self._clock() + self.settings.verify_timeout_seconds
        last: dict[str, Any] = {}
        last_error = ""
        while True:
            try:
                last = self._client.get_machine_action(result.external_ref)
                last_error = ""
            except (MDEApiError, TokenError) as exc:
                last_error = str(exc)
            status = last.get("status")
            observed = {
                "machine_action_id": result.external_ref,
                "machine_action_status": status,
                "machine_id": machine_id,
            }
            if status == "Succeeded":
                return VerifyResult(
                    status="verified",
                    observed=observed,
                    message="machine action succeeded",
                )
            if status in _TERMINAL_BAD:
                return VerifyResult(
                    status="failed",
                    observed=observed,
                    message=f"machine action ended {status}",
                )
            if self._clock() >= deadline:
                message = (
                    f"machine action still {status or 'unreadable'} after "
                    f"{self.settings.verify_timeout_seconds:.0f}s"
                )
                if last_error:
                    message += f" ({last_error})"
                return VerifyResult(
                    status="unknown", observed=observed, message=message
                )
            self._sleep(self.settings.poll_interval_seconds)

    # -------------------------------------------------------------- reverse

    def reverse(self, action: TypedAction, result: ExecResult) -> ExecResult:
        """Put the machine back in ``result.before_state``'s isolation state.

        Works from the machine id recorded at execute, not the target string,
        so a renamed or re-addressed host is still the one that gets undone.
        A noop has nothing to undo; a host isolated before we touched it stays
        isolated.
        """
        before = result.before_state or {}
        machine_id = before.get("machine_id")
        if before.get("isolated") is None or not machine_id:
            return ExecResult(
                status="failed",
                error="no before_state recorded; cannot tell what to restore",
            )
        if result.status == "noop":
            return ExecResult(
                status="noop",
                message="the original action changed nothing; nothing to undo",
                before_state=before,
                after_state=before,
            )
        restore_isolated = bool(before["isolated"])
        try:
            machine = self._client.get_machine(machine_id)
            now = self._capture(machine)
        except (MDEApiError, TokenError) as exc:
            return ExecResult(
                status="failed", error=f"could not read machine state: {exc}"
            )
        isolation_type = str(
            before.get("isolation_type")
            or action.parameters.get("isolation_type")
            or self.settings.default_isolation_type
        )
        if isolation_type not in ISOLATION_TYPES:
            isolation_type = self.settings.default_isolation_type
        reverse_label = "unisolate" if not restore_isolated else "isolate"
        comment = (
            f"AutoSecOps reverse ({reverse_label}) of action "
            f"{action.action_id or action.idempotency_key}"
        )[:_MAX_COMMENT]
        return self._apply(
            now,
            isolate=restore_isolated,
            isolation_type=isolation_type,
            comment=comment,
        )


# ------------------------------------------------------------------ factory


def _as_timedelta(value: Any) -> Optional[timedelta]:
    if value is None or value == "":
        return None
    if isinstance(value, timedelta):
        return value
    return timedelta(seconds=float(value))


def build_executor(
    config: Optional[Mapping[str, Any]] = None,
    *,
    http: Optional[httpx.Client] = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> DefenderIsolationExecutor:
    """A ``DefenderIsolationExecutor`` for the ``microsoft-defender`` integration.

    ``config`` may carry the credentials (``tenant_id``, ``client_id``,
    ``client_secret``) and the executor options (``isolation_ttl`` seconds,
    ``default_isolation_type``, ``verify_timeout_seconds``,
    ``poll_interval_seconds``, ``max_retries``, ``backoff_base_seconds``,
    ``require_approval``, ``api_base``). ``api_base`` only selects among the
    official MDE endpoints (``ALLOWED_API_BASES``); any other host is refused
    with ``ValueError`` so the bearer token cannot be sent elsewhere.
    Credentials missing from it are
    resolved from the integration's stored config and secret store on each
    token fetch, so a rotated secret is picked up without a rebuild and an
    unconfigured integration gives an executor that refuses at validate.
    """
    cfg: Mapping[str, Any] = dict(config or {})
    settings = DefenderExecutorSettings(
        api_base=str(cfg.get("api_base") or API_BASE),
        isolation_ttl=_as_timedelta(cfg.get("isolation_ttl")),
        default_isolation_type=str(cfg.get("default_isolation_type") or "Full"),
        verify_timeout_seconds=float(cfg.get("verify_timeout_seconds", 300.0)),
        poll_interval_seconds=float(cfg.get("poll_interval_seconds", 10.0)),
        max_retries=int(cfg.get("max_retries", 3)),
        backoff_base_seconds=float(cfg.get("backoff_base_seconds", 1.0)),
        require_approval=bool(cfg.get("require_approval", False)),
    )
    explicit = {
        k: cfg[k] for k in ("tenant_id", "client_id", "client_secret") if cfg.get(k)
    }

    def credentials() -> Mapping[str, Any]:
        if len(explicit) == 3:
            return explicit
        return {**resolve(MICROSOFT_DEFENDER), **explicit}

    def configured() -> bool:
        creds = credentials()
        return all(creds.get(k) for k in ("tenant_id", "client_id", "client_secret"))

    client = MDEClient(
        lambda: acquire_token(credentials()),
        api_base=settings.api_base,
        http=http,
        max_retries=settings.max_retries,
        backoff_base=settings.backoff_base_seconds,
        sleep=sleep,
        clock=clock,
    )
    return DefenderIsolationExecutor(
        client, settings, configured=configured, sleep=sleep, clock=clock
    )


__all__ = [
    "ISOLATE",
    "UNISOLATE",
    "DefenderExecutorSettings",
    "DefenderIsolationExecutor",
    "TargetError",
    "build_executor",
]
