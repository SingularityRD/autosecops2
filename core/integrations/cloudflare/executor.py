"""Cloudflare response executor (W2.4): WAF IP block, Gateway domain block,
Access session revoke, behind the ``Executor`` protocol
(``core/response/executors/base.py``).

==============  ===========  ===============================================
action_type     reversible   effect
==============  ===========  ===============================================
waf_block       yes (24h)    IP Access Rule on the account; reverse deletes it
gateway_block   yes (24h)    Zero Trust Gateway DNS/HTTP block rule; reverse
                             deletes it
access_revoke   no           revokes the user's Access sessions; nothing to
                             restore, so it is irreversible
==============  ===========  ===============================================

The integration settings are read at each call, not when the executor is
built, so enabling Cloudflare in Settings takes effect without a restart and a
disabled integration fails the action with ``cloudflare_integration_disabled``
as the pre-registry dispatcher did.

A WAF block Cloudflare reports as a duplicate is a ``noop``: the rule was
there before us, so its reverse is a ``noop`` too and never deletes a rule
this executor did not create.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Callable
from datetime import timedelta
from typing import Any, Dict, Optional, Tuple

from core.integrations.cloudflare import client as cf
from core.response.executors.base import (
    ExecResult,
    PolicyResult,
    TypedAction,
    VerifyResult,
)

logger = logging.getLogger(__name__)

WAF_BLOCK = "waf_block"
GATEWAY_BLOCK = "gateway_block"
ACCESS_REVOKE = "access_revoke"
DEFAULT_TTL = timedelta(hours=24)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Cloudflare's code for "an IP Access Rule for this value already exists".
_DUPLICATE_CODES = {10009}

# (enabled, integration config)
SettingsProvider = Callable[[], Tuple[bool, Dict[str, Any]]]


def _live_settings() -> Tuple[bool, Dict[str, Any]]:
    from core.config import is_integration_enabled
    from core.response.executors.wiring import resolved_integration_config

    if not is_integration_enabled("cloudflare"):
        return False, {}
    # Resolved, not the stored JSON: api_token is a secret field and lives
    # only in the secret store.
    return True, resolved_integration_config("cloudflare")


_SUBJECT_PARAM = {WAF_BLOCK: "ip", GATEWAY_BLOCK: "domain", ACCESS_REVOKE: "email"}
# WAF IP Access Rule modes that block or challenge. "whitelist" is not here: a
# response action never lets traffic through.
WAF_MODES = frozenset({"block", "challenge", "js_challenge", "managed_challenge"})
# Context any action may carry; none of it changes what Cloudflare is told.
_CONTEXT_PARAMS = frozenset(
    {
        "reason",
        "ttl_seconds",
        "tags",
        "asset_tags",
        "investigation_id",
        "finding_id",
        "case_id",
        "evidence",
        "notes",
        "hostname",
        "correlation",
    }
)
# What each type may carry besides context. Anything else is refused: the
# approver saw the target and these, and nothing else may steer the call.
_ALLOWED_PARAMS = {
    WAF_BLOCK: _CONTEXT_PARAMS | {"ip", "mode"},
    GATEWAY_BLOCK: _CONTEXT_PARAMS | {"domain", "rule_name"},
    ACCESS_REVOKE: _CONTEXT_PARAMS | {"email"},
}
_RULE_NAME_MAX = 100


def _canonical(action_type: str, value: str) -> Optional[str]:
    """``value`` in the form compared and sent for ``action_type``; None if invalid."""
    value = value.strip()
    if action_type == WAF_BLOCK:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return None
        if net.prefixlen == net.max_prefixlen:
            return str(net.network_address)
        return str(net)
    if action_type == GATEWAY_BLOCK:
        value = value.casefold().rstrip(".")
        return value if _DOMAIN_RE.match(value) else None
    value = value.casefold()
    return value if _EMAIL_RE.match(value) else None


def _subject(action: TypedAction) -> str:
    """What the action names at Cloudflare: always the target.

    The target is what the approver saw. A subject parameter (``ip``,
    ``domain``, ``email``) is accepted only when it names the same thing;
    ``validate`` refuses one that differs, and execute never reads it.
    """
    canonical = _canonical(action.action_type, action.target)
    return canonical if canonical is not None else action.target.strip()


def _errors_text(data: Dict[str, Any]) -> str:
    errors = data.get("errors") or []
    if data.get("error"):
        return str(data["error"])
    parts = []
    for err in errors if isinstance(errors, list) else [errors]:
        if isinstance(err, dict):
            parts.append(f"{err.get('code')}: {err.get('message')}")
        else:
            parts.append(str(err))
    status = data.get("status_code")
    head = f"HTTP {status}" if status else "Cloudflare call failed"
    return f"{head}: {'; '.join(parts)}" if parts else head


def _is_duplicate(data: Dict[str, Any]) -> bool:
    for err in data.get("errors") or []:
        if isinstance(err, dict) and (
            err.get("code") in _DUPLICATE_CODES
            or "duplicate" in str(err.get("message", "")).lower()
        ):
            return True
    return False


class CloudflareExecutor:
    """Executor for waf_block, gateway_block and access_revoke."""

    action_types = frozenset({WAF_BLOCK, GATEWAY_BLOCK, ACCESS_REVOKE})
    reversible_types = frozenset({WAF_BLOCK, GATEWAY_BLOCK})
    default_ttl: Optional[timedelta] = DEFAULT_TTL

    def __init__(self, settings: Optional[SettingsProvider] = None) -> None:
        self._settings = settings or _live_settings

    # -- validate ----------------------------------------------------------

    def validate(self, action: TypedAction) -> PolicyResult:
        if action.action_type not in self.action_types:
            return PolicyResult.deny(f"cloudflare does not take {action.action_type!r}")
        stray = sorted(set(action.parameters) - _ALLOWED_PARAMS[action.action_type])
        if stray:
            return PolicyResult.deny(
                f"{action.action_type} does not take parameter(s) {', '.join(stray)}"
            )
        subject = _subject(action)
        override = action.parameters.get(_SUBJECT_PARAM[action.action_type])
        if override is not None and str(override).strip():
            if not isinstance(override, str) or _canonical(
                action.action_type, override
            ) != _canonical(action.action_type, action.target):
                return PolicyResult.deny(
                    f"parameters.{_SUBJECT_PARAM[action.action_type]} "
                    f"{str(override)!r} differs from the target {action.target!r}"
                )
        if action.action_type == WAF_BLOCK:
            mode = action.parameters.get("mode")
            if mode is not None and str(mode) not in WAF_MODES:
                return PolicyResult.deny(
                    f"waf_block mode {mode!r} is not one of {sorted(WAF_MODES)}"
                )
            try:
                ipaddress.ip_network(subject, strict=False)
            except ValueError:
                return PolicyResult.deny(f"waf_block target {subject!r} is not an IP")
        elif action.action_type == GATEWAY_BLOCK:
            rule_name = action.parameters.get("rule_name")
            if rule_name is not None and (
                not isinstance(rule_name, str) or len(rule_name) > _RULE_NAME_MAX
            ):
                return PolicyResult.deny(
                    f"gateway_block rule_name must be text of at most {_RULE_NAME_MAX} characters"
                )
            if not _DOMAIN_RE.match(subject):
                return PolicyResult.deny(
                    f"gateway_block target {subject!r} is not a domain"
                )
        elif not _EMAIL_RE.match(subject):
            return PolicyResult.deny(
                f"access_revoke target {subject!r} is not an email"
            )
        return PolicyResult.allow(requires_approval=action.action_type == ACCESS_REVOKE)

    # -- execute -----------------------------------------------------------

    def _credentials(self) -> Tuple[Optional[ExecResult], str, Optional[str]]:
        enabled, cfg = self._settings()
        if not enabled:
            return (
                ExecResult(
                    status="failed",
                    error="cloudflare_integration_disabled",
                    message="Enable the Cloudflare integration in Settings to execute this action.",
                ),
                "",
                None,
            )
        token = cfg.get("api_token")
        if not token:
            return (
                ExecResult(
                    status="failed", error="cloudflare api_token not configured"
                ),
                "",
                None,
            )
        return None, str(token), cfg.get("account_id")

    def execute(self, action: TypedAction) -> ExecResult:
        refusal, token, account_id = self._credentials()
        if refusal is not None:
            return refusal
        subject = _subject(action)
        reason = str(action.parameters.get("reason") or "AutoSecOps response action")
        try:
            if action.action_type == WAF_BLOCK:
                mode = str(action.parameters.get("mode") or "block")
                if mode not in WAF_MODES:
                    return ExecResult(
                        status="failed", error=f"waf_block mode {mode!r} refused"
                    )
                data = cf._waf_block_ip(
                    api_token=token,
                    account_id=account_id,
                    ip=subject,
                    reason=reason,
                    mode=mode,
                )
                if not data.get("success") and _is_duplicate(data):
                    return ExecResult(
                        status="noop",
                        message=f"{subject} already has a WAF access rule",
                        before_state={"rule_present": True, "rule_id": None},
                        after_state={"rule_present": True, "rule_id": None},
                    )
                return self._rule_result(data, subject, "WAF block")
            if action.action_type == GATEWAY_BLOCK:
                data = cf._gateway_block_domain(
                    api_token=token,
                    account_id=account_id,
                    domain=subject,
                    reason=reason,
                    rule_name=action.parameters.get("rule_name"),
                )
                return self._rule_result(data, subject, "Gateway block")
            data = cf._access_revoke_session(
                api_token=token,
                account_id=account_id,
                email=subject,
                reason=reason,
            )
            if not data.get("success"):
                return ExecResult(status="failed", error=_errors_text(data))
            return ExecResult(
                status="executed",
                message=f"Access sessions revoked for {subject}",
                after_state={"sessions_revoked": True},
            )
        except Exception as e:  # noqa: BLE001  transport errors become a failed result
            logger.warning(
                "Cloudflare %s failed: %s", action.action_type, type(e).__name__
            )
            return ExecResult(status="failed", error=f"cloudflare request failed: {e}")

    @staticmethod
    def _rule_result(data: Dict[str, Any], subject: str, what: str) -> ExecResult:
        if not data.get("success"):
            return ExecResult(status="failed", error=_errors_text(data))
        rule_id = data.get("rule_id")
        return ExecResult(
            status="executed",
            message=f"{what} in place for {subject}",
            external_ref=rule_id,
            before_state={"rule_present": False, "rule_id": None},
            after_state={"rule_present": True, "rule_id": rule_id},
        )

    # -- verify ------------------------------------------------------------

    @staticmethod
    def _rule_id(result: ExecResult) -> Optional[str]:
        if result.external_ref:
            return result.external_ref
        state = result.after_state or result.before_state or {}
        rule_id = state.get("rule_id")
        return str(rule_id) if rule_id else None

    def verify(self, action: TypedAction, result: ExecResult) -> VerifyResult:
        """A rule this executor created is present (or, for a reverse, gone)."""
        if action.action_type == ACCESS_REVOKE:
            return VerifyResult(
                status="unknown", message="Access session revocation is not observable"
            )
        if result.status == "failed":
            return VerifyResult(status="failed", message="the action did not run")
        rule_id = self._rule_id(result)
        if not rule_id:
            return VerifyResult(
                status="unknown", message="no rule of ours to look for (noop)"
            )
        refusal, token, account_id = self._credentials()
        if refusal is not None:
            return VerifyResult(status="unknown", message=refusal.error or "")
        getter = (
            cf._waf_get_rule
            if action.action_type == WAF_BLOCK
            else cf._gateway_get_rule
        )
        try:
            found = getter(token, account_id, rule_id)
        except Exception as e:  # noqa: BLE001
            return VerifyResult(
                status="unknown", message=f"lookup failed: {type(e).__name__}"
            )
        if "error" in found:
            return VerifyResult(status="unknown", message=str(found["error"]))
        want_present = action.reverse_of is None
        observed = {"rule_id": rule_id, "rule_present": bool(found.get("found"))}
        if observed["rule_present"] == want_present:
            return VerifyResult(status="verified", observed=observed)
        return VerifyResult(
            status="failed",
            observed=observed,
            message="rule present" if not want_present else "rule missing",
        )

    # -- reverse -----------------------------------------------------------

    def reverse(self, action: TypedAction, result: ExecResult) -> ExecResult:
        """Delete the rule ``result`` created; a noop original reverses to a noop."""
        if action.action_type not in self.reversible_types:
            return ExecResult(
                status="failed", error=f"{action.action_type} cannot be reversed"
            )
        rule_id = self._rule_id(result)
        if result.status == "noop" or not rule_id:
            return ExecResult(
                status="noop",
                message="no rule of ours to remove",
                before_state=result.after_state,
                after_state=result.before_state,
            )
        refusal, token, account_id = self._credentials()
        if refusal is not None:
            return refusal
        try:
            if action.action_type == WAF_BLOCK:
                data = cf._waf_unblock_ip(token, account_id, rule_id)
            else:
                data = cf._gateway_unblock_domain(token, account_id, rule_id)
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "Cloudflare reverse of %s failed: %s",
                action.action_type,
                type(e).__name__,
            )
            return ExecResult(status="failed", error=f"cloudflare request failed: {e}")
        if data.get("status_code") == 404:
            return ExecResult(
                status="noop",
                message=f"rule {rule_id} was already gone",
                external_ref=rule_id,
                before_state={"rule_present": False, "rule_id": rule_id},
                after_state={"rule_present": False, "rule_id": rule_id},
            )
        if not data.get("success"):
            return ExecResult(status="failed", error=_errors_text(data))
        return ExecResult(
            status="executed",
            message=f"rule {rule_id} removed",
            external_ref=rule_id,
            before_state={"rule_present": True, "rule_id": rule_id},
            after_state={"rule_present": False, "rule_id": rule_id},
        )


def build_executor(config: Optional[Dict[str, Any]] = None) -> CloudflareExecutor:
    """The registry factory. ``config`` is ignored: settings are read per call."""
    return CloudflareExecutor()


__all__ = ["CloudflareExecutor", "DEFAULT_TTL", "build_executor"]
