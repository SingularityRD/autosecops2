"""Entra ID (Azure AD) response executor: disable, enable, revoke sessions.

Implements ``core.response.executors.base.Executor`` over Microsoft Graph v1.0.

=================  ==========================================  ============
action_type        Graph call                                  reversible
=================  ==========================================  ============
disable_user       PATCH /users/{id} {"accountEnabled": false}  yes (enable)
enable_user        PATCH /users/{id} {"accountEnabled": true}   yes (disable)
revoke_sessions    POST /users/{id}/revokeSignInSessions       no
=================  ==========================================  ============

``validate`` reads the directory (it never changes it) and refuses unless the
target resolves to exactly one user that is not a protected identity: listed in
``protected_users``, matching ``protected_patterns``, or holding one of
``protected_roles``. A guest is only acted on when the action says
``parameters.user_type == "Guest"``, so an external address that happens to map
to a guest stub is not mistaken for a member. Any Graph failure while
validating is a refusal: the executor fails closed.

``execute`` resolves and checks again (a role can be granted between approval
and execution), captures the user's state, acts only when the state differs
(``noop`` otherwise), and reads the state back. ``reverse`` restores
``before_state`` by object id. See EXECUTOR.md for the live-tenant procedure.

No registry wiring here: ``build_executor`` returns an instance and the work
package that wires executors registers it.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from core.integrations._base.aad_token import TokenError
from core.integrations.azure_ad.client import (
    GraphClient,
    GraphError,
    get_graph_token,
    user_path,
)
from core.response.executors.base import (
    ExecResult,
    PolicyResult,
    TypedAction,
    VerifyResult,
)

logger = logging.getLogger(__name__)

DISABLE_USER = "disable_user"
ENABLE_USER = "enable_user"
REVOKE_SESSIONS = "revoke_sessions"

ACTION_TYPES = frozenset({DISABLE_USER, ENABLE_USER, REVOKE_SESSIONS})
REVERSIBLE_TYPES = frozenset({DISABLE_USER, ENABLE_USER})

# Directory roles whose holders are never acted on unless the config replaces
# this list. Matched by roleTemplateId or display name (case-insensitive).
DEFAULT_PROTECTED_ROLES = (
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
)

USER_SELECT = (
    "id,userPrincipalName,displayName,mail,userType,accountEnabled,"
    "signInSessionsValidFromDateTime,onPremisesSyncEnabled"
)
# The fields kept in before_state / after_state.
STATE_FIELDS = (
    "id",
    "userPrincipalName",
    "userType",
    "accountEnabled",
    "signInSessionsValidFromDateTime",
)

_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NAME = re.compile(r"^[^\s@]+@[^\s@]+$")
_USER_TYPES = {"member": "Member", "guest": "Guest"}


class ExecutorConfigError(ValueError):
    """``build_executor`` was given an unusable configuration."""


class _Refused(Exception):
    """validate's (and execute's re-check's) reason for not acting."""


def _parse_time(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _state(user: Mapping[str, Any]) -> dict[str, Any]:
    return {k: user.get(k) for k in STATE_FIELDS}


def _odata_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class EntraIdExecutor:
    """``Executor`` for Entra ID user accounts. Build it with ``build_executor``."""

    action_types: frozenset[str] = ACTION_TYPES
    reversible_types: frozenset[str] = REVERSIBLE_TYPES

    def __init__(
        self,
        client: GraphClient,
        *,
        protected_users: Iterable[str] = (),
        protected_patterns: Iterable[str] = (),
        protected_roles: Iterable[str] = DEFAULT_PROTECTED_ROLES,
        default_ttl: Optional[timedelta] = None,
    ) -> None:
        self._client = client
        self.protected_users = frozenset(u.strip().lower() for u in protected_users)
        self.protected_patterns = tuple(p.strip().lower() for p in protected_patterns)
        self.protected_roles = frozenset(r.strip().lower() for r in protected_roles)
        self.default_ttl = default_ttl
        # revoke_sessions has no "already in state"; remember what this
        # process already did per idempotency key (parameters.requested_at is
        # the durable guard, see _revoke).
        self._revoked: dict[str, ExecResult] = {}

    def __repr__(self) -> str:
        return (
            f"EntraIdExecutor(protected_users={len(self.protected_users)}, "
            f"protected_patterns={len(self.protected_patterns)}, "
            f"protected_roles={len(self.protected_roles)})"
        )

    # ============================================================ validate

    def validate(self, action: TypedAction) -> PolicyResult:
        try:
            self._check_shape(action)
            self._resolve_and_check(action)
        except _Refused as exc:
            return PolicyResult.deny(str(exc))
        except (GraphError, TokenError) as exc:
            return PolicyResult.deny(f"could not check the target in Entra ID: {exc}")
        irreversible = action.action_type not in REVERSIBLE_TYPES
        return PolicyResult.allow(requires_approval=irreversible)

    def _check_shape(self, action: TypedAction) -> None:
        if action.action_type not in ACTION_TYPES:
            raise _Refused(f"unsupported action type {action.action_type!r}")
        if (
            action.action_type not in REVERSIBLE_TYPES
            and action.reversibility == "reversible"
        ):
            raise _Refused(
                f"{action.action_type!r} cannot be undone; mark it irreversible"
            )
        target = action.target.strip()
        if not (_GUID.match(target) or _NAME.match(target)):
            raise _Refused(
                "target must be a user principal name, e-mail address or object id"
            )
        user_type = action.parameters.get("user_type")
        if user_type is not None and str(user_type).lower() not in _USER_TYPES:
            raise _Refused("parameters.user_type must be 'Member' or 'Guest'")
        requested_at = action.parameters.get("requested_at")
        if requested_at is not None and _parse_time(requested_at) is None:
            raise _Refused("parameters.requested_at must be an ISO-8601 timestamp")

    def _resolve(self, target: str) -> dict[str, Any]:
        """Exactly one user for ``target``, or ``_Refused``."""
        target = target.strip()
        if _GUID.match(target):
            try:
                return self._client.get_json(
                    user_path(target), params={"$select": USER_SELECT}
                )
            except GraphError as exc:
                if exc.status == 404:
                    raise _Refused(f"no Entra ID user with object id {target}") from exc
                raise
        literal = _odata_literal(target)
        users = self._client.get_all(
            "/users",
            params={
                "$filter": f"userPrincipalName eq {literal} or mail eq {literal}",
                "$select": USER_SELECT,
                "$count": "true",
                "$top": "10",
            },
            headers={"ConsistencyLevel": "eventual"},
            max_pages=2,
        )
        if not users:
            raise _Refused(f"no Entra ID user matches {target}")
        if len(users) > 1:
            types = sorted({str(u.get("userType") or "?") for u in users})
            kind = (
                "a guest and a member"
                if {"Guest", "Member"} <= set(types)
                else f"{len(users)} users"
            )
            raise _Refused(
                f"{target} is ambiguous: it matches {kind} "
                f"({len(users)} accounts, userType {', '.join(types)}); "
                "use the object id"
            )
        return users[0]

    def _protected_by_name(self, user: Mapping[str, Any]) -> Optional[str]:
        names = {
            str(v).lower()
            for v in (user.get("id"), user.get("userPrincipalName"), user.get("mail"))
            if v
        }
        hit = names & self.protected_users
        if hit:
            return f"{sorted(hit)[0]} is a protected identity"
        for pattern in self.protected_patterns:
            for name in names:
                if fnmatch.fnmatchcase(name, pattern):
                    return f"{name} matches protected pattern {pattern!r}"
        return None

    def _protected_by_role(self, user_id: str) -> Optional[str]:
        if not self.protected_roles:
            return None
        roles = self._client.get_all(
            f"{user_path(user_id)}/transitiveMemberOf/microsoft.graph.directoryRole",
            # The OData cast is an advanced query on some tenants.
            params={"$select": "id,displayName,roleTemplateId", "$count": "true"},
            headers={"ConsistencyLevel": "eventual"},
        )
        for role in roles:
            keys = {
                str(role.get("roleTemplateId") or "").strip().lower(),
                str(role.get("displayName") or "").strip().lower(),
            } - {""}
            if not keys:
                # An id-only stub (Graph omits what the app may not read) could
                # be any role, a protected one included: fail closed.
                return (
                    f"user holds directory role {role.get('id')!r} whose name and "
                    "template id cannot be read, so it cannot be ruled out as protected"
                )
            if keys & self.protected_roles:
                return (
                    f"user holds protected directory role {role.get('displayName')!r}"
                )
        return None

    def _resolve_and_check(self, action: TypedAction) -> dict[str, Any]:
        user = self._resolve(action.target)
        if not user.get("id"):
            raise GraphError("Graph returned a user without an id")
        reason = self._protected_by_name(user)
        if reason:
            raise _Refused(reason)

        actual = str(user.get("userType") or "Member")
        wanted = action.parameters.get("user_type")
        if wanted is not None:
            wanted = _USER_TYPES[str(wanted).lower()]
            if wanted != actual:
                raise _Refused(
                    f"target is a {actual} account but the action says {wanted}"
                )
        elif actual == "Guest":
            raise _Refused(
                "target resolves to a guest account; set parameters.user_type="
                "'Guest' to confirm the guest is meant"
            )

        if action.action_type in REVERSIBLE_TYPES and user.get("onPremisesSyncEnabled"):
            raise _Refused(
                "account is synchronised from on-premises AD; change accountEnabled "
                "there, not in Entra ID"
            )

        reason = self._protected_by_role(user["id"])
        if reason:
            raise _Refused(reason)
        return user

    # ============================================================= execute

    def execute(self, action: TypedAction) -> ExecResult:
        try:
            self._check_shape(action)
            user = self._resolve_and_check(action)
            if action.action_type == REVOKE_SESSIONS:
                return self._revoke(action, user)
            return self._set_enabled(user, action.action_type == ENABLE_USER)
        except _Refused as exc:
            return ExecResult(status="failed", error=f"refused: {exc}")
        except (GraphError, TokenError) as exc:
            return ExecResult(status="failed", error=str(exc))

    def _read_user(self, user_id: str) -> dict[str, Any]:
        return self._client.get_json(
            user_path(user_id), params={"$select": USER_SELECT}
        )

    def _set_enabled(
        self, user: Mapping[str, Any], enabled: bool, *, before: Optional[dict] = None
    ) -> ExecResult:
        user_id = str(user["id"])
        before = before if before is not None else _state(user)
        verb = "enabled" if enabled else "disabled"
        if before.get("accountEnabled") is enabled:
            return ExecResult(
                status="noop",
                message=f"account already {verb}",
                before_state=before,
                after_state=before,
                external_ref=user_id,
            )
        self._client.set_account_enabled(user_id, enabled)
        try:
            after = _state(self._read_user(user_id))
        except GraphError:
            after = {**before, "accountEnabled": enabled}  # verify re-reads
        logger.info("Entra ID account %s %s", user_id, verb)
        return ExecResult(
            status="executed",
            message=f"account {verb}",
            before_state=before,
            after_state=after,
            external_ref=user_id,
        )

    def _revoke(self, action: TypedAction, user: Mapping[str, Any]) -> ExecResult:
        user_id = str(user["id"])
        before = _state(user)
        key = action.idempotency_key or ""
        done = self._revoked.get(key)
        if done is not None:
            return done.model_copy(
                update={
                    "status": "noop",
                    "message": "sessions already revoked for this action",
                    "before_state": before,
                    "after_state": before,
                }
            )
        requested_at = _parse_time(action.parameters.get("requested_at"))
        valid_from = _parse_time(before.get("signInSessionsValidFromDateTime"))
        if requested_at and valid_from and valid_from >= requested_at:
            return ExecResult(
                status="noop",
                message="sessions already revoked since the action was requested",
                before_state=before,
                after_state=before,
                external_ref=user_id,
            )
        self._client.revoke_sign_in_sessions(user_id)
        try:
            after = _state(self._read_user(user_id))
        except GraphError:
            after = dict(before)  # verify re-reads
        logger.info("Entra ID sign-in sessions revoked for %s", user_id)
        result = ExecResult(
            status="executed",
            message="sign-in sessions revoked",
            before_state=before,
            after_state=after,
            external_ref=user_id,
        )
        if key:
            self._revoked[key] = result
        return result

    # ============================================================== verify

    def verify(self, action: TypedAction, result: ExecResult) -> VerifyResult:
        if result.status == "failed":
            return VerifyResult(
                status="unknown", message="execution failed; nothing to verify"
            )
        user_id = result.external_ref or (result.before_state or {}).get("id")
        if not user_id:
            return VerifyResult(status="unknown", message="no user id recorded")
        try:
            observed = _state(self._read_user(str(user_id)))
        except (GraphError, TokenError) as exc:
            return VerifyResult(status="unknown", message=f"could not read user: {exc}")

        if action.action_type in (DISABLE_USER, ENABLE_USER):
            want = action.action_type == ENABLE_USER
            ok = observed.get("accountEnabled") is want
            return VerifyResult(
                status="verified" if ok else "failed",
                observed=observed,
                message=(
                    f"accountEnabled is {observed.get('accountEnabled')}, "
                    f"expected {want}"
                ),
            )

        if action.action_type == REVOKE_SESSIONS:
            now = _parse_time(observed.get("signInSessionsValidFromDateTime"))
            was = _parse_time(
                (result.before_state or {}).get("signInSessionsValidFromDateTime")
            )
            if result.status == "noop":
                ok = now is not None and (was is None or now >= was)
            else:
                ok = now is not None and (was is None or now > was)
            return VerifyResult(
                status="verified" if ok else "failed",
                observed=observed,
                message=(
                    "signInSessionsValidFromDateTime "
                    f"{'advanced' if ok else 'did not advance'}"
                ),
            )
        return VerifyResult(
            status="unknown", message=f"unsupported action {action.action_type!r}"
        )

    # ============================================================= reverse

    def reverse(self, action: TypedAction, result: ExecResult) -> ExecResult:
        if action.action_type not in REVERSIBLE_TYPES:
            return ExecResult(
                status="failed",
                error=f"{action.action_type!r} is irreversible and has no reverse",
            )
        if result.status != "executed":
            return ExecResult(
                status="noop",
                message=(
                    "nothing to reverse: the original action "
                    f"{'changed nothing' if result.status == 'noop' else 'failed'}"
                ),
                before_state=result.before_state,
                after_state=result.before_state,
                external_ref=result.external_ref,
            )
        before = result.before_state or {}
        user_id = before.get("id") or result.external_ref
        restore = before.get("accountEnabled")
        if not user_id or not isinstance(restore, bool):
            return ExecResult(
                status="failed",
                error="original before_state carries no user id / accountEnabled",
            )
        try:
            current = self._read_user(str(user_id))
            return self._set_enabled(current, restore, before=_state(current))
        except (GraphError, TokenError) as exc:
            return ExecResult(status="failed", error=str(exc))


def _str_list(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [v for v in re.split(r"[,\n]", value)]
    if not isinstance(value, Iterable):
        raise ExecutorConfigError(f"{name} must be a list of strings")
    return tuple(str(v).strip() for v in value if str(v).strip())


def build_executor(
    config: Mapping[str, Any],
    *,
    sleep: Optional[Callable[[float], None]] = None,
) -> EntraIdExecutor:
    """An ``EntraIdExecutor`` from a plain configuration mapping.

    Keys: ``tenant_id``, ``client_id``, ``client_secret`` (or a
    ``token_provider`` callable instead of the three); ``protected_users``
    (UPNs, mail addresses or object ids), ``protected_patterns`` (shell globs on
    UPN / mail, e.g. ``"svc-*"``, ``"breakglass*@*"``), ``protected_roles``
    (role template ids or display names; omitted = ``DEFAULT_PROTECTED_ROLES``,
    an explicit list replaces them), ``timeout`` (s), ``max_retries``,
    ``max_backoff`` (s), ``default_ttl_seconds``. Lists may be given as
    comma-separated strings.
    """
    token_provider = config.get("token_provider")
    if token_provider is None:
        absent = [
            k for k in ("tenant_id", "client_id", "client_secret") if not config.get(k)
        ]
        if absent:
            raise ExecutorConfigError(
                f"Entra ID executor is missing configuration: {', '.join(absent)}"
            )
        creds = {k: config[k] for k in ("tenant_id", "client_id", "client_secret")}

        def token_provider() -> Optional[str]:
            return get_graph_token(creds)

    elif not callable(token_provider):
        raise ExecutorConfigError("token_provider must be callable")

    client_kw: dict[str, Any] = {}
    for key, cast in (("timeout", float), ("max_retries", int), ("max_backoff", float)):
        if config.get(key) is not None:
            try:
                client_kw[key] = cast(config[key])
            except (TypeError, ValueError) as exc:
                raise ExecutorConfigError(f"{key} must be a number") from exc
    if sleep is not None:
        client_kw["sleep"] = sleep

    roles = config.get("protected_roles")
    ttl_seconds = config.get("default_ttl_seconds")
    try:
        default_ttl = timedelta(seconds=float(ttl_seconds)) if ttl_seconds else None
    except (TypeError, ValueError) as exc:
        raise ExecutorConfigError("default_ttl_seconds must be a number") from exc
    if default_ttl is not None and default_ttl <= timedelta(0):
        raise ExecutorConfigError("default_ttl_seconds must be positive")

    return EntraIdExecutor(
        GraphClient(token_provider, **client_kw),
        protected_users=_str_list(config.get("protected_users"), "protected_users"),
        protected_patterns=_str_list(
            config.get("protected_patterns"), "protected_patterns"
        ),
        protected_roles=(
            DEFAULT_PROTECTED_ROLES
            if roles is None
            else _str_list(roles, "protected_roles")
        ),
        default_ttl=default_ttl,
    )


__all__ = [
    "ACTION_TYPES",
    "DEFAULT_PROTECTED_ROLES",
    "DISABLE_USER",
    "ENABLE_USER",
    "REVERSIBLE_TYPES",
    "REVOKE_SESSIONS",
    "EntraIdExecutor",
    "ExecutorConfigError",
    "build_executor",
]
