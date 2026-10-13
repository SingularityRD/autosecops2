"""Single sign-on endpoints: ``/api/auth/sso``.

Browser flow (all GET, all public — the browser has no session yet):

1. ``/providers`` lists the enabled providers for the sign-in screen.
2. ``/{provider_id}/login`` makes a fresh ``state``, ``nonce`` and PKCE
   verifier, keeps them server-side (Redis, ten minutes, single use) under the
   hash of ``state``, binds them to this browser with an HttpOnly cookie, and
   redirects to the provider.
3. ``/{provider_id}/callback`` takes the flow back out of Redis (so a replayed
   ``state`` finds nothing), checks it belongs to this provider and this
   browser, redeems the code with the verifier, validates the ID token
   (``core.auth.oidc``), resolves the account (``core.auth.oidc_accounts``) and
   issues the same session cookies a password sign-in gets. Every failure
   redirects to ``/login?sso_error=<code>``; details go to the log and the audit
   record only.

Administration (``/admin/...``) needs both ``settings.write`` and
``users.write``, and saving a role mapping needs every permission that role
grants, so nobody can configure an identity provider into more privilege than
they hold.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, List, Optional, Protocol

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from core.auth.auth_cookies import (
    _cookie_secure,
    context_path_prefix,
    issue_session_cookies,
)
from core.auth.auth_service import AuthService
from core.auth.login_policy import LOGIN_POLICY_KEY, LoginPolicy, get_login_policy
from core.auth.oidc import (
    ADMIN_ROLE_ID,
    DEFAULT_CLOCK_SKEW_SECONDS,
    MAX_CLOCK_SKEW_SECONDS,
    VIEWER_ROLE_ID,
    OidcConfigError,
    OidcError,
    ProviderConfig,
    ProviderKind,
    RoleMapping,
    authorization_url,
    client_secret_key,
    constant_time_equals,
    digest,
    exchange_code,
    get_discovery,
    new_code_verifier,
    new_flow_secret,
    validate_id_token,
    validate_provider,
)
from core.auth.oidc_accounts import (
    AUTH_CONFIG_TYPE,
    audit_failure,
    audit_success,
    get_provider,
    has_usable_password,
    known_role_ids,
    load_providers,
    printable,
    resolve_user,
    save_providers,
)
from core.auth.permissions import permission_gate
from core.config import get_settings
from core.rate_limit import rate_limit_dependency
from core.redis_client import get_async_redis
from core.routing import Auth, RouterMeta, UnitOfWorkSession
from core.secrets_manager import delete_secret, get_secret, set_secret
from core.storage.models import ConfigAuditLog, Role, SystemConfig, User
from core.time import utcnow

logger = logging.getLogger(__name__)

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/auth/sso",
    tags=["authentication"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "Single sign-on starts before there is a session: /providers, "
        "/{provider_id}/login and /{provider_id}/callback must be reachable "
        "signed out and are listed in PUBLIC_API_PATHS. Every /admin route "
        "declares permission_gate('settings.write') and "
        "permission_gate('users.write') itself."
    ),
)

FLOW_COOKIE_NAME = "oidc_flow"
FLOW_TTL_SECONDS = 600
_FLOW_KEY_PREFIX = "oidc:flow:"


# ---------------------------------------------------------------------------
# Single-use flow store
# ---------------------------------------------------------------------------


class FlowStore(Protocol):
    async def put(self, key: str, value: str, ttl_seconds: int) -> None: ...

    async def take(self, key: str) -> Optional[str]:
        """Return and delete ``key`` atomically; None if absent."""
        ...


class RedisFlowStore:
    async def put(self, key: str, value: str, ttl_seconds: int) -> None:
        client = get_async_redis("single sign-on")
        if client is None:
            raise OidcError("unavailable", "redis client unavailable")
        await client.set(key, value, ex=ttl_seconds)

    async def take(self, key: str) -> Optional[str]:
        client = get_async_redis("single sign-on")
        if client is None:
            raise OidcError("unavailable", "redis client unavailable")
        # GET and DEL in one MULTI: two callbacks racing with the same state
        # cannot both read it.
        async with client.pipeline(transaction=True) as pipe:
            pipe.get(key)
            pipe.delete(key)
            value, _ = await pipe.execute()
        return value


_flow_store: FlowStore = RedisFlowStore()


def set_flow_store(store: FlowStore) -> FlowStore:
    """Swap the flow store (tests); returns the previous one."""
    global _flow_store
    previous = _flow_store
    _flow_store = store
    return previous


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------


def _public_base(request: Request) -> str:
    """Origin (+ context path) the browser reaches AutoSecOps at."""
    configured = get_settings().vigil_frontend_url.rstrip("/")
    if configured:
        return configured
    return str(request.base_url).rstrip("/") + context_path_prefix()


def redirect_uri_for(provider: ProviderConfig, request: Request) -> str:
    if provider.redirect_uri:
        return provider.redirect_uri
    return f"{_public_base(request)}/api/auth/sso/{provider.id}/callback"


def _app_url(path: str) -> str:
    configured = get_settings().vigil_frontend_url.rstrip("/")
    return f"{configured or context_path_prefix()}{path}"


def _safe_next(value: Optional[str]) -> str:
    """A same-site path to land on after sign-in; anything else becomes ``/``."""
    if (
        not value
        or not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or any(ord(c) < 0x20 for c in value)
        or len(value) > 512
    ):
        return "/"
    return value


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _flow_cookie_path() -> str:
    return f"{context_path_prefix()}/api/auth/sso/"


def _set_flow_cookie(response, value: str) -> None:
    # Lax, not the Strict the session cookies use: the callback is a top-level
    # navigation *from the identity provider*, and a Strict cookie would not
    # be sent on it.
    response.set_cookie(
        FLOW_COOKIE_NAME,
        value,
        max_age=FLOW_TTL_SECONDS,
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path=_flow_cookie_path(),
    )


def _clear_flow_cookie(response) -> None:
    response.delete_cookie(
        FLOW_COOKIE_NAME,
        path=_flow_cookie_path(),
        secure=_cookie_secure(),
        samesite="lax",
        httponly=True,
    )


async def _fail(provider_id: str, exc: OidcError, request: Request) -> RedirectResponse:
    logger.warning(
        "SSO login via %s refused (%s): %s",
        printable(provider_id, 64),
        exc.code,
        printable(exc.detail, 500),
    )
    await asyncio.to_thread(
        audit_failure, provider_id, exc.code, exc.detail, _client_ip(request)
    )
    response = RedirectResponse(
        _app_url(f"/login?sso_error={exc.code}"), status_code=status.HTTP_302_FOUND
    )
    _clear_flow_cookie(response)
    return response


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------


class PublicProvider(BaseModel):
    id: str
    display_name: str


class PublicProvidersResponse(BaseModel):
    providers: List[PublicProvider]
    local_login_enabled: bool


@router.get("/providers", response_model=PublicProvidersResponse)
def list_public_providers(session: UnitOfWorkSession):
    """Enabled providers for the sign-in screen. Names only; nothing secret."""
    return PublicProvidersResponse(
        providers=[
            PublicProvider(id=p.id, display_name=p.display_name)
            for p in load_providers(session)
            if p.enabled
        ],
        local_login_enabled=get_login_policy(session).local_login_enabled,
    )


@router.get(
    "/{provider_id}/login",
    dependencies=[Depends(rate_limit_dependency)],
    response_class=RedirectResponse,
    status_code=status.HTTP_302_FOUND,
)
async def sso_login(
    provider_id: str,
    request: Request,
    session: UnitOfWorkSession,
    next: Optional[str] = None,
):
    """Start an Authorization Code + PKCE login at ``provider_id``."""
    provider = await asyncio.to_thread(get_provider, session, provider_id)
    if provider is None or not provider.enabled:
        raise HTTPException(status_code=404, detail="Unknown sign-in provider")

    try:
        discovery = await get_discovery(provider)
        state = new_flow_secret()
        nonce = new_flow_secret()
        binding = new_flow_secret()
        verifier = new_code_verifier()
        redirect_uri = redirect_uri_for(provider, request)
        flow = {
            "provider_id": provider.id,
            "nonce": nonce,
            "verifier": verifier,
            "binding_sha256": digest(binding),
            "redirect_uri": redirect_uri,
            "next": _safe_next(next),
        }
        await _flow_store.put(
            _FLOW_KEY_PREFIX + digest(state), json.dumps(flow), FLOW_TTL_SECONDS
        )
    except OidcError as exc:
        return await _fail(provider_id, exc, request)
    except Exception as exc:  # Redis down, provider unreachable, ...
        return await _fail(provider_id, OidcError("unavailable", repr(exc)), request)

    response = RedirectResponse(
        authorization_url(
            provider,
            discovery,
            redirect_uri=redirect_uri,
            state=state,
            nonce=nonce,
            verifier=verifier,
        ),
        status_code=status.HTTP_302_FOUND,
    )
    _set_flow_cookie(response, binding)
    return response


async def _take_flow(provider_id: str, state: Optional[str], request: Request) -> Dict:
    if not state:
        raise OidcError("state", "callback carried no state")
    raw = await _flow_store.take(_FLOW_KEY_PREFIX + digest(state))
    if raw is None:
        raise OidcError("state", "unknown, expired or already used state")
    flow = json.loads(raw)
    if flow.get("provider_id") != provider_id:
        raise OidcError("state", "state was issued for another provider")
    binding = request.cookies.get(FLOW_COOKIE_NAME)
    if not binding or not constant_time_equals(
        digest(binding), flow.get("binding_sha256")
    ):
        # Login CSRF: someone else's callback URL opened in this browser.
        raise OidcError("state", "state is not bound to this browser")
    return flow


@router.get(
    "/{provider_id}/callback",
    dependencies=[Depends(rate_limit_dependency)],
    response_class=RedirectResponse,
    status_code=status.HTTP_302_FOUND,
)
async def sso_callback(
    provider_id: str,
    request: Request,
    session: UnitOfWorkSession,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
):
    """Finish a login: validate everything, then issue the session cookies."""
    try:
        # The state is consumed first, whatever else is wrong, so a callback
        # URL can never be used twice.
        flow = await _take_flow(provider_id, state, request)
        if error:
            raise OidcError(
                "idp_error", f"provider returned error={printable(error, 100)}"
            )
        if not code:
            raise OidcError("token", "callback carried no code")
        provider = await asyncio.to_thread(get_provider, session, provider_id)
        if provider is None or not provider.enabled:
            raise OidcError("provider", "provider is not configured or disabled")
        discovery = await get_discovery(provider)
        id_token = await exchange_code(
            provider,
            discovery,
            code=code,
            verifier=flow["verifier"],
            redirect_uri=flow["redirect_uri"],
            client_secret=get_secret(client_secret_key(provider.id)),
        )
        claims = await validate_id_token(
            id_token, provider=provider, discovery=discovery, nonce=flow["nonce"]
        )
        login = await asyncio.to_thread(resolve_user, session, provider, claims)
    except OidcError as exc:
        return await _fail(provider_id, exc, request)
    except Exception as exc:
        logger.exception("SSO callback via %s failed unexpectedly", provider_id)
        return await _fail(provider_id, OidcError("unavailable", repr(exc)), request)

    response = RedirectResponse(
        _app_url(flow.get("next") or "/"), status_code=status.HTTP_302_FOUND
    )
    issue_session_cookies(response, login.user, request.headers.get("user-agent"))
    _clear_flow_cookie(response)
    await asyncio.to_thread(
        audit_success, session, provider_id, login, _client_ip(request)
    )
    logger.info(
        "User signed in via SSO (%s): %s%s",
        provider_id,
        login.user.username,
        " (new account)" if login.created else "",
    )
    return response


# ---------------------------------------------------------------------------
# Administration
# ---------------------------------------------------------------------------

_ADMIN_GATES = [permission_gate("settings.write"), permission_gate("users.write")]


class ProviderOut(BaseModel):
    id: str
    display_name: str
    kind: ProviderKind
    issuer: str
    client_id: str
    scopes: List[str]
    enabled: bool
    jit_provisioning: bool
    link_by_verified_email: bool
    default_role_id: str
    role_mappings: List[RoleMapping]
    allow_admin_mapping: bool
    clock_skew_seconds: int
    redirect_uri: str
    #: The callback URL to register at the provider.
    effective_redirect_uri: str
    has_client_secret: bool


class SsoAdminConfig(BaseModel):
    providers: List[ProviderOut]
    login_policy: LoginPolicy


class ProviderUpsert(BaseModel):
    display_name: str = Field(min_length=1, max_length=64)
    kind: ProviderKind = "generic"
    issuer: str = Field(min_length=1, max_length=500)
    client_id: str = Field(min_length=1, max_length=255)
    scopes: List[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    enabled: bool = True
    jit_provisioning: bool = True
    link_by_verified_email: bool = False
    default_role_id: str = VIEWER_ROLE_ID
    role_mappings: List[RoleMapping] = Field(default_factory=list)
    allow_admin_mapping: bool = False
    clock_skew_seconds: int = Field(
        default=DEFAULT_CLOCK_SKEW_SECONDS, ge=0, le=MAX_CLOCK_SKEW_SECONDS
    )
    redirect_uri: str = Field(default="", max_length=500)
    #: Write-only. Omitted or null keeps the stored secret.
    client_secret: Optional[str] = Field(default=None, max_length=2000)
    clear_client_secret: bool = False


def _provider_out(provider: ProviderConfig, request: Request) -> ProviderOut:
    return ProviderOut(
        **provider.model_dump(),
        effective_redirect_uri=redirect_uri_for(provider, request),
        has_client_secret=bool(get_secret(client_secret_key(provider.id))),
    )


def _admin_config(session, request: Request) -> SsoAdminConfig:
    return SsoAdminConfig(
        providers=[_provider_out(p, request) for p in load_providers(session)],
        login_policy=get_login_policy(session),
    )


def _require_role_privileges(session, current_user: User, role_ids: set[str]) -> None:
    """Refuse a mapping into a role holding a permission the caller lacks."""
    held = AuthService.get_user_permissions(current_user.user_id, session)
    for role in session.query(Role).filter(Role.role_id.in_(role_ids)).all():
        for perm, granted in (role.permissions or {}).items():
            if granted and not held.get(perm, False):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"You cannot map users to {role.name}: it grants "
                        f"{perm}, which you do not hold"
                    ),
                )


def _require_every_privilege(session, current_user: User, what: str) -> None:
    """Refuse unless the caller holds every permission any role grants.

    For settings that can put a provider's users into *any* account
    (linking by e-mail) or into Admin: only someone who could already do
    everything may turn them on, so they are never a privilege escalation.
    The Admin role always qualifies, so a permission later granted to some
    other role only cannot lock administrators out of these settings.
    """
    if current_user.role_id == ADMIN_ROLE_ID:
        return
    held = AuthService.get_user_permissions(current_user.user_id, session) or {}
    for role in session.query(Role).all():
        for perm, granted in (role.permissions or {}).items():
            if granted and not held.get(perm, False):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Only an administrator holding every permission can "
                        f"turn on {what}: you do not hold {perm}"
                    ),
                )


@router.get("/admin/config", response_model=SsoAdminConfig)
def get_sso_config(
    request: Request,
    session: UnitOfWorkSession,
    current_user: User = _ADMIN_GATES[0],
    _users_write: User = _ADMIN_GATES[1],
):
    """Providers (never their secrets) and the local sign-in policy."""
    return _admin_config(session, request)


@router.put("/admin/providers/{provider_id}", response_model=SsoAdminConfig)
def upsert_provider(
    provider_id: str,
    body: ProviderUpsert,
    request: Request,
    session: UnitOfWorkSession,
    current_user: User = _ADMIN_GATES[0],
    _users_write: User = _ADMIN_GATES[1],
):
    """Add or replace one provider. The client secret is stored write-only."""
    fields = body.model_dump(exclude={"client_secret", "clear_client_secret"})
    try:
        provider = ProviderConfig(id=provider_id, **fields)
        validate_provider(provider, known_role_ids(session))
    except (OidcConfigError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    mapped = {m.role_id for m in provider.role_mappings} | {provider.default_role_id}
    _require_role_privileges(session, current_user, mapped)
    # Checked on every save, not only when switched on: whoever saves a
    # provider with these on also chooses its issuer.
    if provider.link_by_verified_email:
        _require_every_privilege(session, current_user, "linking by verified email")
    if provider.allow_admin_mapping:
        _require_every_privilege(session, current_user, "mapping to Admin")

    providers = load_providers(session)
    existed = any(p.id == provider_id for p in providers)
    providers = [p for p in providers if p.id != provider_id] + [provider]
    if not any(p.enabled for p in providers) and not (
        get_login_policy(session).local_login_enabled
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Local sign-in is off; disabling the last enabled provider would "
                "leave only break-glass accounts. Turn local sign-in on first."
            ),
        )
    save_providers(
        session,
        providers,
        changed_by=current_user.username,
        action="update" if existed else "create",
    )

    key = client_secret_key(provider_id)
    if body.clear_client_secret:
        delete_secret(key)
    elif body.client_secret:
        if not set_secret(key, body.client_secret):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not store the client secret",
            )
    logger.info("SSO provider %s saved by %s", provider_id, current_user.username)
    session.flush()
    return _admin_config(session, request)


@router.delete("/admin/providers/{provider_id}", response_model=SsoAdminConfig)
def delete_provider(
    provider_id: str,
    request: Request,
    session: UnitOfWorkSession,
    current_user: User = _ADMIN_GATES[0],
    _users_write: User = _ADMIN_GATES[1],
):
    providers = load_providers(session)
    remaining = [p for p in providers if p.id != provider_id]
    if len(remaining) == len(providers):
        raise HTTPException(status_code=404, detail="Unknown sign-in provider")
    policy = get_login_policy(session)
    if not policy.local_login_enabled and not any(p.enabled for p in remaining):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Local sign-in is off; deleting the last enabled provider would "
                "leave only break-glass accounts. Turn local sign-in on first."
            ),
        )
    save_providers(
        session, remaining, changed_by=current_user.username, action="delete"
    )
    delete_secret(client_secret_key(provider_id))
    session.flush()
    return _admin_config(session, request)


@router.put("/admin/login-policy", response_model=SsoAdminConfig)
def update_login_policy(
    body: LoginPolicy,
    request: Request,
    session: UnitOfWorkSession,
    current_user: User = _ADMIN_GATES[0],
    _users_write: User = _ADMIN_GATES[1],
):
    """Turn local sign-in on or off, and name the break-glass accounts."""
    ids = list(dict.fromkeys(body.break_glass_user_ids))
    users = session.query(User).filter(User.user_id.in_(ids)).all() if ids else []
    found = {u.user_id: u for u in users}
    for user_id in ids:
        user = found.get(user_id)
        if user is None:
            raise HTTPException(status_code=400, detail=f"Unknown user: {user_id}")
        if user.service_account is True:
            raise HTTPException(
                status_code=400,
                detail=f"{user.username} is a service account; it never needs break-glass",
            )
        if not has_usable_password(user):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"{user.username} signs in only with single sign-on and has no "
                    "password; a break-glass account needs one"
                ),
            )

    if not body.local_login_enabled:
        if not any(p.enabled for p in load_providers(session)):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Enable a single sign-on provider before turning local sign-in off",
            )
        if not any(u.is_active and u.role_id == ADMIN_ROLE_ID for u in users):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Name at least one active Admin as a break-glass account "
                    "before turning local sign-in off"
                ),
            )

    new_value = {
        "local_login_enabled": body.local_login_enabled,
        "break_glass_user_ids": ids,
    }
    row = (
        session.query(SystemConfig).filter(SystemConfig.key == LOGIN_POLICY_KEY).first()
    )
    old_value = row.value if row is not None else None
    if row is None:
        session.add(
            SystemConfig(
                key=LOGIN_POLICY_KEY,
                value=new_value,
                description="Local sign-in policy (single sign-on)",
                config_type=AUTH_CONFIG_TYPE,
                updated_by=current_user.username,
            )
        )
    else:
        row.value = new_value
        row.updated_by = current_user.username
    session.add(
        ConfigAuditLog(
            config_type=AUTH_CONFIG_TYPE,
            config_key=LOGIN_POLICY_KEY,
            action="update",
            old_value=old_value,
            new_value=new_value,
            changed_by=current_user.username,
            timestamp=utcnow(),
        )
    )
    session.flush()
    logger.info(
        "Local sign-in %s by %s (break-glass: %d)",
        "enabled" if body.local_login_enabled else "disabled",
        current_user.username,
        len(ids),
    )
    return _admin_config(session, request)
