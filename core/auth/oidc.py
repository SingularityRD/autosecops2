"""OpenID Connect relying party: the protocol half of single sign-on.

What lives here is everything that talks to, or checks something from, an
identity provider: provider settings and their validation, the discovery
document, the JWKS, the authorization-code exchange with PKCE, and the ID token
checks. Who the token's subject becomes inside AutoSecOps is
``core.auth.oidc_accounts``; the HTTP endpoints are ``core.auth.oidc_router``.

The ID token is the only thing trusted, and only after:

* its signature verifies against a key from the provider's own JWKS, with the
  algorithm restricted to RS256 or ES256 (never ``none`` or an HMAC, which a
  key-confusion attack would otherwise use with the public key as the secret);
* ``iss`` equals the configured issuer exactly, ``aud`` contains the client id
  (and ``azp`` names it when there is more than one audience);
* ``exp`` is in the future, ``iat`` is neither in the future nor older than
  ``MAX_ID_TOKEN_AGE_SECONDS``, both within the provider's clock-skew allowance
  (capped at ``MAX_CLOCK_SKEW_SECONDS``);
* ``nonce`` equals the one this login put in the authorization request.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import quote_plus, urlencode, urlparse

import httpx
import jwt
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

#: Signature algorithms an ID token may use. Asymmetric only: an HMAC
#: algorithm would let anyone holding the public key forge a token.
ALLOWED_ALGORITHMS = ("RS256", "ES256")
_KTY_FOR_ALG = {"RS256": "RSA", "ES256": "EC"}

DEFAULT_CLOCK_SKEW_SECONDS = 60
MAX_CLOCK_SKEW_SECONDS = 300
#: An ID token is minted for this login, seconds before it is redeemed; one
#: issued longer ago than this is not the answer to our request.
MAX_ID_TOKEN_AGE_SECONDS = 600

#: Discovery and JWKS documents are cached this long; an unknown ``kid``
#: forces a refetch (key rotation), at most once per ``JWKS_MIN_REFRESH``.
METADATA_TTL_SECONDS = 3600
JWKS_MIN_REFRESH_SECONDS = 60

HTTP_TIMEOUT_SECONDS = 10.0
MAX_DOCUMENT_BYTES = 512 * 1024

ADMIN_ROLE_ID = "role-admin"
VIEWER_ROLE_ID = "role-viewer"

ProviderKind = Literal["entra", "okta", "keycloak", "generic"]

# Path segments the router uses next to /{provider_id}/...
_RESERVED_IDS = frozenset({"admin", "providers"})
_PROVIDER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
# Entra's multi-tenant endpoints put "{tenantid}" in the issuer; an exact
# issuer check needs one tenant, and accepting any tenant would let every
# Microsoft account in the world sign in.
_ENTRA_MULTI_TENANT = frozenset({"common", "organizations", "consumers"})


class OidcError(Exception):
    """A login that must not complete.

    ``code`` is the short reason shown to the browser (``/login?sso_error=``);
    ``detail`` goes only to the server log and the audit record.
    """

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class OidcConfigError(ValueError):
    """A provider configuration an administrator may not save."""


# ---------------------------------------------------------------------------
# Provider configuration
# ---------------------------------------------------------------------------


class RoleMapping(BaseModel):
    """One rule: when ``claim`` holds ``value``, the user gets ``role_id``."""

    claim: str = Field(default="groups", min_length=1, max_length=100)
    value: str = Field(min_length=1, max_length=500)
    role_id: str = Field(min_length=1, max_length=50)


class ProviderConfig(BaseModel):
    """An identity provider as an administrator configured it.

    Holds no secret: the client secret lives in the secrets manager under
    :func:`client_secret_key`.
    """

    id: str
    display_name: str = Field(min_length=1, max_length=64)
    kind: ProviderKind = "generic"
    issuer: str = Field(min_length=1, max_length=500)
    client_id: str = Field(min_length=1, max_length=255)
    scopes: List[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    enabled: bool = True
    #: Create an account on first sign-in when none is linked.
    jit_provisioning: bool = True
    #: Link to an existing account with the same email, only when the
    #: provider asserts ``email_verified: true``. Off unless an admin opts in.
    link_by_verified_email: bool = False
    #: Role when no mapping matches. Least privilege by default; never Admin.
    default_role_id: str = VIEWER_ROLE_ID
    role_mappings: List[RoleMapping] = Field(default_factory=list)
    #: A mapping to the Admin role is refused unless this is set.
    allow_admin_mapping: bool = False
    clock_skew_seconds: int = Field(
        default=DEFAULT_CLOCK_SKEW_SECONDS, ge=0, le=MAX_CLOCK_SKEW_SECONDS
    )
    #: Override for the callback URL registered at the provider. Empty: derived
    #: from VIGIL_FRONTEND_URL (or the request) + /api/auth/sso/<id>/callback.
    redirect_uri: str = Field(default="", max_length=500)

    @field_validator("id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        if not _PROVIDER_ID_RE.match(value) or value in _RESERVED_IDS:
            raise ValueError(
                "id must be 1-32 lowercase letters, digits or '-', and not "
                "'admin' or 'providers'"
            )
        return value

    @field_validator("scopes")
    @classmethod
    def _check_scopes(cls, value: List[str]) -> List[str]:
        cleaned = [s.strip() for s in value if s and s.strip()]
        if "openid" not in cleaned:
            raise ValueError("scopes must include 'openid'")
        if any(not re.match(r"^[\x21\x23-\x5b\x5d-\x7e]+$", s) for s in cleaned):
            raise ValueError("scopes contain invalid characters")
        return list(dict.fromkeys(cleaned))


def client_secret_key(provider_id: str) -> str:
    """Secrets-manager key holding a provider's client secret."""
    return "OIDC_CLIENT_SECRET_" + provider_id.upper().replace("-", "_")


def _check_https_url(value: str, what: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise OidcConfigError(f"{what} must be an https:// URL")
    if parsed.username or parsed.password:
        raise OidcConfigError(f"{what} must not contain credentials")
    if parsed.fragment:
        raise OidcConfigError(f"{what} must not contain a fragment")


def _check_redirect_uri(value: str) -> None:
    parsed = urlparse(value)
    local = parsed.hostname in ("localhost", "127.0.0.1", "::1")
    if parsed.scheme not in ("https", "http") or not parsed.hostname:
        raise OidcConfigError("redirect_uri must be an absolute URL")
    if parsed.scheme == "http" and not local:
        raise OidcConfigError("redirect_uri must use https (http only for localhost)")
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise OidcConfigError(
            "redirect_uri must not contain credentials, a query or a fragment"
        )


def validate_provider(cfg: ProviderConfig, known_role_ids: set[str]) -> None:
    """Refuse a configuration that is unsafe or cannot work.

    Raises:
        OidcConfigError: with a message fit to show the administrator.
    """
    _check_https_url(cfg.issuer, "issuer")
    if urlparse(cfg.issuer).query:
        raise OidcConfigError("issuer must not contain a query")
    if cfg.kind == "entra":
        match = re.match(
            r"^https://login\.microsoftonline\.com/([^/]+)/v2\.0$", cfg.issuer
        )
        if not match:
            raise OidcConfigError(
                "Entra ID issuer must look like "
                "https://login.microsoftonline.com/<tenant-id>/v2.0"
            )
        if match.group(1).lower() in _ENTRA_MULTI_TENANT or "{" in match.group(1):
            raise OidcConfigError(
                "Entra ID issuer must name one tenant, not common/organizations/consumers"
            )
    if cfg.redirect_uri:
        _check_redirect_uri(cfg.redirect_uri)

    if cfg.default_role_id == ADMIN_ROLE_ID:
        raise OidcConfigError(
            "The default role cannot be Admin; map an explicit group to Admin instead"
        )
    if cfg.default_role_id not in known_role_ids:
        raise OidcConfigError(f"Unknown default role: {cfg.default_role_id}")
    for mapping in cfg.role_mappings:
        if mapping.role_id not in known_role_ids:
            raise OidcConfigError(f"Unknown role in mapping: {mapping.role_id}")
        if mapping.role_id == ADMIN_ROLE_ID and not cfg.allow_admin_mapping:
            raise OidcConfigError(
                "A mapping to Admin needs 'Allow mapping to Admin' turned on"
            )


# ---------------------------------------------------------------------------
# PKCE, state, nonce
# ---------------------------------------------------------------------------


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def new_flow_secret() -> str:
    """256 bits from a CSPRNG, URL-safe: state, nonce and browser binding."""
    return secrets.token_urlsafe(32)


def new_code_verifier() -> str:
    """RFC 7636 verifier: 86 characters from the unreserved set."""
    return secrets.token_urlsafe(64)


def code_challenge(verifier: str) -> str:
    """S256 challenge for ``verifier``."""
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def digest(value: str) -> str:
    """SHA-256 hex, to store a secret's fingerprint instead of the secret."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def constant_time_equals(a: Optional[str], b: Optional[str]) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ---------------------------------------------------------------------------
# Discovery and JWKS
# ---------------------------------------------------------------------------


@dataclass
class Discovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    token_auth_methods: List[str] = field(default_factory=list)
    signing_algs: List[str] = field(default_factory=list)


@dataclass
class _JwksEntry:
    keys: Dict[str, Any]  # kid -> PyJWK; keys without a kid under "" + index
    fetched_at: float


_discovery_cache: Dict[str, tuple[Discovery, float]] = {}
_jwks_cache: Dict[str, _JwksEntry] = {}


def clear_caches() -> None:
    """Forget every cached discovery document and JWKS."""
    _discovery_cache.clear()
    _jwks_cache.clear()


def _now() -> float:
    return time.time()


async def _get_json(url: str) -> Dict[str, Any]:
    # No redirects: the document must come from the URL the issuer names.
    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False
    ) as client:
        response = await client.get(url, headers={"Accept": "application/json"})
    if response.status_code != 200:
        raise OidcError("provider", f"GET {url} answered {response.status_code}")
    if len(response.content) > MAX_DOCUMENT_BYTES:
        raise OidcError("provider", f"GET {url} returned an oversized document")
    try:
        body = response.json()
    except ValueError as exc:
        raise OidcError("provider", f"GET {url} returned invalid JSON") from exc
    if not isinstance(body, dict):
        raise OidcError("provider", f"GET {url} did not return a JSON object")
    return body


async def get_discovery(provider: ProviderConfig) -> Discovery:
    """The provider's discovery document, checked and cached."""
    cached = _discovery_cache.get(provider.issuer)
    if cached and _now() - cached[1] < METADATA_TTL_SECONDS:
        return cached[0]

    url = provider.issuer.rstrip("/") + "/.well-known/openid-configuration"
    doc = await _get_json(url)
    # OIDC Discovery §4.3: the document's issuer must be the one we asked.
    if doc.get("issuer") != provider.issuer:
        raise OidcError(
            "provider",
            f"discovery issuer {doc.get('issuer')!r} != configured {provider.issuer!r}",
        )
    endpoints = {}
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = doc.get(name)
        if not isinstance(value, str):
            raise OidcError("provider", f"discovery document has no {name}")
        try:
            _check_https_url(value, name)
        except OidcConfigError as exc:
            raise OidcError("provider", str(exc)) from exc
        endpoints[name] = value
    response_types = doc.get("response_types_supported") or []
    if (
        isinstance(response_types, list)
        and response_types
        and "code" not in response_types
    ):
        raise OidcError("provider", "provider does not support response_type=code")
    challenge_methods = doc.get("code_challenge_methods_supported")
    if isinstance(challenge_methods, list) and "S256" not in challenge_methods:
        raise OidcError("provider", "provider does not support PKCE S256")

    discovery = Discovery(
        issuer=provider.issuer,
        authorization_endpoint=endpoints["authorization_endpoint"],
        token_endpoint=endpoints["token_endpoint"],
        jwks_uri=endpoints["jwks_uri"],
        token_auth_methods=list(doc.get("token_endpoint_auth_methods_supported") or []),
        signing_algs=list(doc.get("id_token_signing_alg_values_supported") or []),
    )
    _discovery_cache[provider.issuer] = (discovery, _now())
    return discovery


def _parse_jwks(doc: Dict[str, Any]) -> Dict[str, Any]:
    keys: Dict[str, Any] = {}
    raw_keys = doc.get("keys")
    if not isinstance(raw_keys, list):
        raise OidcError("provider", "JWKS has no keys")
    for index, raw in enumerate(raw_keys):
        if not isinstance(raw, dict) or raw.get("kty") not in ("RSA", "EC"):
            continue
        if raw.get("use") not in (None, "sig"):
            continue
        try:
            key = jwt.PyJWK(raw)
        except Exception as exc:  # malformed or unsupported key: skip it
            logger.debug("Skipping unusable JWKS key: %s", exc)
            continue
        keys[str(raw.get("kid") or f"#{index}")] = key
    return keys


async def _get_jwks(discovery: Discovery, *, force: bool = False) -> Dict[str, Any]:
    entry = _jwks_cache.get(discovery.jwks_uri)
    now = _now()
    if entry is not None:
        fresh = now - entry.fetched_at < METADATA_TTL_SECONDS
        throttled = now - entry.fetched_at < JWKS_MIN_REFRESH_SECONDS
        if (fresh and not force) or (force and throttled):
            return entry.keys
    keys = _parse_jwks(await _get_json(discovery.jwks_uri))
    _jwks_cache[discovery.jwks_uri] = _JwksEntry(keys=keys, fetched_at=now)
    return keys


def _select_key(keys: Dict[str, Any], kid: Optional[str], alg: str) -> Optional[Any]:
    if kid:
        return keys.get(kid)
    # No kid: acceptable only when exactly one key of the right type exists.
    candidates = [k for k in keys.values() if k.key_type == _KTY_FOR_ALG[alg]]
    return candidates[0] if len(candidates) == 1 else None


# ---------------------------------------------------------------------------
# Authorization request and code exchange
# ---------------------------------------------------------------------------


def authorization_url(
    provider: ProviderConfig,
    discovery: Discovery,
    *,
    redirect_uri: str,
    state: str,
    nonce: str,
    verifier: str,
) -> str:
    params = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(provider.scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge(verifier),
        "code_challenge_method": "S256",
    }
    sep = "&" if urlparse(discovery.authorization_endpoint).query else "?"
    return f"{discovery.authorization_endpoint}{sep}{urlencode(params)}"


async def exchange_code(
    provider: ProviderConfig,
    discovery: Discovery,
    *,
    code: str,
    verifier: str,
    redirect_uri: str,
    client_secret: Optional[str],
) -> str:
    """Redeem ``code`` at the token endpoint; return the raw ID token."""
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": provider.client_id,
        "code_verifier": verifier,
    }
    auth = None
    if client_secret:
        methods = discovery.token_auth_methods
        if (
            methods
            and "client_secret_basic" not in methods
            and ("client_secret_post" in methods)
        ):
            form["client_secret"] = client_secret
        else:
            # RFC 6749 §2.3.1: both halves are form-urlencoded before the
            # Basic encoding, or a secret holding ':' / '%' / '+' breaks.
            auth = httpx.BasicAuth(
                quote_plus(provider.client_id), quote_plus(client_secret)
            )
    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False
        ) as client:
            response = await client.post(
                discovery.token_endpoint,
                data=form,
                auth=auth,
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise OidcError("token", f"token endpoint unreachable: {exc}") from exc
    if response.status_code != 200:
        # The body is the provider's error (invalid_grant, ...); log its code
        # only, it can echo request details.
        try:
            reason = response.json().get("error", "")
        except ValueError:
            reason = ""
        raise OidcError(
            "token", f"token endpoint answered {response.status_code} {reason}".strip()
        )
    try:
        body = response.json()
    except ValueError as exc:
        raise OidcError("token", "token endpoint returned invalid JSON") from exc
    id_token = body.get("id_token") if isinstance(body, dict) else None
    if not isinstance(id_token, str) or not id_token:
        raise OidcError("token", "token response carried no id_token")
    return id_token


# ---------------------------------------------------------------------------
# ID token validation
# ---------------------------------------------------------------------------


def _decode_header(id_token: str) -> Dict[str, Any]:
    try:
        return jwt.get_unverified_header(id_token)
    except jwt.InvalidTokenError as exc:
        raise OidcError("signature", f"malformed ID token: {exc}") from exc


def validate_id_token_with_keys(
    id_token: str,
    *,
    provider: ProviderConfig,
    discovery: Discovery,
    keys: Dict[str, Any],
    nonce: str,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Every check from the module docstring, against an already-fetched JWKS.

    Raises:
        OidcError: ``signature`` (no usable key, bad signature, forbidden alg),
            ``expired``, ``claims`` (iss/aud/azp/iat/sub) or ``nonce``.
    """
    header = _decode_header(id_token)
    alg = header.get("alg")
    if alg not in ALLOWED_ALGORITHMS:
        raise OidcError("signature", f"ID token algorithm {alg!r} is not allowed")
    if discovery.signing_algs and alg not in discovery.signing_algs:
        raise OidcError("signature", f"provider does not advertise {alg}")
    kid = header.get("kid")
    key = _select_key(keys, kid if isinstance(kid, str) else None, alg)
    if key is None:
        raise OidcError("signature", f"no JWKS key for kid {kid!r}")
    if key.key_type != _KTY_FOR_ALG[alg]:
        raise OidcError("signature", f"key {kid!r} is not usable with {alg}")

    skew = min(int(provider.clock_skew_seconds), MAX_CLOCK_SKEW_SECONDS)
    try:
        claims = jwt.decode(
            id_token,
            key.key,
            algorithms=[alg],
            audience=provider.client_id,
            issuer=provider.issuer,
            leeway=skew,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise OidcError("expired", "ID token has expired") from exc
    except jwt.InvalidSignatureError as exc:
        raise OidcError("signature", "ID token signature does not verify") from exc
    except (jwt.InvalidAudienceError, jwt.InvalidIssuerError) as exc:
        raise OidcError("claims", f"ID token {exc}") from exc
    except jwt.ImmatureSignatureError as exc:
        raise OidcError("claims", f"ID token not yet valid: {exc}") from exc
    except jwt.InvalidTokenError as exc:
        raise OidcError("claims", f"ID token rejected: {exc}") from exc

    current = _now() if now is None else now
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or isinstance(iat, bool):
        raise OidcError("claims", "ID token iat is not a number")
    if iat > current + skew:
        raise OidcError("claims", "ID token issued in the future")
    if current - iat > MAX_ID_TOKEN_AGE_SECONDS + skew:
        raise OidcError("expired", "ID token was issued too long ago")

    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) > 1:
        if claims.get("azp") != provider.client_id:
            raise OidcError("claims", "ID token azp does not name this client")
    elif "azp" in claims and claims["azp"] != provider.client_id:
        raise OidcError("claims", "ID token azp does not name this client")

    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub or len(sub) > 255:
        raise OidcError("claims", "ID token sub is missing or invalid")

    if not constant_time_equals(claims.get("nonce"), nonce):
        raise OidcError("nonce", "ID token nonce does not match this login")
    return claims


async def validate_id_token(
    id_token: str,
    *,
    provider: ProviderConfig,
    discovery: Discovery,
    nonce: str,
) -> Dict[str, Any]:
    """Validate ``id_token``, refetching the JWKS once if its key is unknown."""
    keys = await _get_jwks(discovery)
    header = _decode_header(id_token)
    alg = header.get("alg")
    kid = header.get("kid")
    if (
        alg in ALLOWED_ALGORITHMS
        and _select_key(keys, kid if isinstance(kid, str) else None, alg) is None
    ):
        # The provider may have rotated its keys since we cached them.
        keys = await _get_jwks(discovery, force=True)
    return validate_id_token_with_keys(
        id_token, provider=provider, discovery=discovery, keys=keys, nonce=nonce
    )


def claims_summary(claims: Dict[str, Any]) -> str:
    """A log-safe description of a token's subject (no raw claims)."""
    return json.dumps(
        {"iss": claims.get("iss"), "sub_sha256": digest(str(claims.get("sub")))[:16]}
    )
