"""An in-process OpenID provider for the single sign-on tests.

Real keys (RSA 2048 and P-256, generated per instance), a real discovery
document and JWKS, and a token endpoint that enforces what a real provider
does: the code is single use, the redirect_uri must match the authorization
request, and the PKCE verifier must hash to the challenge. Served through
``respx``, so ``core.auth.oidc``'s own httpx calls reach it unchanged.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import respx
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

ISSUER = "https://idp.test/realms/soc"
CLIENT_ID = "autosecops"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class MockIdP:
    def __init__(self, issuer: str = ISSUER, client_id: str = CLIENT_ID):
        self.issuer = issuer
        self.client_id = client_id
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec_key = ec.generate_private_key(ec.SECP256R1())
        self.rsa_kid = "rsa-1"
        self.ec_kid = "ec-1"
        self.codes: Dict[str, Dict[str, Any]] = {}
        self.token_requests: list[Dict[str, Any]] = []
        self.jwks_fetches = 0
        #: Claims every token for the next login gets, on top of the defaults.
        self.claims: Dict[str, Any] = {}
        #: When set, the token endpoint returns this ID token verbatim.
        self.id_token_override: Optional[str] = None
        self.discovery_overrides: Dict[str, Any] = {}

    # -- documents --------------------------------------------------------

    @property
    def base(self) -> str:
        return self.issuer.rstrip("/")

    def discovery(self) -> Dict[str, Any]:
        doc = {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.base}/protocol/openid-connect/auth",
            "token_endpoint": f"{self.base}/protocol/openid-connect/token",
            "jwks_uri": f"{self.base}/protocol/openid-connect/certs",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
        }
        doc.update(self.discovery_overrides)
        return doc

    def jwks(self) -> Dict[str, Any]:
        rsa_jwk = json.loads(RSAAlgorithm.to_jwk(self.rsa_key.public_key()))
        rsa_jwk.update({"kid": self.rsa_kid, "use": "sig", "alg": "RS256"})
        ec_jwk = json.loads(ECAlgorithm.to_jwk(self.ec_key.public_key()))
        ec_jwk.update({"kid": self.ec_kid, "use": "sig", "alg": "ES256"})
        return {"keys": [rsa_jwk, ec_jwk]}

    # -- tokens -----------------------------------------------------------

    def claims_for(self, nonce: Optional[str], **overrides: Any) -> Dict[str, Any]:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": "subject-alice",
            "iat": now,
            "exp": now + 300,
            "email": "alice@example.com",
            "email_verified": True,
            "preferred_username": "alice",
            "name": "Alice Analyst",
        }
        if nonce is not None:
            claims["nonce"] = nonce
        claims.update(self.claims)
        claims.update(overrides)
        return {k: v for k, v in claims.items() if v is not None}

    def sign(
        self,
        claims: Dict[str, Any],
        *,
        alg: str = "RS256",
        kid: Optional[str] = "default",
        key: Any = None,
    ) -> str:
        if key is None:
            key = self.ec_key if alg == "ES256" else self.rsa_key
        if kid == "default":
            kid = self.ec_kid if alg == "ES256" else self.rsa_kid
        headers = {"kid": kid} if kid else {}
        return jwt.encode(claims, key, algorithm=alg, headers=headers)

    # -- the browser's trip to the provider ---------------------------------

    def authorize(self, authorize_url: str) -> tuple[str, str]:
        """What the provider does when the browser arrives: returns (code, state)."""
        query = {k: v[0] for k, v in parse_qs(urlparse(authorize_url).query).items()}
        assert query["response_type"] == "code"
        assert query["client_id"] == self.client_id
        assert query["code_challenge_method"] == "S256"
        assert "openid" in query["scope"].split()
        code = secrets.token_urlsafe(16)
        self.codes[code] = {
            "challenge": query["code_challenge"],
            "nonce": query["nonce"],
            "redirect_uri": query["redirect_uri"],
            "used": False,
        }
        return code, query["state"]

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.token_requests.append(
            {"form": form, "authorization": request.headers.get("authorization")}
        )
        entry = self.codes.get(form.get("code", ""))
        if form.get("grant_type") != "authorization_code" or entry is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        if entry["used"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        entry["used"] = True
        if form.get("redirect_uri") != entry["redirect_uri"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        verifier = form.get("code_verifier", "")
        if _b64url(hashlib.sha256(verifier.encode()).digest()) != entry["challenge"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        id_token = self.id_token_override or self.sign(self.claims_for(entry["nonce"]))
        return httpx.Response(
            200,
            json={"access_token": "at", "token_type": "Bearer", "id_token": id_token},
        )

    def _jwks(self, request: httpx.Request) -> httpx.Response:
        self.jwks_fetches += 1
        return httpx.Response(200, json=self.jwks())

    def install(self, mock: respx.MockRouter) -> None:
        mock.get(f"{self.base}/.well-known/openid-configuration").mock(
            side_effect=lambda request: httpx.Response(200, json=self.discovery())
        )
        mock.get(f"{self.base}/protocol/openid-connect/certs").mock(
            side_effect=self._jwks
        )
        mock.post(f"{self.base}/protocol/openid-connect/token").mock(
            side_effect=self._token
        )
