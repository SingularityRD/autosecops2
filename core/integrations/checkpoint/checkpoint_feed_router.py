"""The block list a Check Point gateway polls (W0.60).

``GET /api/feeds/checkpoint/blocklist`` answers the Generic Data Center JSON
document; ``.../blocklist.txt`` one address per line (Network Feed flat list,
or any firewall's IP feed). The caller is a gateway, so there is no session:
the feed token (the ``checkpoint`` integration's ``feed_token`` secret) comes
in ``Authorization: Bearer``, ``X-Feed-Token`` or, for gateways that can only
fetch a URL, ``?token=`` (masked in the access log). The routes answer 404
unless the integration is enabled with a token, and 401 on a wrong token.
"""

from __future__ import annotations

import hmac
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse

from core.integrations.checkpoint import feed
from core.routing import Auth, RouterMeta, UnitOfWorkSession

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/feeds/checkpoint",
    tags=["checkpoint"],
    auth=Auth.ROUTER_MANAGED,
    reason=(
        "Polled by a Check Point gateway, a machine with no session. Each route "
        "compares the feed token in constant time and answers 404 unless the "
        "checkpoint integration is enabled with a token, 401 on a wrong one."
    ),
)


def _expected_token() -> Optional[str]:
    from core.config import is_integration_enabled
    from core.integrations._base.config import resolve
    from core.integrations.checkpoint.descriptor import CHECKPOINT

    if not is_integration_enabled(CHECKPOINT.id):
        return None
    token = resolve(CHECKPOINT).get("feed_token")
    return str(token) if token else None


def _authorise(
    authorization: Optional[str], x_feed_token: Optional[str], token: Optional[str]
) -> None:
    expected = _expected_token()
    if not expected:
        raise HTTPException(404, "Not Found")
    given = x_feed_token or token or ""
    if authorization and authorization.lower().startswith("bearer "):
        given = authorization[7:].strip()
    if not hmac.compare_digest(given.encode(), expected.encode()):
        raise HTTPException(401, "Invalid feed token")


@router.get("/blocklist")
def blocklist_json(
    session: UnitOfWorkSession,
    authorization: Optional[str] = Header(None),
    x_feed_token: Optional[str] = Header(None),
    token: Optional[str] = Query(None),
) -> JSONResponse:
    _authorise(authorization, x_feed_token, token)
    return JSONResponse(
        feed.generic_data_center(session), headers={"Cache-Control": "no-store"}
    )


@router.get("/blocklist.txt")
def blocklist_text(
    session: UnitOfWorkSession,
    authorization: Optional[str] = Header(None),
    x_feed_token: Optional[str] = Header(None),
    token: Optional[str] = Query(None),
) -> PlainTextResponse:
    _authorise(authorization, x_feed_token, token)
    return PlainTextResponse(
        feed.plain_text(session), headers={"Cache-Control": "no-store"}
    )
