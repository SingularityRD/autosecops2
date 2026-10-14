"""Download a case's signed evidence pack (W3.7).

    GET /api/cases/{case_id}/evidence-pack   cases.read   application/zip

The pack is built from the case's rows at request time and signed with the
``EVIDENCE_PACK_SIGNING_KEY`` secret (a one-off key when unset, which the pack
states). Each download is written to ``case_audit_logs`` (action ``export``,
field ``evidence_pack``, the manifest's sha256 as the new value) after the
pack is built, so a pack never contains its own export record.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Tuple

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from core.auth.permissions import require_permission
from core.compliance.evidence import CaseRecord, collect_case_record
from core.compliance.evidence_bundle import (
    Bundle,
    SigningKeyError,
    build_bundle,
    load_signing_key,
)
from core.routing import Auth, RouterMeta, UnitOfWorkSession
from core.storage.models import CaseAuditLog, User
from core.time import utcnow

logger = logging.getLogger(__name__)

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/cases",
    tags=["evidence"],
    auth=Auth.REQUIRED,
)

_READ = require_permission("cases.read")

# Seams for tests: the reader and the key.
_collect: Callable[[Any, str], Any] = collect_case_record
_signing_key: Callable[[], Tuple[Any, str]] = load_signing_key


def _actor(user: User) -> str:
    return user.username or user.user_id


def _record_export(session, case_id: str, bundle: Bundle, actor: str) -> None:
    if session is None:
        return
    session.add(
        CaseAuditLog(
            entity_type="case",
            entity_id=case_id,
            action="export",
            field_name="evidence_pack",
            old_value=None,
            new_value=bundle.manifest_sha256,
            change_summary=(
                f"Exported the evidence pack (manifest sha256 {bundle.manifest_sha256[:16]}…, "
                f"key {bundle.key_id}, {bundle.key_source})"
            ),
            changed_by=actor[:100],
        )
    )
    session.flush()


@router.get(
    "/{case_id}/evidence-pack",
    response_class=Response,
    responses={
        200: {
            "content": {"application/zip": {}},
            "description": "The signed evidence pack (ZIP).",
        },
        404: {"description": "Case not found"},
    },
)
def download_evidence_pack(
    case_id: str, session: UnitOfWorkSession, user: User = Depends(_READ)
) -> Response:
    """The case's signed, self-verifying evidence pack as a ZIP.

    Verify it offline with ``autosecops verify-bundle <file>`` (or the
    ``verify_bundle.py`` inside it).
    """
    record: CaseRecord = _collect(session, case_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Case not found")
    try:
        key, source = _signing_key()
    except SigningKeyError as exc:
        logger.error("evidence pack signing key unusable: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="EVIDENCE_PACK_SIGNING_KEY is set but is not an Ed25519 key",
        ) from None
    actor = _actor(user)
    bundle = build_bundle(record, actor, utcnow(), key, source)
    _record_export(session, case_id, bundle, actor)
    return Response(
        content=bundle.data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{bundle.filename}"',
            "X-Evidence-Pack-Manifest-SHA256": bundle.manifest_sha256,
            "X-Evidence-Pack-Key-Id": bundle.key_id,
            "X-Evidence-Pack-Key-Source": bundle.key_source,
            "Cache-Control": "no-store",
        },
    )
