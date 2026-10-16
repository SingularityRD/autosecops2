"""Public signing keys, for offline verification (W0.36).

    GET /api/audit/signing-keys   settings.read

The Ed25519 public keys of the audit-checkpoint and evidence-pack signing keys,
with key ids and PEM. No private part ever leaves the secrets store. The
evidence-pack key is the backend's own. The checkpoint key is held by the daemon
alone on Helm, so when this process does not hold it the key of the newest
signed checkpoint is shown with ``source: latest_checkpoint``: that value comes
from the database, so an auditor should compare it with the key exported at
install (``python -m core.audit.signing_keys export``) rather than trust it.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text

from core.audit import signing_keys
from core.auth.permissions import require_permission
from core.routing import Auth, RouterMeta
from core.storage.models import User

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/audit",
    tags=["audit"],
    auth=Auth.REQUIRED,
)


class PublicSigningKey(BaseModel):
    purpose: str
    secret: str
    algorithm: str
    configured: bool
    # secret: this process holds the key; latest_checkpoint: read from the
    # newest signed checkpoint row; none: no key known.
    source: str
    key_id: Optional[str] = None
    public_key: Optional[str] = None
    public_key_pem: Optional[str] = None


class SigningKeysResponse(BaseModel):
    keys: List[PublicSigningKey]


def _latest_checkpoint_key() -> Optional[tuple[str, str]]:
    from core.storage.connection import get_db_manager

    try:
        with get_db_manager().engine.connect() as conn:
            if (
                conn.execute(text("SELECT to_regclass('audit_checkpoints')")).scalar()
                is None
            ):
                return None
            row = conn.execute(
                text(
                    "SELECT key_id, public_key FROM audit_checkpoints "
                    "ORDER BY id DESC LIMIT 1"
                )
            ).first()
    except Exception:  # noqa: BLE001 - absent is the honest answer
        return None
    return (row[0], row[1]) if row else None


def _entry(row: signing_keys.KeyStatus) -> Dict[str, Any]:
    out = row.to_dict()
    entry = {
        "purpose": out["purpose"],
        "secret": out["secret"],
        "algorithm": out["algorithm"],
        "configured": row.usable,
        "source": "secret" if row.usable else "none",
        "key_id": out["key_id"],
        "public_key": out["public_key"],
        "public_key_pem": out["public_key_pem"],
    }
    if not row.usable and row.spec is signing_keys.AUDIT_CHECKPOINTS:
        latest = _latest_checkpoint_key()
        if latest is not None:
            kid, public = latest
            try:
                pem = signing_keys.KeyStatus(
                    row.spec,
                    configured=True,
                    usable=True,
                    key_id=kid,
                    public_key=public,
                ).public_pem()
            except ValueError:
                pem = None
            entry.update(
                configured=True,
                source="latest_checkpoint",
                key_id=kid,
                public_key=public,
                public_key_pem=pem,
            )
    return entry


@router.get("/signing-keys", response_model=SigningKeysResponse)
def get_signing_keys(
    _user: User = Depends(require_permission("settings.read")),
) -> Dict[str, Any]:
    """The public halves of the signing keys, for offline verification."""
    return {"keys": [_entry(row) for row in signing_keys.status()]}
