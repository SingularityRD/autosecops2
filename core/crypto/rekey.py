"""Re-encrypt what the data key protects: MFA secrets and the database secret store.

The API runs :func:`startup_rekey` at every start (each replica; an advisory lock
lets one do the work while the others wait and then find nothing to do). It
moves MFA secrets still encrypted under the key derived from ``JWT_SECRET_KEY``
to the data key, and re-encrypts rows under a previous ``VIGIL_DATA_KEY`` entry
with the first one. Every step is idempotent: a row already under the primary key
is not rewritten, so the second run changes nothing.

From the command line, in a backend container or on the host:

    python -m core.crypto.rekey status              # what would change, no writes
    python -m core.crypto.rekey run                 # the start-up step, on demand
    python -m core.crypto.rekey rotate-master-key   # Compose / single host only

``rotate-master-key`` replaces the State Directory's ``master.key`` and
re-encrypts ``secrets.enc`` and the database rows under the new key. Stop the
services first; it needs the database. The admin guide's "Sır döndürme" section
is the runbook.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import text

from core.crypto import data_key
from core.crypto.data_key import DataKeyUnavailable, KeyRing

logger = logging.getLogger(__name__)

_LOCK = "SELECT pg_advisory_xact_lock(hashtextextended('autosecops_data_key_rekey', 0))"
_STORE_TABLE = "platform_secrets"


class RekeyError(RuntimeError):
    """A rekey or rotation that cannot proceed; nothing was changed."""


def _jwt_secret() -> str:
    from core.auth import auth_service

    return auth_service.JWT_SECRET_KEY


def rekey_mfa_secrets(
    session, ring: KeyRing, *, jwt_secret: str, dry_run: bool = False
) -> dict[str, Any]:
    """Move every MFA secret to ``ring``'s primary key.

    ``legacy`` rows (a bare Fernet token under the JWT-derived key, or plaintext
    from before encryption) are encrypted under the data key; ``rotated`` rows
    were under another key of the ring. ``undecryptable`` lists users whose
    secret no key here opens: they are left as they are (their recovery codes
    still work) and reported.
    """
    from core.auth.auth_service import (
        MFA_DATA_KEY_PREFIX,
        AuthService,
        MFASecretDecryptionError,
    )
    from core.storage.models import User

    report: dict[str, Any] = {
        "legacy": 0,
        "rotated": 0,
        "current": 0,
        "undecryptable": [],
    }
    query = (
        session.query(User).filter(User.mfa_secret.isnot(None)).order_by(User.user_id)
    )
    if not dry_run:
        query = query.with_for_update()
    for user in query.all():
        value = user.mfa_secret
        if value.startswith(MFA_DATA_KEY_PREFIX):
            token = value[len(MFA_DATA_KEY_PREFIX) :]
            if ring.is_current(token):
                report["current"] += 1
                continue
            try:
                new_value = MFA_DATA_KEY_PREFIX + ring.rotate(token)
            except InvalidToken:
                report["undecryptable"].append(user.user_id)
                continue
            report["rotated"] += 1
        else:
            try:
                plain = AuthService._decrypt_mfa_secret(value, jwt_secret=jwt_secret)
            except MFASecretDecryptionError:
                report["undecryptable"].append(user.user_id)
                continue
            new_value = MFA_DATA_KEY_PREFIX + ring.encrypt(plain.encode())
            report["legacy"] += 1
        if not dry_run:
            user.mfa_secret = new_value
    return report


def rekey_platform_secrets(
    session, ring: KeyRing, *, dry_run: bool = False
) -> Optional[dict[str, Any]]:
    """Re-encrypt the database secret store's rows under the primary key.

    None when the table does not exist (an install that never ran its SQL).
    """
    if (
        session.execute(text(f"SELECT to_regclass('public.{_STORE_TABLE}')")).scalar()
        is None
    ):
        return None
    report: dict[str, Any] = {"rotated": 0, "current": 0, "undecryptable": []}
    lock = "" if dry_run else " FOR UPDATE"
    rows = session.execute(
        text(
            f"SELECT name, ciphertext FROM {_STORE_TABLE} ORDER BY name{lock}"
        )  # nosec B608 - constants
    ).fetchall()
    for name, token in rows:
        if ring.is_current(token):
            report["current"] += 1
            continue
        try:
            new_token = ring.rotate(token)
        except InvalidToken:
            report["undecryptable"].append(name)
            continue
        report["rotated"] += 1
        if not dry_run:
            session.execute(
                text(
                    f"UPDATE {_STORE_TABLE} SET ciphertext = :token, "  # nosec B608 - constant
                    "updated_at = now() WHERE name = :name"
                ),
                {"token": new_token, "name": name},
            )
    return report


def _changed(report: dict[str, Any]) -> int:
    mfa = report["mfa"]
    store = report["platform_secrets"] or {"rotated": 0}
    return mfa["legacy"] + mfa["rotated"] + store["rotated"]


def _undecryptable(report: dict[str, Any]) -> int:
    store = report["platform_secrets"] or {"undecryptable": []}
    return len(report["mfa"]["undecryptable"]) + len(store["undecryptable"])


def _audit(actor: str, action: str, report: dict[str, Any]) -> None:
    from core.storage.config_service import get_config_service

    get_config_service(user_id=actor).record_audit(
        config_type="secrets",
        config_key="data_key",
        action=action,
        old_value=None,
        new_value=report,
    )


def _rekey(session, ring: KeyRing, *, dry_run: bool) -> dict[str, Any]:
    if not dry_run:
        session.execute(text(_LOCK))
    return {
        "key_source": ring.source,
        "keys": len(ring.fernets),
        "mfa": rekey_mfa_secrets(
            session, ring, jwt_secret=_jwt_secret(), dry_run=dry_run
        ),
        "platform_secrets": rekey_platform_secrets(session, ring, dry_run=dry_run),
    }


def run(*, actor: str, dry_run: bool = False) -> dict[str, Any]:
    """Rekey under the current key ring; audited when a row changed.

    Raises:
        DataKeyUnavailable: no data key (database store without VIGIL_DATA_KEY).
    """
    from core.storage.connection import get_db_manager

    ring = data_key.current()
    with get_db_manager().session_scope() as session:
        report = _rekey(session, ring, dry_run=dry_run)
    report["pending"] = _changed(report) if dry_run else 0
    if not dry_run and _changed(report):
        _audit(actor, "rekey", report)
    return report


def startup_rekey() -> Optional[dict[str, Any]]:
    """The API's start-up step. Logs and returns; never stops the start.

    Skipped with ``DATA_KEY_REKEY_ON_START=false`` (the test suite, which shares a
    database with other checkouts, and installs that run it by hand).
    """
    from core.config import get_settings

    if not get_settings().data_key_rekey_on_start:
        logger.info("Data key rekey at start-up is off (DATA_KEY_REKEY_ON_START)")
        return None
    try:
        report = run(actor="system:data-key")
    except DataKeyUnavailable as e:
        logger.error("MFA secrets not rekeyed: %s", e)
        return None
    except Exception as e:  # noqa: BLE001 - start-up continues on the old rows
        logger.warning("MFA/secret rekey skipped: %s: %s", type(e).__name__, e)
        return None
    changed = _changed(report)
    if changed:
        logger.info(
            "Data key: re-encrypted %d MFA secret(s) from the JWT-derived key, "
            "%d MFA secret(s) and %d stored secret(s) from a previous data key",
            report["mfa"]["legacy"],
            report["mfa"]["rotated"],
            (report["platform_secrets"] or {"rotated": 0})["rotated"],
        )
    if _undecryptable(report):
        logger.error(
            "Data key: %d MFA secret(s) and %d stored secret(s) cannot be decrypted "
            "with any key this process holds; those users sign in with a recovery "
            "code and set MFA up again. Run `python -m core.crypto.rekey status`.",
            len(report["mfa"]["undecryptable"]),
            len((report["platform_secrets"] or {"undecryptable": []})["undecryptable"]),
        )
    return report


def _write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    os.chmod(path, 0o600)


def rotate_master_key(*, actor: str) -> dict[str, Any]:
    """Replace ``master.key``; re-encrypt ``secrets.enc`` and the rows under it.

    For Compose and single-host installs, with the services stopped: a running
    process keeps the old key in memory. The database work commits before the
    files are swapped, and the new files are written next to the old ones
    first, so a failure leaves the old key and ``secrets.enc`` in place.

    Raises:
        RekeyError: the database store is in use, or there is no key to rotate,
            or ``secrets.enc`` is not under the current ``master.key``.
    """
    from core.secrets_manager import EncryptedFileBackend
    from core.storage.connection import get_db_manager

    if data_key.database_mode():
        raise RekeyError(
            "SECRETS_BACKEND=database keeps no master.key; rotate VIGIL_DATA_KEY "
            "instead (admin guide, Sır döndürme)"
        )
    backend = EncryptedFileBackend()
    old_key = backend._read_master_key()
    if old_key is None:
        raise RekeyError(f"no master.key at {backend.master_key_path}")
    old = Fernet(old_key)
    stored: Optional[bytes] = None
    if backend.secrets_path.exists():
        try:
            stored = old.decrypt(backend.secrets_path.read_bytes())
        except InvalidToken as exc:
            raise RekeyError(
                f"{backend.secrets_path} is not encrypted under {backend.master_key_path}; "
                "restore the matching master.key first"
            ) from exc
    new_key = Fernet.generate_key()
    ring = data_key.current()
    # With VIGIL_DATA_KEY the rows move to its first key; the old master.key
    # is in that ring already (decrypt-only). Without it master.key is the data
    # key, and the rows follow it.
    target = (
        ring if ring.source == "env" else KeyRing((Fernet(new_key), old), "master.key")
    )

    tmp_secrets = backend.secrets_path.with_suffix(".rotate")
    tmp_key = backend.master_key_path.with_suffix(".rotate")
    try:
        with get_db_manager().session_scope() as session:
            report = _rekey(session, target, dry_run=False)
            if stored is not None:
                _write_private(tmp_secrets, Fernet(new_key).encrypt(stored))
            _write_private(tmp_key, new_key)
    except BaseException:
        for path in (tmp_secrets, tmp_key):
            path.unlink(missing_ok=True)
        raise
    if stored is not None:
        os.replace(tmp_secrets, backend.secrets_path)
    os.replace(tmp_key, backend.master_key_path)
    report["master_key_rotated"] = True
    report["secrets_enc_reencrypted"] = stored is not None
    _audit(actor, "rotate_master_key", report)
    return report


def _actor(value: Optional[str]) -> str:
    if value and value.strip():
        return value.strip()
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no login name in a bare container
        return "cli"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m core.crypto.rekey",
        description="Re-encrypt MFA secrets and stored secrets under the data key.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="report what a rekey would change; writes nothing")
    for name, help_text in (
        ("run", "re-encrypt under the current key (the start-up step)"),
        (
            "rotate-master-key",
            "replace master.key (Compose / single host, services stopped)",
        ),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--actor", help="name recorded in config_audit_log")
    args = parser.parse_args(argv)

    from core.storage.connection import get_db_manager

    try:
        get_db_manager().initialize()
        if args.command == "status":
            report = run(actor="cli", dry_run=True)
        elif args.command == "run":
            report = run(actor=_actor(args.actor))
        else:
            report = rotate_master_key(actor=_actor(args.actor))
    except (DataKeyUnavailable, RekeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if _undecryptable(report) else 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    logging.basicConfig(level=logging.WARNING)
    sys.exit(main())
