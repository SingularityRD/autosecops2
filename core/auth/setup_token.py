"""The one-time setup token that guards first-admin creation (W0.33, KS-02).

``POST /api/auth/bootstrap`` is unauthenticated by necessity, so without a
secret the first caller to reach a fresh install over the network becomes its
administrator. The token is that secret. It proves the caller can read the
backend's log or its State Directory, which is what an operator has and a
stranger on the network does not.

Lifecycle:

* **Issue.** At API startup (and on the login screen's ``GET /api/auth/bootstrap``
  if startup could not reach the database) an install with no sign-in account
  and no outstanding token gets one: 32 random bytes, printed once to the
  backend log and written to ``<State Directory>/setup-token`` (0600). An
  operator who sets ``VIGIL_SETUP_TOKEN`` chooses it instead; that value is
  never logged.
* **Store.** Only its SHA-256 lives in ``system_config['auth.setup_token']``, so
  every backend replica checks against the same token whichever pod printed it.
  No API route reads that row; the plaintext is never returned by any route.
* **Use.** The bootstrap route takes it in the ``X-Setup-Token`` header,
  compares the presented token's digest in
  constant time under the bootstrap advisory lock, creates the account and
  deletes the row in the same transaction, so a token works once and two
  racing callers get exactly one admin.
* **Regenerate.** ``python -m core.auth.setup_token regenerate`` inside the
  backend's environment (``docker compose exec backend …``, ``kubectl exec
  deploy/<release>-backend -- …``) replaces the token and prints the new one on
  stdout. It refuses once an account exists.

Every issue, regeneration and use writes a ``config_audit_log`` row whose
values carry where the token came from and when, never the token or its digest.

Exit codes for the CLI (sysexits, as ``core.auth.service_account``): 0 done ·
64 bad usage · 70 database error · 75 database not ready · 77 refused (an
account already exists).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Optional, TextIO

from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError, SQLAlchemyError
from sqlalchemy.orm import Session

from core.config import get_settings, vigil_path
from core.storage.models import ConfigAuditLog, SystemConfig, User
from core.time import utcnow

logger = logging.getLogger(__name__)

SETUP_TOKEN_KEY = "auth.setup_token"
TOKEN_FILENAME = "setup-token"
# How the bootstrap route receives it: a header, never the body or the URL, so
# no validation error echoes it and no access log records it.
HEADER_NAME = "X-Setup-Token"
# Serializes issue, regenerate and first-admin creation. The bootstrap route
# takes the same lock, so a token cannot be replaced halfway through a use.
BOOTSTRAP_LOCK = 8_274_119
# An operator-chosen token shorter than this is refused: it has to stand up to
# guessing from anywhere the bootstrap route is reachable.
MIN_PRESET_LENGTH = 24
REGENERATE_COMMAND = "python -m core.auth.setup_token regenerate"

EX_OK = 0
EX_USAGE = 64
EX_SOFTWARE = 70
EX_TEMPFAIL = 75
EX_REFUSED = 77


class SetupClosed(Exception):
    """A sign-in account exists, so there is no first admin left to create."""


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def has_sign_in_account(session: Session) -> bool:
    """Whether any account a person can sign in with exists.

    A service account (Medic's gateway) can't sign anyone in, so it must not
    close bootstrap: enabling Medic before the first sign-in would otherwise
    leave the install with no way to make an admin.
    """
    return (
        session.query(User.user_id).filter(User.service_account.is_(False)).first()
        is not None
    )


def lock(session: Session) -> None:
    """Hold the bootstrap lock to the end of the session's transaction."""
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": BOOTSTRAP_LOCK})


def token_path() -> Path:
    return vigil_path(TOKEN_FILENAME)


def _row(session: Session) -> Optional[SystemConfig]:
    return (
        session.query(SystemConfig).filter(SystemConfig.key == SETUP_TOKEN_KEY).first()
    )


def _audit(
    session: Session,
    action: str,
    actor: str,
    *,
    old: Optional[dict] = None,
    new: Optional[dict] = None,
    reason: str,
) -> None:
    session.add(
        ConfigAuditLog(
            config_type="auth",
            config_key=SETUP_TOKEN_KEY,
            action=action,
            old_value=old,
            new_value=new,
            changed_by=actor,
            change_reason=reason,
        )
    )


def _public(value: Optional[dict]) -> Optional[dict]:
    """The row's value without its digest: what an audit row may carry."""
    if not isinstance(value, dict):
        return None
    return {k: v for k, v in value.items() if k != "sha256"}


def _store(session: Session, token: str, source: str, actor: str) -> None:
    value = {
        "sha256": _digest(token),
        "source": source,
        "issued_at": utcnow().isoformat(),
    }
    row = _row(session)
    old = _public(row.value) if row is not None else None
    if row is None:
        session.add(
            SystemConfig(
                key=SETUP_TOKEN_KEY,
                value=value,
                description="Digest of the one-time first-admin setup token",
                config_type="auth",
                updated_by=actor,
            )
        )
    else:
        row.value = value
        row.updated_by = actor
    _audit(
        session,
        "create" if old is None else "update",
        actor,
        old=old,
        new=_public(value),
        reason=f"setup token issued ({source})",
    )


def _preset() -> Optional[str]:
    preset = (get_settings().vigil_setup_token or "").strip()
    if not preset:
        return None
    if len(preset) < MIN_PRESET_LENGTH:
        logger.error(
            "VIGIL_SETUP_TOKEN is shorter than %d characters and is ignored; "
            "a generated setup token is used instead.",
            MIN_PRESET_LENGTH,
        )
        return None
    return preset


def ensure(session: Session) -> Optional[str]:
    """Make sure an install with no account has an outstanding token.

    Returns the plaintext only when this call generated it, so the caller can
    announce it once after commit. An operator-chosen ``VIGIL_SETUP_TOKEN`` is
    stored but never returned: the operator already has it, and it must not
    reach the log. Once an account exists a leftover token is deleted.
    """
    lock(session)
    row = _row(session)
    if has_sign_in_account(session):
        if row is not None:
            _audit(
                session,
                "delete",
                "system",
                old=_public(row.value),
                reason="setup token retired: an account exists",
            )
            session.delete(row)
        return None
    preset = _preset()
    if preset is not None:
        current = row.value if row is not None and isinstance(row.value, dict) else {}
        # A token regenerated by hand outranks the environment until it is used.
        if current.get("source") == "cli":
            return None
        if current.get("sha256") != _digest(preset):
            _store(session, preset, "env", "system")
        return None
    if row is not None:
        return None
    token = secrets.token_urlsafe(32)
    _store(session, token, "generated", "system")
    return token


def regenerate(session: Session, actor: str = "cli") -> str:
    """Replace the outstanding token with a new one and return it."""
    lock(session)
    if has_sign_in_account(session):
        raise SetupClosed(
            "an account already exists; there is no first admin to create"
        )
    token = secrets.token_urlsafe(32)
    _store(session, token, "cli", actor)
    return token


def matches(session: Session, presented: Optional[str]) -> bool:
    """Whether ``presented`` is the outstanding token. Constant time."""
    row = _row(session)
    value = row.value if row is not None and isinstance(row.value, dict) else {}
    stored = value.get("sha256")
    # Compare even when there is nothing to compare against, so the answer's
    # timing says nothing about whether a token is outstanding.
    expected = stored if isinstance(stored, str) else _digest(secrets.token_urlsafe(32))
    same = hmac.compare_digest(_digest(presented or ""), expected)
    return same and bool(presented) and isinstance(stored, str)


def consume(session: Session, actor: str) -> None:
    """Retire the token in the caller's transaction (first admin created)."""
    row = _row(session)
    if row is None:
        return
    _audit(
        session,
        "delete",
        actor,
        old=_public(row.value),
        reason="setup token used: first admin created",
    )
    session.delete(row)


def write_file(token: str) -> Optional[Path]:
    """Write the token to the State Directory, 0600. None if it cannot."""
    try:
        path = vigil_path(TOKEN_FILENAME, write=True)
        fd, tmp = tempfile.mkstemp(prefix=".setup-token-", dir=path.parent)  # 0600
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(token + "\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return path
    except OSError as exc:
        logger.warning("Could not write the setup token file: %s", type(exc).__name__)
        return None


def remove_file() -> None:
    """Best effort: only the pod that wrote the file can remove it."""
    try:
        token_path().unlink(missing_ok=True)
    except OSError:
        pass


def announce(token: str) -> None:
    """Print a generated token to the log, once, and write its file."""
    path = write_file(token)
    where = f" and in {path}" if path else ""
    # One line, so `kubectl logs ... | grep "setup token"` returns the token.
    logger.warning(
        "AutoSecOps setup token (one-time, creates the first administrator): %s "
        "-- also in the State Directory%s. Regenerate with: %s",
        token,
        where,
        REGENERATE_COMMAND,
    )


def issue_on_startup(session_factory) -> None:
    """Startup hook: issue (and announce) a token if the install needs one.

    ``session_factory`` is a context manager yielding a committing session
    (``DatabaseManager.session_scope``). Never raises: a backend whose database
    is not reachable yet still starts, and the login screen's bootstrap check
    issues the token later.
    """
    try:
        with session_factory() as session:
            token = ensure(session)
            outstanding = token is None and _row(session) is not None
    except Exception as exc:  # noqa: BLE001 - startup must not fail on this
        logger.warning(
            "Could not check the first-admin setup token: %s", type(exc).__name__
        )
        return
    if token:
        announce(token)
    elif outstanding:
        logger.warning(
            "No administrator exists yet. Create one with the setup token: it was "
            "printed when it was issued, is in %s on the backend that issued it "
            "(or VIGIL_SETUP_TOKEN), and %s replaces it.",
            token_path(),
            REGENERATE_COMMAND,
        )


def main(
    argv: list[str], stdout: Optional[TextIO] = None, stderr: Optional[TextIO] = None
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    if argv != ["regenerate"]:
        print(f"usage: {REGENERATE_COMMAND}", file=stderr)
        return EX_USAGE
    from core.storage.connection import get_db_manager

    try:
        manager = get_db_manager()
        if manager.engine is None:
            manager.initialize()
        with manager.session_scope() as session:
            token = regenerate(session, actor="cli")
    except SetupClosed as exc:
        print(f"refused: {exc}", file=stderr)
        return EX_REFUSED
    except (OperationalError, ProgrammingError) as exc:
        print(f"database not ready: {type(exc).__name__}", file=stderr)
        return EX_TEMPFAIL
    except SQLAlchemyError as exc:
        print(f"database error: {type(exc).__name__}", file=stderr)
        return EX_SOFTWARE
    path = write_file(token)
    logger.warning("The first-admin setup token was regenerated from the command line")
    print(token, file=stdout)
    if path:
        print(f"(also written to {path})", file=stderr)
    return EX_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
