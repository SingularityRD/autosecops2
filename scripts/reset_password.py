#!/usr/bin/env python3
"""
Issue a password reset link without email.

    reset_password.py --list                         show every account
    reset_password.py <username|email> [--operator NAME]
                                                     print a single-use link

The link opens the console's /reset-password screen, so the strength policy,
reuse check, lockout clear and session revocation all happen in the existing
/password-reset/confirm route; this script never handles a password.

The link is valid for PASSWORD_RESET_TTL_SECONDS (default one hour) and works
once. It is bound to the account's current email address, like an emailed
link: changing the address retires it. Single-sign-on-only accounts (no local
password) and service accounts are refused.

Every issued link is recorded before it is printed: a ``case_audit_logs`` row
(entity ``user``, action ``reset_link_issued``) that the W1.10 audit chain
hashes and the SIEM export (W3.6, source ``case_audit``) sends on. The record
names the operator, the account and the expiry; never the token.

It signs with JWT_SECRET_KEY, which must be the running backend's. Natively,
run it through scripts/reset-password.sh; on compose, use
``docker exec deeptempo-backend python scripts/reset_password.py``; on
Kubernetes, ``kubectl exec deploy/<release>-vigil-backend -- python
scripts/reset_password.py``.
"""

import argparse
import getpass
import json
import os
import sys
from datetime import timedelta
from pathlib import Path

# Ensure project root is on sys.path when invoked directly
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from core.auth.password_reset import (  # noqa: E402
    REFUSED_INACTIVE,
    REFUSED_SERVICE_ACCOUNT,
    REFUSED_SSO_ONLY,
    generate_reset_token,
    reset_link,
    reset_refusal,
    ttl_text,
)
from core.config import get_settings  # noqa: E402
from core.storage.connection import get_db_manager, init_database  # noqa: E402
from core.storage.models import CaseAuditLog  # noqa: E402
from core.storage.models.auth import User  # noqa: E402
from core.time import utcnow  # noqa: E402

#: ``case_audit_logs.action`` of an operator-issued link (String(20)).
AUDIT_ACTION = "reset_link_issued"
AUDIT_SOURCE = "scripts/reset_password.py"
#: The event the SIEM export's ``case_audit`` source makes of that row
#: (``case.<entity_type>.<action>``, core/compliance/audit_export.py).
SIEM_ACTION = "case.user.reset_link_issued"

_REFUSALS = {
    REFUSED_INACTIVE: "is inactive; reactivate it before resetting.",
    REFUSED_SSO_ONLY: (
        "signs in with single sign-on only and has no AutoSecOps password; "
        "its password is reset at the identity provider."
    ),
    REFUSED_SERVICE_ACCOUNT: (
        "is a service account; rotate its password with "
        "`python -m core.auth.service_account ensure`."
    ),
}


def default_base_url() -> str:
    settings = get_settings()
    if settings.vigil_frontend_url:
        return settings.vigil_frontend_url
    # start.sh serves the console on 6988; in the compose image the backend
    # serves it itself on 6987.
    port = 6987 if os.path.exists("/.dockerenv") else 6988
    return f"http://localhost:{port}{settings.vigil_context_path.rstrip('/')}"


def default_operator() -> str:
    """Who runs this: the sudo caller if any, else the OS user."""
    name = os.environ.get("SUDO_USER")
    if name:
        return name
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no passwd entry in some containers
        return "unknown"


def _kind(user) -> str:
    refusal = reset_refusal(user)
    if refusal == REFUSED_SSO_ONLY:
        return "sso-only"
    if refusal == REFUSED_SERVICE_ACCOUNT:
        return "service"
    return "local"


def list_users(session) -> int:
    users = session.query(User).order_by(User.username).all()
    if not users:
        print("No users.")
        return 0
    rows = [
        (
            u.username,
            u.email,
            u.role_id or "",
            _kind(u),
            "active" if u.is_active else "inactive",
        )
        for u in users
    ]
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    for r in rows:
        print("  ".join(c.ljust(w) for c, w in zip(r, widths)) + "  " + r[4])
    return 0


def find_user(session, who: str):
    return (
        session.query(User).filter((User.username == who) | (User.email == who)).first()
    )


def record_issue(session, user, operator: str, ttl_seconds: int) -> None:
    """Write the audit record for an issued link (chained and exported).

    Holds who issued it, for whom and until when; never the token.
    """
    now = utcnow()
    session.add(
        CaseAuditLog(
            entity_type="user",
            entity_id=str(user.user_id)[:100],
            action=AUDIT_ACTION,
            field_name="password_reset_link",
            old_value=None,
            new_value=json.dumps(
                {
                    "username": user.username,
                    "issued_at": now.isoformat() + "Z",
                    "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat()
                    + "Z",
                    "ttl_seconds": ttl_seconds,
                    "issued_by": operator,
                    "via": AUDIT_SOURCE,
                },
                sort_keys=True,
            ),
            change_summary=(
                f"Operator {operator} issued a password reset link for "
                f"{user.username} (valid {ttl_text(ttl_seconds)}, single use)"
            ),
            changed_by=f"cli:{operator}"[:100],
            user_agent=AUDIT_SOURCE,
        )
    )
    session.flush()


def issue_link(session, who: str, base_url: str, operator: str):
    """Return ``(exit_code, issued)``; ``issued`` is None on refusal, else
    ``(username, email, link, ttl_seconds)``.

    The audit row is written in ``session``; the caller prints the link only
    after that transaction committed, so no link exists without its record.
    """
    user = find_user(session, who)
    if user is None:
        print(f"No user with username or email {who!r}. Try --list.", file=sys.stderr)
        return 1, None
    refusal = reset_refusal(user)
    if refusal is not None:
        print(f"User {user.username!r} {_REFUSALS[refusal]}", file=sys.stderr)
        return 1, None
    ttl = int(get_settings().password_reset_ttl_seconds)
    record_issue(session, user, operator, ttl)
    link = reset_link(base_url, generate_reset_token(user.user_id, user.email))
    return 0, (user.username, user.email, link, ttl)


def print_issued(issued) -> None:
    username, email, link, ttl = issued
    print(f"Reset link for {username} <{email}>:")
    print(link)
    print(
        f"Valid for {ttl_text(ttl)}; it works once. Hand it to the user over a "
        "trusted channel. This issue was recorded in the audit log."
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0].strip())
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="list every account")
    group.add_argument("user", nargs="?", help="username or email to reset")
    parser.add_argument("--base-url", help="console URL the link opens")
    parser.add_argument(
        "--operator",
        help="who is issuing the link, for the audit record "
        "(default: $SUDO_USER or the OS user)",
    )
    args = parser.parse_args(argv)
    operator = (args.operator or default_operator()).strip()[:80] or "unknown"

    init_database(echo=False, create_tables=False)
    with get_db_manager().session_scope() as session:
        if args.list:
            return list_users(session)
        code, issued = issue_link(
            session, args.user, args.base_url or default_base_url(), operator
        )
    # Committed: the audit record exists, so the link may be shown.
    if code == 0 and issued is not None:
        print_issued(issued)
    return code


if __name__ == "__main__":
    sys.exit(main())
