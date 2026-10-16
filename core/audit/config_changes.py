"""One ``config_audit_log`` row per settings change: who, what, old -> new.

For the settings that had none (W0.35, G5): LLM providers, skills, custom
workflows, detection rule sources and SLA policies. Values pass through
:func:`redact` first, so a credential in a provider's ``config``, a rule
source URL or a skill body is never written to the audit log.

:func:`record_change` joins the caller's transaction (a failure rolls the
change back with it, as ``ConfigService._create_audit_log`` does).
:func:`record_change_now` commits on its own, for changes that live outside
the database (skills and rule sources on disk): it never raises and logs a
failure at ERROR.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

REDACTED = "[REDACTED]"

# Keys whose value is a credential, whatever it looks like.
_SECRET_KEY = re.compile(
    r"(^|[_-])pass(wd|phrase)?$|password|secret|(^|[_-])token$|api[_-]?key"
    r"|private[_-]?key|credential|authorization|cookie|bearer|signing[_-]?key"
    r"|access[_-]?key",
    re.IGNORECASE,
)
# Values that are recognisably a credential wherever they appear.
_SECRET_VALUE = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"),  # OpenAI / Anthropic style keys
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWT
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),  # GitHub tokens
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
)
# user:password@ in a URL.
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")


def _redact_text(value: str) -> str:
    value = _URL_USERINFO.sub(lambda m: f"{m.group(1)}{REDACTED}@", value)
    for pattern in _SECRET_VALUE:
        value = pattern.sub(REDACTED, value)
    return value


def redact(value: Any) -> Any:
    """A copy of ``value`` with credentials replaced by ``[REDACTED]``."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            # A flag (has_api_key) says whether a secret is set, not what it is.
            if (
                isinstance(key, str)
                and _SECRET_KEY.search(key)
                and item not in (None, "")
                and not isinstance(item, bool)
            ):
                out[key] = REDACTED
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _row(
    *,
    config_type: str,
    config_key: str,
    action: str,
    old: Optional[Any],
    new: Optional[Any],
    actor: str,
    reason: Optional[str],
):
    from core.storage.models import ConfigAuditLog

    return ConfigAuditLog(
        config_type=config_type[:50],
        config_key=str(config_key)[:200],
        action=action[:20],
        old_value=redact(old),
        new_value=redact(new),
        changed_by=(actor or "unknown")[:100],
        change_reason=reason,
    )


def record_change(
    session: Session,
    *,
    config_type: str,
    config_key: str,
    action: str,
    old: Optional[Any],
    new: Optional[Any],
    actor: str,
    reason: Optional[str] = None,
) -> None:
    """Add the audit row to ``session``; it commits with the change."""
    session.add(
        _row(
            config_type=config_type,
            config_key=config_key,
            action=action,
            old=old,
            new=new,
            actor=actor,
            reason=reason,
        )
    )


def record_change_now(
    *,
    config_type: str,
    config_key: str,
    action: str,
    old: Optional[Any],
    new: Optional[Any],
    actor: str,
    reason: Optional[str] = None,
) -> bool:
    """Commit the audit row on its own. Never raises."""
    from core.storage.unit_of_work import unit_of_work

    try:
        with unit_of_work() as session:
            record_change(
                session,
                config_type=config_type,
                config_key=config_key,
                action=action,
                old=old,
                new=new,
                actor=actor,
                reason=reason,
            )
        return True
    except Exception as exc:  # noqa: BLE001 - the change itself already happened
        logger.error(
            "Could not audit %s %s %s by %s: %s",
            config_type,
            config_key,
            action,
            actor,
            type(exc).__name__,
        )
        return False
