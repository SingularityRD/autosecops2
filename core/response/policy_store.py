"""Read and change the ``response.policy`` row without losing a concurrent change (W0.36).

Every writer of the row (``PUT /api/response/policy``, ``PUT
/api/response/four-eyes/{type}``) goes through :func:`update_policy`: the row
is read ``SELECT ... FOR UPDATE``, changed and written in one transaction, with
its ``config_audit_log`` row (who, reason, old and new value) in that same
transaction. Two writers therefore serialise instead of each writing back what
it read.

A client that edits the whole policy also sends the :func:`policy_version` it
read; if the row changed since, :class:`PolicyConflict` is raised (409) rather
than overwriting someone else's change with a stale copy.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Dict, Optional, Tuple

from sqlalchemy.exc import IntegrityError

from core.response.policy import POLICY_CONFIG_KEY
from core.storage.connection import get_db_manager
from core.storage.models import ConfigAuditLog, SystemConfig

DESCRIPTION = "Response action policy (W2.4, W3.2)"
CONFIG_TYPE = "response_policy"


class PolicyConflict(RuntimeError):
    """The stored policy is not the version the caller read."""


def policy_version(raw: Optional[Dict[str, Any]]) -> str:
    """A version of the stored value: sha256 of its canonical JSON ("null" when absent)."""
    text = json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_policy() -> Tuple[Dict[str, Any], str]:
    """The stored value (``{}`` when absent) and its version. Raises on a failed read."""
    with get_db_manager().session_scope() as session:
        row = session.get(SystemConfig, POLICY_CONFIG_KEY)
        raw = dict(row.value) if row is not None else None
    return raw or {}, policy_version(raw)


def update_policy(
    actor: str,
    reason: str,
    change: Callable[[Dict[str, Any]], Dict[str, Any]],
    *,
    expected_version: Optional[str] = None,
) -> Tuple[Dict[str, Any], str, bool]:
    """Apply ``change`` to the locked row; ``(value, version, written)``.

    ``change`` gets a copy of the stored value and returns the new one. Nothing
    is written (and no audit row) when the value does not change. Raises
    :class:`PolicyConflict` when ``expected_version`` is given and the row is
    at another version, or when a concurrent first write created the row.
    """
    try:
        with get_db_manager().session_scope() as session:
            row = (
                session.query(SystemConfig)
                .filter(SystemConfig.key == POLICY_CONFIG_KEY)
                .with_for_update()
                .one_or_none()
            )
            old = dict(row.value) if row is not None else None
            if expected_version is not None and expected_version != policy_version(old):
                raise PolicyConflict("the response policy changed since it was read")
            new = change(dict(old or {}))
            if old is not None and new == old:
                return old, policy_version(old), False
            if row is None:
                session.add(
                    SystemConfig(
                        key=POLICY_CONFIG_KEY,
                        value=new,
                        description=DESCRIPTION,
                        config_type=CONFIG_TYPE,
                        updated_by=actor,
                    )
                )
            else:
                row.value = new
                row.updated_by = actor
            session.add(
                ConfigAuditLog(
                    config_type=CONFIG_TYPE,
                    config_key=POLICY_CONFIG_KEY,
                    action="create" if row is None else "update",
                    old_value=old,
                    new_value=new,
                    changed_by=actor,
                    change_reason=reason,
                )
            )
            session.flush()
    except IntegrityError:
        # Two first writes raced: the other one created the row.
        raise PolicyConflict("the response policy was created concurrently") from None
    return new, policy_version(new), True
