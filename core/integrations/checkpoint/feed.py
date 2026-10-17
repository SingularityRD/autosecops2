"""The IP block list a Check Point gateway polls (W0.60).

Check Point applies a Generic Data Center object (or, on R81.20+, a Network
Feed) without a policy install: the gateway fetches a URL on its own schedule
and the rule that references the object follows the list. So blocking an IP is
a change to this list, held in ``system_config`` under ``FEED_KEY``; nothing is
sent to the firewall, and it works air-gapped.

The list is ``{ip: {"added_at", "expires_at", "action_id"}}``. Readers drop
expired entries even before the TTL sweep reverses them, so a block never
outlives its ttl on the gateway by more than one poll.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.storage.models import SystemConfig
from core.time import utcnow

FEED_KEY = "checkpoint.blocklist"
OBJECT_NAME = "AutoSecOps block list"
# A fixed id: the gateway's Generic Data Center object keys on it.
OBJECT_ID = str(uuid.uuid5(uuid.NAMESPACE_URL, "autosecops:checkpoint:blocklist"))
_LOCK_KEY = 0x434B_5046_4545  # "CKPFEE"
MAX_ENTRIES = 50_000


class FeedFull(ValueError):
    pass


def _lock(session: Session) -> None:
    session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_KEY})


def _row(session: Session) -> Optional[SystemConfig]:
    return session.query(SystemConfig).filter(SystemConfig.key == FEED_KEY).first()


def _live(entries: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    out = {}
    for ip, meta in entries.items():
        expires = (meta or {}).get("expires_at")
        if expires and datetime.fromisoformat(expires) <= now:
            continue
        out[ip] = meta
    return out


def entries(session: Session, now: Optional[datetime] = None) -> Dict[str, Any]:
    row = _row(session)
    stored = row.value.get("entries", {}) if row and isinstance(row.value, dict) else {}
    return _live(dict(stored), now or utcnow())


def contains(session: Session, ip: str, now: Optional[datetime] = None) -> bool:
    return ip in entries(session, now)


def add(
    session: Session,
    ip: str,
    *,
    ttl: timedelta,
    action_id: Optional[str],
    actor: str,
    now: Optional[datetime] = None,
) -> None:
    now = now or utcnow()
    _lock(session)
    current = entries(session, now)
    if ip not in current and len(current) >= MAX_ENTRIES:
        raise FeedFull(f"the block list holds {MAX_ENTRIES} addresses already")
    current[ip] = {
        "added_at": now.isoformat(),
        "expires_at": (now + ttl).isoformat(),
        "action_id": action_id,
    }
    _write(session, current, actor)


def remove(session: Session, ip: str, *, actor: str) -> None:
    _lock(session)
    current = entries(session)
    current.pop(ip, None)
    _write(session, current, actor)


def _write(session: Session, value: Dict[str, Any], actor: str) -> None:
    row = _row(session)
    doc = {"entries": value}
    if row is None:
        session.add(
            SystemConfig(
                key=FEED_KEY,
                value=doc,
                description="Check Point block list (W0.60)",
                config_type="integration",
                updated_by=actor,
            )
        )
    else:
        row.value = doc
        row.updated_by = actor
    session.flush()


def _sorted(ips: List[str]) -> List[str]:
    return sorted(
        ips, key=lambda a: (ipaddress.ip_address(a).version, ipaddress.ip_address(a))
    )


def generic_data_center(session: Session) -> Dict[str, Any]:
    """The Check Point Generic Data Center JSON document."""
    return {
        "version": "1.0",
        "description": "IP addresses AutoSecOps blocks (approved response actions)",
        "objects": [
            {
                "name": OBJECT_NAME,
                "id": OBJECT_ID,
                "description": "block_ip actions; each expires with its ttl",
                "ranges": _sorted(list(entries(session))),
            }
        ],
    }


def plain_text(session: Session) -> str:
    """One address per line: Network Feed flat list, or any firewall's IP feed."""
    ips = _sorted(list(entries(session)))
    return "".join(f"{ip}\n" for ip in ips)
