"""QRadar offenses as findings (W0.41).

An offense is QRadar's correlated alert: its ``description`` names the rules
that fired, ``offense_source`` is what it is about (an address, a user name,
a log source, depending on ``offense_type``), and ``magnitude`` (1-10) is
QRadar's own priority. Offense ids only grow, so the federation cursor is
the last id read (:mod:`core.integrations.qradar.adapter`).

An offense is read once, when it is first seen: events QRadar adds to it
later do not update the finding.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from core.integrations._base.config import resolve
from core.integrations._base.config_gap import (
    report_config_complete,
    report_config_gap,
)
from core.integrations._base.ids import EXTERNAL_ID_MAX, FINDING_ID_MAX, fit_id
from core.integrations.qradar.client import QRadarClient
from core.integrations.qradar.descriptor import QRADAR
from core.time import utcnow

logger = logging.getLogger(__name__)

# offense_type ids (QRadar /api/siem/offense_types) whose offense_source is an
# address or a user name; the others (log source, rule, event name ...) stay
# in metadata only.
OFFENSE_SOURCE_IP = 0
OFFENSE_DESTINATION_IP = 1
OFFENSE_USERNAME = 3


def build_client(config: Mapping[str, Any]) -> Optional[QRadarClient]:
    """A client from the stored config, or None when it is not configured."""
    missing = [k for k in ("console_url", "api_token") if not config.get(k)]
    if missing:
        report_config_gap(logger, "QRadar", missing)
        return None
    report_config_complete(logger, "QRadar")
    verify = (
        True if config.get("verify_ssl") is None else bool(config.get("verify_ssl"))
    )
    return QRadarClient(
        config["console_url"],
        config["api_token"],
        api_version=config.get("api_version") or None,
        verify_ssl=verify,
        ca_cert_path=config.get("ca_cert_path") or None,
    )


def offense_time(offense: Mapping[str, Any]) -> Optional[datetime]:
    """``start_time`` (epoch ms) as aware UTC."""
    raw = offense.get("start_time")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(raw / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def severity_of(offense: Mapping[str, Any]) -> str:
    for key in ("magnitude", "severity"):
        value = offense.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        if value >= 9:
            return "critical"
        if value >= 7:
            return "high"
        if value >= 4:
            return "medium"
        return "low"
    return "medium"


def _ip(value: Any) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def transform_offense(offense: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    offense_id = offense.get("id")
    if isinstance(offense_id, bool) or not isinstance(offense_id, int):
        return None
    description = str(offense.get("description") or "").strip()
    first_line = description.splitlines()[0].strip() if description else ""
    title = (first_line or f"QRadar offense {offense_id}")[:200]
    source = offense.get("offense_source")
    offense_type = offense.get("offense_type")
    categories = [str(c) for c in offense.get("categories") or [] if c]

    entity_context: Dict[str, List[str]] = {}
    if source is not None:
        if offense_type == OFFENSE_SOURCE_IP and _ip(source):
            entity_context["src_ips"] = [_ip(source)]
        elif offense_type == OFFENSE_DESTINATION_IP and _ip(source):
            entity_context["dest_ips"] = [_ip(source)]
        elif offense_type == OFFENSE_USERNAME:
            entity_context["usernames"] = [str(source)]

    parts = [title]
    if source is not None:
        parts.append(f"Offense source: {source}")
    if categories:
        parts.append(f"Categories: {', '.join(categories[:10])}")
    if offense.get("event_count") is not None:
        parts.append(f"Events: {offense.get('event_count')}")
    if offense.get("magnitude") is not None:
        parts.append(f"Magnitude: {offense.get('magnitude')}")

    created = offense_time(offense)
    rules = [
        r.get("id")
        for r in offense.get("rules") or []
        if isinstance(r, Mapping) and isinstance(r.get("id"), int)
    ]
    return {
        "finding_id": fit_id("qradar-", str(offense_id), FINDING_ID_MAX),
        "external_id": fit_id("", str(offense_id), EXTERNAL_ID_MAX),
        "data_source": "qradar",
        "timestamp": (created or utcnow().replace(tzinfo=timezone.utc)).isoformat(),
        "severity": severity_of(offense),
        "status": "new",
        "title": title,
        "description": ". ".join(parts)[:500],
        "entity_context": entity_context,
        "raw_event": dict(offense),
        "anomaly_score": 0.5,
        "mitre_predictions": {},
        "metadata": {
            "offense_id": offense_id,
            "offense_type": offense_type,
            "offense_source": source,
            "offense_status": offense.get("status"),
            "magnitude": offense.get("magnitude"),
            "credibility": offense.get("credibility"),
            "relevance": offense.get("relevance"),
            "event_count": offense.get("event_count"),
            "flow_count": offense.get("flow_count"),
            "categories": categories,
            "rule_ids": rules,
            "domain_id": offense.get("domain_id"),
        },
    }


def qradar_config() -> Dict[str, Any]:
    return resolve(QRADAR)
