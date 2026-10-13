"""Which autonomy category an alert falls in (W3.1).

The tier and the QA bound are both keyed by an *autonomy category*. This
module is the one place that turns what a finding says into one.

Two sources, in order of trust:

1. **Sensor-authored fields.** ``mitre_predictions`` when the finding's
   provenance map (``core.federation.provenance``) attributes it to the
   sensor, and ``data_source`` for the few sources whose kind fixes the
   category (``aws_security_hub`` is cloud). Alert text cannot change these.
2. **The triage verdict's category** (W1.2 JSON verdict, ``category`` on the
   finding). The model chose it after reading alert text that an attacker
   may have written, so it is used only when the sensor fields say nothing.

Each source goes through an explicit table (``TRIAGE_TO_AUTONOMY``,
``MITRE_TECHNIQUE_CATEGORY``, ``DATA_SOURCE_CATEGORY``); a value no table
names is ``other``. When the sensor fields point at more than one category,
the verdict's category breaks the tie only if it is one of them; otherwise
the alert is ``other``. ``other`` can never be autonomous
(``tiers.NEVER_AUTONOMOUS_CATEGORIES``), so an unknown, ambiguous or
unmapped alert always waits for a person.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any, Iterable, Optional

from core.autonomy.tiers import OTHER, TRIAGE_TO_AUTONOMY

logger = logging.getLogger(__name__)

#: MITRE ATT&CK technique (parent id) -> autonomy category. Only techniques
#: whose category is unambiguous are listed; the rest say nothing.
MITRE_TECHNIQUE_CATEGORY: Mapping[str, str] = {
    # Phishing / social engineering delivery.
    "T1566": "phishing",
    "T1598": "phishing",
    "T1534": "phishing",
    # Identity: credentials, accounts, authentication.
    "T1078": "identity",
    "T1110": "identity",
    "T1556": "identity",
    "T1621": "identity",
    "T1098": "identity",
    "T1550": "identity",
    "T1558": "identity",
    "T1003": "identity",
    "T1552": "identity",
    "T1136": "identity",
    # Malware: execution, persistence, impact on a host.
    "T1204": "malware",
    "T1059": "malware",
    "T1486": "malware",
    "T1105": "malware",
    "T1027": "malware",
    "T1055": "malware",
    "T1547": "malware",
    "T1053": "malware",
    "T1490": "malware",
    # Network: C2, scanning, lateral movement, exfiltration over the wire.
    "T1046": "network",
    "T1071": "network",
    "T1090": "network",
    "T1095": "network",
    "T1571": "network",
    "T1572": "network",
    "T1048": "network",
    "T1498": "network",
    "T1499": "network",
    "T1021": "network",
    # Cloud control plane and storage.
    "T1530": "cloud",
    "T1537": "cloud",
    "T1580": "cloud",
    "T1538": "cloud",
    "T1619": "cloud",
    "T1578": "cloud",
    "T1526": "cloud",
}

#: ``data_source`` -> autonomy category, for sources whose kind fixes it.
#: General-purpose SIEMs (splunk, elastic, sentinel, ...) say nothing.
DATA_SOURCE_CATEGORY: Mapping[str, str] = {
    "aws_security_hub": "cloud",
}

_TECHNIQUE = re.compile(r"^(T\d{4})(?:\.\d{3})?$")


def from_triage(value: Any) -> str:
    """The autonomy category for a triage verdict's category; ``other`` if unmapped."""
    return TRIAGE_TO_AUTONOMY.get(str(value or "").strip().lower(), OTHER)


def _technique_ids(predictions: Any) -> Iterable[str]:
    from core.threat_intel.mitre_lookup import iter_techniques

    for tech in iter_techniques({"mitre_predictions": predictions}):
        raw = tech.get("technique_id") or tech.get("id")
        match = _TECHNIQUE.match(str(raw or "").strip().upper())
        if match:
            yield match.group(1)


def _sensor_authored(finding: Mapping[str, Any], field: str) -> bool:
    from core.federation.provenance import provenance_for

    return provenance_for(finding.get("data_source")).get(field) == "sensor"


def sensor_categories(finding: Mapping[str, Any]) -> set[str]:
    """The categories the finding's sensor-authored fields point at."""
    found: set[str] = set()
    source = str(finding.get("data_source") or "").strip().lower()
    if source in DATA_SOURCE_CATEGORY:
        found.add(DATA_SOURCE_CATEGORY[source])
    predictions = finding.get("mitre_predictions")
    if predictions:
        try:
            if _sensor_authored(finding, "mitre_predictions"):
                for tid in _technique_ids(predictions):
                    category = MITRE_TECHNIQUE_CATEGORY.get(tid)
                    if category:
                        found.add(category)
        except Exception as e:  # noqa: BLE001
            logger.warning("Cannot read sensor categories: %s", e)
    return found


def _triage_category(source: Mapping[str, Any]) -> str:
    """The triage verdict's category, through the shared table."""
    candidates: list[Any] = [source.get("category"), source.get("verdict_category")]
    inner = source.get("verdict")
    if isinstance(inner, Mapping):
        candidates.append(inner.get("category"))
    for value in candidates:
        if value:
            return from_triage(value)
    return OTHER


def resolve_category(source: Optional[Mapping[str, Any]]) -> tuple[str, str]:
    """``(category, basis)``; basis is ``sensor``, ``triage`` or ``none``.

    See the module docstring for the rules. Never raises.
    """
    if not source:
        return OTHER, "none"
    triage = _triage_category(source)
    sensor = sensor_categories(source)
    if len(sensor) == 1:
        return next(iter(sensor)), "sensor"
    if sensor:
        # The sensor fields disagree among themselves: the verdict may pick
        # one of them, never add another.
        if triage in sensor:
            return triage, "sensor"
        return OTHER, "sensor"
    if triage != OTHER:
        return triage, "triage"
    return OTHER, "none"


def category_of(source: Optional[Mapping[str, Any]]) -> str:
    """The autonomy category of a finding, decision or verdict document."""
    return resolve_category(source)[0]


__all__ = [
    "DATA_SOURCE_CATEGORY",
    "MITRE_TECHNIQUE_CATEGORY",
    "category_of",
    "from_triage",
    "resolve_category",
    "sensor_categories",
]
