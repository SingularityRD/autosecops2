"""Apply lessons to one alert's verdict: the rule lane.

Pure: no I/O, the alert is never mutated. Replay and (later) the daemon call
the same function, so what was measured is what runs.

Safety rules, enforced here whatever the stored row says:

* a lesson whose provenance is not ``analyst`` never applies;
* an expired lesson never applies;
* no lesson applies to a ``critical`` alert, or to an alert whose severity is
  unknown or above the lesson's ``max_severity``;
* the output is a verdict hint and nothing else: there is no field that
  closes, resolves or suppresses a finding or a case;
* when an ``escalate`` and a ``benign_hint`` lesson both match, escalate wins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from core.lessons.model import (
    LIST_MATCHERS,
    SEVERITY_RANK,
    TRUSTED_PROVENANCE,
    Lesson,
    as_list,
)

CRITICAL_RANK = SEVERITY_RANK["critical"]


def rule_name(alert: Mapping[str, Any]) -> Optional[str]:
    raw = alert.get("raw_event")
    if isinstance(raw, Mapping):
        value = raw.get("rule_name")
        return str(value) if value is not None else None
    return None


def severity_rank(alert: Mapping[str, Any]) -> Optional[int]:
    return SEVERITY_RANK.get(str(alert.get("severity") or "").strip().lower())


def matches(
    scope: Mapping[str, Any],
    alert: Mapping[str, Any],
    *,
    category: Optional[str] = None,
    lesson_category: Optional[str] = None,
) -> bool:
    """Every matcher present in ``scope`` holds for ``alert`` (AND).

    String matchers compare exactly, case-insensitively. A list matcher holds
    when the alert's entity list shares at least one value with it.
    """
    if lesson_category and category != lesson_category:
        return False
    if (
        "data_source" in scope
        and str(alert.get("data_source") or "").lower()
        != str(scope["data_source"]).lower()
    ):
        return False
    if (
        "rule_name" in scope
        and (rule_name(alert) or "").lower() != str(scope["rule_name"]).lower()
    ):
        return False
    if "mitre_technique" in scope:
        mitre = alert.get("mitre_predictions")
        keys = {
            str(k).upper() for k in (mitre.keys() if isinstance(mitre, Mapping) else [])
        }
        if str(scope["mitre_technique"]).upper() not in keys:
            return False
    entities = alert.get("entity_context")
    entities = entities if isinstance(entities, Mapping) else {}
    for key in LIST_MATCHERS:
        if key not in scope:
            continue
        have = {v.lower() for v in as_list(entities.get(key))}
        if not have & {str(v).lower() for v in scope[key]}:
            return False
    return True


@dataclass
class Outcome:
    """The verdict after lessons. ``applied`` lists the lesson ids that changed it."""

    verdict: str
    before: str
    applied: List[str] = field(default_factory=list)
    matched: List[str] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.verdict != self.before

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "before": self.before,
            "applied": list(self.applied),
            "matched": list(self.matched),
            "skipped": [{"lesson_id": i, "reason": r} for i, r in self.skipped],
        }


def why_not(
    lesson: Lesson, alert: Mapping[str, Any], now: datetime, *, require_active: bool
) -> Optional[str]:
    """Why ``lesson`` may not touch ``alert`` at all, or ``None``."""
    if lesson.provenance != TRUSTED_PROVENANCE:
        return f"provenance:{lesson.provenance}"
    if require_active and lesson.status != "active":
        return f"status:{lesson.status}"
    if lesson.expired(now):
        return "expired"
    rank = severity_rank(alert)
    if rank is None:
        return "severity:unknown"
    if rank >= CRITICAL_RANK:
        return "severity:critical"
    limit = SEVERITY_RANK.get(str(lesson.applies_to.get("max_severity") or ""))
    if limit is None or rank > limit:
        return "severity:above_scope"
    return None


def apply_lessons(
    alert: Mapping[str, Any],
    verdict: str,
    lessons: Iterable[Lesson],
    now: datetime,
    *,
    category: Optional[str] = None,
    require_active: bool = True,
) -> Outcome:
    """The verdict hint for ``alert`` given the triage ``verdict`` and ``lessons``.

    ``require_active=False`` is for replaying a proposed lesson; every other
    rule still holds.
    """
    out = Outcome(verdict=verdict, before=verdict)
    benign: List[str] = []
    escalate: List[str] = []
    escalate_matched = False
    for lesson in list(lessons):
        if not matches(
            lesson.applies_to,
            alert,
            category=category,
            lesson_category=lesson.category,
        ):
            continue
        reason = why_not(lesson, alert, now, require_active=require_active)
        if reason:
            out.skipped.append((lesson.id, reason))
            continue
        out.matched.append(lesson.id)
        escalate_matched = escalate_matched or lesson.effect == "escalate"
        if lesson.effect == "escalate" and verdict in ("benign", "inconclusive"):
            escalate.append(lesson.id)
        elif lesson.effect == "benign_hint" and verdict in (
            "malicious",
            "inconclusive",
        ):
            benign.append(lesson.id)
    if escalate:
        out.verdict, out.applied = "malicious", escalate
    elif benign and not escalate_matched:
        # A matching escalate lesson, even one with nothing to change, keeps
        # every benign hint off the alert.
        out.verdict, out.applied = "benign", benign
    return out
