"""Tag a lesson whose content came from text the alert's author controls.

An alert's title, description and free text in its raw event are written, in
part, by whoever caused the alert: a phishing subject, a file name, a command
line. A lesson built from that text (a scope value copied out of it, or a
paragraph pasted from it) would let the attacker write the rule that waves
their own alert through. Such a lesson is tagged ``adversary_text`` and never
applies (``core.lessons.apply``) or reaches ``active`` (the service and the
``lessons_active_gate`` constraint).

Structured fields (``entity_context``, data source, vendor rule name, MITRE
keys, ids) are sensor data: a scope value found there is fine even when the
same value also appears in the free text.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from core.lessons.model import LIST_MATCHERS, STRING_MATCHERS, as_list

#: A pasted span this long or longer from the alert's free text taints the lesson text.
COPIED_SPAN = 32

FREE_TEXT_FIELDS = ("title", "description")
#: raw_event keys whose values are the vendor's own, not the actor's.
RAW_STRUCTURED_KEYS = frozenset({"rule_name", "vendor", "synthetic", "event_count"})

_WS = re.compile(r"\s+")


def _norm(text: str) -> str:
    return _WS.sub(" ", text).strip().lower()


def _strings(value: Any, skip: frozenset = frozenset()) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if key in skip:
                continue
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def structured_values(alert: Mapping[str, Any]) -> Set[str]:
    values: Set[str] = set()
    for key in ("data_source", "finding_id", "external_id"):
        if alert.get(key):
            values.add(_norm(str(alert[key])))
    raw = alert.get("raw_event")
    if isinstance(raw, Mapping) and raw.get("rule_name"):
        values.add(_norm(str(raw["rule_name"])))
    entities = alert.get("entity_context")
    if isinstance(entities, Mapping):
        for item in entities.values():
            values.update(_norm(v) for v in as_list(item))
    mitre = alert.get("mitre_predictions")
    if isinstance(mitre, Mapping):
        values.update(_norm(str(k)) for k in mitre)
    return values


def free_text(alert: Mapping[str, Any]) -> str:
    parts: List[str] = [str(alert.get(f)) for f in FREE_TEXT_FIELDS if alert.get(f)]
    parts.extend(_strings(alert.get("raw_event"), RAW_STRUCTURED_KEYS))
    return _norm("\n".join(parts))


def _scope_values(scope: Mapping[str, Any]) -> Iterable[Tuple[str, str]]:
    for key in STRING_MATCHERS:
        if scope.get(key):
            yield key, str(scope[key])
    for key in LIST_MATCHERS:
        for value in as_list(scope.get(key)):
            yield key, value


def copied_span(text: str, source: str, span: int = COPIED_SPAN) -> Optional[str]:
    """The first ``span``-character piece of ``source`` found verbatim in ``text``."""
    text, source = _norm(text), _norm(source)
    if len(text) < span or len(source) < span:
        return None
    for start in range(0, len(source) - span + 1):
        piece = source[start : start + span]
        if piece in text:
            return piece
    return None


def assess(
    scope: Mapping[str, Any],
    lesson_text: str,
    source_alert: Optional[Mapping[str, Any]],
) -> Tuple[str, Dict[str, Any]]:
    """``(provenance, detail)`` for a lesson a signed-in person submitted.

    Without a source alert there is nothing to trace, so the lesson is the
    analyst's own; ``detail.checked`` says so.
    """
    if source_alert is None:
        return "analyst", {"checked": False}
    structured = structured_values(source_alert)
    text = free_text(source_alert)
    tainted: List[Dict[str, str]] = []
    for key, value in _scope_values(scope):
        needle = _norm(value)
        if needle and needle not in structured and needle in text:
            tainted.append({"matcher": key, "value": value})
    detail: Dict[str, Any] = {"checked": True}
    if tainted:
        detail["scope_from_alert_text"] = tainted
    narrative = "\n".join(
        str(source_alert.get(f)) for f in FREE_TEXT_FIELDS if source_alert.get(f)
    )
    span = copied_span(lesson_text, narrative)
    if span:
        detail["lesson_text_copied"] = span
    if tainted or span:
        return "adversary_text", detail
    return "analyst", detail
