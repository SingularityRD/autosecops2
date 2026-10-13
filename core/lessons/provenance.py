"""Tag a lesson whose content came from text the alert's author controls.

An alert's title, description, raw event and most of its entity lists are
written, in part, by whoever caused the alert: a phishing subject, a file
name, a command line, the name of a machine or an account the attacker
created. A lesson built from that text (a scope value copied out of it, or a
paragraph pasted from it) would let the attacker write the rule that waves
their own alert through. Such a lesson is tagged ``adversary_text`` and never
applies (``core.lessons.apply``) or reaches ``active`` (the service and the
``lessons_active_gate`` constraint).

Trusted values mirror the W1.2 field-provenance contract
(``core/federation/provenance.py`` on ``wp/w1.2-triage-provenance``): only
fields it marks ``sensor``-authored and typed are trusted, and a value that
fails its type check is not. Concretely:

* trusted: ``data_source``, ``finding_id``, ``external_id``, the vendor
  ``raw_event.rule_name``, MITRE technique ids, and
  ``entity_context.src_ips`` / ``dest_ips`` (must parse as IP addresses) and
  ``entity_context.file_hashes`` (must be MD5/SHA-1/SHA-256/SHA-512 hex);
* everything else is adversary text, in particular ``hostnames``,
  ``usernames``, ``domains``, ``urls``, ``user_agents``, ``file_names``,
  ``command_lines``, e-mail subjects, and the raw event kept under
  ``entity_context.source_evidence`` (``core/ingestion/ingestion_service.py``).

So a hostname or user name copied from the source finding taints the lesson.
An analyst who names a host from their own knowledge (``source_kind=manual``,
no source finding) still may, but ``validate_scope`` then requires a
non-adversary anchor (``data_source``, ``rule_name`` or ``mitre_technique``)
next to it, and a second person must promote it.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from core.lessons.model import LIST_MATCHERS, STRING_MATCHERS, as_list

#: A pasted span this long or longer from the alert's free text taints the lesson text.
COPIED_SPAN = 32
#: Free text beyond this many characters is not scanned for copied spans
#: (scope values are still checked against all of it).
MAX_SCAN_CHARS = 1_000_000

FREE_TEXT_FIELDS = ("title", "description")
#: raw_event keys whose values are the vendor's own, not the actor's.
RAW_STRUCTURED_KEYS = frozenset({"rule_name", "vendor", "synthetic", "event_count"})

#: entity_context lists W1.2 marks sensor-authored, with their type check.
_HEX = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTHS = frozenset({32, 40, 64, 128})


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def _is_hash(value: str) -> bool:
    value = value.strip().lower()
    return len(value) in _HASH_LENGTHS and bool(_HEX.match(value))


SENSOR_ENTITY_FIELDS = {
    "src_ips": _is_ip,
    "dest_ips": _is_ip,
    "file_hashes": _is_hash,
}

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
    """Values the sensor wrote: a scope value found here is not adversary text."""
    values: Set[str] = set()
    for key in ("data_source", "finding_id", "external_id"):
        if alert.get(key):
            values.add(_norm(str(alert[key])))
    raw = alert.get("raw_event")
    if isinstance(raw, Mapping) and raw.get("rule_name"):
        values.add(_norm(str(raw["rule_name"])))
    entities = alert.get("entity_context")
    if isinstance(entities, Mapping):
        for key, check in SENSOR_ENTITY_FIELDS.items():
            values.update(_norm(v) for v in as_list(entities.get(key)) if check(v))
    mitre = alert.get("mitre_predictions")
    if isinstance(mitre, Mapping):
        values.update(_norm(str(k)) for k in mitre)
    return values


def free_text(alert: Mapping[str, Any]) -> str:
    """Everything the alert's author may have written, normalised.

    Title and description, the raw event (``raw_event`` and the
    ``entity_context.source_evidence`` ingestion keeps it under), evidence
    links, and every ``entity_context`` value outside the sensor allowlist.
    A sensor-listed value that fails its type check counts as text.
    """
    parts: List[str] = [str(alert.get(f)) for f in FREE_TEXT_FIELDS if alert.get(f)]
    parts.extend(_strings(alert.get("raw_event"), RAW_STRUCTURED_KEYS))
    parts.extend(_strings(alert.get("evidence_links")))
    entities = alert.get("entity_context")
    if isinstance(entities, Mapping):
        for key, item in entities.items():
            check = SENSOR_ENTITY_FIELDS.get(key)
            if check is None:
                parts.extend(_strings(item))
            else:
                parts.extend(v for v in as_list(item) if not check(v))
    return _norm("\n".join(parts))


def _scope_values(scope: Mapping[str, Any]) -> Iterable[Tuple[str, str]]:
    for key in STRING_MATCHERS:
        if scope.get(key):
            yield key, str(scope[key])
    for key in LIST_MATCHERS:
        for value in as_list(scope.get(key)):
            yield key, value


def copied_span(text: str, source: str, span: int = COPIED_SPAN) -> Optional[str]:
    """The first ``span``-character piece of ``source`` found verbatim in ``text``.

    Linear in ``len(source)``: the lesson's pieces go in a set, the source's
    are looked up in it.
    """
    text, source = _norm(text), _norm(source)[:MAX_SCAN_CHARS]
    if len(text) < span or len(source) < span:
        return None
    pieces = {text[i : i + span] for i in range(len(text) - span + 1)}
    for start in range(len(source) - span + 1):
        piece = source[start : start + span]
        if piece in pieces:
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
    span = copied_span(lesson_text, text)
    if span:
        detail["lesson_text_copied"] = span
    if tainted or span:
        return "adversary_text", detail
    return "analyst", detail
