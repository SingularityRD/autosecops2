"""Tag a lesson whose content came from text the alert's author controls.

An alert's title, description, raw event and most of its entity lists are
written, in part, by whoever caused the alert: a phishing subject, a file
name, a command line, the name of a machine or an account the attacker
created. A lesson built from that text (a scope value copied out of it, or a
paragraph pasted from it) would let the attacker write the rule that waves
their own alert through. Such a lesson is tagged ``adversary_text`` and never
applies (``core.lessons.apply``) or reaches ``active`` (the service and the
``lessons_active_gate`` constraint).

Which alert values are trusted is W1.2's field-provenance judgement
(``core/federation/provenance.py``), imported, not restated: a scope value is
trusted only when the alert carries it *in the field that matcher reads*
(``core.lessons.model.MATCHER_FIELDS``) and :func:`author_of` under
``provenance_for(alert.data_source)`` says ``sensor`` for it (so a value that
fails the field's type check is not). Trust is per matcher: a host name equal
to the alert's ``external_id`` or to one of its IPs is not trusted. Concretely
today: ``data_source``; ``entity_context.src_ips`` / ``file_hashes`` (typed);
MITRE ids only where the adapter map marks ``mitre_predictions`` sensor (not
for webhooks, where they are the sender's third-party assertion); never the
vendor rule name (adversary for Splunk/Elastic and by default elsewhere),
host or user names. Every other value the alert carries that W1.2 does not
mark sensor (title, description, the raw event, also as
``entity_context.source_evidence``, evidence links, ``external_id``) is
adversary text.

So a hostname or user name copied from the source finding taints the lesson.
An analyst who names a host from their own knowledge (``source_kind=manual``,
no source finding) still may, but ``validate_scope`` then requires a
sensor-authored anchor next to it (``core.lessons.model.anchored``; under
the W1.2 maps that is ``data_source``), and a second person must promote it.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from core.federation.provenance import SENSOR, author_of, provenance_for
from core.lessons.model import (
    IDENTIFYING_MATCHERS,
    LIST_MATCHERS,
    STRING_MATCHERS,
    as_list,
    matcher_author,
)

#: A pasted span this long or longer from the alert's free text taints the lesson text.
COPIED_SPAN = 32
#: Free text beyond this many characters is not scanned for copied spans
#: (scope values are still checked against all of it).
MAX_SCAN_CHARS = 1_000_000

#: Alert sections walked for free text, under their W1.2 field names.
TEXT_SECTIONS = (
    "title",
    "description",
    "external_id",
    "evidence_links",
    "entity_context",
    "entities",
    "metadata",
    "raw_event",
    "raw_data",
    "enrichment",
)
_MAX_DEPTH = 32
_SEGMENT = re.compile(r"[A-Za-z0-9_-]{1,64}")
_WS = re.compile(r"\s+")


def _norm(text: str) -> str:
    return _WS.sub(" ", text).strip().lower()


def _path(prefix: Optional[str], key: Any) -> Optional[str]:
    """``prefix.key`` as W1.2 names it, or None when the key cannot be named
    (W1.2 leaves such keys out; here their values are adversary text)."""
    if prefix is None:
        return None
    segments = str(key).split(".")
    if not all(_SEGMENT.fullmatch(s) for s in segments):
        return None
    return f"{prefix}.{key}"


def _scalars(
    path: Optional[str], value: Any, depth: int = 0
) -> Iterable[Tuple[Optional[str], str]]:
    """``(field, text)`` for every scalar under ``value``; lists of objects
    get an index segment, lists of scalars share the list's field."""
    if value is None or isinstance(value, bool):
        return
    if depth > _MAX_DEPTH:
        yield None, str(value)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _scalars(_path(path, key), item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            if isinstance(item, (Mapping, list, tuple)):
                yield from _scalars(_path(path, i), item, depth + 1)
            else:
                yield from _scalars(path, item, depth + 1)
    else:
        yield path, str(value)


def trusted_values(alert: Mapping[str, Any]) -> Dict[str, Set[str]]:
    """Per matcher, the normalised values the sensor wrote in the field that
    matcher reads (W1.2, for this alert's ``data_source``)."""
    source = alert.get("data_source")
    out: Dict[str, Set[str]] = {key: set() for key in IDENTIFYING_MATCHERS}
    if isinstance(source, str) and source.strip():
        out["data_source"].add(_norm(source))
    candidates: Dict[str, List[str]] = {}
    raw = alert.get("raw_event")
    if isinstance(raw, Mapping) and isinstance(raw.get("rule_name"), (str, int)):
        candidates["rule_name"] = [str(raw["rule_name"])]
    mitre = alert.get("mitre_predictions")
    if isinstance(mitre, Mapping):
        candidates["mitre_technique"] = [str(k) for k in mitre]
    entities = alert.get("entity_context")
    if isinstance(entities, Mapping):
        for key in LIST_MATCHERS:
            candidates[key] = as_list(entities.get(key))
    for key, values in candidates.items():
        out[key].update(
            _norm(v) for v in values if matcher_author(key, v, source) == SENSOR
        )
    return out


def free_text(alert: Mapping[str, Any]) -> str:
    """Everything in the alert W1.2 does not mark sensor-authored, normalised.

    Title, description, ``external_id``, evidence links, the raw event (also
    as ``entity_context.source_evidence``), every entity value outside the
    source's sensor fields or failing its type check, and MITRE ids where they
    are not sensor (a webhook's third-party assertion).
    """
    provenance = provenance_for(alert.get("data_source"))
    parts: List[str] = []
    for section in TEXT_SECTIONS:
        for name, text in _scalars(section, alert.get(section)):
            if name is None or author_of(name, text, provenance) != SENSOR:
                parts.append(text)
    mitre = alert.get("mitre_predictions")
    if isinstance(mitre, Mapping):
        parts.extend(
            str(k)
            for k in mitre
            if author_of("mitre_predictions", str(k), provenance) != SENSOR
        )
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
    trusted = trusted_values(source_alert)
    text = free_text(source_alert)
    tainted: List[Dict[str, str]] = []
    for key, value in _scope_values(scope):
        needle = _norm(value)
        if needle and needle not in trusted[key] and needle in text:
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
