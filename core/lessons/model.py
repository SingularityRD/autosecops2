"""The lesson record and its scope document.

``applies_to`` (the scope) holds only matchers over structured alert fields:
the data source, the vendor rule name, a MITRE technique and entity lists.
There is deliberately no free-text matcher (title, description): those fields
are written by whoever triggered the alert, and a lesson keyed on them would
let an attacker opt their own alert into a benign hint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional

from core.federation.provenance import (
    ADAPTER_PROVENANCE,
    ADVERSARY,
    SENSOR,
    author_of,
    provenance_for,
)

STATUSES = ("proposed", "active", "retired")
SOURCE_KINDS = (
    "qa_review",
    "eval_failure",
    "analyst_override",
    "canary_miss",
    "manual",
)
CATEGORIES = ("phishing", "malware", "identity", "network", "cloud", "other")

#: ``benign_hint`` turns a matching malicious / inconclusive verdict into a
#: benign hint (the false-positive lane). ``escalate`` turns a matching benign /
#: inconclusive verdict into malicious. Neither changes a finding's or case's
#: status: there is no closing effect.
EFFECTS = ("benign_hint", "escalate")

#: ``analyst``: typed by a signed-in person and not traced to alert text.
#: ``adversary_text``: a scope value or the lesson text came from text the
#: alert's author controls. ``system``: written by automation. Only
#: ``analyst`` lessons ever apply or reach ``active``.
PROVENANCES = ("analyst", "adversary_text", "system")
TRUSTED_PROVENANCE = "analyst"

SEVERITY_RANK = {
    "informational": 0,
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
#: What ``max_severity`` may name. ``critical`` is not here: no lesson may
#: reach a critical alert.
MAX_SEVERITIES = ("low", "medium", "high")
DEFAULT_MAX_SEVERITY = "medium"

LIST_MATCHERS = ("hostnames", "usernames", "src_ips", "file_hashes")
STRING_MATCHERS = ("data_source", "rule_name", "mitre_technique")
#: Matchers that identify what a lesson is about. ``max_severity`` only narrows.
IDENTIFYING_MATCHERS = STRING_MATCHERS + LIST_MATCHERS
#: Scope keys that may anchor a lesson: the source, the vendor's rule, the
#: technique id. Every lesson names at least one that is *sensor-authored*
#: under the W1.2 field-provenance maps (``core/federation/provenance.py``)
#: for every source the lesson can match (:func:`anchored`), so a lesson is
#: never keyed on host or user names (or bare IPs/hashes) alone: whoever
#: controls a machine names it. Mirrored by ``lessons_active_gate``.
ANCHOR_MATCHERS = STRING_MATCHERS
#: The W1.2 field each matcher reads on an alert (``core.lessons.apply``).
#: ``data_source`` is the routing key itself, not a field of the finding: the
#: adapter sets it, or the authenticated webhook/Kafka/import sender (W1.2's
#: trust boundary), so it is sensor for every source.
MATCHER_FIELDS = {
    "rule_name": "raw_event.rule_name",
    "mitre_technique": "mitre_predictions",
    "hostnames": "entity_context.hostnames",
    "usernames": "entity_context.usernames",
    "src_ips": "entity_context.src_ips",
    "file_hashes": "entity_context.file_hashes",
}
#: Every map a finding can be judged under: the adapters', and the webhook map
#: (``None``) any other ``data_source`` gets.
ALL_SOURCES = tuple(ADAPTER_PROVENANCE) + (None,)


def matcher_author(key: str, value: str, data_source: Optional[str]) -> str:
    """W1.2's author of ``value`` in the field matcher ``key`` reads, for a
    finding from ``data_source`` (a sensor field whose value fails its type
    check is ``adversary``)."""
    if key == "data_source":
        return SENSOR
    if ", " in value:
        # author_of reads ", " as W1.2's list rendering and checks each part;
        # one matcher value is one item.
        return ADVERSARY
    return author_of(MATCHER_FIELDS[key], value, provenance_for(data_source))


def anchors(scope: Mapping[str, Any]) -> List[str]:
    """The anchor matchers in ``scope`` that are sensor-authored.

    With ``data_source`` in scope the lesson matches only that source, and
    ``data_source`` anchors it. Without it the lesson matches every source,
    so a ``rule_name`` / ``mitre_technique`` anchors only when it is sensor
    under every map: under W1.2 rule names are adversary (Splunk, Elastic and
    by default elsewhere) and webhook MITRE ids third-party, so neither does.
    """
    out = []
    source = scope.get("data_source")
    for key in ANCHOR_MATCHERS:
        value = scope.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        sources = (source,) if source else ALL_SOURCES
        if all(matcher_author(key, value, ds) == SENSOR for ds in sources):
            out.append(key)
    return out


def anchored(scope: Mapping[str, Any]) -> bool:
    return bool(anchors(scope))


SCOPE_KEYS = IDENTIFYING_MATCHERS + ("max_severity",)

MAX_LIST_VALUES = 50
MAX_VALUE_LEN = 255
MAX_EXPIRY_DAYS = 90
DEFAULT_EXPIRY_DAYS = 30


class ScopeError(ValueError):
    """The scope document is not one this module can apply safely."""


def _clean(value: Any, key: str) -> str:
    if not isinstance(value, str):
        raise ScopeError(f"{key}: expected a string")
    value = value.strip()
    if not value:
        raise ScopeError(f"{key}: empty value")
    if len(value) > MAX_VALUE_LEN:
        raise ScopeError(f"{key}: longer than {MAX_VALUE_LEN} characters")
    return value


def validate_scope(raw: Mapping[str, Any]) -> Dict[str, Any]:
    """A normalised copy of ``raw``, or :class:`ScopeError`.

    Unknown keys are refused rather than ignored: a matcher the code does not
    apply would make a lesson broader than the analyst who wrote it thinks.
    """
    if not isinstance(raw, Mapping):
        raise ScopeError("applies_to must be an object")
    unknown = sorted(set(raw) - set(SCOPE_KEYS))
    if unknown:
        raise ScopeError(f"unknown matcher(s): {', '.join(unknown)}")
    scope: Dict[str, Any] = {}
    for key in STRING_MATCHERS:
        if raw.get(key) is not None:
            scope[key] = _clean(raw[key], key)
    for key in LIST_MATCHERS:
        if raw.get(key) is None:
            continue
        values = raw[key]
        if not isinstance(values, list) or not values:
            raise ScopeError(f"{key}: expected a non-empty list")
        if len(values) > MAX_LIST_VALUES:
            raise ScopeError(f"{key}: at most {MAX_LIST_VALUES} values")
        scope[key] = sorted({_clean(v, key) for v in values})
    if not any(key in scope for key in IDENTIFYING_MATCHERS):
        raise ScopeError(
            "a lesson needs at least one of: " + ", ".join(IDENTIFYING_MATCHERS)
        )
    if not anchored(scope):
        raise ScopeError(
            "a lesson needs at least one of "
            + ", ".join(ANCHOR_MATCHERS)
            + " that the sensor writes for every source it can match (W1.2"
            " field provenance: give data_source; rule names and webhook"
            " MITRE ids are not sensor-authored): host names, user names,"
            " IPs and hashes only narrow it"
        )
    max_severity = raw.get("max_severity", DEFAULT_MAX_SEVERITY)
    if max_severity not in MAX_SEVERITIES:
        raise ScopeError(
            "max_severity must be one of "
            + ", ".join(MAX_SEVERITIES)
            + " (no lesson applies to critical alerts)"
        )
    scope["max_severity"] = max_severity
    return scope


@dataclass
class Lesson:
    id: str
    lesson: str
    effect: str
    applies_to: Dict[str, Any]
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime]
    status: str = "proposed"
    provenance: str = "system"
    provenance_detail: Dict[str, Any] = field(default_factory=dict)
    source_kind: str = "manual"
    source_id: Optional[str] = None
    category: Optional[str] = None
    tenant_id: str = "default"
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    replay: Optional[Dict[str, Any]] = None
    replay_passed: bool = False
    replayed_at: Optional[datetime] = None
    retired_at: Optional[datetime] = None
    retired_by: Optional[str] = None
    retire_reason: Optional[str] = None
    #: Bumped by every write; a write names the version it read (optimistic lock).
    version: int = 0

    def expired(self, now: datetime) -> bool:
        return self.expires_at is None or self.expires_at <= now

    def definition(self) -> Dict[str, Any]:
        """What the replay measured: a promoted lesson must match it."""
        return {
            "effect": self.effect,
            "applies_to": self.applies_to,
            "category": self.category,
        }

    def to_dict(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        def iso(value: Optional[datetime]) -> Optional[str]:
            return value.isoformat() if value else None

        out = {
            "id": self.id,
            "lesson": self.lesson,
            "effect": self.effect,
            "applies_to": self.applies_to,
            "category": self.category,
            "status": self.status,
            "provenance": self.provenance,
            "provenance_detail": self.provenance_detail,
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "created_by": self.created_by,
            "created_at": iso(self.created_at),
            "expires_at": iso(self.expires_at),
            "approved_by": self.approved_by,
            "approved_at": iso(self.approved_at),
            "replay": self.replay,
            "replay_passed": self.replay_passed,
            "replayed_at": iso(self.replayed_at),
            "retired_at": iso(self.retired_at),
            "retired_by": self.retired_by,
            "retire_reason": self.retire_reason,
        }
        if now is not None:
            out["expired"] = self.expired(now)
        return out


EVENT_ACTIONS = ("proposed", "replayed", "promoted", "promotion_refused", "rolled_back")


@dataclass
class LessonEvent:
    lesson_id: str
    action: str
    actor: str
    at: datetime
    detail: Dict[str, Any] = field(default_factory=dict)
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "lesson_id": self.lesson_id,
            "action": self.action,
            "actor": self.actor,
            "at": self.at.isoformat(),
            "detail": self.detail,
        }


def as_list(value: Any) -> List[str]:
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None]
    return []
