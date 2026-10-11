"""The triage verdict contract (W0.5).

``verdict.schema.json`` beside this file is the source of truth. This module
is its Python form and ``services/agent/contracts/verdict.ts`` is its
TypeScript form; both test suites load the JSON Schema and run the shared
cases in ``verdict.cases.json`` through it and through their own validator,
so the three cannot drift apart silently.

Provenance
----------
Each cited field carries ``authored``: who wrote the value the verdict
relies on.

``sensor``
    Our own instrumentation observed it (EDR process tree, mail gateway
    connection IP, cloud audit log actor).
``adversary``
    The party under suspicion controls it (email subject and body, a
    ``From:`` display name, a file name, a user agent).
``third_party``
    Someone else asserted it (threat-intel feed, reputation service).

``authored`` is filled by code from the subject's provenance map, never taken
from the model. A model reading adversary-controlled text can be told to
claim that text is sensor data; if the model's word were taken, a phishing
email could cite itself as proof it is benign. ``verdict_from_model_output``
discards whatever ``authored`` the model wrote and resolves each field
against the map. A field the map does not know is attributed to
``adversary``, the least trusted source: a citation the code cannot place
cannot be what makes a verdict stand.

The map matches exactly. A key ``email.sender_ip`` covers that field and
nothing under it: ``email.sender_ip.country`` or ``email.sender_ip.`` are
inventions the code cannot vouch for. A key ending in ``.*`` (``edr.process.*``)
declares that every child of its prefix has that author; a child must be one
or more non-empty dotted segments of ``[A-Za-z0-9_-]``. The longest declared
prefix wins, and an exact key beats any prefix. Empty segments, trailing dots,
``*`` and other characters in a cited field never match a prefix. ``model`` and ``prompt_version`` are
likewise stamped by the caller, not read from the model's output.

``enforce_provenance`` then applies the one rule the contract fixes: a
``benign`` verdict that cites no sensor-authored field is downgraded to
``inconclusive``. Clearing a subject on nothing but what the adversary (or a
third party) said is the failure this contract exists to prevent.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_PATH = Path(__file__).with_name("verdict.schema.json")
CASES_PATH = Path(__file__).with_name("verdict.cases.json")

VerdictValue = Literal["malicious", "benign", "inconclusive"]
Category = Literal["phishing", "malware", "identity", "network", "cloud", "other"]
Authored = Literal["sensor", "adversary", "third_party"]

VERDICTS: tuple[str, ...] = ("malicious", "benign", "inconclusive")
CATEGORIES: tuple[str, ...] = (
    "phishing",
    "malware",
    "identity",
    "network",
    "cloud",
    "other",
)
AUTHORED: tuple[str, ...] = ("sensor", "adversary", "third_party")

# What a field the provenance map does not know is attributed to.
UNKNOWN_FIELD_AUTHOR: Authored = "adversary"

# The gap enforce_provenance records when it downgrades a benign verdict, so a
# reader of the stored verdict can see why it says inconclusive.
NO_SENSOR_CITATION_GAP = (
    "benign verdict cited no sensor-authored field; downgraded to inconclusive"
)

ProvenanceMap = Mapping[str, Authored]

_STRICT = ConfigDict(strict=True, extra="forbid", frozen=True)


class CitedField(BaseModel):
    model_config = _STRICT

    field: str = Field(min_length=1)
    authored: Authored


class RecommendedAction(BaseModel):
    model_config = _STRICT

    type: str = Field(min_length=1)
    target: str = Field(min_length=1)


class Verdict(BaseModel):
    """One verdict on one subject. Strict: no coercion, no unknown keys."""

    model_config = _STRICT

    verdict: VerdictValue
    confidence: float = Field(ge=0, le=1)
    category: Category
    cited_fields: tuple[CitedField, ...]
    gaps: tuple[Annotated[str, Field(min_length=1)], ...]
    recommended_action: Optional[RecommendedAction] = None
    model: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)

    def to_json_dict(self) -> dict[str, Any]:
        """The document as the JSON Schema describes it (absent action omitted)."""
        return self.model_dump(mode="json", exclude_none=True)


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_verdict(document: Any) -> Verdict:
    """Parse a JSON-shaped document; raises ``pydantic.ValidationError``.

    Strict mode matches the JSON Schema: ``"0.9"`` is not a confidence and
    ``true`` is not a number. Lists are accepted for the tuple fields because
    JSON has no tuple.
    """
    if isinstance(document, Mapping):
        document = dict(document)
        for key in ("cited_fields", "gaps"):
            if isinstance(document.get(key), list):
                document[key] = tuple(document[key])
    return Verdict.model_validate(document)


# A provenance-map key ending in this covers every child of its prefix.
CHILDREN_SUFFIX = ".*"
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")


def _checked(key: str, authored: Any) -> Authored:
    if authored not in AUTHORED:
        raise ValueError(f"provenance map gives {key!r} unknown author {authored!r}")
    return authored


def resolve_authored(field: str, provenance: ProvenanceMap) -> Authored:
    """Who authored ``field``: an exact key, else the longest ``prefix.*`` key.

    ``email.headers.*`` mapped to ``adversary`` covers ``email.headers.subject``;
    a plain ``email.sender_ip`` key covers only that exact field. A field
    nothing in the map covers is ``UNKNOWN_FIELD_AUTHOR``. A malformed map
    (an author outside ``AUTHORED``) raises ``ValueError``: that is the
    caller's bug, not the model's.
    """
    if not field.endswith(CHILDREN_SUFFIX) and field in provenance:
        return _checked(field, provenance[field])
    segments = field.split(".")
    if not all(_SEGMENT.fullmatch(s) for s in segments):
        return UNKNOWN_FIELD_AUTHOR
    for end in range(len(segments) - 1, 0, -1):
        key = ".".join(segments[:end]) + CHILDREN_SUFFIX
        if key in provenance:
            return _checked(key, provenance[key])
    return UNKNOWN_FIELD_AUTHOR


def attach_provenance(
    cited: Iterable[Any], provenance: ProvenanceMap
) -> tuple[CitedField, ...]:
    """Citations with ``authored`` set by code.

    Each item is a field name or a mapping with a ``field`` key; any
    ``authored`` the item carries (i.e. the model's claim) is ignored.
    """
    out = []
    for item in cited:
        field = item.get("field") if isinstance(item, Mapping) else item
        if not isinstance(field, str) or not field:
            raise ValueError(f"cited field must be a non-empty string, got {field!r}")
        out.append(
            CitedField(field=field, authored=resolve_authored(field, provenance))
        )
    return tuple(out)


def enforce_provenance(v: Verdict) -> Verdict:
    """Benign without any sensor-authored citation becomes inconclusive."""
    if v.verdict != "benign":
        return v
    if any(c.authored == "sensor" for c in v.cited_fields):
        return v
    gaps = (
        v.gaps
        if NO_SENSOR_CITATION_GAP in v.gaps
        else (*v.gaps, NO_SENSOR_CITATION_GAP)
    )
    return v.model_copy(update={"verdict": "inconclusive", "gaps": gaps})


def _cite(item: Any, provenance: ProvenanceMap) -> Any:
    """One model citation with ``authored`` set by code.

    Anything that is not a non-empty field name (or a mapping holding one) is
    passed on with the least trusted author for ``validate_verdict`` to
    refuse, so a malformed citation fails validation rather than raising
    something else.
    """
    field = item.get("field") if isinstance(item, Mapping) else item
    if isinstance(field, str) and field:
        return {"field": field, "authored": resolve_authored(field, provenance)}
    if isinstance(item, (Mapping, str)):
        return {"field": field, "authored": UNKNOWN_FIELD_AUTHOR}
    return item


def verdict_from_model_output(
    raw: Any,
    provenance: ProvenanceMap,
    *,
    model: str,
    prompt_version: str,
) -> Verdict:
    """Build the stored verdict from a model's JSON answer.

    ``authored``, ``model`` and ``prompt_version`` come from code; whatever the
    model wrote for them is overwritten. The result has had
    ``enforce_provenance`` applied.

    ``gaps`` and ``cited_fields`` that are absent or null mean none. Anything
    else wrong with the answer (not an object, ``cited_fields`` not a list, a
    citation without a field name, ...) raises ``pydantic.ValidationError``,
    the one error a caller handles; ``verdictFromModelOutput`` in
    services/agent/contracts/verdict.ts returns ``{ok: false}`` for exactly the
    same inputs (verdict.cases.json ``assembly``). A malformed provenance map
    raises ``ValueError`` in both, since it is the caller's bug.
    """
    if not isinstance(raw, Mapping):
        return validate_verdict(raw)  # raises ValidationError
    document = dict(raw)
    cited = document.get("cited_fields")
    if cited is None:
        cited = []
    if isinstance(cited, (list, tuple)):
        cited = [_cite(c, provenance) for c in cited]
    document["cited_fields"] = cited
    if document.get("gaps") is None:
        document["gaps"] = []
    document["model"] = model
    document["prompt_version"] = prompt_version
    return enforce_provenance(validate_verdict(document))


__all__ = [
    "AUTHORED",
    "CATEGORIES",
    "CASES_PATH",
    "CHILDREN_SUFFIX",
    "NO_SENSOR_CITATION_GAP",
    "SCHEMA_PATH",
    "UNKNOWN_FIELD_AUTHOR",
    "VERDICTS",
    "Authored",
    "Category",
    "CitedField",
    "ProvenanceMap",
    "RecommendedAction",
    "Verdict",
    "VerdictValue",
    "attach_provenance",
    "enforce_provenance",
    "load_schema",
    "resolve_authored",
    "validate_verdict",
    "verdict_from_model_output",
]
