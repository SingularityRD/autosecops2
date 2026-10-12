"""The current triage path, driven offline.

The prompt is built by ``FindingProcessor._build_triage_prompt`` and the reply
parsed by ``FindingProcessor._apply_triage_result``: the real methods, not a
copy, so the eval measures what the daemon runs. Neither reads instance state,
so the processor is made with ``__new__`` and its constructor (queues,
settings, telemetry) never runs.

The legacy reply carries no malicious/benign verdict. ``legacy_verdict`` maps
it onto ``core.contracts.verdict`` (adapter ``legacy-v1``, documented in
docs/wp/w1.1.md and evalkit/README.md).
"""

from __future__ import annotations

import copy
import functools
import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from core.contracts.verdict import (
    CATEGORIES,
    NO_SENSOR_CITATION_GAP,
    Verdict,
    enforce_provenance,
    validate_verdict,
)

ADAPTER_VERSION = "legacy-v1"

# probes.py treats dismiss/monitor as the right answer for a benign finding
# and investigate for a suspicious one; containment is malicious a fortiori.
MALICIOUS_ACTIONS = frozenset({"isolate", "block", "investigate"})
BENIGN_ACTIONS = frozenset({"dismiss", "monitor"})

# Legacy CATEGORY vocabulary -> contract category.
CATEGORY_MAP = {
    "malware": "malware",
    "credential_theft": "identity",
    "intrusion": "network",
    "lateral_movement": "network",
    "data_exfil": "network",
    "other": "other",
}

# Legacy action -> contract recommended_action.type; target is taken from the
# alert's own entity context (sensor data), never from the model's text.
ACTION_TYPES = {"isolate": "isolate_host", "block": "block_ip"}

NO_CITATIONS_GAP = "legacy triage output carries no citations"
NO_CONFIDENCE_GAP = "model gave no usable confidence"
NO_ACTION_GAP = "model gave no recognised recommended action"

PROVENANCE_MODES = ("off", "enforce")


@functools.lru_cache(maxsize=1)
def processor():
    """A FindingProcessor without its constructor's side effects."""
    # Imported lazily: the daemon module pulls in settings and telemetry.
    from services.daemon.processor import FindingProcessor

    return FindingProcessor.__new__(FindingProcessor)


def build_prompt(alert: Dict[str, Any]) -> str:
    """The exact prompt the daemon sends for this alert."""
    return processor()._build_triage_prompt(copy.deepcopy(alert))


def apply_result(alert: Dict[str, Any], response: str) -> Dict[str, Any]:
    """The finding as the daemon stores it after parsing ``response``."""
    return processor()._apply_triage_result(copy.deepcopy(alert), response)


def prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def prompt_version() -> str:
    """Identifies the prompt template: changes whenever its fixed text does."""
    sentinel = {
        "finding_id": "evalkit-sentinel",
        "data_source": "evalkit",
        "severity": "low",
        "title": "",
        "description": "",
        "entity_context": {},
        "mitre_predictions": {},
    }
    return f"legacy-triage@{prompt_hash(build_prompt(sentinel))[:12]}"


@dataclass(frozen=True)
class Decision:
    """What the harness scores for one case."""

    verdict: Verdict
    raw_action: Optional[str]
    raw_category: Optional[str]
    provenance_downgraded: bool


def _first(values: Any) -> Optional[str]:
    if isinstance(values, (list, tuple)) and values:
        return str(values[0])
    return None


def map_category(raw: Optional[str]) -> str:
    value = (raw or "").strip().lower()
    if value in CATEGORIES:
        return value
    return CATEGORY_MAP.get(value, "other")


def legacy_verdict(
    alert: Dict[str, Any],
    finding: Optional[Dict[str, Any]],
    *,
    model: str,
    prompt_version: str,
    provenance: str = "off",
    error: Optional[str] = None,
) -> Decision:
    """Map a parsed legacy triage onto a contract verdict.

    ``finding`` is ``None`` when the backend failed; the verdict is then
    inconclusive with the error recorded as a gap.
    """
    if provenance not in PROVENANCE_MODES:
        raise ValueError(f"provenance must be one of {PROVENANCE_MODES}")
    gaps: List[str] = [NO_CITATIONS_GAP]
    result = ((finding or {}).get("ai_triage") or {}).get("result") or {}
    action = result.get("recommended_action")
    raw_category = result.get("category")

    if finding is None:
        gaps.append(f"no model answer: {error or 'unknown error'}")
        verdict = "inconclusive"
    elif action in MALICIOUS_ACTIONS:
        verdict = "malicious"
    elif action in BENIGN_ACTIONS:
        verdict = "benign"
    else:
        gaps.append(NO_ACTION_GAP)
        verdict = "inconclusive"

    confidence = result.get("confidence")
    if not isinstance(confidence, float):
        confidence = 0.0
        if finding is not None:
            gaps.append(NO_CONFIDENCE_GAP)

    document: Dict[str, Any] = {
        "verdict": verdict,
        "confidence": confidence,
        "category": map_category(raw_category),
        "cited_fields": [],
        "gaps": gaps,
        "model": model,
        "prompt_version": prompt_version,
    }
    entities = alert.get("entity_context") or {}
    target = None
    if action == "isolate":
        target = _first(entities.get("hostnames"))
    elif action == "block":
        target = _first(entities.get("src_ips"))
    if action in ACTION_TYPES:
        document["recommended_action"] = {
            "type": ACTION_TYPES[action],
            "target": target or str(alert.get("finding_id") or "unknown"),
        }

    v = validate_verdict(document)
    # The contract's rule, computed either way so the report can show its effect.
    enforced = enforce_provenance(v)
    downgraded = (
        enforced.verdict != v.verdict and NO_SENSOR_CITATION_GAP in enforced.gaps
    )
    if provenance == "enforce":
        v = enforced
    return Decision(
        verdict=v,
        raw_action=action,
        raw_category=raw_category,
        provenance_downgraded=downgraded,
    )
