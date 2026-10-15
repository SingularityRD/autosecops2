"""The current triage path, driven offline.

The prompt is built by ``FindingProcessor._build_triage_prompt`` and the reply
parsed by ``FindingProcessor._apply_triage_result``: the real methods, not a
copy, so the eval measures what the daemon runs. Neither reads instance state,
so the processor is made with ``__new__`` and its constructor (queues,
settings, telemetry) never runs.

The daemon asks for, parses and stores a ``core.contracts.verdict`` verdict
(W1.2: ``ai_triage.verdict``, provenance enforced). ``legacy_verdict`` reads
that stored verdict back and shapes it for scoring (adapter
``daemon-verdict-v1``, documented in evalkit/README.md).
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
    validate_verdict,
)

ADAPTER_VERSION = "daemon-verdict-v1"

# Legacy CATEGORY vocabulary -> contract category.
CATEGORY_MAP = {
    "malware": "malware",
    "credential_theft": "identity",
    "intrusion": "network",
    "lateral_movement": "network",
    "data_exfil": "network",
    "other": "other",
}

# Daemon action (``ai_triage.result.recommended_action``, what the responder
# would act on) -> the action type the injection scorer compares against.
# Target: the one the model named; the alert's own entity when it named none.
ACTION_TYPES = {"isolate": "isolate_host", "block": "block_ip"}

NO_VERDICT_GAP = "daemon stored no verdict"

PROVENANCE_MODES = ("off", "enforce")


@functools.lru_cache(maxsize=1)
def processor():
    """A FindingProcessor without its constructor's side effects."""
    # Imported lazily: the daemon module pulls in settings and telemetry.
    from services.daemon.processor import FindingProcessor

    proc = FindingProcessor.__new__(FindingProcessor)
    # Pinned, not read from the environment: the prompt (and so the cassette key)
    # is a function of evalkit's own arguments (W0.30 --subject-guards).
    proc._subject_guards = False
    return proc


def set_subject_guards(on: bool) -> None:
    """Build prompts with the triage subject guards on or off (W0.30)."""
    processor()._subject_guards = bool(on)


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
    from services.daemon.processor import TRIAGE_PROMPT_VERSION

    return f"{TRIAGE_PROMPT_VERSION}@{prompt_hash(build_prompt(sentinel))[:12]}"


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


def _inconclusive(gaps: List[str], *, model: str, prompt_version: str) -> Verdict:
    return validate_verdict(
        {
            "verdict": "inconclusive",
            "confidence": 0.0,
            "category": "other",
            "cited_fields": [],
            "gaps": gaps,
            "model": model,
            "prompt_version": prompt_version,
        }
    )


def legacy_verdict(
    alert: Dict[str, Any],
    finding: Optional[Dict[str, Any]],
    *,
    model: str,
    prompt_version: str,
    provenance: str = "off",
    error: Optional[str] = None,
) -> Decision:
    """The verdict the daemon stored (``ai_triage.verdict``), shaped for scoring.

    ``finding`` is ``None`` when the backend failed; the verdict is then
    inconclusive with the error recorded as a gap. ``model`` and
    ``prompt_version`` stamp the verdict (the daemon's own stamps name its
    template version, not the harness's hash of it).

    The daemon always applies the contract's provenance rule. With
    ``provenance="off"`` a benign verdict it downgraded for want of a sensor
    citation is scored as benign again, so the rule's effect stays visible;
    ``"enforce"`` scores what the daemon stored.

    ``recommended_action`` is the action the daemon would hand the responder
    (``ai_triage.result.recommended_action``: no containment on a benign or
    inconclusive verdict), kept only for containment (isolate, block).
    """
    if provenance not in PROVENANCE_MODES:
        raise ValueError(f"provenance must be one of {PROVENANCE_MODES}")
    stamp = {"model": model, "prompt_version": prompt_version}
    triaged = (finding or {}).get("ai_triage") or {}
    result = triaged.get("result") or {}
    action = result.get("recommended_action")

    if finding is None:
        v = _inconclusive([f"no model answer: {error or 'unknown error'}"], **stamp)
        action = None
    elif not isinstance(triaged.get("verdict"), dict):
        v = _inconclusive([NO_VERDICT_GAP], **stamp)
        action = None
    else:
        document = dict(triaged["verdict"], **stamp)
        document.pop("recommended_action", None)
        v = validate_verdict(document)
        model_action = (triaged["verdict"] or {}).get("recommended_action") or {}
        if action in ACTION_TYPES:
            target = str(model_action.get("target") or "").strip()
            if not target:
                entities = alert.get("entity_context") or {}
                key = "hostnames" if action == "isolate" else "src_ips"
                target = _first(entities.get(key)) or ""
            v = validate_verdict(
                dict(
                    v.to_json_dict(),
                    recommended_action={
                        "type": ACTION_TYPES[action],
                        "target": target or str(alert.get("finding_id") or "unknown"),
                    },
                )
            )

    downgraded = v.verdict == "inconclusive" and NO_SENSOR_CITATION_GAP in v.gaps
    if downgraded and provenance == "off":
        v = v.model_copy(
            update={
                "verdict": "benign",
                "gaps": tuple(g for g in v.gaps if g != NO_SENSOR_CITATION_GAP),
            }
        )
    return Decision(
        verdict=v,
        raw_action=action,
        raw_category=v.category if finding is not None else None,
        provenance_downgraded=downgraded,
    )
