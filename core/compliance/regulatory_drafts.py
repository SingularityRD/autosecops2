"""Regulatory report drafts (DORA, NIS2) built from a case's evidence pack.

The pack is built by ``core.compliance.evidence`` (W3.7), the same citable
index the signed evidence pack carries as ``citable_index.json``. It is what
the case already holds: the case row, its linked findings,
its ``case_evidence`` rows, its ``case_audit_logs`` rows and its regulatory
clock events. Each item has a stable id (``case:<id>``, ``finding:<id>``,
``evidence:<id>``, ``audit:<id>``, ``clock:<seq>``). Every line of a draft
cites the item(s) it states, and :func:`validate_citations` refuses a draft
that cites anything the pack does not hold. What the pack cannot answer
(affected clients, economic impact, ...) is listed under "To complete", never
filled in.

The deterministic template is always available. A ``writer`` (for example an
LLM) may be passed to word the sections; its output is held to the same
citation rule and the template is used instead whenever it fails it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from core.compliance.clocks import ClockStatus

# The pack builder is W3.7's (core/compliance/evidence.py); these names stay
# importable from here for the drafts' callers.
from core.compliance.evidence import (  # noqa: F401
    LINE_CHARS,
    EvidenceItem,
    EvidencePack,
    _at,
    _clip,
    build_evidence_pack,
)
from core.compliance.regulatory_service import ClockEvent

KINDS: Dict[str, tuple] = {
    "dora": ("initial", "intermediate", "final"),
    "nis2": ("early_warning", "notification", "intermediate", "final"),
}

TITLES = {
    ("dora", "initial"): "DORA initial notification of a major ICT-related incident",
    ("dora", "intermediate"): "DORA intermediate report",
    ("dora", "final"): "DORA final report",
    ("nis2", "early_warning"): "NIS2 early warning",
    ("nis2", "notification"): "NIS2 incident notification",
    ("nis2", "intermediate"): "NIS2 intermediate report",
    ("nis2", "final"): "NIS2 final report",
}

# What the regulator asks for that a case does not record. Listed, never invented.
TO_COMPLETE = {
    ("dora", "initial"): [
        "Classification criteria met (clients, duration, geographical spread, data losses, critical services, economic impact)",
        "Member states and competent authorities affected",
        "Whether the incident is recurring",
    ],
    ("dora", "intermediate"): [
        "Number of clients and counterparts affected",
        "Duration and service downtime",
        "Root cause, if known",
        "Measures taken or planned to recover",
    ],
    ("dora", "final"): [
        "Root cause analysis",
        "Direct and indirect costs and losses",
        "Lessons learned and remediation",
    ],
    ("nis2", "early_warning"): [
        "Whether the incident is suspected to be caused by unlawful or malicious acts",
        "Whether it could have a cross-border impact",
    ],
    ("nis2", "notification"): [
        "Initial assessment of severity and impact",
        "Indicators of compromise, where available",
    ],
    ("nis2", "intermediate"): ["Relevant status updates requested by the CSIRT"],
    ("nis2", "final"): [
        "Detailed description including severity and impact",
        "Type of threat or root cause that likely triggered the incident",
        "Applied and ongoing mitigation measures",
        "Cross-border impact, where applicable",
    ],
}

MAX_FINDINGS = 25
MAX_EVIDENCE = 25
MAX_AUDIT = 20


class DraftCitationError(ValueError):
    """A draft cites an id the evidence pack does not hold, or a line cites nothing."""


def _line(text_value: str, cites: Sequence[str]) -> Dict[str, Any]:
    return {"text": text_value, "cites": list(cites)}


def _instant_lines(
    pack: EvidencePack, regime: str, events: Sequence[ClockEvent]
) -> List[Dict[str, Any]]:
    current: Dict[str, ClockEvent] = {}
    for ev in sorted(events, key=lambda e: e.seq):
        if ev.regime == regime:
            current[ev.instant] = ev
    lines = []
    for instant, ev in current.items():
        if ev.value is None or f"clock:{ev.seq}" not in pack.ids:
            continue
        lines.append(
            _line(
                f"{instant}: {_at(ev.value)} (recorded by {ev.actor} at {_at(ev.recorded_at)})",
                [f"clock:{ev.seq}"],
            )
        )
    return lines


def _clock_lines(
    clocks: Sequence[ClockStatus], regime: str, case_cite: str
) -> List[Dict[str, Any]]:
    lines = []
    for c in clocks:
        if c.regime != regime:
            continue
        if c.due_at is None:
            word = f"not started (waiting for {c.waiting_for})"
        else:
            word = (
                f"{c.state.replace('_', ' ')}, due {_at(c.due_at)} (from {c.bound_to})"
            )
        lines.append(_line(f"{c.label}: {word}", [case_cite]))
    return lines


def template_sections(
    pack: EvidencePack,
    regime: str,
    kind: str,
    clocks: Sequence[ClockStatus],
    events: Sequence[ClockEvent],
) -> List[Dict[str, Any]]:
    """The deterministic draft. Every line cites pack items only."""
    case_item = pack.of_kind("case")[0]
    case_cite = case_item.id
    sections: List[Dict[str, Any]] = [
        {
            "heading": "Incident identification",
            "lines": [
                _line(f"Internal reference: {pack.case_id}", [case_cite]),
                _line(f"Title: {case_item.title}", [case_cite]),
                _line(f"Case state: {case_item.detail}", [case_cite]),
            ],
        },
        {
            "heading": "Key instants",
            "lines": _instant_lines(pack, regime, events)
            or [_line("No instant recorded yet for this regime.", [case_cite])],
        },
    ]
    findings = pack.of_kind("finding")
    finding_lines = [
        _line(f"{f.title} ({f.detail}; observed {f.at or 'time unknown'})", [f.id])
        for f in findings[:MAX_FINDINGS]
    ]
    if len(findings) > MAX_FINDINGS:
        finding_lines.append(
            _line(
                f"{len(findings) - MAX_FINDINGS} more finding(s) on the case.",
                [f.id for f in findings[MAX_FINDINGS:]],
            )
        )
    sections.append(
        {
            "heading": "Detected activity",
            "lines": finding_lines
            or [_line("No findings are linked to the case.", [case_cite])],
        }
    )
    evidence = pack.of_kind("evidence")
    evidence_lines = [
        _line(f"{e.title}: {e.detail} at {e.at or 'time unknown'}", [e.id])
        for e in evidence[:MAX_EVIDENCE]
    ]
    if len(evidence) > MAX_EVIDENCE:
        evidence_lines.append(
            _line(
                f"{len(evidence) - MAX_EVIDENCE} more evidence item(s) on the case.",
                [e.id for e in evidence[MAX_EVIDENCE:]],
            )
        )
    sections.append(
        {
            "heading": "Evidence collected",
            "lines": evidence_lines
            or [_line("No evidence is attached to the case.", [case_cite])],
        }
    )
    if kind in ("intermediate", "final"):
        audits = pack.of_kind("audit")[-MAX_AUDIT:]
        sections.append(
            {
                "heading": "Actions recorded on the case",
                "lines": [
                    _line(f"{a.at or ''} {a.title} ({a.detail})".strip(), [a.id])
                    for a in audits
                ]
                or [_line("No case changes are recorded.", [case_cite])],
            }
        )
    sections.append(
        {
            "heading": "Reporting deadlines",
            "lines": _clock_lines(clocks, regime, case_cite),
        }
    )
    return sections


def validate_citations(
    sections: Sequence[Mapping[str, Any]], pack: EvidencePack
) -> List[str]:
    """The ids cited, in order. Raises on an unknown id or a line citing nothing."""
    known = pack.ids
    cited: List[str] = []
    if not isinstance(sections, (list, tuple)) or not sections:
        raise DraftCitationError("a draft needs at least one section")
    for section in sections:
        if not isinstance(section, Mapping) or not isinstance(
            section.get("lines"), list
        ):
            raise DraftCitationError("a section is a heading and a list of lines")
        if not isinstance(section.get("heading"), str):
            raise DraftCitationError("a section needs a heading")
        for line in section["lines"]:
            if not isinstance(line, Mapping) or not isinstance(line.get("text"), str):
                raise DraftCitationError("a line is text with cites")
            cites = line.get("cites")
            if not isinstance(cites, list) or not cites:
                raise DraftCitationError(f"line cites nothing: {line.get('text')!r}")
            for cite in cites:
                if cite not in known:
                    raise DraftCitationError(
                        f"cites {cite!r}, which is not in the evidence pack"
                    )
                if cite not in cited:
                    cited.append(cite)
    return cited


def render_markdown(draft: Mapping[str, Any]) -> str:
    out = [
        f"# {draft['title']}",
        "",
        f"Case {draft['case_id']} · draft generated {draft['created_at']} by {draft['created_by']} ({draft['generator']}).",
        "",
    ]
    for section in draft["sections"]:
        out.append(f"## {section['heading']}")
        out.append("")
        for line in section["lines"]:
            out.append(f"- {line['text']} [{', '.join(line['cites'])}]")
        out.append("")
    out.append("## To complete before submission")
    out.append("")
    for item in draft["to_complete"]:
        out.append(f"- [ ] {item}")
    out.append("")
    out.append(f"Evidence pack digest: `{draft['pack_digest']}`")
    return "\n".join(out) + "\n"


Writer = Callable[[EvidencePack, str, str], List[Dict[str, Any]]]


def generate_draft(
    pack: EvidencePack,
    regime: str,
    kind: str,
    clocks: Sequence[ClockStatus],
    events: Sequence[ClockEvent],
    actor: str,
    now: datetime,
    writer: Optional[Writer] = None,
) -> Dict[str, Any]:
    """A draft dict. ``writer`` output is used only if every line cites the pack."""
    if regime not in KINDS or kind not in KINDS[regime]:
        raise ValueError(f"{regime} has no {kind!r} report")
    generator = "template"
    fallback_reason: Optional[str] = None
    sections: Optional[List[Dict[str, Any]]] = None
    if writer is not None:
        try:
            candidate = writer(pack, regime, kind)
            validate_citations(candidate, pack)
            sections = [
                {
                    "heading": str(s["heading"]),
                    "lines": [
                        {"text": str(line["text"]), "cites": list(line["cites"])}
                        for line in s["lines"]
                    ],
                }
                for s in candidate
            ]
            generator = "llm"
        except Exception as exc:  # noqa: BLE001 -- any writer failure falls back
            fallback_reason = _clip(f"{type(exc).__name__}: {exc}", 200)
    if sections is None:
        sections = template_sections(pack, regime, kind, clocks, events)
    cited = validate_citations(sections, pack)
    draft: Dict[str, Any] = {
        "draft_id": str(uuid.uuid4()),
        "case_id": pack.case_id,
        "regime": regime,
        "kind": kind,
        "title": TITLES[(regime, kind)],
        "generator": generator,
        "fallback_reason": fallback_reason,
        "sections": sections,
        "to_complete": list(TO_COMPLETE[(regime, kind)]),
        "cited_ids": cited,
        "pack_digest": pack.digest,
        "pack_size": len(pack.items),
        "created_by": actor,
        "created_at": _at(now),
    }
    draft["markdown"] = render_markdown(draft)
    return draft
