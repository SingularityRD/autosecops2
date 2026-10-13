"""Report drafts cite only what the case's evidence pack holds (W3.8)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from core.compliance.clocks import ClockConfig, evaluate
from core.compliance.regulatory_drafts import (
    KINDS,
    DraftCitationError,
    build_evidence_pack,
    generate_draft,
    validate_citations,
)
from core.compliance.regulatory_service import (
    MemoryClockStore,
    RegulatoryService,
    fold_instants,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)

CASE = {
    "case_id": "CASE-7",
    "title": "Ransomware on payment gateway",
    "priority": "critical",
    "status": "in_progress",
    "description": "Encrypted hosts in DC1",
    "created_at": datetime(2026, 3, 2, 8, 30),
}
FINDINGS = [
    {
        "finding_id": "f-1",
        "title": "Mass file rename on pay-01",
        "severity": "critical",
        "data_source": "edr",
        "timestamp": datetime(2026, 3, 2, 8, 0),
    },
    {
        "finding_id": "f-2",
        "title": "C2 beacon from pay-02",
        "severity": "high",
        "data_source": "ndr",
    },
]
EVIDENCE = [
    {
        "evidence_id": 11,
        "name": "pay-01 memory image",
        "evidence_type": "memory",
        "collected_by": "ayse",
        "collected_at": datetime(2026, 3, 2, 9, 0),
        "file_hash_sha256": "ab" * 32,
    },
]
AUDITS = [
    {
        "audit_id": 501,
        "action": "update",
        "field_name": "status",
        "change_summary": "Status open -> in_progress",
        "changed_by": "ayse",
        "timestamp": datetime(2026, 3, 2, 8, 45),
    },
]


@pytest.fixture()
def recorded():
    store = MemoryClockStore(cases={"CASE-7"})
    service = RegulatoryService(store, now=lambda: NOW)
    service.record_instant(
        "CASE-7",
        "dora",
        "aware_at",
        datetime(2026, 3, 2, 8, 0, tzinfo=timezone.utc),
        "ayse",
    )
    service.record_instant(
        "CASE-7",
        "dora",
        "classification_at",
        datetime(2026, 3, 2, 9, 0, tzinfo=timezone.utc),
        "ayse",
    )
    service.record_instant(
        "CASE-7",
        "nis2",
        "aware_at",
        datetime(2026, 3, 2, 8, 0, tzinfo=timezone.utc),
        "ayse",
    )
    return service, store.events("CASE-7")


def _pack(events, findings=FINDINGS, evidence=EVIDENCE, audits=AUDITS):
    return build_evidence_pack(CASE, findings, evidence, audits, events)


def _draft(pack, events, regime, kind, writer=None):
    clocks = evaluate(fold_instants(events), ClockConfig(), NOW)
    return generate_draft(
        pack, regime, kind, clocks, events, "ayse", NOW, writer=writer
    )


def test_pack_holds_case_findings_evidence_audit_and_clock_rows(recorded):
    _, events = recorded
    pack = _pack(events)
    assert pack.ids == {
        "case:CASE-7",
        "finding:f-1",
        "finding:f-2",
        "evidence:11",
        "audit:501",
        "clock:1",
        "clock:2",
        "clock:3",
    }
    assert re.fullmatch(r"[0-9a-f]{64}", pack.digest)
    assert pack.digest == _pack(events).digest  # deterministic


@pytest.mark.parametrize(
    "regime,kind", [(r, k) for r, kinds in KINDS.items() for k in kinds]
)
def test_every_template_draft_cites_only_the_pack(recorded, regime, kind):
    _, events = recorded
    pack = _pack(events)
    draft = _draft(pack, events, regime, kind)
    assert draft["generator"] == "template"
    assert set(draft["cited_ids"]) <= pack.ids
    for section in draft["sections"]:
        for line in section["lines"]:
            assert line["cites"], line
            assert set(line["cites"]) <= pack.ids
    # every finding and evidence item is cited, and nothing else invented
    assert {"finding:f-1", "finding:f-2", "evidence:11"} <= set(draft["cited_ids"])
    cited_in_markdown = set(re.findall(r"\[([^\]]+)\]$", draft["markdown"], re.M))
    for group in cited_in_markdown:
        assert set(group.split(", ")) <= pack.ids
    assert draft["pack_digest"] == pack.digest
    assert draft["to_complete"]


def test_the_draft_is_deterministic_apart_from_its_id(recorded):
    _, events = recorded
    pack = _pack(events)
    a, b = _draft(pack, events, "dora", "initial"), _draft(
        pack, events, "dora", "initial"
    )
    assert a["draft_id"] != b["draft_id"]
    a.pop("draft_id"), b.pop("draft_id")
    assert a == b


def test_a_draft_states_the_recorded_instants_and_deadlines(recorded):
    _, events = recorded
    draft = _draft(_pack(events), events, "dora", "initial")
    text = draft["markdown"]
    assert "classification_at: 2026-03-02T09:00:00+00:00 (recorded by ayse" in text
    assert (
        "DORA initial notification: running, due 2026-03-02T13:00:00+00:00 (from classification_at)"
        in text
    )
    assert "NIS2" not in "".join(
        line["text"]
        for s in draft["sections"]
        if s["heading"] == "Key instants"
        for line in s["lines"]
    )


def test_an_empty_case_still_cites_only_the_case(recorded):
    pack = build_evidence_pack(CASE)
    draft = _draft(pack, [], "nis2", "early_warning")
    assert draft["cited_ids"] == ["case:CASE-7"]
    assert "No findings are linked to the case." in draft["markdown"]


def test_a_finding_not_in_the_pack_cannot_be_cited(recorded):
    _, events = recorded
    pack = _pack(events, findings=FINDINGS[:1])
    sections = [
        {"heading": "x", "lines": [{"text": "beacon", "cites": ["finding:f-2"]}]}
    ]
    with pytest.raises(DraftCitationError, match="finding:f-2"):
        validate_citations(sections, pack)


@pytest.mark.parametrize(
    "sections",
    [
        [],
        [{"heading": "x", "lines": [{"text": "uncited claim", "cites": []}]}],
        [{"heading": "x", "lines": [{"text": "uncited claim"}]}],
        [{"heading": "x", "lines": "text"}],
        [{"lines": [{"text": "t", "cites": ["case:CASE-7"]}]}],
    ],
)
def test_malformed_or_uncited_sections_are_refused(recorded, sections):
    _, events = recorded
    with pytest.raises(DraftCitationError):
        validate_citations(sections, _pack(events))


@pytest.mark.parametrize(
    "text,heading",
    [
        ("Ransomware confirmed [evidence:99].", "Summary"),
        ("Seen on pay-01 [finding:f-1, audit:999].", "Summary"),
        ("Ransomware on pay-01.", "Summary [clock:42]"),
    ],
)
def test_a_reference_in_the_text_must_be_in_the_pack(recorded, text, heading):
    _, events = recorded
    sections = [
        {"heading": heading, "lines": [{"text": text, "cites": ["finding:f-1"]}]}
    ]
    with pytest.raises(DraftCitationError, match="text references"):
        validate_citations(sections, _pack(events))


def test_a_writer_whose_text_invents_a_reference_falls_back(recorded):
    _, events = recorded
    pack = _pack(events)

    def writer(p, regime, kind):
        return [
            {
                "heading": "Summary",
                "lines": [
                    {"text": "Exfiltration proven [evidence:404].", "cites": ["finding:f-1"]}
                ],
            }
        ]

    draft = _draft(pack, events, "dora", "initial", writer=writer)
    assert draft["generator"] == "template"
    assert "evidence:404" in draft["fallback_reason"]


def test_a_reference_in_the_text_that_is_in_the_pack_passes(recorded):
    _, events = recorded
    sections = [
        {
            "heading": "Summary",
            "lines": [{"text": "Beacon seen [finding:f-1].", "cites": ["finding:f-1"]}],
        }
    ]
    assert validate_citations(sections, _pack(events)) == ["finding:f-1"]


def test_a_writer_that_cites_the_pack_is_used(recorded):
    _, events = recorded
    pack = _pack(events)

    def writer(p, regime, kind):
        return [
            {
                "heading": "Summary",
                "lines": [
                    {
                        "text": "Ransomware on pay-01.",
                        "cites": ["finding:f-1", "case:CASE-7"],
                    }
                ],
            }
        ]

    draft = _draft(pack, events, "dora", "initial", writer=writer)
    assert draft["generator"] == "llm" and draft["fallback_reason"] is None
    assert draft["cited_ids"] == ["finding:f-1", "case:CASE-7"]


@pytest.mark.parametrize(
    "output",
    [
        [
            {
                "heading": "Summary",
                "lines": [
                    {
                        "text": "Customer data of 10,000 clients leaked.",
                        "cites": ["finding:f-99"],
                    }
                ],
            }
        ],
        [
            {
                "heading": "Summary",
                "lines": [{"text": "Invented with no citation.", "cites": []}],
            }
        ],
        "free text",
        RuntimeError("model unavailable"),
    ],
)
def test_a_writer_that_invents_falls_back_to_the_template(recorded, output):
    _, events = recorded
    pack = _pack(events)

    def writer(p, regime, kind):
        if isinstance(output, Exception):
            raise output
        return output

    draft = _draft(pack, events, "nis2", "notification", writer=writer)
    assert draft["generator"] == "template"
    assert draft["fallback_reason"]
    assert "10,000" not in draft["markdown"]
    assert set(draft["cited_ids"]) <= pack.ids


def test_unknown_kind_is_refused(recorded):
    _, events = recorded
    with pytest.raises(ValueError):
        _draft(_pack(events), events, "dora", "early_warning")
