"""The harness drives the daemon's real prompt builder and parser."""

import json

import pytest

from core.contracts.verdict import NO_SENSOR_CITATION_GAP
from evalkit import triage
from evalkit.corpus import load_suite
from services.daemon.processor import FindingProcessor

ALERT = {
    "finding_id": "f-1",
    "data_source": "crowdstrike",
    "severity": "medium",
    "title": "New file in web root",
    "description": "Something happened on WEB-1.",
    "entity_context": {
        "hostnames": ["WEB-1"],
        "src_ips": ["192.0.2.5"],
        "usernames": ["u1"],
    },
    "mitre_predictions": {"T1505.003": 0.7},
}


def answer(action="isolate", confidence="0.8", category="malware"):
    return (
        "SEVERITY: high\n"
        f"CONFIDENCE: {confidence}\n"
        f"CATEGORY: {category}\n"
        f"RECOMMENDED_ACTION: {action}\n"
        "REASONING: because\n"
    )


def decide(action="isolate", provenance="off", **kw):
    finding = triage.apply_result(ALERT, answer(action=action, **kw))
    return triage.legacy_verdict(
        ALERT, finding, model="m", prompt_version="p", provenance=provenance
    )


def test_prompt_is_the_daemons_own():
    p = FindingProcessor.__new__(FindingProcessor)
    assert triage.build_prompt(ALERT) == p._build_triage_prompt(dict(ALERT))


def test_real_methods_are_called(monkeypatch):
    calls = []

    def fake_build(self, finding):
        calls.append("build")
        return "PROMPT"

    def fake_apply(self, finding, response):
        calls.append(("apply", response))
        return finding

    monkeypatch.setattr(FindingProcessor, "_build_triage_prompt", fake_build)
    monkeypatch.setattr(FindingProcessor, "_apply_triage_result", fake_apply)
    assert triage.build_prompt(ALERT) == "PROMPT"
    triage.apply_result(ALERT, "X")
    assert calls == ["build", ("apply", "X")]


def test_inputs_are_not_mutated():
    alert = json.loads(json.dumps(ALERT))
    triage.build_prompt(alert)
    triage.apply_result(alert, answer())
    assert alert == ALERT


def test_labels_never_reach_the_prompt():
    for case in load_suite("test", limit=60) + load_suite("injection", limit=60):
        prompt = triage.build_prompt(case.alert)
        assert case.labels["rationale"] not in prompt
        assert case.meta.get("template_id", "@@") not in prompt
        assert "expected_behavior" not in prompt


@pytest.mark.parametrize(
    "action,verdict",
    [
        ("isolate", "malicious"),
        ("block", "malicious"),
        ("investigate", "malicious"),
        ("monitor", "benign"),
        ("dismiss", "benign"),
        ("shrug", "inconclusive"),
    ],
)
def test_action_to_verdict(action, verdict):
    assert decide(action=action).verdict.verdict == verdict


def test_unparseable_answer_is_inconclusive():
    finding = triage.apply_result(ALERT, "I cannot help with that.")
    d = triage.legacy_verdict(ALERT, finding, model="m", prompt_version="p")
    assert d.verdict.verdict == "inconclusive"
    assert triage.NO_ACTION_GAP in d.verdict.gaps
    assert triage.NO_CONFIDENCE_GAP in d.verdict.gaps
    assert d.verdict.confidence == 0.0


def test_backend_error_is_inconclusive_with_reason():
    d = triage.legacy_verdict(ALERT, None, model="m", prompt_version="p", error="boom")
    assert d.verdict.verdict == "inconclusive"
    assert any("boom" in g for g in d.verdict.gaps)


def test_repeated_key_is_dropped_by_the_daemon_parser():
    # _apply_triage_result refuses a repeated key; the harness inherits that.
    reply = answer(action="dismiss") + "RECOMMENDED_ACTION: isolate\n"
    finding = triage.apply_result(ALERT, reply)
    d = triage.legacy_verdict(ALERT, finding, model="m", prompt_version="p")
    assert d.verdict.verdict == "inconclusive"


@pytest.mark.parametrize(
    "raw,mapped",
    [
        ("malware", "malware"),
        ("credential_theft", "identity"),
        ("lateral_movement", "network"),
        ("intrusion", "network"),
        ("data_exfil", "network"),
        ("phishing", "phishing"),
        ("cloud", "cloud"),
        ("ransomware", "other"),
        (None, "other"),
    ],
)
def test_category_mapping(raw, mapped):
    assert triage.map_category(raw) == mapped


def test_recommended_action_target_comes_from_the_alert():
    v = decide(action="isolate").verdict
    assert (v.recommended_action.type, v.recommended_action.target) == (
        "isolate_host",
        "WEB-1",
    )
    v = decide(action="block").verdict
    assert (v.recommended_action.type, v.recommended_action.target) == (
        "block_ip",
        "192.0.2.5",
    )
    assert decide(action="investigate").verdict.recommended_action is None


def test_provenance_enforce_downgrades_uncited_benign():
    off = decide(action="dismiss", provenance="off")
    on = decide(action="dismiss", provenance="enforce")
    assert off.verdict.verdict == "benign" and off.provenance_downgraded
    assert on.verdict.verdict == "inconclusive"
    assert NO_SENSOR_CITATION_GAP in on.verdict.gaps
    assert not decide(action="isolate").provenance_downgraded


def test_out_of_range_confidence_is_not_kept():
    d = decide(confidence="1.7")
    assert d.verdict.confidence == 0.0
    assert triage.NO_CONFIDENCE_GAP in d.verdict.gaps


def test_prompt_version_is_stable_and_tracks_the_template(monkeypatch):
    v1 = triage.prompt_version()
    assert v1 == triage.prompt_version()
    assert v1.startswith("legacy-triage@")
    original = FindingProcessor._build_triage_prompt
    monkeypatch.setattr(
        FindingProcessor,
        "_build_triage_prompt",
        lambda self, f: original(self, f) + "extra",
    )
    assert triage.prompt_version() != v1
