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


VERDICT_FOR = {
    "isolate": "malicious",
    "block": "malicious",
    "investigate": "malicious",
    "monitor": "benign",
    "dismiss": "benign",
}


def answer(
    action="isolate", confidence=0.8, category="malware", cited=None, target=None
):
    """A reply in the daemon's JSON verdict format (W1.2)."""
    return json.dumps(
        {
            "verdict": VERDICT_FOR.get(action, "inconclusive"),
            "confidence": confidence,
            "category": category,
            "cited_fields": cited if cited is not None else [],
            "gaps": [],
            "recommended_action": (
                {"type": action, "target": target or "x"}
                if action in VERDICT_FOR
                else None
            ),
        }
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
    assert any("not a JSON verdict" in g for g in d.verdict.gaps)
    assert d.verdict.confidence == 0.0
    assert d.verdict.recommended_action is None


def test_old_key_value_reply_is_inconclusive():
    reply = "SEVERITY: high\nCONFIDENCE: 0.9\nRECOMMENDED_ACTION: dismiss\n"
    finding = triage.apply_result(ALERT, reply)
    d = triage.legacy_verdict(ALERT, finding, model="m", prompt_version="p")
    assert d.verdict.verdict == "inconclusive"


def test_reads_the_stored_verdict_not_the_result_block():
    finding = triage.apply_result(ALERT, answer(action="dismiss", cited=["severity"]))
    assert finding["ai_triage"]["verdict"]["verdict"] == "benign"
    finding["ai_triage"]["result"] = {"recommended_action": "isolate"}
    finding["ai_triage"]["verdict"]["verdict"] = "malicious"
    d = triage.legacy_verdict(ALERT, finding, model="m", prompt_version="p")
    assert d.verdict.verdict == "malicious"
    assert (d.verdict.model, d.verdict.prompt_version) == ("m", "p")


def test_missing_stored_verdict_is_inconclusive():
    d = triage.legacy_verdict(
        ALERT, {"ai_triage": {"result": {}}}, model="m", prompt_version="p"
    )
    assert d.verdict.verdict == "inconclusive"
    assert triage.NO_VERDICT_GAP in d.verdict.gaps


def test_backend_error_is_inconclusive_with_reason():
    d = triage.legacy_verdict(ALERT, None, model="m", prompt_version="p", error="boom")
    assert d.verdict.verdict == "inconclusive"
    assert any("boom" in g for g in d.verdict.gaps)


def test_repeated_key_is_refused_by_the_daemon_parser():
    # _apply_triage_result refuses a repeated key; the harness inherits that.
    reply = answer(action="dismiss")[:-1] + ', "verdict": "malicious"}'
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


def test_recommended_action_target_is_the_models_or_the_alerts():
    v = decide(action="isolate", target="WEB-9").verdict
    assert (v.recommended_action.type, v.recommended_action.target) == (
        "isolate_host",
        "WEB-9",
    )
    finding = triage.apply_result(ALERT, answer(action="isolate"))
    finding["ai_triage"]["verdict"]["recommended_action"]["target"] = " "
    v = triage.legacy_verdict(ALERT, finding, model="m", prompt_version="p").verdict
    assert v.recommended_action.target == "WEB-1"
    finding = triage.apply_result(ALERT, answer(action="block"))
    finding["ai_triage"]["verdict"]["recommended_action"]["target"] = ""
    v = triage.legacy_verdict(ALERT, finding, model="m", prompt_version="p").verdict
    assert (v.recommended_action.type, v.recommended_action.target) == (
        "block_ip",
        "192.0.2.5",
    )
    assert decide(action="investigate").verdict.recommended_action is None


def test_containment_the_daemon_refuses_is_not_scored():
    # isolate on a benign verdict never reaches the responder.
    reply = json.loads(answer(action="dismiss", cited=["severity"]))
    reply["recommended_action"] = {"type": "isolate", "target": "WEB-1"}
    finding = triage.apply_result(ALERT, json.dumps(reply))
    d = triage.legacy_verdict(ALERT, finding, model="m", prompt_version="p")
    assert d.verdict.verdict == "benign"
    assert d.verdict.recommended_action is None


def test_provenance_enforce_downgrades_uncited_benign():
    off = decide(action="dismiss", provenance="off")
    on = decide(action="dismiss", provenance="enforce")
    assert off.verdict.verdict == "benign" and off.provenance_downgraded
    assert NO_SENSOR_CITATION_GAP not in off.verdict.gaps
    assert on.verdict.verdict == "inconclusive" and on.provenance_downgraded
    assert NO_SENSOR_CITATION_GAP in on.verdict.gaps
    assert not decide(action="isolate").provenance_downgraded


def test_sensor_cited_benign_stands_under_enforce():
    # severity is a sensor field for crowdstrike; the title is not.
    on = decide(action="dismiss", provenance="enforce", cited=["severity"])
    assert on.verdict.verdict == "benign" and not on.provenance_downgraded
    on = decide(action="dismiss", provenance="enforce", cited=["title"])
    assert on.verdict.verdict == "inconclusive"


def test_out_of_range_confidence_is_not_kept():
    d = decide(confidence=1.7)
    assert d.verdict.verdict == "inconclusive"
    assert d.verdict.confidence == 0.0


def test_prompt_version_is_stable_and_tracks_the_template(monkeypatch):
    v1 = triage.prompt_version()
    assert v1 == triage.prompt_version()
    assert v1.startswith("daemon-triage-v2@")
    original = FindingProcessor._build_triage_prompt
    monkeypatch.setattr(
        FindingProcessor,
        "_build_triage_prompt",
        lambda self, f: original(self, f) + "extra",
    )
    assert triage.prompt_version() != v1
