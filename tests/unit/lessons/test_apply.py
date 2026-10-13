"""The rule lane: scope matching and the safety rules (W3.11)."""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from core.lessons.apply import apply_lessons, matches
from core.lessons.model import ScopeError, validate_scope
from tests.unit.lessons._factory import NOW, SCANNER_IP, make_lesson

pytestmark = pytest.mark.unit


def alert(**kw):
    base = {
        "finding_id": "f-1",
        "data_source": "entra",
        "severity": "high",
        "title": "Failed sign-ins",
        "description": "many failures",
        "entity_context": {"src_ips": [SCANNER_IP], "usernames": ["ali"]},
        "raw_event": {
            "rule_name": "Failed sign-ins across many accounts from one address"
        },
        "mitre_predictions": {"T1110.003": 0.8},
    }
    base.update(kw)
    return base


def test_matching_lesson_turns_malicious_into_benign_hint():
    out = apply_lessons(alert(), "malicious", [make_lesson()], NOW)
    assert out.verdict == "benign" and out.applied == ["l-1"] and out.changed


@pytest.mark.parametrize(
    "change",
    [
        {"data_source": "okta"},
        {"entity_context": {"src_ips": ["203.0.113.9"]}},
        {"entity_context": {}},
    ],
)
def test_every_matcher_must_hold(change):
    out = apply_lessons(alert(**change), "malicious", [make_lesson()], NOW)
    assert out.verdict == "malicious" and not out.matched


def test_matching_is_case_insensitive_and_covers_rule_and_mitre():
    scope = {
        "rule_name": "failed SIGN-INS across many accounts from one address",
        "mitre_technique": "t1110.003",
        "usernames": ["ALI"],
    }
    assert matches(validate_scope(scope), alert())
    assert not matches(validate_scope({**scope, "mitre_technique": "T1059"}), alert())


@pytest.mark.parametrize("severity", ["critical", "CRITICAL", None, "", "bogus"])
def test_no_benign_hint_on_critical_or_unknown_severity(severity):
    lesson = make_lesson()
    out = apply_lessons(alert(severity=severity), "malicious", [lesson], NOW)
    assert out.verdict == "malicious"
    assert out.skipped and out.skipped[0][1].startswith("severity:")


def test_max_severity_bounds_the_scope():
    lesson = make_lesson(
        {"data_source": "entra", "src_ips": [SCANNER_IP], "max_severity": "medium"}
    )
    assert (
        apply_lessons(alert(severity="high"), "malicious", [lesson], NOW).verdict
        == "malicious"
    )
    assert (
        apply_lessons(alert(severity="low"), "malicious", [lesson], NOW).verdict
        == "benign"
    )


@pytest.mark.parametrize("provenance", ["adversary_text", "system"])
def test_untrusted_provenance_never_applies(provenance):
    lesson = make_lesson(provenance=provenance)
    for require_active in (True, False):
        out = apply_lessons(
            alert(), "malicious", [lesson], NOW, require_active=require_active
        )
        assert out.verdict == "malicious"
        assert out.skipped == [("l-1", f"provenance:{provenance}")]


def test_expired_or_inactive_lessons_do_not_apply():
    expired = make_lesson(expires_at=NOW - timedelta(seconds=1))
    assert apply_lessons(alert(), "malicious", [expired], NOW).skipped == [
        ("l-1", "expired")
    ]
    for status in ("proposed", "retired"):
        out = apply_lessons(alert(), "malicious", [make_lesson(status=status)], NOW)
        assert out.verdict == "malicious"
    proposed = make_lesson(status="proposed")
    assert (
        apply_lessons(
            alert(), "malicious", [proposed], NOW, require_active=False
        ).verdict
        == "benign"
    )


def test_escalate_wins_over_benign_hint():
    esc = make_lesson(id="l-esc", effect="escalate")
    hint = make_lesson(id="l-hint")
    assert apply_lessons(alert(), "benign", [hint, esc], NOW).verdict == "malicious"
    # An escalate lesson that has nothing to change still blocks the hint.
    assert apply_lessons(alert(), "malicious", [hint, esc], NOW).verdict == "malicious"


def test_lesson_category_must_match_the_verdict_category():
    lesson = make_lesson(category="identity")
    assert (
        apply_lessons(alert(), "malicious", [lesson], NOW, category="malware").verdict
        == "malicious"
    )
    assert (
        apply_lessons(alert(), "malicious", [lesson], NOW, category="identity").verdict
        == "benign"
    )


def test_output_is_a_hint_only_and_the_alert_is_untouched():
    a = alert()
    before = copy.deepcopy(a)
    out = apply_lessons(a, "malicious", [make_lesson()], NOW)
    assert a == before
    assert set(out.to_dict()) == {"verdict", "before", "applied", "matched", "skipped"}
    assert out.verdict in ("malicious", "benign", "inconclusive")


@pytest.mark.parametrize(
    "scope,message",
    [
        ({"max_severity": "low"}, "at least one"),
        (
            {"data_source": "x", "src_ips": [SCANNER_IP], "max_severity": "critical"},
            "critical",
        ),
        ({"data_source": "x", "max_severity": "CRITICAL"}, "critical"),
        # Host / user names are chosen by whoever controls the machine or
        # account; IPs and hashes alone are too broad. An anchor is required.
        ({"hostnames": ["WS-12"]}, "data_source, rule_name, mitre_technique"),
        ({"usernames": ["ali"], "src_ips": [SCANNER_IP]}, "data_source, rule_name"),
        ({"file_hashes": ["a" * 64]}, "data_source, rule_name"),
        ({"src_ips": [SCANNER_IP], "title_contains": "scanner"}, "unknown matcher"),
        ({"description": "x"}, "unknown matcher"),
        ({"src_ips": []}, "non-empty"),
        ({"src_ips": [" "]}, "empty"),
        ({"data_source": 3}, "string"),
    ],
)
def test_scope_validation_refuses_unsafe_scopes(scope, message):
    with pytest.raises(ScopeError, match=message):
        validate_scope(scope)


def test_scope_defaults_to_medium_and_sorts_lists():
    scope = validate_scope({"rule_name": "r", "hostnames": ["b", "a", "a"]})
    assert scope == {
        "rule_name": "r",
        "hostnames": ["a", "b"],
        "max_severity": "medium",
    }


def test_a_stored_lesson_without_an_anchor_never_applies():
    lesson = make_lesson()
    lesson.applies_to = {"src_ips": [SCANNER_IP], "max_severity": "high"}
    out = apply_lessons(alert(), "malicious", [lesson], NOW)
    assert out.verdict == "malicious"
    assert out.skipped == [("l-1", "scope:unanchored")]
