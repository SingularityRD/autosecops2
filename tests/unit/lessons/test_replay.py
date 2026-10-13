"""Replay a lesson over labelled historical alerts with evalkit (W3.11).

The baseline is the real harness: the v1 corpus held-out splits and the
injection suite, answered by the committed stub cassette. Offline and
deterministic.
"""

from __future__ import annotations

import pytest

from core.lessons.replay import ReplayCase, replay
from evalkit.lessons import baseline
from tests.unit.lessons._factory import GOOD_SCOPE, NOW, RULE_SCOPE, make_lesson

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def history():
    return baseline()


def test_baseline_is_the_eval_corpus_through_the_cassette(history):
    cases, meta = history
    assert len(cases) > 1000
    assert meta["harness"] == "evalkit" and meta["backend"] == "cassette"
    assert meta["cassette_misses"] == 0
    assert set(meta["suites"]) == {"test", "test_unseen", "injection"}
    assert {c.expected for c in cases} == {"malicious", "benign"}


def test_a_narrow_lesson_cuts_false_positives_without_recall_loss(history):
    cases, meta = history
    report = replay(make_lesson(GOOD_SCOPE, status="proposed"), cases, NOW, meta=meta)
    assert report["passed"] is True, report["reasons"]
    assert report["regressions"] == 0
    assert report["improvements"] >= 1
    assert report["with_lesson"]["fp"] < report["baseline"]["fp"]
    assert report["with_lesson"]["tp"] == report["baseline"]["tp"]
    assert report["with_lesson"]["recall"] == report["baseline"]["recall"]
    assert all(c["expected"] == "benign" for c in report["changed_cases"])
    assert report["harness"]["cassette"] == "stub-v1.jsonl"


def test_a_rule_wide_lesson_fails_on_recall(history):
    cases, _ = history
    report = replay(make_lesson(RULE_SCOPE, status="proposed"), cases, NOW)
    assert report["passed"] is False
    assert report["regressions"] > 0
    assert report["with_lesson"]["tp"] < report["baseline"]["tp"]
    assert any("worse verdict" in r for r in report["reasons"])
    assert all(c["expected"] == "malicious" for c in report["regressed_cases"])
    # The critical alerts of that rule were never touched.
    assert report["skipped"].get("severity:critical", 0) > 0


def test_a_lesson_with_no_evidence_is_not_promotable(history):
    cases, _ = history
    lesson = make_lesson(
        {"data_source": "entra", "hostnames": ["NO-SUCH-HOST"]}, status="proposed"
    )
    report = replay(lesson, cases, NOW)
    assert report["passed"] is False and report["matched"] == 0
    assert report["reasons"] == ["the lesson improved no historical verdict"]


def test_an_adversary_text_lesson_never_applies_in_replay(history):
    cases, _ = history
    lesson = make_lesson(GOOD_SCOPE, status="proposed", provenance="adversary_text")
    report = replay(lesson, cases, NOW)
    assert report["passed"] is False and report["changed"] == 0
    assert report["skipped"].get("provenance:adversary_text", 0) >= 1


def test_escalate_that_raises_false_positives_regresses():
    alert = {
        "data_source": "x",
        "severity": "low",
        "entity_context": {"hostnames": ["H"]},
    }
    cases = [
        ReplayCase("a", "t", alert, expected="benign", actual="benign"),
        ReplayCase("b", "t", alert, expected="malicious", actual="benign"),
    ]
    lesson = make_lesson(
        {"data_source": "x", "hostnames": ["H"]}, effect="escalate", status="proposed"
    )
    report = replay(lesson, cases, NOW)
    assert report["improvements"] == 1 and report["regressions"] == 1
    assert report["passed"] is False


def test_inconclusive_made_benign_on_a_malicious_case_is_a_regression():
    alert = {
        "data_source": "x",
        "severity": "low",
        "entity_context": {"hostnames": ["H"]},
    }
    cases = [
        ReplayCase("a", "t", alert, expected="benign", actual="malicious"),
        ReplayCase("b", "t", alert, expected="malicious", actual="inconclusive"),
    ]
    report = replay(
        make_lesson({"data_source": "x", "hostnames": ["H"]}, status="proposed"),
        cases,
        NOW,
    )
    assert report["regressions"] == 1 and report["passed"] is False
    assert report["with_lesson"]["tp"] == report["baseline"]["tp"]
