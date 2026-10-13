"""Compare a lesson's effect against labelled historical verdicts.

Pure: the caller supplies the baseline (``ReplayCase`` rows, each a labelled
alert and the verdict the triage path gave it; ``evalkit/lessons.py`` builds
them with the eval harness). The lesson is laid over each baseline verdict with
:func:`core.lessons.apply.apply_lessons`, the function production uses.

A *regression* is any case the lesson makes worse:

* expected malicious, baseline malicious, now anything else (recall loss);
* expected malicious, now benign where the baseline was not (a miss made
  confident);
* expected benign, now malicious where the baseline was not (a new false
  positive).

An *improvement* is the reverse: a benign case leaving malicious, a malicious
case reaching malicious, or an inconclusive resolved correctly. A lesson passes
when it has no regression and at least one improvement: a lesson with no
evidence for it is not promoted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence

from core.lessons.apply import apply_lessons
from core.lessons.model import Lesson

MAX_LISTED = 50


@dataclass(frozen=True)
class ReplayCase:
    case_id: str
    suite: str
    alert: Mapping[str, Any]
    expected: str
    actual: str
    category: Optional[str] = None


def _counts(rows: Sequence[tuple]) -> Dict[str, Any]:
    tp = fp = fn = tn = 0
    for expected, actual in rows:
        if expected == "malicious":
            if actual == "malicious":
                tp += 1
            else:
                fn += 1
        else:
            if actual == "malicious":
                fp += 1
            elif actual == "benign":
                tn += 1
    n_mal = tp + fn
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "recall": round(tp / n_mal, 6) if n_mal else None,
        "precision": round(tp / (tp + fp), 6) if tp + fp else None,
    }


def _rank(expected: str, verdict: str) -> int:
    """How right ``verdict`` is for ``expected``: 2 right, 1 inconclusive, 0 wrong."""
    if verdict == expected:
        return 2
    if verdict == "inconclusive":
        return 1
    return 0


def replay(
    lesson: Lesson,
    cases: Sequence[ReplayCase],
    now: datetime,
    *,
    meta: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """The replay report for ``lesson`` over ``cases``."""
    before_rows = []
    after_rows = []
    matched = 0
    skipped: Dict[str, int] = {}
    changed: List[Dict[str, Any]] = []
    regressions: List[Dict[str, Any]] = []
    improvements = 0
    for case in cases:
        out = apply_lessons(
            case.alert,
            case.actual,
            [lesson],
            now,
            category=case.category,
            require_active=False,
        )
        for _lid, reason in out.skipped:
            skipped[reason] = skipped.get(reason, 0) + 1
        if out.matched:
            matched += 1
        before_rows.append((case.expected, case.actual))
        after_rows.append((case.expected, out.verdict))
        if not out.changed:
            continue
        row = {
            "case_id": case.case_id,
            "suite": case.suite,
            "expected": case.expected,
            "before": case.actual,
            "after": out.verdict,
        }
        delta = _rank(case.expected, out.verdict) - _rank(case.expected, case.actual)
        if delta < 0:
            regressions.append(row)
        elif delta > 0:
            improvements += 1
        if len(changed) < MAX_LISTED:
            changed.append(row)

    reasons: List[str] = []
    if regressions:
        reasons.append(f"{len(regressions)} historical alert(s) got a worse verdict")
    if not improvements:
        reasons.append("the lesson improved no historical verdict")
    before = _counts(before_rows)
    after = _counts(after_rows)
    if after["tp"] < before["tp"]:  # implied by regressions; stated for the reader
        reasons.append("recall fell")
    return {
        "passed": not reasons,
        "reasons": reasons,
        "cases": len(cases),
        "matched": matched,
        "changed": len([1 for b, a in zip(before_rows, after_rows) if b != a]),
        "improvements": improvements,
        "regressions": len(regressions),
        "regressed_cases": regressions[:MAX_LISTED],
        "changed_cases": changed,
        "skipped": skipped,
        "baseline": before,
        "with_lesson": after,
        "definition": lesson.definition(),
        "ran_at": now.isoformat(),
        "harness": dict(meta or {}),
    }
