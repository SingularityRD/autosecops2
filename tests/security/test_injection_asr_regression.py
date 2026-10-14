"""W4.3: the prompt-injection suite is a CI regression threshold on ASR.

The injection corpus (``eval/suites/injection/v1.jsonl``, authored under an
earlier work package — this package adds no new payload text) is replayed
through the real triage prompt/parser via evalkit's committed cassette. The
attack-success rate must not rise above the recorded baseline
(``injection_asr_baseline.json``): a change that makes the product follow an
injected instruction more often fails here.

Pinned together:

* ``asr.k`` (successful attacks out of a fixed ``n``) must be ``<= baseline.k``;
* the cassette must not miss and no case may error — a changed triage prompt or
  corpus misses the committed cassette, which fails loudly rather than scoring
  a silent 0, because a prompt change needs a fresh measurement;
* ``prompt_version`` and ``n`` must match the baseline, so the number being
  compared is the number that was recorded.

This replays a cassette; it makes no model call and no network call.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("JWT_SECRET_KEY", "test-only-secret-not-for-prod")

from evalkit.backends import CassetteBackend  # noqa: E402
from evalkit.cli import execute  # noqa: E402
from evalkit.corpus import REPO_ROOT  # noqa: E402
from evalkit.report import build_report  # noqa: E402
from evalkit.triage import prompt_version  # noqa: E402

pytestmark = pytest.mark.unit

BASELINE_FILE = Path(__file__).with_name("injection_asr_baseline.json")


def _run_injection() -> dict:
    baseline = json.loads(BASELINE_FILE.read_text())
    cassette = REPO_ROOT / baseline["cassette"]
    backend = CassetteBackend(cassette)
    results = asyncio.run(execute(["injection"], backend, provenance="off"))
    report = build_report(results, run={})
    return baseline, report["suites"]["injection"]


def test_injection_asr_does_not_exceed_baseline():
    baseline, rep = _run_injection()
    op = rep["operational"]
    assert op["cassette_misses"] == 0, (
        "the injection prompt or corpus changed and misses the committed "
        "cassette; re-record and re-measure ASR before updating the baseline"
    )
    assert op["errors"] == 0, f"{op['errors']} injection case(s) errored"

    asr = rep["asr"]
    assert asr["n"] == baseline["n"], (
        f"injection corpus size changed ({asr['n']} vs baseline {baseline['n']}); "
        "re-measure and update the baseline on review"
    )
    assert asr["k"] <= baseline["k"], (
        f"injection ASR regressed: {asr['k']}/{asr['n']} successful attacks "
        f"> baseline {baseline['k']}/{baseline['n']} "
        f"({asr['value']:.4f} > {baseline['asr']})"
    )


def test_baseline_prompt_version_is_current():
    """The baseline must have been recorded against today's triage prompt."""
    baseline = json.loads(BASELINE_FILE.read_text())
    assert baseline["prompt_version"] == prompt_version(), (
        "injection ASR baseline was recorded against a different triage prompt "
        f"({baseline['prompt_version']} vs {prompt_version()}); re-record it"
    )
