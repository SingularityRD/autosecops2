"""Stub determinism, cassette record/replay, and the committed cassette."""

import asyncio
import json

import pytest

from evalkit.backends import (
    DEFAULT_CASSETTE,
    BackendResult,
    CassetteBackend,
    CassetteError,
    CassetteRecorder,
    StubBackend,
    read_cassette,
    stub_answer,
)
from evalkit.corpus import DEFAULT_SUITES, load_suite
from evalkit.report import build_report
from evalkit.runner import run_cases
from evalkit.triage import apply_result, build_prompt, prompt_hash, prompt_version


def _run(cases, backend):
    return asyncio.run(run_cases(cases, backend, prompt_version=prompt_version()))


def _metrics(results_by_suite):
    report = build_report(results_by_suite, run={})
    return report["suites"]


def test_stub_is_deterministic_and_in_prompt_format():
    case = load_suite("test", limit=1)[0]
    prompt = build_prompt(case.alert)
    a = stub_answer(prompt)
    assert a == stub_answer(prompt)
    assert set(json.loads(a)) == {
        "verdict",
        "confidence",
        "category",
        "cited_fields",
        "gaps",
        "recommended_action",
    }
    # The daemon's own parser takes it as a verdict, not a parse failure.
    finding = apply_result(case.alert, a)
    assert not any(
        "could not" in g or "not a JSON" in g or "did not match" in g
        for g in finding["ai_triage"]["verdict"]["gaps"]
    )


def test_replay_matches_stub(tmp_path):
    suites = {s: load_suite(s, limit=40) for s in DEFAULT_SUITES}
    stub = {s: _run(cs, StubBackend()) for s, cs in suites.items()}

    path = tmp_path / "c.jsonl"
    recorder = CassetteRecorder(StubBackend(), path, prompt_version=prompt_version())
    for cs in suites.values():
        _run(cs, recorder)
    assert recorder.save() == sum(len(cs) for cs in suites.values())

    replay = CassetteBackend(path)
    replayed = {s: _run(cs, replay) for s, cs in suites.items()}
    assert replay.misses == 0
    assert _metrics(replayed) == _metrics(stub)
    for s in suites:
        assert [r.verdict for r in replayed[s]] == [r.verdict for r in stub[s]]


def test_miss_is_an_errored_case(tmp_path):
    path = tmp_path / "c.jsonl"
    CassetteRecorder(StubBackend(), path, prompt_version="p").save()
    backend = CassetteBackend(path)
    [r] = _run(load_suite("test", limit=1), backend)
    assert r.cassette_miss and r.error.startswith("cassette miss")
    assert r.actual_verdict == "inconclusive" and r.verdict is None
    assert backend.misses == 1


def test_recorder_merges_and_sorts(tmp_path):
    path = tmp_path / "c.jsonl"
    cases = load_suite("dev", limit=6)
    r1 = CassetteRecorder(StubBackend(), path, prompt_version="p")
    _run(cases[:3], r1)
    r1.save()
    r2 = CassetteRecorder(StubBackend(), path, prompt_version="p")
    _run(cases[3:], r2)
    assert r2.save() == 6
    lines = path.read_text().splitlines()
    assert "_meta" in json.loads(lines[0])
    keys = [json.loads(line)["key"] for line in lines[1:]]
    assert keys == sorted(keys)


def test_recorder_does_not_keep_budget_refusals(tmp_path):
    class Refusing:
        name = "live"
        model = "m"

        async def complete(self, prompt):
            return BackendResult(content=None, model="m", error="budget: cap")

    rec = CassetteRecorder(Refusing(), tmp_path / "c.jsonl", prompt_version="p")
    asyncio.run(rec.complete("x"))
    assert rec.save() == 0


def test_not_a_cassette_is_refused(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text('{"_meta": {"format": "something-else"}}\n')
    with pytest.raises(CassetteError):
        CassetteBackend(path)


def test_committed_cassette_covers_every_ci_prompt():
    """The CI guard: a change to the prompt template or the corpus makes the
    committed cassette miss, and this test names the fix."""
    meta, entries = read_cassette(DEFAULT_CASSETTE)
    assert meta["backend"] == "stub"
    assert meta["prompt_version"] == prompt_version(), (
        "prompt template changed: re-record with "
        "`python -m evalkit record --backend stub --overwrite`"
    )
    for suite in DEFAULT_SUITES:
        for case in load_suite(suite):
            assert prompt_hash(build_prompt(case.alert)) in entries, case.case_id
