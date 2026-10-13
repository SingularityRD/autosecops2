"""The CLI end to end, offline."""

import json

import pytest

from evalkit.backends import CassetteRecorder, StubBackend
from evalkit.cli import main
from evalkit.triage import prompt_version


def test_ci_replays_the_committed_cassette(tmp_path):
    assert main(["ci", "--out", str(tmp_path)]) == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["schema"] == "evalkit.report/v1"
    assert sorted(report["suites"]) == ["injection", "test", "test_unseen"]
    assert "asr" in report["suites"]["injection"]
    for rep in report["suites"].values():
        assert rep["operational"]["cassette_misses"] == 0
        assert rep["operational"]["errors"] == 0
    md = (tmp_path / "report.md").read_text()
    assert "## Split `test`" in md and "## Split `test_unseen`" in md
    assert "Enjeksiyon paketi" in md
    assert len((tmp_path / "cases.jsonl").read_text().splitlines()) == 432 + 720 + 240


def test_ci_fails_on_a_cassette_miss(tmp_path):
    empty = tmp_path / "empty.jsonl"
    CassetteRecorder(StubBackend(), empty, prompt_version=prompt_version()).save()
    rc = main(
        ["ci", "--cassette", str(empty), "--limit", "3", "--out", str(tmp_path / "o")]
    )
    assert rc == 1


def test_run_stub_with_limit(tmp_path):
    rc = main(
        [
            "run",
            "--backend",
            "stub",
            "--suite",
            "dev",
            "--limit",
            "5",
            "--out",
            str(tmp_path),
        ]
    )
    assert rc == 0
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["suites"]["dev"]["overall"]["n"] == 5
    assert report["run"]["backend"]["backend"] == "stub"


def test_record_writes_a_cassette(tmp_path):
    cassette = tmp_path / "c.jsonl"
    rc = main(
        [
            "record",
            "--suite",
            "dev",
            "--limit",
            "4",
            "--record",
            str(cassette),
            "--out",
            str(tmp_path / "o"),
        ]
    )
    assert rc == 0
    assert len(cassette.read_text().splitlines()) == 1 + 4


def test_live_needs_a_budget(tmp_path):
    with pytest.raises(SystemExit):
        main(["run", "--backend", "live", "--limit", "1", "--out", str(tmp_path)])


def test_unknown_suite_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        main(["run", "--backend", "stub", "--suite", "nope", "--out", str(tmp_path)])
