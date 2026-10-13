"""`python -m evalkit.local_lane rank` against a stub Bifrost (offline).

Three stand-in "models" behind one stub gateway: ``good`` answers with the
lexical baseline's verdict as schema-valid JSON, ``lazy`` always dismisses
(recall 0), ``sloppy`` answers in the old text format (every answer off-schema).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from core.llm import local_lane as ll
from evalkit import local_lane as el
from tests.unit.llm.stub_bifrost import StubBifrost, schema_answer

LIMIT = "24"


def responder(body):
    model = body["model"]
    if model == "ollama/good:1b":
        return schema_answer(body)
    if model == "ollama/lazy:1b":
        return json.dumps(
            {
                "severity": "low",
                "confidence": 0.9,
                "category": "other",
                "recommended_action": "dismiss",
                "reasoning": "looks fine",
            }
        )
    if model == "ollama/sloppy:1b":
        return "SEVERITY: high\nCONFIDENCE: 0.9\nRECOMMENDED_ACTION: isolate"
    return (404, {"error": {"message": f"model {model} not found"}})


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy",
                 "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        "core.llm.cost.budget.enforcement_status", lambda: ("disabled", None)
    )


@pytest.fixture
def stub():
    with StubBifrost(responder) as s:
        yield s


def _rank(stub, tmp_path, *extra):
    return el.main(
        [
            "rank",
            "--bifrost-url",
            stub.url,
            "--suite",
            "dev",
            "--limit",
            LIMIT,
            "--timeout-s",
            "120",
            "--concurrency",
            "4",
            "--out",
            str(tmp_path / "out"),
            *extra,
        ]
    )


def test_candidates_compete_and_the_eval_picks_the_default(stub, tmp_path):
    selection = tmp_path / "selection.json"
    code = _rank(
        stub,
        tmp_path,
        "--candidates",
        "lazy:1b,sloppy:1b,good:1b",
        "--write-selection",
        str(selection),
    )
    assert code == 0

    ranking = json.loads((tmp_path / "out" / "ranking.json").read_text())
    assert ranking["selected"] == "ollama/good:1b"
    assert ranking["n_cases"] == int(LIMIT)
    assert ranking["slice"] == "small_lane"
    assert ranking["criteria"]["min_recall_source"].startswith("stub")
    rows = {r["model"]: r for r in ranking["candidates"]}
    assert rows["ollama/good:1b"]["rank"] == 1 and rows["ollama/good:1b"]["eligible"]
    assert rows["ollama/good:1b"]["schema_errors"] == 0
    assert not rows["ollama/lazy:1b"]["eligible"]
    assert any("recall" in r for r in rows["ollama/lazy:1b"]["reasons"])
    assert not rows["ollama/sloppy:1b"]["eligible"]
    assert rows["ollama/sloppy:1b"]["schema_error_rate"] == 1.0
    assert any("schema" in r for r in rows["ollama/sloppy:1b"]["reasons"])

    md = (tmp_path / "out" / "ranking.md").read_text()
    assert "AutoSecOps" in md and "`ollama/good:1b`" in md
    for model in ("good_1b", "lazy_1b", "sloppy_1b"):
        assert (tmp_path / "out" / model / "report.json").exists()

    # Every request went to the stub, schema-constrained, as ollama/<model>.
    assert {b["model"] for b in stub.requests} == {
        "ollama/good:1b",
        "ollama/lazy:1b",
        "ollama/sloppy:1b",
    }
    assert all(b["response_format"]["type"] == "json_schema" for b in stub.requests)
    # No critical alert reached the small-lane slice.
    assert all("Current Severity: critical" not in b["messages"][-1]["content"]
               for b in stub.requests)

    # The selection is what the runtime picks up as its default model.
    sel = json.loads(selection.read_text())
    assert sel["format"] == ll.SELECTION_FORMAT and sel["model"] == "good:1b"
    settings = SimpleNamespace(
        local_lane_model="",
        local_lane_selection_file=str(selection),
        local_lane_timeout_s=30.0,
        local_lane_max_tokens=256,
        local_lane_allow_nonlocal_gateway=False,
        bifrost_url=stub.url,
    )
    lane = ll.get_local_lane(settings)
    assert lane is not None and lane.target == ("ollama", "good:1b")


def test_no_eligible_candidate_exits_3_without_selection(stub, tmp_path):
    selection = tmp_path / "selection.json"
    code = _rank(
        stub,
        tmp_path,
        "--candidates",
        "lazy:1b,missing:1b",
        "--write-selection",
        str(selection),
    )
    assert code == el.EXIT_NO_ELIGIBLE
    assert not selection.exists()
    ranking = json.loads((tmp_path / "out" / "ranking.json").read_text())
    assert ranking["selected"] is None
    missing = next(r for r in ranking["candidates"] if r["model"] == "ollama/missing:1b")
    assert missing["errors"] == int(LIMIT)


def test_explicit_floor_and_slice_all(stub, tmp_path):
    code = _rank(
        stub,
        tmp_path,
        "--candidates",
        "lazy:1b",
        "--min-recall",
        "0",
        "--slice",
        "all",
    )
    assert code == 0
    ranking = json.loads((tmp_path / "out" / "ranking.json").read_text())
    assert ranking["selected"] == "ollama/lazy:1b"
    assert ranking["criteria"]["min_recall"] == 0.0


def test_rank_refuses_a_nonlocal_gateway(tmp_path):
    with pytest.raises(ll.NonLocalGateway):
        el.main(
            [
                "rank",
                "--candidates",
                "good:1b",
                "--bifrost-url",
                "https://gateway.example.com",
                "--limit",
                "1",
                "--out",
                str(tmp_path),
            ]
        )


def test_bad_arguments(tmp_path):
    assert el.main(["rank", "--min-recall", "2", "--out", str(tmp_path)]) == 2
    assert (
        el.main(["rank", "--candidates", "a", "--suite", "injection",
                 "--out", str(tmp_path)])
        == 2
    )


def test_rank_ordering():
    def m(recall, f1, p50, schema=0.0):
        return {
            "n": 10, "recall": recall, "f1": f1, "latency_p50_ms": p50,
            "schema_error_rate": schema,
        }

    rows = el.rank(
        {
            "a": m(0.9, 0.80, 900),
            "b": m(0.9, 0.85, 2000),
            "c": m(0.9, 0.85, 1000),
            "d": m(0.5, 0.95, 10),
            "e": m(0.95, 0.99, 10, schema=0.5),
        },
        min_recall=0.8,
        max_schema_error_rate=0.02,
    )
    assert [r["model"] for r in rows if r["eligible"]] == ["c", "b", "a"]
    assert [r["rank"] for r in rows[:3]] == [1, 2, 3]
    assert {r["model"] for r in rows if not r["eligible"]} == {"d", "e"}


def test_small_lane_slice_and_committed_candidates():
    from evalkit.corpus import load_suites

    dev = load_suites(["dev"])["dev"]
    sliced = el.slice_cases(dev, "small_lane")
    assert 0 < len(sliced) < len(dev)
    assert all(c.alert["severity"] != "critical" for c in sliced)
    assert el.slice_cases(dev, "all") == list(dev)

    candidates = el.load_candidates(el.CANDIDATES_FILE)
    assert len(candidates) >= 2
    assert all("/" not in c for c in candidates)
