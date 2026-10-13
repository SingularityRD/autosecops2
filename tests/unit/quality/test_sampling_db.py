"""QA sampling against a real Postgres: who is drawn, with what probability, and
what the Scorecard counts.

DB-backed because qa_samples is SQL-owned and the queries are SQL.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

import pytest
from sqlalchemy import text

from core.quality import sampling
from core.quality.bounds import clopper_pearson_upper
from core.storage.unit_of_work import unit_of_work
from tests.unit.quality._factory import PREFIX, add_decisions

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

NOW = datetime(2003, 6, 10, 12, 0, 0)
IN_WINDOW = NOW - timedelta(days=1)


@pytest.fixture(autouse=True)
def _db(qa_db):
    yield


def _draw(**kw):
    with unit_of_work() as session:
        return sampling.draw_samples(
            session, now=NOW, rng=random.Random(kw.pop("seed", 7)), **kw
        )


def _rows():
    with unit_of_work() as session:
        return [
            dict(r)
            for r in session.execute(
                text(
                    "SELECT sampling_kind, subject_id, inclusion_probability, verdict "
                    "FROM qa_samples ORDER BY id"
                )
            ).mappings()
        ]


def _seed_population():
    rows = []
    rows += [
        {"id": f"ph-{i}", "verdict": "benign", "category": "phishing"}
        for i in range(40)
    ]
    rows += [
        {"id": f"mw-{i}", "verdict": "benign", "category": "malware"} for i in range(5)
    ]
    # Not candidates: a malicious or inconclusive verdict, whatever the type says.
    rows += [
        {
            "id": "mal-1",
            "verdict": "malicious",
            "category": "phishing",
            "decision_type": "auto_close",
        },
        {"id": "inc-1", "verdict": "inconclusive", "category": "phishing"},
        # A plain triage decision with no verdict and no closure.
        {"id": "plain-1", "decision_type": "triage", "action": "escalate"},
        # Out of the window.
        {
            "id": "old-1",
            "verdict": "benign",
            "category": "phishing",
            "at": NOW - timedelta(days=30),
        },
    ]
    # Legacy closure without a verdict document: derived, filed under its metadata category.
    rows += [
        {
            "id": "legacy-1",
            "decision_type": "auto_close",
            "meta": {"category": "identity"},
        },
        {"id": "legacy-2", "decision_type": "triage", "action": "dismiss"},
    ]
    add_decisions(rows, at=IN_WINDOW)


def test_simple_random_sample_per_category_with_inclusion_probability():
    _seed_population()

    result = _draw(days=7, per_category=10)

    assert result.per_category["phishing"] == {
        "population": 40,
        "drawn": 10,
        "inclusion_probability": 0.25,
    }
    assert result.per_category["malware"] == {
        "population": 5,
        "drawn": 5,
        "inclusion_probability": 1.0,
    }
    assert result.per_category["identity"]["drawn"] == 1
    assert result.per_category["other"]["drawn"] == 1
    assert result.per_category["cloud"] == {
        "population": 0,
        "drawn": 0,
        "inclusion_probability": 0.0,
    }

    rows = _rows()
    assert {r["sampling_kind"] for r in rows} == {"simple_random"}
    ids = {r["subject_id"] for r in rows}
    for excluded in ("mal-1", "inc-1", "plain-1", "old-1"):
        assert f"{PREFIX}{excluded}" not in ids
    legacy = next(r for r in rows if r["subject_id"] == f"{PREFIX}legacy-1")
    assert legacy["verdict"]["verdict"] == "benign"
    assert legacy["verdict"]["category"] == "identity"
    assert legacy["verdict"]["gaps"] == [sampling.DERIVED_VERDICT_GAP]


def test_the_same_seed_draws_the_same_sample():
    _seed_population()
    first = {r["subject_id"] for r in (_draw(per_category=10) and _rows())}
    with unit_of_work() as session:
        session.execute(text("DELETE FROM qa_samples"))
    second = {r["subject_id"] for r in (_draw(per_category=10) and _rows())}
    assert first == second


def test_a_second_draw_only_takes_what_the_first_left():
    _seed_population()
    _draw(per_category=10)
    again = _draw(per_category=10, seed=99)

    assert again.per_category["phishing"]["population"] == 30
    assert again.per_category["malware"]["population"] == 0
    subject_ids = [r["subject_id"] for r in _rows()]
    assert len(subject_ids) == len(set(subject_ids))


def test_risk_weighted_extras_are_tracked_separately():
    _seed_population()
    add_decisions(
        [
            {
                "id": f"hi-{i}",
                "verdict": "benign",
                "category": "network",
                "confidence": 0.1,
                "meta": {"severity": "critical"},
            }
            for i in range(3)
        ],
        at=IN_WINDOW,
    )

    result = _draw(per_category=2, risk_weighted_extra=5)

    rows = _rows()
    srs = [r for r in rows if r["sampling_kind"] == "simple_random"]
    rw = [r for r in rows if r["sampling_kind"] == "risk_weighted"]
    assert result.risk_weighted_drawn == len(rw) > 0
    # Never the same decision under both kinds in one draw.
    assert not {r["subject_id"] for r in srs} & {r["subject_id"] for r in rw}
    for r in rw:
        assert 0 < r["inclusion_probability"] <= 1
    # Low confidence + critical outweighs the confident majority.
    weights = {r["subject_id"]: r["inclusion_probability"] for r in rw}
    hi = [p for sid, p in weights.items() if "hi-" in sid]
    lo = [p for sid, p in weights.items() if "hi-" not in sid]
    if hi and lo:
        assert min(hi) > max(lo)


def test_review_rules():
    _seed_population()
    _draw(per_category=2)
    with unit_of_work() as session:
        pending = sampling.list_samples(session, status="pending")
    first, second, third = pending[0]["id"], pending[1]["id"], pending[2]["id"]

    with unit_of_work() as session:
        agreed = sampling.review_sample(
            session, first, agrees=True, review_verdict=None, reviewer="ana"
        )
    assert agreed["review_verdict"] == "benign"
    assert agreed["agrees"] is True
    assert agreed["reviewer"] == "ana"
    assert agreed["reasoning"] == "looked fine"  # joined from the decision

    with unit_of_work() as session:
        with pytest.raises(sampling.SampleAlreadyReviewed):
            sampling.review_sample(
                session, first, agrees=True, review_verdict=None, reviewer="bob"
            )
        with pytest.raises(sampling.InvalidReview):
            sampling.review_sample(
                session, second, agrees=False, review_verdict=None, reviewer="ana"
            )
        with pytest.raises(sampling.InvalidReview):
            sampling.review_sample(
                session, second, agrees=False, review_verdict="benign", reviewer="ana"
            )
        with pytest.raises(sampling.SampleNotFound):
            sampling.review_sample(
                session, 10**9, agrees=True, review_verdict=None, reviewer="ana"
            )

    with unit_of_work() as session:
        missed = sampling.review_sample(
            session,
            third,
            agrees=False,
            review_verdict="malicious",
            reviewer="ana",
            notes="beaconing",
        )
    assert missed["review_verdict"] == "malicious"
    assert missed["notes"] == "beaconing"

    with unit_of_work() as session:
        assert len(sampling.list_samples(session, status="reviewed")) == 2


def _insert_reviewed(kind: str, category: str, n: int, misses: int, tag: str):
    with unit_of_work() as session:
        for i in range(n):
            session.execute(
                text(
                    "INSERT INTO qa_samples (sampling_kind, inclusion_probability, "
                    "subject_kind, subject_id, verdict, reviewer, reviewed_at, "
                    "review_verdict, agrees) VALUES (:k, 0.5, 'ai_decision', :sid, "
                    "CAST(:v AS JSONB), 'ana', now(), :rv, :a)"
                ),
                {
                    "k": kind,
                    "sid": f"{tag}-{i}",
                    "v": f'{{"verdict": "benign", "category": "{category}"}}',
                    "rv": "malicious" if i < misses else "benign",
                    "a": i >= misses,
                },
            )


def test_scorecard_bound_uses_simple_random_reviews_only():
    _insert_reviewed("simple_random", "phishing", 299, 0, "p")
    _insert_reviewed("simple_random", "malware", 298, 0, "m")
    # Many risk-weighted misses on phishing: reported, but not in the bound.
    _insert_reviewed("risk_weighted", "phishing", 20, 5, "pr")
    # One inconclusive disagreement on network is not a miss.
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO qa_samples (sampling_kind, inclusion_probability, subject_kind, "
                "subject_id, verdict, reviewed_at, review_verdict, agrees) VALUES "
                "('simple_random', 1, 'ai_decision', 'n-1', "
                '\'{"verdict": "benign", "category": "network"}\'::jsonb, now(), '
                "'inconclusive', false)"
            )
        )

    with unit_of_work() as session:
        card = sampling.scorecard(session)
    by = {c["category"]: c for c in card["categories"]}

    assert [c["category"] for c in card["categories"]] == [
        "phishing",
        "malware",
        "identity",
        "network",
        "cloud",
        "other",
    ]
    assert by["phishing"]["reviewed"] == 299
    assert by["phishing"]["misses"] == 0
    assert by["phishing"]["fn_upper_bound"] < 0.01
    assert by["phishing"]["status"] == "meets"
    assert by["phishing"]["reviews_needed"] == 0
    assert by["phishing"]["risk_weighted"] == {
        "reviewed": 20,
        "misses": 5,
        "pending": 0,
    }

    assert by["malware"]["reviewed"] == 298
    assert by["malware"]["fn_upper_bound"] > 0.01
    assert by["malware"]["status"] == "not_met"
    assert by["malware"]["reviews_needed"] == 1

    assert by["network"]["misses"] == 0
    assert by["network"]["disagreements"] == 1
    assert by["network"]["fn_upper_bound"] == pytest.approx(clopper_pearson_upper(0, 1))

    assert by["cloud"]["status"] == "no_data"
    assert by["cloud"]["fn_upper_bound"] == 1.0
