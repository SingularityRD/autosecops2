"""QA sampling of the AI decisions AutoSecOps closed without a person.

The Scorecard's claim is about verdicts nobody looked at: "of the alerts the AI
called benign and closed, at most 1% were really malicious". That is only an
honest claim if the reviewed verdicts are a *simple random sample* of those
closures, so this module draws one per category and records each draw's
inclusion probability in ``qa_samples`` (``46_eval_qa_canary.sql``).

A simple random sample spends most reviews on the easy majority. Optional
``risk_weighted`` extras over-sample the closures that would hurt most if wrong
(low confidence, high severity). They are stored with their own inclusion
probability so they could be re-weighted later, but they are *not* a simple
random sample and never enter the bound: the Scorecard reports them beside it.

``qa_samples`` is SQL-owned (no ORM model), so this module talks to it in SQL.
Candidates come from the ORM's ``ai_decision_logs``, the table behind
``/api/ai/decisions``.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.contracts.verdict import CATEGORIES, VERDICTS
from core.quality.bounds import (
    DEFAULT_CONFIDENCE,
    DEFAULT_TARGET,
    clopper_pearson_upper,
    reviews_needed,
)
from core.storage.models import AIDecisionLog
from core.time import utcnow

SUBJECT_KIND = "ai_decision"
DEFAULT_TENANT = "default"
SIMPLE_RANDOM = "simple_random"
RISK_WEIGHTED = "risk_weighted"
SAMPLING_KINDS = (SIMPLE_RANDOM, RISK_WEIGHTED)

# A decision whose type or action says it closed the subject, for decisions
# logged before verdict documents existed. Compared lower-cased.
AUTO_CLOSE_MARKERS = frozenset(
    {
        "auto_close",
        "auto_closed",
        "autoclose",
        "close",
        "closed",
        "dismiss",
        "dismissed",
        "benign",
        "false_positive",
        "no_action",
        "suppress",
    }
)
HIGH_SEVERITIES = frozenset({"high", "critical"})

# The gap recorded on a verdict document this module had to derive.
DERIVED_VERDICT_GAP = (
    "no verdict document was logged with this decision; derived from "
    "ai_decision_logs (decision_type / recommended_action)"
)


class SampleNotFound(LookupError):
    """No sample with that id."""


class SampleAlreadyReviewed(RuntimeError):
    """The sample has a review; reviews are not overwritten."""


class InvalidReview(ValueError):
    """The review contradicts itself (a disagreement naming the AI's own verdict)."""


@dataclass(frozen=True)
class Candidate:
    """One auto-closed decision eligible for review."""

    decision_id: str
    category: str
    confidence: float
    severity: Optional[str]
    verdict: dict[str, Any]


@dataclass
class DrawResult:
    """What one draw added, per category."""

    per_category: dict[str, dict[str, Any]] = field(default_factory=dict)
    risk_weighted_drawn: int = 0
    risk_weighted_population: int = 0


def _marker(value: Any) -> bool:
    return isinstance(value, str) and value.strip().lower() in AUTO_CLOSE_MARKERS


def candidate_from_decision(decision: AIDecisionLog) -> Optional[Candidate]:
    """The candidate a decision makes, or ``None`` when it did not close as benign.

    A logged verdict document decides on its own: ``benign`` qualifies and
    anything else does not, whatever the decision type says. Without one, a
    decision type or action that names a closure qualifies, filed under the
    category its metadata names or ``other``.
    """
    meta = (
        decision.decision_metadata
        if isinstance(decision.decision_metadata, dict)
        else {}
    )
    doc = meta.get("verdict")
    confidence = float(decision.confidence_score or 0.0)
    severity = meta.get("severity")
    severity = severity.lower() if isinstance(severity, str) else None

    if isinstance(doc, dict) and doc.get("verdict") in VERDICTS:
        if doc["verdict"] != "benign":
            return None
        category = doc.get("category") if doc.get("category") in CATEGORIES else "other"
        return Candidate(decision.decision_id, category, confidence, severity, doc)

    if not (_marker(decision.decision_type) or _marker(decision.recommended_action)):
        return None
    category = meta.get("category") if meta.get("category") in CATEGORIES else "other"
    derived = {
        "verdict": "benign",
        "confidence": min(1.0, max(0.0, confidence)),
        "category": category,
        "cited_fields": [],
        "gaps": [DERIVED_VERDICT_GAP],
        "recommended_action": None,
        "model": decision.agent_id or "unknown",
        "prompt_version": "unknown",
    }
    return Candidate(decision.decision_id, category, confidence, severity, derived)


def risk_weight(candidate: Candidate) -> float:
    """How much a wrong closure here would hurt; floors at 0.05 so all can be drawn."""
    w = 0.05 + (1.0 - min(1.0, max(0.0, candidate.confidence)))
    if candidate.severity in HIGH_SEVERITIES:
        w += 0.5
    return w


def _already_sampled(session: Session, tenant_id: str) -> dict[str, set[str]]:
    rows = session.execute(
        text(
            "SELECT sampling_kind, subject_id FROM qa_samples "
            "WHERE tenant_id = :t AND subject_kind = :k"
        ),
        {"t": tenant_id, "k": SUBJECT_KIND},
    ).all()
    seen: dict[str, set[str]] = {kind: set() for kind in SAMPLING_KINDS}
    for kind, subject_id in rows:
        seen.setdefault(kind, set()).add(subject_id)
    return seen


def _insert(
    session: Session,
    tenant_id: str,
    kind: str,
    candidate: Candidate,
    probability: float,
    sampled_at: datetime,
) -> bool:
    inserted = session.execute(
        text(
            "INSERT INTO qa_samples (tenant_id, sampling_kind, inclusion_probability, "
            "subject_kind, subject_id, verdict, sampled_at) "
            "VALUES (:t, :kind, :p, :sk, :sid, CAST(:verdict AS JSONB), :at) "
            "ON CONFLICT (tenant_id, sampling_kind, subject_kind, subject_id) DO NOTHING "
            "RETURNING id"
        ),
        {
            "t": tenant_id,
            "kind": kind,
            "p": probability,
            "sk": SUBJECT_KIND,
            "sid": candidate.decision_id,
            "verdict": json.dumps(candidate.verdict),
            "at": sampled_at,
        },
    ).first()
    return inserted is not None


def load_candidates(
    session: Session, *, since: datetime, until: Optional[datetime] = None
) -> list[Candidate]:
    """Every auto-closed decision logged in ``[since, until)``."""
    query = session.query(AIDecisionLog).filter(AIDecisionLog.timestamp >= since)
    if until is not None:
        query = query.filter(AIDecisionLog.timestamp < until)
    found = (candidate_from_decision(d) for d in query.all())
    return sorted((c for c in found if c is not None), key=lambda c: c.decision_id)


def draw_samples(
    session: Session,
    *,
    days: int = 7,
    per_category: int = 30,
    risk_weighted_extra: int = 0,
    rng: Optional[random.Random] = None,
    tenant_id: str = DEFAULT_TENANT,
    now: Optional[datetime] = None,
    candidates: Optional[Iterable[Candidate]] = None,
) -> DrawResult:
    """Draw a simple random sample per category, then optional risk-weighted extras.

    The population of a category is its auto-closed decisions in the window
    that no earlier draw took as ``simple_random``. ``n = min(per_category, N)``
    are taken uniformly without replacement, each with inclusion probability
    ``n / N``.

    Extras are Poisson-sampled from what is left (decisions not already in
    ``qa_samples`` under either kind): each is taken independently with
    ``pi_i = min(1, k * w_i / sum(w))``, so about ``k`` are drawn and each
    records its own ``pi_i``.
    """
    rng = rng or random.Random()
    now = now or utcnow()
    if candidates is None:
        candidates = load_candidates(
            session, since=now - timedelta(days=days), until=now
        )
    seen = _already_sampled(session, tenant_id)

    by_category: dict[str, list[Candidate]] = {c: [] for c in CATEGORIES}
    for cand in candidates:
        if cand.decision_id not in seen[SIMPLE_RANDOM]:
            by_category[cand.category].append(cand)

    result = DrawResult()
    taken: set[str] = set()
    for category in CATEGORIES:
        pool = by_category[category]
        n = min(max(per_category, 0), len(pool))
        probability = n / len(pool) if pool else 0.0
        drawn = 0
        for cand in rng.sample(pool, n):
            if _insert(session, tenant_id, SIMPLE_RANDOM, cand, probability, now):
                drawn += 1
                taken.add(cand.decision_id)
        result.per_category[category] = {
            "population": len(pool),
            "drawn": drawn,
            "inclusion_probability": probability,
        }

    if risk_weighted_extra > 0:
        sampled_any = seen[SIMPLE_RANDOM] | seen[RISK_WEIGHTED] | taken
        rest = [
            c
            for category in CATEGORIES
            for c in by_category[category]
            if c.decision_id not in sampled_any
        ]
        result.risk_weighted_population = len(rest)
        total = sum(risk_weight(c) for c in rest)
        for cand in rest:
            probability = min(1.0, risk_weighted_extra * risk_weight(cand) / total)
            if rng.random() < probability and _insert(
                session, tenant_id, RISK_WEIGHTED, cand, probability, now
            ):
                result.risk_weighted_drawn += 1
    return result


_LIST_SQL = """
SELECT q.id, q.sampling_kind, q.inclusion_probability, q.subject_kind, q.subject_id,
       q.verdict, q.sampled_at, q.reviewer, q.reviewed_at, q.review_verdict,
       q.agrees, q.notes,
       d.agent_id, d.decision_type, d.reasoning, d.recommended_action,
       d.finding_id, d.case_id, d.confidence_score, d.timestamp AS decided_at
FROM qa_samples q
LEFT JOIN ai_decision_logs d
       ON q.subject_kind = 'ai_decision' AND d.decision_id = q.subject_id
WHERE q.tenant_id = :t
  {status}
  {category}
  {kind}
ORDER BY q.sampled_at, q.id
LIMIT :limit
"""


def list_samples(
    session: Session,
    *,
    status: str = "pending",
    category: Optional[str] = None,
    sampling_kind: Optional[str] = None,
    limit: int = 100,
    tenant_id: str = DEFAULT_TENANT,
) -> list[dict[str, Any]]:
    """Samples with the decision they were drawn from, oldest first."""
    params: dict[str, Any] = {"t": tenant_id, "limit": limit}
    status_sql = {
        "pending": "AND q.reviewed_at IS NULL",
        "reviewed": "AND q.reviewed_at IS NOT NULL",
        "all": "",
    }[status]
    category_sql = ""
    if category:
        category_sql = "AND q.verdict->>'category' = :cat"
        params["cat"] = category
    kind_sql = ""
    if sampling_kind:
        kind_sql = "AND q.sampling_kind = :kind"
        params["kind"] = sampling_kind
    rows = session.execute(
        text(_LIST_SQL.format(status=status_sql, category=category_sql, kind=kind_sql)),
        params,
    ).mappings()
    return [dict(r) for r in rows]


def review_sample(
    session: Session,
    sample_id: int,
    *,
    agrees: bool,
    review_verdict: Optional[str],
    reviewer: str,
    notes: Optional[str] = None,
    tenant_id: str = DEFAULT_TENANT,
) -> dict[str, Any]:
    """Record an analyst's review. Agreeing takes the AI's verdict as the answer."""
    row = session.execute(
        text(
            "SELECT verdict->>'verdict' AS ai_verdict, reviewed_at FROM qa_samples "
            "WHERE id = :id AND tenant_id = :t"
        ),
        {"id": sample_id, "t": tenant_id},
    ).first()
    if row is None:
        raise SampleNotFound(sample_id)
    if row.reviewed_at is not None:
        raise SampleAlreadyReviewed(sample_id)

    ai_verdict = row.ai_verdict
    if agrees:
        if review_verdict is not None and review_verdict != ai_verdict:
            raise InvalidReview(
                f"agreeing with a {ai_verdict} verdict cannot name {review_verdict}"
            )
        review_verdict = ai_verdict
    else:
        if review_verdict is None:
            raise InvalidReview("a disagreement must name the correct verdict")
        if review_verdict == ai_verdict:
            raise InvalidReview(
                f"a disagreement must name a verdict other than {ai_verdict}"
            )

    updated = session.execute(
        text(
            "UPDATE qa_samples SET reviewer = :r, reviewed_at = :at, "
            "review_verdict = :rv, agrees = :a, notes = :n "
            "WHERE id = :id AND tenant_id = :t AND reviewed_at IS NULL RETURNING id"
        ),
        {
            "r": reviewer,
            "at": utcnow(),
            "rv": review_verdict,
            "a": agrees,
            "n": notes,
            "id": sample_id,
            "t": tenant_id,
        },
    ).first()
    if updated is None:  # a concurrent review won
        raise SampleAlreadyReviewed(sample_id)
    return list_one(session, sample_id, tenant_id=tenant_id)


def list_one(
    session: Session, sample_id: int, *, tenant_id: str = DEFAULT_TENANT
) -> dict[str, Any]:
    rows = session.execute(
        text(_LIST_SQL.format(status="AND q.id = :id", category="", kind="")),
        {"t": tenant_id, "id": sample_id, "limit": 1},
    ).mappings()
    found = [dict(r) for r in rows]
    if not found:
        raise SampleNotFound(sample_id)
    return found[0]


_COUNTS_SQL = """
SELECT COALESCE(verdict->>'category', 'other') AS category,
       sampling_kind,
       COUNT(*) FILTER (WHERE reviewed_at IS NOT NULL) AS reviewed,
       COUNT(*) FILTER (WHERE reviewed_at IS NULL) AS pending,
       COUNT(*) FILTER (
           WHERE reviewed_at IS NOT NULL
             AND verdict->>'verdict' = 'benign'
             AND review_verdict = 'malicious'
       ) AS misses,
       COUNT(*) FILTER (WHERE reviewed_at IS NOT NULL AND agrees IS FALSE) AS disagreements
FROM qa_samples
WHERE tenant_id = :t AND subject_kind = :k
GROUP BY 1, 2
"""


def category_status(reviewed: int, upper: float, target: float) -> str:
    """``no_data`` before any review, else whether the bound is at or under target."""
    if reviewed == 0:
        return "no_data"
    return "meets" if upper <= target else "not_met"


def scorecard(
    session: Session,
    *,
    target: float = DEFAULT_TARGET,
    confidence: float = DEFAULT_CONFIDENCE,
    tenant_id: str = DEFAULT_TENANT,
) -> dict[str, Any]:
    """Per-category FN upper bounds from simple-random reviews only."""
    empty = {"reviewed": 0, "pending": 0, "misses": 0, "disagreements": 0}
    counts: dict[tuple[str, str], dict[str, int]] = {}
    for r in session.execute(
        text(_COUNTS_SQL), {"t": tenant_id, "k": SUBJECT_KIND}
    ).mappings():
        counts[(r["category"], r["sampling_kind"])] = {
            k: int(r[k]) for k in ("reviewed", "pending", "misses", "disagreements")
        }

    categories = []
    for category in CATEGORIES:
        srs = counts.get((category, SIMPLE_RANDOM), empty)
        rw = counts.get((category, RISK_WEIGHTED), empty)
        n, x = srs["reviewed"], srs["misses"]
        upper = clopper_pearson_upper(x, n, confidence)
        categories.append(
            {
                "category": category,
                "reviewed": n,
                "misses": x,
                "disagreements": srs["disagreements"],
                "pending": srs["pending"],
                "fn_upper_bound": upper,
                "status": category_status(n, upper, target),
                "reviews_needed": reviews_needed(x, n, target, confidence),
                "risk_weighted": {
                    "reviewed": rw["reviewed"],
                    "misses": rw["misses"],
                    "pending": rw["pending"],
                },
            }
        )
    return {"target": target, "confidence": confidence, "categories": categories}
