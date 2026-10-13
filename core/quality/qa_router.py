"""QA sampling and the Scorecard: /api/qa (W1.6).

Draw review samples of the decisions AutoSecOps closed as benign, let analysts
review them, and report per category an exact upper bound on the
false-negative rate computed from the simple-random reviews only. The sampling
and the math live in ``core.quality.sampling`` and ``core.quality.bounds``.

Reads are open to any signed-in user. Drawing samples changes what analysts are
asked to do, so it takes ``ai_decisions.approve``; a review is analyst work on
a verdict, so it takes ``findings.write``.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from core.auth.permissions import permission_gate, require_permission
from core.quality import sampling
from core.quality.bounds import DEFAULT_CONFIDENCE, DEFAULT_TARGET
from core.routing import Auth, RouterMeta, UnitOfWorkSession
from core.storage.models import User

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/qa",
    tags=["qa"],
    auth=Auth.REQUIRED,
)

VerdictValue = Literal["malicious", "benign", "inconclusive"]
CategoryValue = Literal["phishing", "malware", "identity", "network", "cloud", "other"]
SamplingKind = Literal["simple_random", "risk_weighted"]


# ---------------------------------------------------------------- models


class QADrawRequest(BaseModel):
    days: int = Field(7, ge=1, le=365, description="Window of decisions to draw from.")
    per_category: int = Field(
        30, ge=0, le=1000, description="Simple random sample size per category."
    )
    risk_weighted_extra: int = Field(
        0,
        ge=0,
        le=1000,
        description="Expected number of risk-weighted extras. Never enter the bound.",
    )
    seed: Optional[int] = Field(None, description="Seed, for a reproducible draw.")


class QACategoryDraw(BaseModel):
    population: int = Field(
        ..., description="Unsampled auto-closed decisions in the window."
    )
    drawn: int
    inclusion_probability: float


class QARiskWeightedDraw(BaseModel):
    population: int
    drawn: int


class QADrawResponse(BaseModel):
    categories: dict[str, QACategoryDraw]
    risk_weighted: QARiskWeightedDraw


class QASample(BaseModel):
    id: int
    sampling_kind: SamplingKind
    inclusion_probability: float
    subject_kind: str
    subject_id: str
    category: str
    ai_verdict: str
    ai_confidence: Optional[float] = None
    verdict: dict[str, Any]
    sampled_at: datetime
    reviewer: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_verdict: Optional[VerdictValue] = None
    agrees: Optional[bool] = None
    notes: Optional[str] = None
    agent_id: Optional[str] = None
    decision_type: Optional[str] = None
    reasoning: Optional[str] = None
    recommended_action: Optional[str] = None
    finding_id: Optional[str] = None
    case_id: Optional[str] = None
    decided_at: Optional[datetime] = None


class QASampleList(BaseModel):
    samples: list[QASample]
    count: int


class QAReviewRequest(BaseModel):
    agrees: bool = Field(..., description="Whether the AI's verdict was right.")
    review_verdict: Optional[VerdictValue] = Field(
        None, description="The correct verdict. Required when agrees is false."
    )
    notes: Optional[str] = Field(None, max_length=4000)


class QARiskWeightedCounts(BaseModel):
    reviewed: int
    misses: int
    pending: int


class QACategoryScore(BaseModel):
    category: CategoryValue
    reviewed: int = Field(..., description="Simple-random samples reviewed.")
    misses: int = Field(
        ..., description="Reviewed benign closures that were malicious."
    )
    disagreements: int
    pending: int
    fn_upper_bound: float = Field(
        ..., description="One-sided Clopper-Pearson upper bound on the FN rate."
    )
    status: Literal["meets", "not_met", "no_data"]
    reviews_needed: Optional[int] = Field(
        None,
        description="Further agreeing reviews before the bound meets the target.",
    )
    risk_weighted: QARiskWeightedCounts


class QAScorecardResponse(BaseModel):
    target: float
    confidence: float
    categories: list[QACategoryScore]


# ---------------------------------------------------------------- helpers

_INVALID_REVIEW = (
    "A disagreement must name the correct verdict, different from the AI's; "
    "an agreement cannot name a different one."
)


def _sample(row: dict[str, Any]) -> QASample:
    verdict = row.get("verdict") or {}
    confidence = verdict.get("confidence")
    return QASample(
        **{k: row.get(k) for k in QASample.model_fields if k in row},
        category=verdict.get("category") or "other",
        ai_verdict=verdict.get("verdict") or "benign",
        ai_confidence=confidence if isinstance(confidence, (int, float)) else None,
    )


# ---------------------------------------------------------------- routes


@router.post(
    "/samples/draw",
    response_model=QADrawResponse,
    dependencies=[permission_gate("ai_decisions.approve")],
)
def draw_samples(body: QADrawRequest, session: UnitOfWorkSession) -> QADrawResponse:
    """Draw per-category simple random samples (and optional risk-weighted extras)."""
    rng = random.Random(body.seed) if body.seed is not None else random.Random()
    result = sampling.draw_samples(
        session,
        days=body.days,
        per_category=body.per_category,
        risk_weighted_extra=body.risk_weighted_extra,
        rng=rng,
    )
    return QADrawResponse(
        categories={k: QACategoryDraw(**v) for k, v in result.per_category.items()},
        risk_weighted=QARiskWeightedDraw(
            population=result.risk_weighted_population,
            drawn=result.risk_weighted_drawn,
        ),
    )


@router.get("/samples", response_model=QASampleList)
def list_samples(
    session: UnitOfWorkSession,
    status_filter: Literal["pending", "reviewed", "all"] = Query(
        "pending", alias="status"
    ),
    category: Optional[CategoryValue] = None,
    sampling_kind: Optional[SamplingKind] = None,
    limit: int = Query(100, ge=1, le=500),
) -> QASampleList:
    """The review queue (``status=pending``) or past reviews, oldest first."""
    rows = sampling.list_samples(
        session,
        status=status_filter,
        category=category,
        sampling_kind=sampling_kind,
        limit=limit,
    )
    samples = [_sample(r) for r in rows]
    return QASampleList(samples=samples, count=len(samples))


@router.post("/samples/{sample_id}/review", response_model=QASample)
def review_sample(
    sample_id: int,
    body: QAReviewRequest,
    session: UnitOfWorkSession,
    user: User = Depends(require_permission("findings.write")),
) -> QASample:
    """Record whether the AI's benign closure was right, and if not what was."""
    try:
        row = sampling.review_sample(
            session,
            sample_id,
            agrees=body.agrees,
            review_verdict=body.review_verdict,
            reviewer=user.username,
            notes=body.notes,
        )
    except sampling.SampleNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "QA sample not found")
    except sampling.SampleAlreadyReviewed:
        raise HTTPException(status.HTTP_409_CONFLICT, "QA sample is already reviewed")
    except sampling.InvalidReview:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, _INVALID_REVIEW)
    return _sample(row)


@router.get("/scorecard", response_model=QAScorecardResponse)
def get_scorecard(
    session: UnitOfWorkSession,
    target: float = Query(DEFAULT_TARGET, gt=0, lt=1),
    confidence: float = Query(DEFAULT_CONFIDENCE, gt=0, lt=1),
) -> QAScorecardResponse:
    """Per category: reviews, misses and the FN upper bound against the target."""
    data = sampling.scorecard(session, target=target, confidence=confidence)
    return QAScorecardResponse(**data)
