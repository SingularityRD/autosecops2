"""Run cases through the triage path with a given backend."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from evalkit.backends import Backend, BackendResult
from evalkit.corpus import Case
from evalkit.triage import apply_result, build_prompt, legacy_verdict, prompt_hash


@dataclass
class CaseResult:
    case: Case
    prompt_sha256: str
    expected_verdict: str
    expected_category: Optional[str]
    actual_verdict: str
    actual_category: str
    confidence: float
    recommended_action: Optional[Dict[str, str]]
    raw_action: Optional[str]
    raw_category: Optional[str]
    verdict: Optional[Dict[str, Any]]
    latency_ms: Optional[int]
    cost_usd: Optional[float]
    error: Optional[str]
    cassette_miss: bool = False
    provenance_downgraded: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def case_id(self) -> str:
        return self.case.case_id


async def run_case(
    case: Case,
    backend: Backend,
    *,
    prompt_version: str,
    provenance: str = "off",
) -> CaseResult:
    prompt = build_prompt(case.alert)
    try:
        answer = await backend.complete(prompt)
    except Exception as exc:  # noqa: BLE001 — a crashing backend is one errored case
        answer = BackendResult(
            content=None, model=backend.model, error=f"{type(exc).__name__}: {exc}"
        )

    finding = None
    error = answer.error
    if answer.content is not None and not answer.error:
        finding = apply_result(case.alert, answer.content)
    elif error is None:
        error = "empty model answer"

    decision = legacy_verdict(
        case.alert,
        finding,
        model=answer.model or backend.model,
        prompt_version=prompt_version,
        provenance=provenance,
        error=error,
    )
    v = decision.verdict
    action = v.recommended_action
    return CaseResult(
        case=case,
        prompt_sha256=prompt_hash(prompt),
        expected_verdict=case.expected_verdict,
        expected_category=case.expected_category,
        actual_verdict=v.verdict,
        actual_category=v.category,
        confidence=v.confidence,
        recommended_action=(
            {"type": action.type, "target": action.target} if action else None
        ),
        raw_action=decision.raw_action,
        raw_category=decision.raw_category,
        verdict=v.to_json_dict() if error is None else None,
        latency_ms=answer.latency_ms,
        cost_usd=answer.cost_usd,
        error=error,
        cassette_miss=answer.cassette_miss,
        provenance_downgraded=decision.provenance_downgraded,
    )


async def run_cases(
    cases: Sequence[Case],
    backend: Backend,
    *,
    prompt_version: str,
    provenance: str = "off",
    concurrency: int = 4,
) -> List[CaseResult]:
    """All cases, results in input order."""
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(case: Case) -> CaseResult:
        async with sem:
            return await run_case(
                case, backend, prompt_version=prompt_version, provenance=provenance
            )

    return list(await asyncio.gather(*(one(c) for c in cases)))
