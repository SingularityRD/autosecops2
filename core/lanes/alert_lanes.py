"""Alert lanes: route each stored finding to the cheapest path that can settle it.

Three lanes, chosen before any LLM call:

``rules``
    An enabled, unexpired ``suppression_rules`` row of the finding's tenant
    matches, or a known playbook declared in INTENT.md does. The outcome is
    deterministic and no model is called.
``small_model``
    Low difficulty. The processor's existing structured triage runs, on the
    cheaper / local model named by ``ALERT_LANES_SMALL_PROVIDER`` and
    ``ALERT_LANES_SMALL_MODEL`` (an Ollama model behind Bifrost, say).
``verdict``
    Uncertain or high risk. A ``verdict`` run is enqueued through an injected
    function; the run kind belongs to another work package, so without both the
    function and ``ALERT_LANES_VERDICT_ENABLED`` this lane degrades to
    ``small_model`` and marks the finding ``deferred_verdict``.

Budget pressure degrades ``verdict`` to ``small_model`` and queues the finding
for a verdict run once the pressure lifts. No path drops a finding: every
decision leaves the finding stored (intake stored it before routing) and either
triaged, deterministically settled, or enqueued, with the decision written to
``ai_enrichment.alert_lane`` and, by the daemon's recorder, a tenant-scoped row
in ``alert_lane_decisions`` (core/lanes/decision_store.py).

Thresholds come from the ``alert_lanes:`` section of INTENT.md and are enforced
only while ``ALERT_LANES_ENABLED`` is on (default off: the hook is a no-op).
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
import time
from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Awaitable,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)

logger = logging.getLogger(__name__)

LANE_RULES = "rules"
LANE_SMALL = "small_model"
LANE_VERDICT = "verdict"
LANES = (LANE_RULES, LANE_SMALL, LANE_VERDICT)

# Finding key the decision is written under; the processor persists it inside
# ai_enrichment with the rest of the AI analysis.
ENRICHMENT_KEY = "alert_lane"

DEFAULT_TENANT = "default"

SEVERITY_RANK = {
    "info": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_SEVERITY_WEIGHT = {"critical": 0.5, "high": 0.35, "medium": 0.15, "low": 0.05}
_CRITICALITY_WEIGHT = {"critical": 0.25, "high": 0.15, "medium": 0.05}
_SOURCE_WEIGHT = 0.15
_LOW_CONFIDENCE_WEIGHT = 0.15
_HIGH_CONFIDENCE_WEIGHT = -0.10
_INCONCLUSIVE_WEIGHT = 0.25

# The responder's vocabulary (services/daemon/probes.ACTIONS); core can't import it.
PLAYBOOK_ACTIONS = frozenset({"isolate", "block", "investigate", "monitor", "dismiss"})

VerdictEnqueuer = Callable[
    [Dict[str, Any], "LaneDecision"], Union[Optional[str], Awaitable[Optional[str]]]
]


# --------------------------------------------------------------------------
# Rules and thresholds
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SuppressionRule:
    id: str
    tenant_id: str
    name: str
    match: Mapping[str, Any]
    reason: str = ""
    enabled: bool = True
    expires_at: Optional[datetime] = None  # timezone-aware

    def active(self, now: datetime) -> bool:
        if not self.enabled:
            return False
        if self.expires_at is None:
            return True
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires > now


@dataclass(frozen=True)
class KnownPlaybook:
    name: str
    match: Mapping[str, Any]
    recommended_action: str
    reason: str = ""


@dataclass(frozen=True)
class LaneThresholds:
    verdict_risk_threshold: float = 0.6
    verdict_severities: FrozenSet[str] = frozenset({"critical"})
    # Severities above this are never suppressed (critical, by default).
    suppress_max_severity: str = "high"
    low_confidence: float = 0.7
    high_confidence: float = 0.9
    high_risk_sources: FrozenSet[str] = frozenset()
    known_playbooks: Tuple[KnownPlaybook, ...] = ()


INTENT_SECTION = "alert_lanes"


def _unit_float(raw: Any, name: str, default: float) -> float:
    if (
        isinstance(raw, bool)
        or not isinstance(raw, (int, float))
        or not 0.0 <= raw <= 1.0
    ):
        logger.warning(
            "INTENT.md alert_lanes.%s=%r is not a number in [0, 1]; using %s",
            name,
            raw,
            default,
        )
        return default
    return float(raw)


def _str_set(raw: Any, name: str, default: FrozenSet[str]) -> FrozenSet[str]:
    if not isinstance(raw, list) or not all(isinstance(v, str) for v in raw):
        logger.warning(
            "INTENT.md alert_lanes.%s=%r is not a list of strings; using default",
            name,
            raw,
        )
        return default
    return frozenset(v.strip().lower() for v in raw)


def _playbooks(raw: Any) -> Tuple[KnownPlaybook, ...]:
    if not isinstance(raw, list):
        logger.warning("INTENT.md alert_lanes.known_playbooks is not a list; ignored")
        return ()
    out: List[KnownPlaybook] = []
    for item in raw:
        if not isinstance(item, dict):
            logger.warning(
                "INTENT.md known playbook %r is not a mapping; ignored", item
            )
            continue
        name, match = item.get("name"), item.get("match")
        action = str(item.get("recommended_action") or "").lower()
        if (
            not name
            or not isinstance(match, dict)
            or not match
            or action not in PLAYBOOK_ACTIONS
        ):
            logger.warning(
                "INTENT.md known playbook %r needs name, match and a known action; ignored",
                name,
            )
            continue
        out.append(
            KnownPlaybook(str(name), match, action, str(item.get("reason") or ""))
        )
    return tuple(out)


def thresholds_from_mapping(section: Mapping[str, Any]) -> LaneThresholds:
    """Thresholds from the ``alert_lanes`` mapping; a bad value keeps its default."""
    d = LaneThresholds()
    kwargs: Dict[str, Any] = {}
    for name in ("verdict_risk_threshold", "low_confidence", "high_confidence"):
        if name in section:
            kwargs[name] = _unit_float(section[name], name, getattr(d, name))
    for name in ("verdict_severities", "high_risk_sources"):
        if name in section:
            kwargs[name] = _str_set(section[name], name, getattr(d, name))
    if "suppress_max_severity" in section:
        raw = str(section["suppress_max_severity"]).lower()
        if raw in SEVERITY_RANK:
            kwargs["suppress_max_severity"] = raw
        else:
            logger.warning(
                "INTENT.md alert_lanes.suppress_max_severity=%r unknown; using %s",
                raw,
                d.suppress_max_severity,
            )
    if "known_playbooks" in section:
        kwargs["known_playbooks"] = _playbooks(section["known_playbooks"])
    unknown = sorted(set(section) - set(LaneThresholds.__dataclass_fields__))
    for name in unknown:
        logger.warning("INTENT.md key 'alert_lanes.%s' has no reader; ignored", name)
    return replace(d, **kwargs)


def load_thresholds(path: Optional[Path] = None) -> LaneThresholds:
    """The ``alert_lanes:`` section of INTENT.md, defaults where absent or unreadable."""
    from core.frontmatter import FrontmatterError, split_frontmatter
    from core.intent import intent_file

    path = path or intent_file()
    try:
        front, _ = split_frontmatter(path.read_text(encoding="utf-8"))
    except (OSError, FrontmatterError) as exc:
        logger.warning(
            "alert lane thresholds: INTENT.md not read (%s): %s; using defaults",
            path,
            exc,
        )
        return LaneThresholds()
    section = (front or {}).get(INTENT_SECTION)
    if section is None:
        return LaneThresholds()
    if not isinstance(section, dict):
        logger.warning("INTENT.md alert_lanes is not a mapping; using defaults")
        return LaneThresholds()
    return thresholds_from_mapping(section)


# --------------------------------------------------------------------------
# Predicate documents
# --------------------------------------------------------------------------

_MISSING = object()


def _lookup(finding: Mapping[str, Any], path: str) -> Any:
    target: Any = finding
    for part in path.split("."):
        if not isinstance(target, Mapping) or part not in target:
            return _MISSING
        target = target[part]
    return target


def _eq(have: Any, want: Any) -> bool:
    if isinstance(have, str) and isinstance(want, str):
        return have.strip().lower() == want.strip().lower()
    if isinstance(have, bool) or isinstance(want, bool):
        return have is want
    return have == want


def _value_matches(have: Any, cond: Any) -> Optional[bool]:
    """True/False, or None for a condition this evaluator doesn't understand."""
    if isinstance(cond, Mapping):
        if len(cond) != 1:
            return None
        ((op, arg),) = cond.items()
        if op == "contains" and isinstance(arg, str):
            return isinstance(have, str) and arg.lower() in have.lower()
        if op == "in" and isinstance(arg, list):
            return any(_eq(have, a) for a in arg)
        return None
    if isinstance(cond, list):
        return any(_eq(have, c) for c in cond)
    return _eq(have, cond)


def matches(match: Any, finding: Mapping[str, Any]) -> bool:
    """Whether every key of a predicate document holds for ``finding``.

    Keys are dotted paths into the finding; a list-valued field matches when any
    element does. An empty document, a missing field or an operator this
    evaluator doesn't know is no match: a suppression must never widen by accident.
    """
    if not isinstance(match, Mapping) or not match:
        return False
    for path, cond in match.items():
        have = _lookup(finding, str(path))
        if have is _MISSING or have is None:
            return False
        values = have if isinstance(have, list) else [have]
        results = [_value_matches(v, cond) for v in values]
        if any(r is None for r in results) or not any(results):
            return False
    return True


# --------------------------------------------------------------------------
# Risk / difficulty
# --------------------------------------------------------------------------


def _severity(finding: Mapping[str, Any]) -> str:
    return str(finding.get("severity") or "").strip().lower()


def _criticality(finding: Mapping[str, Any]) -> str:
    ctx = finding.get("entity_context") or {}
    for source in (ctx if isinstance(ctx, Mapping) else {}, finding):
        for key in ("criticality", "asset_criticality", "entity_criticality"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
    return ""


def _prior_verdict(finding: Mapping[str, Any]) -> Tuple[Optional[str], Optional[float]]:
    """(verdict label, confidence) from an earlier verdict or triage, if any."""
    label: Optional[str] = None
    confidence: Optional[float] = None
    for container in (finding, finding.get("ai_enrichment") or {}):
        if not isinstance(container, Mapping):
            continue
        prior = container.get("verdict") or container.get("prior_verdict")
        if isinstance(prior, Mapping):
            label = label or (
                str(prior.get("verdict") or prior.get("label") or "").lower() or None
            )
            raw = prior.get("confidence")
            if (
                confidence is None
                and isinstance(raw, (int, float))
                and not isinstance(raw, bool)
            ):
                confidence = float(raw)
        elif isinstance(prior, str) and not label:
            label = prior.lower()
    raw = finding.get("triage_confidence")
    if (
        confidence is None
        and isinstance(raw, (int, float))
        and not isinstance(raw, bool)
    ):
        confidence = float(raw)
    return label, confidence


def score_risk(
    finding: Mapping[str, Any], th: LaneThresholds
) -> Tuple[float, List[str]]:
    """Difficulty/risk in [0, 1] and the factors that produced it."""
    score = 0.0
    factors: List[str] = []
    sev = _severity(finding)
    if sev in _SEVERITY_WEIGHT:
        score += _SEVERITY_WEIGHT[sev]
        factors.append(f"severity:{sev}")
    crit = _criticality(finding)
    if crit in _CRITICALITY_WEIGHT:
        score += _CRITICALITY_WEIGHT[crit]
        factors.append(f"entity_criticality:{crit}")
    source = str(finding.get("data_source") or finding.get("source") or "").lower()
    if source and source in th.high_risk_sources:
        score += _SOURCE_WEIGHT
        factors.append(f"high_risk_source:{source}")
    label, confidence = _prior_verdict(finding)
    if confidence is not None and 0.0 <= confidence <= 1.0:
        if confidence < th.low_confidence:
            score += _LOW_CONFIDENCE_WEIGHT
            factors.append("low_prior_confidence")
        elif confidence >= th.high_confidence:
            score += _HIGH_CONFIDENCE_WEIGHT
            factors.append("high_prior_confidence")
    if label == "inconclusive" or finding.get("ai_triage_error"):
        score += _INCONCLUSIVE_WEIGHT
        factors.append("inconclusive")
    return round(min(1.0, max(0.0, score)), 3), factors


# --------------------------------------------------------------------------
# Decision
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LaneDecision:
    finding_id: str
    tenant_id: str
    lane: str
    reason: str
    risk: float
    factors: Tuple[str, ...] = ()
    rule: Optional[Dict[str, str]] = None  # {"kind", "id", "name"}
    outcome: Optional[Dict[str, Any]] = None
    deferred_verdict: bool = False
    degraded_from: Optional[str] = None
    verdict_run_id: Optional[str] = None
    model: Optional[str] = None
    decided_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_enrichment(self) -> Dict[str, Any]:
        return {
            "lane": self.lane,
            "reason": self.reason,
            "risk": self.risk,
            "factors": list(self.factors),
            "tenant_id": self.tenant_id,
            "rule": self.rule,
            "outcome": self.outcome,
            "deferred_verdict": self.deferred_verdict,
            "degraded_from": self.degraded_from,
            "verdict_run_id": self.verdict_run_id,
            "model": self.model,
            "decided_at": self.decided_at,
        }


def tenant_of(finding: Mapping[str, Any]) -> str:
    return str(finding.get("tenant_id") or DEFAULT_TENANT)


def decide_lane(
    finding: Mapping[str, Any],
    *,
    now: datetime,
    rules: Sequence[SuppressionRule] = (),
    thresholds: Optional[LaneThresholds] = None,
    budget_pressure: bool = False,
    verdict_available: bool = False,
) -> LaneDecision:
    """Pure lane choice for one finding. Never raises on odd finding shapes."""
    th = thresholds or LaneThresholds()
    finding_id = str(finding.get("finding_id") or "unknown")
    tenant = tenant_of(finding)
    sev = _severity(finding)
    risk, factors = score_risk(finding, th)
    base = dict(finding_id=finding_id, tenant_id=tenant, risk=risk)

    # Lane 1a: an analyst's suppression, if live, same tenant, and the severity allows.
    sev_rank = SEVERITY_RANK.get(sev, SEVERITY_RANK["medium"])
    suppressible = sev_rank <= SEVERITY_RANK[th.suppress_max_severity]
    for rule in rules:
        if (
            rule.tenant_id != tenant
            or not rule.active(now)
            or not matches(rule.match, finding)
        ):
            continue
        if not suppressible:
            factors.append(f"suppression_ignored:{rule.name}")
            continue
        return LaneDecision(
            lane=LANE_RULES,
            reason="suppression_rule",
            factors=tuple(factors),
            rule={"kind": "suppression", "id": rule.id, "name": rule.name},
            outcome={
                "suppressed": True,
                "recommended_action": "dismiss",
                "note": rule.reason,
            },
            **base,
        )

    # Lane 1b: a known playbook declared in INTENT.md.
    for pb in th.known_playbooks:
        if matches(pb.match, finding):
            return LaneDecision(
                lane=LANE_RULES,
                reason="known_playbook",
                factors=tuple(factors),
                rule={"kind": "playbook", "id": pb.name, "name": pb.name},
                outcome={
                    "suppressed": False,
                    "recommended_action": pb.recommended_action,
                    "note": pb.reason,
                },
                **base,
            )

    wants_verdict = risk >= th.verdict_risk_threshold or sev in th.verdict_severities
    if not wants_verdict:
        return LaneDecision(
            lane=LANE_SMALL, reason="low_difficulty", factors=tuple(factors), **base
        )

    reason = "high_risk" if risk >= th.verdict_risk_threshold else "verdict_severity"
    if budget_pressure:
        return LaneDecision(
            lane=LANE_SMALL,
            reason="budget_pressure",
            factors=tuple(factors) + (reason,),
            deferred_verdict=True,
            degraded_from=LANE_VERDICT,
            **base,
        )
    if not verdict_available:
        return LaneDecision(
            lane=LANE_SMALL,
            reason="verdict_lane_unavailable",
            factors=tuple(factors) + (reason,),
            deferred_verdict=True,
            degraded_from=LANE_VERDICT,
            **base,
        )
    return LaneDecision(
        lane=LANE_VERDICT, reason=reason, factors=tuple(factors), **base
    )


# --------------------------------------------------------------------------
# Budget signal
# --------------------------------------------------------------------------


class BudgetPressure:
    """A fuse: ``trip()`` reports pressure for ``cooldown`` seconds, or ``probe`` does."""

    def __init__(
        self,
        cooldown_seconds: float = 300.0,
        probe: Optional[Callable[[], bool]] = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._cooldown = cooldown_seconds
        self._probe = probe
        self._clock = clock
        self._until = 0.0

    def trip(self) -> None:
        self._until = self._clock() + self._cooldown

    def __call__(self) -> bool:
        if self._clock() < self._until:
            return True
        if self._probe is None:
            return False
        try:
            return bool(self._probe())
        except Exception as exc:  # noqa: BLE001
            # An unreadable budget reads as pressure: degrade, don't overspend.
            logger.warning("budget pressure probe failed, assuming pressure: %s", exc)
            return True


def _is_budget_error(exc: BaseException) -> bool:
    try:
        from core.llm.cost.budget import BudgetExceeded
    except Exception:  # noqa: BLE001
        return False
    return isinstance(exc, BudgetExceeded)


def log_decision(decision: LaneDecision) -> None:
    logger.info(
        "alert lane %s for %s (tenant %s): %s risk=%.3f%s",
        decision.lane,
        decision.finding_id,
        decision.tenant_id,
        decision.reason,
        decision.risk,
        " deferred_verdict" if decision.deferred_verdict else "",
    )


# --------------------------------------------------------------------------
# Router
# --------------------------------------------------------------------------


class AlertLanes:
    """Decides, enqueues verdict runs, defers under budget pressure, records.

    Every collaborator is injected; ``route`` never raises and always returns a
    decision, falling back to ``small_model`` (the pre-lanes behaviour) on error.
    """

    def __init__(
        self,
        *,
        thresholds: Optional[LaneThresholds] = None,
        rules_source: Optional[Callable[[str], Sequence[SuppressionRule]]] = None,
        on_suppression_hit: Optional[Callable[[SuppressionRule], None]] = None,
        budget_pressure: Optional[Callable[[], bool]] = None,
        verdict_enqueuer: Optional[VerdictEnqueuer] = None,
        verdict_enabled: bool = False,
        recorder: Optional[Callable[[LaneDecision], None]] = None,
        small_target: Optional[Tuple[str, str]] = None,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        max_deferred: int = 10_000,
    ):
        self.thresholds = thresholds or LaneThresholds()
        self._rules_source = rules_source or (lambda _tenant: ())
        self._on_hit = on_suppression_hit
        self.budget = (
            budget_pressure if budget_pressure is not None else BudgetPressure()
        )
        self.verdict_enqueuer = verdict_enqueuer
        self.verdict_enabled = verdict_enabled
        self._recorder = recorder or log_decision
        # (provider_id, model) of the small-model lane; None: the default triage model.
        self.small_target = small_target
        self._clock = clock
        self._max_deferred = max_deferred
        self._deferred: Deque[Tuple[Dict[str, Any], LaneDecision]] = deque()
        self._deferred_lock = threading.Lock()
        self.stats: Dict[str, int] = {lane: 0 for lane in LANES}
        self.stats.update(deferred=0, deferred_overflow=0, verdict_enqueued=0, errors=0)

    # -- verdict availability / budget ------------------------------------

    @property
    def verdict_available(self) -> bool:
        return self.verdict_enabled and self.verdict_enqueuer is not None

    def _pressure(self) -> bool:
        try:
            return bool(self.budget())
        except Exception as exc:  # noqa: BLE001
            logger.warning("budget pressure unreadable, assuming pressure: %s", exc)
            return True

    def _trip_budget(self) -> None:
        trip = getattr(self.budget, "trip", None)
        if callable(trip):
            trip()

    async def _enqueue(
        self, finding: Dict[str, Any], decision: LaneDecision
    ) -> Optional[str]:
        assert self.verdict_enqueuer is not None
        result = self.verdict_enqueuer(finding, decision)
        if inspect.isawaitable(result):
            result = await result
        return None if result is None else str(result)

    # -- deferred verdicts -------------------------------------------------

    @property
    def deferred_count(self) -> int:
        return len(self._deferred)

    def _defer(self, finding: Dict[str, Any], decision: LaneDecision) -> None:
        # Only worth holding in memory when something can drain it. Without an
        # enqueuer, ai_enrichment.alert_lane.deferred_verdict is the durable mark.
        if not self.verdict_available:
            return
        with self._deferred_lock:
            if len(self._deferred) >= self._max_deferred:
                self.stats["deferred_overflow"] += 1
                logger.warning(
                    "deferred verdict queue full (%d); %s keeps only its durable "
                    "deferred_verdict mark",
                    self._max_deferred,
                    decision.finding_id,
                )
                return
            self._deferred.append((dict(finding), decision))
        self.stats["deferred"] += 1

    async def drain_deferred(self, limit: int = 50) -> int:
        """Enqueue held verdicts while there is no budget pressure; returns count."""
        sent = 0
        while sent < limit and self.verdict_available and not self._pressure():
            with self._deferred_lock:
                if not self._deferred:
                    break
                finding, decision = self._deferred.popleft()
            try:
                await self._enqueue(finding, replace(decision, lane=LANE_VERDICT))
            except Exception as exc:  # noqa: BLE001
                with self._deferred_lock:
                    self._deferred.appendleft((finding, decision))
                if _is_budget_error(exc):
                    self._trip_budget()
                logger.warning(
                    "deferred verdict for %s not enqueued yet: %s",
                    decision.finding_id,
                    exc,
                )
                break
            sent += 1
            self.stats["verdict_enqueued"] += 1
        return sent

    # -- routing -------------------------------------------------------------

    async def route(self, finding: Dict[str, Any]) -> LaneDecision:
        try:
            decision = await self._route(finding)
        except Exception as exc:  # noqa: BLE001
            self.stats["errors"] += 1
            logger.error(
                "alert lane routing failed for %s: %s", finding.get("finding_id"), exc
            )
            decision = LaneDecision(
                finding_id=str(finding.get("finding_id") or "unknown"),
                tenant_id=tenant_of(finding),
                lane=LANE_SMALL,
                reason="router_error",
                risk=0.0,
            )
        if decision.lane == LANE_SMALL and decision.model is None:
            label = "/".join(self.small_target) if self.small_target else "default"
            decision = replace(decision, model=label)
        self.stats[decision.lane] = self.stats.get(decision.lane, 0) + 1
        try:
            # The default recorder writes a row; keep the database off the loop.
            await asyncio.to_thread(self._recorder, decision)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "alert lane decision not recorded for %s: %s", decision.finding_id, exc
            )
        return decision

    async def _route(self, finding: Dict[str, Any]) -> LaneDecision:
        tenant = tenant_of(finding)
        try:
            rules = await asyncio.to_thread(self._rules_source, tenant)
        except Exception as exc:  # noqa: BLE001
            logger.warning("suppression rules unavailable for %s: %s", tenant, exc)
            rules = ()

        if self._deferred:
            await self.drain_deferred()

        pressure = self._pressure()
        decision = decide_lane(
            finding,
            now=self._clock(),
            rules=rules,
            thresholds=self.thresholds,
            budget_pressure=pressure,
            verdict_available=self.verdict_available,
        )

        if (
            decision.rule
            and decision.rule.get("kind") == "suppression"
            and self._on_hit
        ):
            hit = next((r for r in rules if r.id == decision.rule["id"]), None)
            if hit is not None:
                await asyncio.to_thread(self._on_hit, hit)

        if decision.lane == LANE_VERDICT:
            try:
                run_id = await self._enqueue(finding, decision)
            except Exception as exc:  # noqa: BLE001
                budget = _is_budget_error(exc)
                if budget:
                    self._trip_budget()
                logger.warning(
                    "verdict run not enqueued for %s: %s", decision.finding_id, exc
                )
                decision = replace(
                    decision,
                    lane=LANE_SMALL,
                    reason="budget_pressure" if budget else "verdict_enqueue_failed",
                    factors=decision.factors + (decision.reason,),
                    deferred_verdict=True,
                    degraded_from=LANE_VERDICT,
                )
            else:
                self.stats["verdict_enqueued"] += 1
                decision = replace(decision, verdict_run_id=run_id)

        if decision.deferred_verdict:
            self._defer(finding, decision)
        return decision


# --------------------------------------------------------------------------
# Processor hook
# --------------------------------------------------------------------------

# The (provider_id, model) the current task's triage should use. Set by the hook
# for the small-model lane; read by the processor's triage target resolution.
# Each background enrich runs in its own asyncio task, so the value never leaks
# from one finding to the next.
_TRIAGE_TARGET: ContextVar[Optional[Tuple[str, str]]] = ContextVar(
    "alert_lane_triage_target", default=None
)


def lane_triage_target() -> Optional[Tuple[str, str]]:
    """The small-model override for this task's triage, or None for the default."""
    return _TRIAGE_TARGET.get()


def resolve_small_model(provider_id: str, model: str) -> Optional[Tuple[str, str]]:
    """(provider_id, model) for the small-model lane; None when not configured."""
    if not provider_id and not model:
        return None
    from core.llm.target import model_for, provider_for

    provider = provider_for(provider_id or None)
    if provider is None:
        return None
    return provider.provider_id, model_for(
        provider, model or None, None, "triage_small"
    )


def wants_llm_triage(finding: Mapping[str, Any]) -> bool:
    """False when the lane already settled the finding (rules, or an enqueued verdict)."""
    lane = finding.get(ENRICHMENT_KEY)
    if not isinstance(lane, Mapping):
        return True
    if lane.get("lane") == LANE_RULES:
        return False
    if lane.get("lane") == LANE_VERDICT and lane.get("verdict_run_id"):
        return False
    return True


def apply_decision(finding: Dict[str, Any], decision: LaneDecision) -> None:
    """Write the decision onto the finding (persisted in ai_enrichment)."""
    finding[ENRICHMENT_KEY] = decision.to_enrichment()
    if decision.lane == LANE_RULES and decision.outcome:
        action = decision.outcome.get("recommended_action")
        if action in PLAYBOOK_ACTIONS:
            finding["recommended_action"] = action


class LaneHook:
    """The processor's one call: ``await hook(finding)`` before triage.

    A no-op returning None while ``ALERT_LANES_ENABLED`` is off. The verdict WP
    assigns ``verdict_enqueuer``; ``ALERT_LANES_VERDICT_ENABLED`` gates its use.
    """

    def __init__(
        self,
        lanes: Optional[AlertLanes] = None,
        enabled: Optional[Callable[[], bool]] = None,
    ):
        self._lanes = lanes
        self._enabled = enabled
        self.verdict_enqueuer: Optional[VerdictEnqueuer] = None

    def _is_enabled(self) -> bool:
        if self._enabled is not None:
            return bool(self._enabled())
        from core.config import get_settings

        return bool(get_settings().alert_lanes_enabled)

    def _build(self) -> AlertLanes:
        from core.config import get_settings
        from core.lanes.decision_store import record_decision
        from core.lanes.suppression_store import CachedRules, record_hit

        settings = get_settings()
        return AlertLanes(
            thresholds=load_thresholds(),
            rules_source=CachedRules(),
            on_suppression_hit=record_hit,
            recorder=record_decision,
            verdict_enabled=settings.alert_lanes_verdict_enabled,
            small_target=resolve_small_model(
                settings.alert_lanes_small_provider, settings.alert_lanes_small_model
            ),
        )

    @property
    def lanes(self) -> Optional[AlertLanes]:
        return self._lanes

    async def __call__(self, finding: Dict[str, Any]) -> Optional[LaneDecision]:
        try:
            if not self._is_enabled():
                return None
            if self._lanes is None:
                self._lanes = self._build()
            if self.verdict_enqueuer is not None:
                self._lanes.verdict_enqueuer = self.verdict_enqueuer
            decision = await self._lanes.route(finding)
            apply_decision(finding, decision)
            small = decision.lane == LANE_SMALL
            _TRIAGE_TARGET.set(self._lanes.small_target if small else None)
            return decision
        except Exception as exc:  # noqa: BLE001
            # The lanes are an optimisation; the finding takes the default path.
            logger.error(
                "alert lane hook failed for %s: %s", finding.get("finding_id"), exc
            )
            return None
