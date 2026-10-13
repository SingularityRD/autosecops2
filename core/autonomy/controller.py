"""The autonomy controller (W3.1): one decision per proposed action.

``decide`` answers, for an action about to be recorded, which tier governs it:

* the configured tier for (category, action class): the exact row, else the
  category ``*`` row, else ``approve`` (the GA default);
* ``autonomous`` holds only when every one of these is true, else the action
  is treated as ``approve``:

  - the class is in ``AUTONOMOUS_ELIGIBLE`` (reversible by nature);
  - the action is ``reversible`` (the row's claim and, at dispatch, the
    executor registry's);
  - the class is not under the two-person rule;
  - the row carries a ttl (``max_ttl_seconds``) and a confidence floor
    (``min_confidence``) the action's confidence reaches;
  - the category's W1.6 bound holds (``bounds.judge``).

When the bound is readable and does not hold, the controller does more than
refuse this one action: it demotes the stored row to ``approve`` (the circuit
breaker), audits why, and logs a warning. Only a person, with an evidence
link, raises a tier again (``set_tier``); the breaker only lowers.

Irreversible actions are never autonomous: no stored row, API call or
argument makes ``decide`` return ``autonomous`` for one. The response policy
still runs on every action before an executor; a tier never skips it.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

from core.autonomy.bounds import BoundReader, BoundStatus, read_bounds, safe_bound
from core.autonomy.store import SqlTierStore, TierStore
from core.autonomy.tiers import (
    ACTION_CLASSES,
    ANY_CATEGORY,
    APPROVE,
    AUTONOMOUS,
    AUTONOMOUS_ELIGIBLE,
    AUTONOMOUS_MAX_TTL_SECONDS,
    DEFAULT_TIER,
    FN_BOUND_MIN_REVIEWS,
    FN_BOUND_TARGET,
    NEVER_AUTONOMOUS_CATEGORIES,
    TIER_CATEGORIES,
    TIERS,
    WATCH,
    TierEntry,
    normalise_category,
)

logger = logging.getLogger(__name__)

#: ``changed_by`` on the audit rows the circuit breaker writes.
BREAKER_ACTOR = "system:autonomy-breaker"

_RANK = {tier: i for i, tier in enumerate(TIERS)}


class AutonomyWatchOnly(ValueError):
    """The tier is ``watch``: the action is observed, not recorded."""


class PromotionRefused(ValueError):
    """A tier change was refused. ``code``: invalid | actor | bound."""

    def __init__(self, message: str, code: str = "invalid") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class AutonomyDecision:
    """The tier that governs one action, and why.

    ``configured`` is the stored (or default) tier, ``effective`` the one
    applied. ``rule`` has the ``decision_rule`` shape (``autonomy.tier=...``)
    so it can close an approval row's reason like the other rules.
    """

    category: str
    action_type: str
    configured: str
    effective: str
    reasons: tuple[str, ...] = ()
    ttl_seconds: Optional[int] = None
    min_confidence: Optional[float] = None
    bound: Optional[BoundStatus] = None
    demoted: bool = False

    @property
    def rule(self) -> str:
        return f"autonomy.tier={self.effective}"

    @property
    def autonomous(self) -> bool:
        return self.effective == AUTONOMOUS

    def record(self) -> dict[str, Any]:
        """What the approval row keeps of the decision (``parameters.autonomy``)."""
        return {
            "category": self.category,
            "configured": self.configured,
            "effective": self.effective,
            "reasons": list(self.reasons),
            "ttl_seconds": self.ttl_seconds,
            "demoted": self.demoted,
        }


@dataclass
class _Snapshot:
    entries: dict[tuple[str, str], TierEntry] = field(default_factory=dict)


def _valid_url(value: Optional[str]) -> bool:
    """An absolute https link with a host: no whitespace, controls or userinfo.

    The link is shown to auditors as the evidence a raise rests on, so it has
    to be one they can open as written: ``https://host[:port]/...``.
    """
    if not isinstance(value, str):
        return False
    text = value.strip()
    if not text or len(text) > 2048:
        return False
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        return False
    try:
        parsed = urlparse(text)
        _ = parsed.port  # raises ValueError on a bad port
    except ValueError:
        return False
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return False
    if "@" in parsed.netloc or "\\" in text:
        return False
    host = parsed.hostname
    return not host.startswith(".") and ".." not in host


def _confidence_ok(confidence: Any, floor: Optional[float]) -> bool:
    if floor is None or isinstance(confidence, bool):
        return False
    try:
        value = float(confidence)
    except (TypeError, ValueError):
        return False
    return math.isfinite(value) and 0.0 <= value <= 1.0 and value >= floor


class AutonomyController:
    """Reads tiers, decides per action, demotes on a broken bound, audits."""

    def __init__(
        self,
        store: Optional[TierStore] = None,
        bound_reader: Optional[BoundReader] = None,
    ) -> None:
        self.store: TierStore = store if store is not None else SqlTierStore()
        self.bound_reader: BoundReader = bound_reader or read_bounds

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def _snapshot(self) -> _Snapshot:
        snap = _Snapshot()
        for entry in self.store.entries():
            snap.entries[(entry.category, entry.action_type)] = entry
        return snap

    @staticmethod
    def _lookup(snap: _Snapshot, category: str, action_type: str) -> TierEntry:
        exact = snap.entries.get((category, action_type))
        if exact is not None:
            return exact
        fallback = snap.entries.get((ANY_CATEGORY, action_type))
        if fallback is not None:
            return fallback
        return TierEntry(category=category, action_type=action_type)

    def entry_for(self, category: str, action_type: str) -> TierEntry:
        return self._lookup(self._snapshot(), category, action_type)

    @staticmethod
    def governs(action_type: str) -> bool:
        """Whether tiers apply to ``action_type`` (workflow checkpoints are not)."""
        return action_type in ACTION_CLASSES

    @staticmethod
    def ineligibility(
        action_type: str,
        reversibility: Optional[str],
        *,
        four_eyes: bool,
        entry: TierEntry,
        confidence: Any,
    ) -> list[str]:
        """Why an action may not run autonomously under ``entry``; empty if it may."""
        reasons = []
        if action_type not in AUTONOMOUS_ELIGIBLE:
            reasons.append(f"{action_type} is never autonomous")
        if reversibility != "reversible":
            reasons.append(f"reversibility is {reversibility or 'unknown'}")
        if four_eyes:
            reasons.append(f"{action_type} needs two approvers")
        if entry.category == ANY_CATEGORY:
            reasons.append("autonomy is granted per category, not for '*'")
        if entry.category in NEVER_AUTONOMOUS_CATEGORIES:
            reasons.append(f"the {entry.category} category is never autonomous")
        ttl = entry.max_ttl_seconds
        if not ttl or ttl <= 0 or ttl > AUTONOMOUS_MAX_TTL_SECONDS:
            reasons.append("no valid ttl on the autonomy tier")
        if not _confidence_ok(confidence, entry.min_confidence):
            reasons.append(
                f"confidence {confidence!r} below the tier floor "
                f"{entry.min_confidence!r}"
            )
        return reasons

    # ------------------------------------------------------------------
    # Deciding
    # ------------------------------------------------------------------

    def decide(
        self,
        *,
        category: Any,
        action_type: str,
        reversibility: Optional[str],
        confidence: Any,
        four_eyes: bool = False,
    ) -> Optional[AutonomyDecision]:
        """The tier that governs this action; None for a type tiers do not govern.

        Never raises: a failure to read the tiers is ``approve``.
        """
        if not self.governs(action_type):
            return None
        cat = normalise_category(category)
        try:
            entry = self.entry_for(cat, action_type)
        except Exception as e:  # noqa: BLE001
            logger.error("Cannot read autonomy tiers; holding for approval: %s", e)
            return AutonomyDecision(
                cat, action_type, APPROVE, APPROVE, ("autonomy tiers unreadable",)
            )
        if entry.tier != AUTONOMOUS:
            return AutonomyDecision(cat, action_type, entry.tier, entry.tier)

        reasons = self.ineligibility(
            action_type,
            reversibility,
            four_eyes=four_eyes,
            entry=entry,
            confidence=confidence,
        )
        if reasons:
            return AutonomyDecision(
                cat, action_type, AUTONOMOUS, APPROVE, tuple(reasons)
            )

        bound = safe_bound(self.bound_reader, cat)
        if not bound.holds:
            demoted = False
            if bound.readable:
                demoted = self._demote_quietly(entry, bound)
            return AutonomyDecision(
                cat,
                action_type,
                AUTONOMOUS,
                APPROVE,
                (bound.reason,),
                bound=bound,
                demoted=demoted,
            )
        return AutonomyDecision(
            cat,
            action_type,
            AUTONOMOUS,
            AUTONOMOUS,
            ttl_seconds=entry.max_ttl_seconds,
            min_confidence=entry.min_confidence,
            bound=bound,
        )

    # ------------------------------------------------------------------
    # The circuit breaker
    # ------------------------------------------------------------------

    def demote(
        self,
        entry: TierEntry,
        reason: str,
        *,
        actor: str = BREAKER_ACTOR,
        detail: Optional[dict[str, Any]] = None,
    ) -> TierEntry:
        """Lower ``entry`` to ``approve`` and audit it. Only ever lowers."""
        lowered = TierEntry(
            category=entry.category,
            action_type=entry.action_type,
            tier=APPROVE,
            updated_by=actor,
            explicit=True,
        )
        self.store.put(
            lowered,
            old=entry,
            audit_action="demote",
            actor=actor,
            reason=reason,
            detail=detail,
        )
        logger.warning(
            "Autonomy demoted: %s/%s autonomous -> approve (%s)",
            entry.category,
            entry.action_type,
            reason,
        )
        return lowered

    def _demote_quietly(self, entry: TierEntry, bound: BoundStatus) -> bool:
        if entry.category == ANY_CATEGORY or not entry.explicit:
            return False
        try:
            self.demote(
                entry,
                f"circuit breaker: {bound.reason}",
                detail={"bound": bound.as_dict()},
            )
            return True
        except Exception as e:  # noqa: BLE001
            # The decision already refuses autonomy; a failed write is retried
            # by the next decision or check.
            logger.error("Autonomy demotion could not be recorded: %s", e)
            return False

    def check_all(self) -> list[dict[str, Any]]:
        """Demote every autonomous row whose category's bound no longer holds.

        Run by the daemon's response loop and ``POST /api/autonomy/check``.
        An unreadable bound demotes nothing.
        """
        demoted: list[dict[str, Any]] = []
        autonomous = [e for e in self.store.entries() if e.tier == AUTONOMOUS]
        if not autonomous:
            return demoted
        try:
            bounds = self.bound_reader()
        except Exception as e:  # noqa: BLE001
            logger.error("Autonomy check skipped, QA bound unreadable: %s", e)
            return demoted
        for entry in autonomous:
            if entry.category == ANY_CATEGORY:
                status = BoundStatus(
                    ANY_CATEGORY,
                    holds=False,
                    reason="autonomy is granted per category, not for '*'",
                )
            elif entry.category in NEVER_AUTONOMOUS_CATEGORIES:
                status = BoundStatus(
                    entry.category,
                    holds=False,
                    reason=f"the {entry.category} category is never autonomous",
                )
            else:
                status = bounds.get(entry.category) or BoundStatus(
                    entry.category, holds=False, reason="no QA data for category"
                )
            if status.holds:
                continue
            self.demote(
                entry,
                f"circuit breaker: {status.reason}",
                detail={"bound": status.as_dict()},
            )
            demoted.append(
                {
                    "category": entry.category,
                    "action_type": entry.action_type,
                    "from": AUTONOMOUS,
                    "to": APPROVE,
                    "reason": status.reason,
                }
            )
        return demoted

    # ------------------------------------------------------------------
    # Changing a tier (people only, when raising)
    # ------------------------------------------------------------------

    def set_tier(
        self,
        *,
        category: str,
        action_type: str,
        tier: str,
        actor: str,
        actor_is_human: bool,
        reason: str,
        evidence_url: Optional[str] = None,
        min_confidence: Optional[float] = None,
        max_ttl_seconds: Optional[int] = None,
    ) -> TierEntry:
        """Store a tier. Raises ``PromotionRefused`` when the change is not allowed.

        Raising a tier takes a person (``actor_is_human``) and an absolute
        https evidence link with a host. ``autonomous`` additionally takes an eligible class, a
        named category, a ttl in ``(0, AUTONOMOUS_MAX_TTL_SECONDS]``, a
        confidence floor in ``[0, 1]`` and a bound that holds now.
        """
        if category not in TIER_CATEGORIES:
            raise PromotionRefused(f"unknown category {category!r}")
        if action_type not in ACTION_CLASSES:
            raise PromotionRefused(f"unknown action class {action_type!r}")
        if tier not in TIERS:
            raise PromotionRefused(f"unknown tier {tier!r}")
        if not reason or not reason.strip():
            raise PromotionRefused("a reason is required")

        # Raising is measured against the tier that applies now, which may
        # come from the '*' row or the default; the audit's old value is the
        # stored row for this exact pair, if there is one.
        current = self.entry_for(category, action_type)
        old = (
            current
            if current.explicit and current.category == category
            else TierEntry(category=category, action_type=action_type)
        )
        raising = _RANK[tier] > _RANK[current.tier]

        # Re-setting autonomous (a longer ttl, a lower floor) loosens it too.
        if raising or tier == AUTONOMOUS:
            if not actor_is_human:
                raise PromotionRefused(
                    "only a person may raise an autonomy tier", code="actor"
                )
            if not _valid_url(evidence_url):
                raise PromotionRefused(
                    "raising a tier needs an absolute https evidence link"
                )

        if tier == AUTONOMOUS:
            self._check_autonomous(
                category, action_type, min_confidence, max_ttl_seconds
            )
            entry = TierEntry(
                category=category,
                action_type=action_type,
                tier=AUTONOMOUS,
                min_confidence=float(min_confidence),  # type: ignore[arg-type]
                max_ttl_seconds=int(max_ttl_seconds),  # type: ignore[arg-type]
                updated_by=actor,
                explicit=True,
            )
        else:
            entry = TierEntry(
                category=category,
                action_type=action_type,
                tier=tier,
                updated_by=actor,
                explicit=True,
            )

        if raising:
            action = "promote"
        elif _RANK[tier] < _RANK[current.tier]:
            action = "demote"
        else:
            action = "set"
        self.store.put(
            entry,
            old=old if old.explicit else None,
            audit_action=action,
            actor=actor,
            reason=reason.strip(),
            evidence_url=evidence_url.strip() if evidence_url else None,
        )
        return entry

    def _check_autonomous(
        self,
        category: str,
        action_type: str,
        min_confidence: Optional[float],
        max_ttl_seconds: Optional[int],
    ) -> None:
        if category == ANY_CATEGORY:
            raise PromotionRefused("autonomy is granted per category, not for '*'")
        if category in NEVER_AUTONOMOUS_CATEGORIES:
            raise PromotionRefused(
                f"the {category} category holds unknown and unmapped alerts; "
                "it can never be autonomous"
            )
        if action_type not in AUTONOMOUS_ELIGIBLE:
            raise PromotionRefused(
                f"{action_type} is irreversible or not undoable by ttl; "
                "it can never be autonomous"
            )
        if (
            max_ttl_seconds is None
            or isinstance(max_ttl_seconds, bool)
            or not 0 < int(max_ttl_seconds) <= AUTONOMOUS_MAX_TTL_SECONDS
        ):
            raise PromotionRefused(
                "autonomous needs max_ttl_seconds in "
                f"(0, {AUTONOMOUS_MAX_TTL_SECONDS}]"
            )
        if (
            min_confidence is None
            or isinstance(min_confidence, bool)
            or not math.isfinite(float(min_confidence))
            or not 0.0 <= float(min_confidence) <= 1.0
        ):
            raise PromotionRefused("autonomous needs min_confidence in [0, 1]")
        bound = safe_bound(self.bound_reader, category)
        if not bound.holds:
            raise PromotionRefused(
                f"the {category} QA bound does not hold: {bound.reason}",
                code="bound",
            )

    # ------------------------------------------------------------------
    # Views
    # ------------------------------------------------------------------

    def matrix(self) -> dict[str, Any]:
        """Every (category, action class) with its tier, and each category's bound."""
        snap = self._snapshot()
        try:
            bounds = {k: v.as_dict() for k, v in self.bound_reader().items()}
            bounds_readable = True
        except Exception as e:  # noqa: BLE001
            logger.error("QA bound unreadable for the autonomy matrix: %s", e)
            bounds, bounds_readable = {}, False
        entries = []
        for category in TIER_CATEGORIES:
            for action_type in ACTION_CLASSES:
                stored = snap.entries.get((category, action_type))
                effective = self._lookup(snap, category, action_type)
                row = (stored or effective).as_dict()
                row["category"] = category
                row["tier"] = (stored or effective).tier
                row["explicit"] = stored is not None
                row["eligible"] = (
                    action_type in AUTONOMOUS_ELIGIBLE
                    and category != ANY_CATEGORY
                    and category not in NEVER_AUTONOMOUS_CATEGORIES
                )
                entries.append(row)
        return {
            "default_tier": DEFAULT_TIER,
            "tiers": list(TIERS),
            "categories": list(TIER_CATEGORIES),
            "action_classes": list(ACTION_CLASSES),
            "eligible": sorted(AUTONOMOUS_ELIGIBLE),
            "max_ttl_seconds": AUTONOMOUS_MAX_TTL_SECONDS,
            "fn_bound_target": FN_BOUND_TARGET,
            "fn_bound_min_reviews": FN_BOUND_MIN_REVIEWS,
            "bounds_readable": bounds_readable,
            "bounds": bounds,
            "entries": entries,
        }

    def audit(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.store.audit(limit)


__all__ = [
    "BREAKER_ACTOR",
    "AutonomyController",
    "AutonomyDecision",
    "AutonomyWatchOnly",
    "PromotionRefused",
    "WATCH",
]
