"""Approval service for managing pending autonomous actions.

Actions are persisted in the ``approval_actions`` table (#128). Prior
to that migration, pending actions lived in ``data/pending_actions.json``
— fine for the daemon's single-process loop but invisible to the API
and with no FK into workflow runs. The DB move gives us a queryable,
joinable surface that links workflow phase approvals back to the run
they paused.

Public API (``create_action``, ``approve_action``, ``reject_action``,
``mark_executed``, ``mark_failed``, ``list_actions``, ``get_action``)
is intentionally preserved so ``daemon/orchestrator.py`` (and any
other existing callers) keep working.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from opentelemetry.metrics import Observation
from sqlalchemy import func, or_, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from core.autonomy import AutonomyController, AutonomyDecision, AutonomyWatchOnly
from core.autonomy.tiers import APPROVE, AUTONOMOUS, WATCH
from core.response.config import (
    ResponseConfig,
    approval_requirement,
    decision_rule,
    split_decision_rule,
)
from core.response.policy import PolicyConfig
from core.storage.config_service import get_config_service
from core.storage.connection import get_db_manager
from core.storage.models import ApprovalAction as ApprovalActionRow
from core.storage.models import Investigation, Role, User, WorkflowRun
from core.telemetry import get_meter
from core.time import utcnow

logger = logging.getLogger(__name__)

APPROVAL_CONFIG_KEY = "approval.force_manual_approval"

# A reversal claim (``begin_reversal``) still pending after this long was
# abandoned: the process died, or recording the outcome failed, between the
# claim and ``finish_reversal``. Executors' vendor calls are bounded far below
# it. Left alone, such a row holds ``reverse:<id>`` forever and the action can
# never be reverted, by a person or by its ttl.
REVERSAL_CLAIM_STALE = timedelta(hours=1)

_pending_gauge: Any = None


def register_pending_gauge(service: "ApprovalService") -> None:
    """Export the approval queue depth as an observable gauge, once per process.

    Not in ``__init__``: the service is constructed in many places and each
    registration would stack another callback onto the same instrument. The
    caller that owns the process-wide instance (API boot) calls this.
    """
    global _pending_gauge
    if _pending_gauge is not None:
        return

    def _observe(_options: Any) -> Iterable[Observation]:
        try:
            return [Observation(len(service.list_pending_approvals()))]
        except Exception as e:  # a DB outage drops the sample, not the process
            logger.debug("approvals.pending observation failed: %s", e)
            return []

    _pending_gauge = get_meter("vigil.response.approvals").create_observable_gauge(
        "vigil.approvals.pending",
        callbacks=[_observe],
        description="Actions awaiting approval",
        unit="1",
    )


class ActionType(Enum):
    """Types of actions that can be approved."""

    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    QUARANTINE_FILE = "quarantine_file"
    DISABLE_USER = "disable_user"
    EXECUTE_SPL_QUERY = "execute_spl_query"
    WORKFLOW_PHASE = "workflow_phase"  # #128 — phase with approval_required=True
    WAF_BLOCK = "waf_block"  # Cloudflare WAF IP Access Rule
    GATEWAY_BLOCK = "gateway_block"  # Cloudflare Zero Trust Gateway DNS/HTTP rule
    ACCESS_REVOKE = "access_revoke"  # Cloudflare Zero Trust Access session revoke
    # Entra ID (W2.6): two-person rule by default (policy.DEFAULT_FOUR_EYES_TYPES).
    REVOKE_SESSIONS = "revoke_sessions"
    # Undo types (policy.DEFAULT_UNDO_TYPES), taken by the Palo Alto, Defender
    # and Entra executors. Without a member here a proposal of one was stored
    # as ``custom``, which no executor takes, so it could never run.
    UNBLOCK_IP = "unblock_ip"
    UNISOLATE_HOST = "unisolate_host"
    ENABLE_USER = "enable_user"
    CUSTOM = "custom"


class ActionStatus(Enum):
    """Status of pending actions."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class Reversibility(Enum):
    """Whether an executed action can be undone."""

    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"


@dataclass
class PendingAction:
    """Represents a pending action awaiting approval.

    Kept as a dataclass for API-stable serialisation; populated from
    ``ApprovalAction`` ORM rows by ``_row_to_pending``.
    """

    action_id: str
    action_type: str  # ActionType value
    title: str
    description: str
    target: str  # IP, hostname, username, etc.
    confidence: float
    reason: str
    evidence: List[str]
    created_at: str
    created_by: str
    requires_approval: bool
    status: str  # ActionStatus value
    approved_at: Optional[str] = None
    approved_by: Optional[str] = None
    executed_at: Optional[str] = None
    execution_result: Optional[Dict] = None
    rejection_reason: Optional[str] = None
    parameters: Optional[Dict] = None
    # #128 — workflow phase approvals link back here.
    workflow_run_id: Optional[str] = None
    workflow_phase_id: Optional[str] = None
    reversibility: str = Reversibility.REVERSIBLE.value
    idempotency_key: Optional[str] = None
    # Execution lifecycle (49_approval_action_lifecycle.sql, W2.4).
    expires_at: Optional[str] = None
    verified_at: Optional[str] = None
    verify_status: Optional[str] = None
    reversed_at: Optional[str] = None
    reverse_of: Optional[str] = None
    before_state: Optional[Dict] = None
    after_state: Optional[Dict] = None
    second_approver: Optional[str] = None


class SecondApproverConflict(ValueError):
    """The two-person rule's second approval came from the first approver."""


class SecondApproverRoleConflict(SecondApproverConflict):
    """The second approver holds the first approver's role, or a role is unknown.

    Raised only for types in ``PolicyConfig.distinct_role_types`` (W3.2).
    """


def second_approver_detail(error: SecondApproverConflict) -> str:
    """The 409 / tool error text for a refused second approval."""
    if isinstance(error, SecondApproverRoleConflict):
        return "A second approver with a different role must give the second approval"
    return "A different person must give the second approval"


# approval_decisions (61_approval_decisions.sql): one row per decision with the
# decider's role at that moment. Written in a savepoint: an install that has not
# applied the file still decides, and the report falls back to current roles.
_INSERT_DECISION = text("""
    INSERT INTO approval_decisions
        (action_id, step, actor, actor_user_id, actor_role_id, actor_role)
    VALUES (:action_id, :step, :actor, :user_id, :role_id, :role)
    """)
_FIRST_ROLE = text("""
    SELECT actor_role_id, actor_role FROM approval_decisions
    WHERE action_id = :action_id AND step = 'first_approval'
    ORDER BY id DESC LIMIT 1
    """)
_decisions_warned = False

#: ``(user_id, role_id, role name)`` of no account.
NO_ACCOUNT: tuple[Optional[str], Optional[str], Optional[str]] = (None, None, None)


def account_of(
    session, username: Optional[str]
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """``(user_id, role_id, role name)`` of the account named ``username``.

    Usernames are unique only as written ("Carol" and "carol" can be two
    accounts), so the exact name wins. Failing that, a case-insensitive match
    counts only when exactly one account has it; two or more are ambiguous
    and give ``NO_ACCOUNT``, as does a name that is no account (an agent,
    ``analyst``). Case folding is the database's ``lower()`` on both sides, so
    the stored name and the asked one fold the same way (Turkish dotted I
    included).
    """
    if not username or not username.strip():
        return NO_ACCOUNT
    name = username.strip()
    stmt = select(User.user_id, User.role_id, Role.name).outerjoin(
        Role, Role.role_id == User.role_id
    )
    row = session.execute(stmt.where(User.username == name)).first()
    if row is not None:
        return row[0], row[1], row[2]
    rows = session.execute(
        stmt.where(func.lower(User.username) == func.lower(name)).limit(2)
    ).all()
    if len(rows) == 1:
        return rows[0][0], rows[0][1], rows[0][2]
    if rows:
        logger.warning(
            "%r matches more than one account case-insensitively; no role is used",
            name,
        )
    return NO_ACCOUNT


def role_of(session, username: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """``(role_id, role name)`` of the account named ``username`` (``account_of``).

    ``(None, None)`` for a name that is no account, or that only matches
    several accounts case-insensitively.
    """
    _user_id, role_id, role = account_of(session, username)
    return role_id, role


def _record_decision(
    session, action_id: str, step: str, actor: str, account: tuple
) -> None:
    global _decisions_warned
    try:
        with session.begin_nested():
            session.execute(
                _INSERT_DECISION,
                {
                    "action_id": action_id,
                    "step": step,
                    "actor": (actor or "")[:100],
                    "user_id": account[0],
                    "role_id": account[1],
                    "role": account[2],
                },
            )
    except SQLAlchemyError as e:
        if not _decisions_warned:
            logger.warning(
                "approval_decisions not written (apply 61_approval_decisions.sql): %s",
                type(e).__name__,
            )
            _decisions_warned = True


def _first_approver_role(
    session, action_id: str, first_approver: str
) -> tuple[Optional[str], Optional[str]]:
    """The first approver's role as recorded at their decision, else as now."""
    try:
        with session.begin_nested():
            row = session.execute(_FIRST_ROLE, {"action_id": action_id}).first()
        if row and row[0]:
            return row[0], row[1]
    except SQLAlchemyError:
        pass
    return role_of(session, first_approver)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _row_to_pending(row: ApprovalActionRow) -> PendingAction:
    return PendingAction(
        action_id=row.action_id,
        action_type=row.action_type,
        title=row.title,
        description=row.description,
        target=row.target,
        confidence=float(row.confidence or 0),
        reason=row.reason,
        evidence=list(row.evidence or []),
        created_at=row.created_at.isoformat() if row.created_at else "",
        created_by=row.created_by,
        requires_approval=bool(row.requires_approval),
        status=row.status,
        approved_at=row.approved_at.isoformat() if row.approved_at else None,
        approved_by=row.approved_by,
        executed_at=row.executed_at.isoformat() if row.executed_at else None,
        execution_result=row.execution_result,
        rejection_reason=row.rejection_reason,
        parameters=dict(row.parameters or {}),
        workflow_run_id=row.workflow_run_id,
        workflow_phase_id=row.workflow_phase_id,
        reversibility=row.reversibility or Reversibility.REVERSIBLE.value,
        idempotency_key=row.idempotency_key,
        expires_at=_iso(row.expires_at),
        verified_at=_iso(row.verified_at),
        verify_status=row.verify_status,
        reversed_at=_iso(row.reversed_at),
        reverse_of=row.reverse_of,
        before_state=row.before_state,
        after_state=row.after_state,
        second_approver=row.second_approver,
    )


def _cap_ttl(parameters: Dict[str, Any], ttl_seconds: Optional[int]) -> None:
    """Hold an autonomous action's ttl to its tier's ``max_ttl_seconds``.

    A ttl the caller set and that is shorter stays; a longer one, or none, is
    replaced. One that is not a number is left for the dispatcher to refuse.
    """
    if not ttl_seconds:
        return
    raw = parameters.get("ttl_seconds")
    if raw is not None and not isinstance(raw, bool):
        try:
            current = float(raw)
        except (TypeError, ValueError):
            return
        if 0 < current <= ttl_seconds:
            return
    parameters["ttl_seconds"] = int(ttl_seconds)


def _nonfailed_by_key(session, key: str) -> Optional[ApprovalActionRow]:
    """The live row for ``key``, if any. Failed rows are excluded so they can retry."""
    return session.execute(
        select(ApprovalActionRow)
        .where(ApprovalActionRow.idempotency_key == key)
        .where(ApprovalActionRow.status != ActionStatus.FAILED.value)
        .limit(1)
    ).scalar_one_or_none()


class ApprovalService:
    """Service for managing approval workflow for autonomous actions."""

    def __init__(
        self,
        config: Optional[ResponseConfig] = None,
        policy_config: Optional[PolicyConfig] = None,
        autonomy: Optional[AutonomyController] = None,
    ):
        """
        Initialize approval service.

        Args:
            config: the confidence band; read from Settings when omitted so
                the no-arg form callers use still honours env (#916).
            policy_config: the response policy (four-eyes types); read from
                the ``response.policy`` system config at each decision when
                omitted.
            autonomy: the autonomy controller (W3.1); one reading
                ``autonomy_tiers`` when omitted.
        """
        self.config = config or ResponseConfig.from_settings()
        self.force_manual_approval = False
        self._policy_config = policy_config
        self._autonomy = autonomy

    @property
    def autonomy(self) -> AutonomyController:
        if self._autonomy is None:
            self._autonomy = AutonomyController()
        return self._autonomy

    def autonomy_decision(
        self,
        action_type: str,
        category: Optional[str],
        reversibility: str,
        confidence: float,
    ) -> Optional[AutonomyDecision]:
        """The tier that governs this action (W3.1); None if tiers do not apply."""
        try:
            four_eyes = self.policy_config().needs_second_approver(action_type)
        except Exception:  # noqa: BLE001
            four_eyes = True
        return self.autonomy.decide(
            category=category,
            action_type=action_type,
            reversibility=reversibility,
            confidence=confidence,
            four_eyes=four_eyes,
        )

    def policy_config(self) -> PolicyConfig:
        return (
            self._policy_config
            if self._policy_config is not None
            else PolicyConfig.load()
        )

    # ------------------------------------------------------------------
    # Config (force_manual_approval) — db/config-backed, read per decision
    # ------------------------------------------------------------------
    #
    # ``self.force_manual_approval`` is this process forcing approval on
    # (the daemon does when DAEMON_FORCE_APPROVAL is set) and is never
    # written to the row. The row is what Settings writes and the SQL seed
    # creates (Act); it is read at each decision so a long-lived service sees
    # a change without a restart. Nothing here writes it.

    def _stored_force_manual_approval(self) -> bool:
        """The stored flag; Act when no row exists, Assist when the read fails."""
        try:
            value = get_config_service().read_system_config(APPROVAL_CONFIG_KEY)
        except Exception as e:  # noqa: BLE001
            logger.error(
                "Cannot read the approval setting; requiring manual approval: %s", e
            )
            return True
        return bool(value.get("enabled", False)) if value else False

    def set_force_manual_approval(self, force: bool):
        """Force manual approval for this process; the stored row is left as is."""
        self.force_manual_approval = force
        logger.info("Force manual approval set to: %s", force)

    # ------------------------------------------------------------------
    # CRUD — DB-backed
    # ------------------------------------------------------------------

    def create_action(
        self,
        action_type: ActionType,
        title: str,
        description: str,
        target: str,
        confidence: float,
        reason: str,
        evidence: List[str],
        created_by: str = "system",
        parameters: Optional[Dict] = None,
        workflow_run_id: Optional[str] = None,
        workflow_phase_id: Optional[str] = None,
        reversibility: Reversibility = Reversibility.REVERSIBLE,
        idempotency_key: Optional[str] = None,
        human_only: bool = False,
        annotate_rule: bool = True,
        category: Optional[str] = None,
    ) -> PendingAction:
        """Create a new pending action.

        Workflow phase approvals pass ``workflow_run_id`` and
        ``workflow_phase_id`` so the approvals UI / resume endpoint can
        link back to the paused run.

        Irreversible actions always require approval. ``human_only`` holds the
        row for a person whatever ``confidence`` says: for callers whose
        confidence is their own claim (an agent, a model's reading of alert
        text) and so cannot be what releases the action. A second call with
        the same ``idempotency_key`` returns the existing non-failed row.
        ``annotate_rule=False`` keeps the deciding rule off ``reason`` for rows
        whose reason is read by an analyst and no confidence was ever compared.

        ``category`` is the alert category the autonomy tier is looked up by
        (W3.1); ``other`` when omitted. Under a ``watch`` tier nothing is
        recorded and ``AutonomyWatchOnly`` is raised.
        """
        action, _inserted = self._put_action(
            action_type=action_type,
            title=title,
            description=description,
            target=target,
            confidence=confidence,
            reason=reason,
            evidence=evidence,
            created_by=created_by,
            parameters=parameters,
            workflow_run_id=workflow_run_id,
            workflow_phase_id=workflow_phase_id,
            reversibility=reversibility,
            idempotency_key=idempotency_key,
            human_only=human_only,
            annotate_rule=annotate_rule,
            category=category,
        )
        return action

    def _put_action(
        self,
        action_type: ActionType,
        title: str,
        description: str,
        target: str,
        confidence: float,
        reason: str,
        evidence: List[str],
        created_by: str = "system",
        parameters: Optional[Dict] = None,
        workflow_run_id: Optional[str] = None,
        workflow_phase_id: Optional[str] = None,
        reversibility: Reversibility = Reversibility.REVERSIBLE,
        idempotency_key: Optional[str] = None,
        human_only: bool = False,
        annotate_rule: bool = True,
        category: Optional[str] = None,
    ) -> tuple[PendingAction, bool]:
        """Insert an approval row, or return the existing non-failed one.

        The bool is True when this call inserted. Isolation uses it so a
        reused approved/pending row is not executed again.
        """
        key = idempotency_key or None

        # The branch that set requires_approval is appended to the caller's
        # narrative so the row records the rule it was decided by (#917).
        forced = (
            human_only
            or self.force_manual_approval
            or self._stored_force_manual_approval()
        )
        requires_approval, rule = approval_requirement(
            forced, reversibility, confidence, self.config
        )
        if human_only:
            rule = decision_rule("approval.human_only", True)
        elif self.policy_config().needs_second_approver(action_type.value):
            # Two people decide these; a confidence figure is not one of them.
            requires_approval = True
            rule = decision_rule("policy.four_eyes", True)

        # The autonomy tier (W3.1). Only it releases an action without a
        # person: below ``autonomous`` every action waits for one, whatever its
        # confidence. ``parameters["autonomy"]`` is the controller's alone.
        parameters = dict(parameters or {})
        parameters.pop("autonomy", None)
        decision = self.autonomy_decision(
            action_type.value, category, reversibility.value, confidence
        )
        if decision is not None:
            if decision.effective == WATCH:
                raise AutonomyWatchOnly(
                    f"{action_type.value} on {decision.category} alerts is at "
                    "the watch tier: observed, not recorded"
                )
            if not decision.autonomous:
                if not requires_approval:
                    requires_approval = True
                    rule = decision_rule("autonomy.tier", decision.effective)
            elif not requires_approval:
                # Released by the tier; the confidence rule stays the one
                # named, and the tier is on the row's autonomy record.
                _cap_ttl(parameters, decision.ttl_seconds)
            record = decision.record()
            if decision.autonomous and requires_approval:
                # The tier would release it, but another rule (force-manual,
                # irreversible, the confidence band, four-eyes, human_only)
                # holds it for a person: the record says what was applied.
                record["effective"] = APPROVE
                record["reasons"] = [*record["reasons"], f"held: {rule}"]
            parameters["autonomy"] = record
        if annotate_rule:
            reason = f"{reason}; {rule}" if reason else rule

        action_id = f"action-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}"
        status = (
            ActionStatus.PENDING.value
            if requires_approval
            else ActionStatus.APPROVED.value
        )

        try:
            db = get_db_manager()
            with db.session_scope() as session:
                if key:
                    existing = _nonfailed_by_key(session, key)
                    if existing is not None:
                        return _row_to_pending(existing), False
                row = ApprovalActionRow(
                    action_id=action_id,
                    action_type=action_type.value,
                    title=title,
                    description=description,
                    target=target,
                    confidence=float(confidence),
                    reason=reason,
                    evidence=list(evidence or []),
                    created_at=utcnow(),
                    created_by=created_by,
                    requires_approval=requires_approval,
                    status=status,
                    parameters=parameters,
                    workflow_run_id=workflow_run_id,
                    workflow_phase_id=workflow_phase_id,
                    reversibility=reversibility.value,
                    idempotency_key=key,
                )
                session.add(row)
                session.flush()
                pending = _row_to_pending(row)
            logger.info(
                "Created action %s: %s (confidence: %s)",
                action_id,
                title,
                confidence,
            )
            return pending, True
        except IntegrityError:
            if not key:
                raise
            db = get_db_manager()
            with db.session_scope() as session:
                existing = _nonfailed_by_key(session, key)
            if existing is None:
                raise
            return _row_to_pending(existing), False
        except SQLAlchemyError as e:
            logger.error("DB error creating action: %s", e)
            raise

    def get_action(self, action_id: str) -> Optional[PendingAction]:
        """Get a specific action by ID."""
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                row = session.get(ApprovalActionRow, action_id)
                return _row_to_pending(row) if row else None
        except SQLAlchemyError as e:
            logger.error("DB error fetching action %s: %s", action_id, e)
            return None

    def list_actions(
        self,
        status: Optional[ActionStatus] = None,
        action_type: Optional[ActionType] = None,
        requires_approval: Optional[bool] = None,
        workflow_run_id: Optional[str] = None,
        limit: int = 500,
        action_types: Optional[Iterable[str]] = None,
        undispatched: bool = False,
    ) -> List[PendingAction]:
        """List actions with optional filters, newest first.

        ``undispatched`` is the dispatcher's view: rows not yet claimed
        (``executed_at`` unset), not a reverse row, and decided by a person,
        held for one, or released by the autonomy tier (W3.1; the autonomy
        record's ``effective`` is ``autonomous``), oldest first. Together with ``action_types`` (the
        types something can execute) it keeps rows that will never be run
        (workflow phases, custom, types without an executor) from filling the
        page: newest-first with a cap, an action approved long after it was
        proposed sat below 500 such rows and was never dispatched.
        """
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                stmt = select(ApprovalActionRow)
                if status:
                    stmt = stmt.where(ApprovalActionRow.status == status.value)
                if action_type:
                    stmt = stmt.where(
                        ApprovalActionRow.action_type == action_type.value
                    )
                if action_types is not None:
                    stmt = stmt.where(
                        ApprovalActionRow.action_type.in_(sorted(set(action_types)))
                    )
                if undispatched:
                    stmt = (
                        stmt.where(ApprovalActionRow.executed_at.is_(None))
                        .where(ApprovalActionRow.reverse_of.is_(None))
                        .where(
                            or_(
                                ApprovalActionRow.requires_approval.is_(True),
                                ApprovalActionRow.approved_by.is_not(None),
                                # Released by the autonomy tier (W3.1) and by
                                # nothing else: _dispatch re-decides the tier
                                # before it runs. Any other row released
                                # without a person is not listed.
                                ApprovalActionRow.parameters["autonomy"][
                                    "effective"
                                ].astext
                                == AUTONOMOUS,
                            )
                        )
                    )
                if requires_approval is not None:
                    stmt = stmt.where(
                        ApprovalActionRow.requires_approval == requires_approval
                    )
                if workflow_run_id:
                    stmt = stmt.where(
                        ApprovalActionRow.workflow_run_id == workflow_run_id
                    )
                order = (
                    ApprovalActionRow.created_at.asc()
                    if undispatched
                    else ApprovalActionRow.created_at.desc()
                )
                stmt = stmt.order_by(order).limit(limit)
                rows = session.execute(stmt).scalars().all()
                return [_row_to_pending(r) for r in rows]
        except SQLAlchemyError as e:
            logger.error("DB error listing actions: %s", e)
            return []

    def list_stale_pending(self, cutoff: datetime) -> List[str]:
        """Ids of pending actions created before ``cutoff``, oldest first.

        Deliberately not expressed as ``list_actions(...)`` filtered in Python:
        that orders newest-first and caps at 500, so once the queue is larger
        than the cap it hides the oldest rows — the exact ones a sweep is for.
        Ids rather than ``PendingAction`` because the caller only rejects them,
        and because ``PendingAction.created_at`` is a serialized string, not a
        datetime to compare against.
        """
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                stmt = (
                    select(ApprovalActionRow.action_id)
                    .where(ApprovalActionRow.status == ActionStatus.PENDING.value)
                    .where(ApprovalActionRow.reverse_of.is_(None))
                    .where(ApprovalActionRow.created_at < cutoff)
                    .order_by(ApprovalActionRow.created_at.asc())
                )
                return list(session.execute(stmt).scalars().all())
        except SQLAlchemyError as e:
            logger.error("DB error listing stale pending actions: %s", e)
            return []

    def approve_action(
        self,
        action_id: str,
        approved_by: str = "analyst",
    ) -> Optional[PendingAction]:
        """Approve a pending action.

        An action type under the two-person rule (``PolicyConfig.four_eyes_types``)
        needs two approvals: the first records ``approved_by`` and leaves the
        row pending; the second, from a different user (case-insensitively),
        records ``second_approver`` and approves it. The first approver
        approving again raises ``SecondApproverConflict``. For a type in
        ``PolicyConfig.distinct_role_types`` (W3.2) the second approver must
        also hold a different role from the first (the first's role as recorded
        at their approval), else ``SecondApproverRoleConflict``; an approver
        whose role cannot be found is refused the same way. Every decision is
        recorded in ``approval_decisions`` with the decider's role.
        """
        policy = self.policy_config()
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                row = session.get(ApprovalActionRow, action_id, with_for_update=True)
                if row is None:
                    logger.warning("Action %s not found", action_id)
                    return None
                if row.status != ActionStatus.PENDING.value or row.reverse_of:
                    # A reverse row is a reversal in flight, not a question: an
                    # approval would overwrite who reverted it.
                    logger.warning(
                        "Action %s is not an open approval (status: %s)",
                        action_id,
                        row.status,
                    )
                    return _row_to_pending(row)
                if policy.needs_second_approver(row.action_type):
                    account = account_of(session, approved_by)
                    role = account[1:]
                    if not row.approved_by:
                        row.approved_at = utcnow()
                        row.approved_by = approved_by
                        session.flush()
                        _record_decision(
                            session, action_id, "first_approval", approved_by, account
                        )
                        pending = _row_to_pending(row)
                        logger.info(
                            "Action %s first approval by %s; a second approver is required",
                            action_id,
                            approved_by,
                        )
                        return pending
                    if (
                        row.approved_by.strip().casefold()
                        == approved_by.strip().casefold()
                    ):
                        raise SecondApproverConflict(
                            f"{approved_by} already approved {action_id}; "
                            "a different person must give the second approval"
                        )
                    if policy.needs_distinct_role(row.action_type):
                        first_role = _first_approver_role(
                            session, action_id, row.approved_by
                        )
                        if role[0] is None or first_role[0] is None:
                            raise SecondApproverRoleConflict(
                                f"the role of {row.approved_by if first_role[0] is None else approved_by} "
                                f"is unknown; {row.action_type} needs approvers of two different roles"
                            )
                        if role[0] == first_role[0]:
                            raise SecondApproverRoleConflict(
                                f"{approved_by} holds the first approver's role "
                                f"({first_role[1] or first_role[0]}); {row.action_type} "
                                "needs a second approver of a different role"
                            )
                    row.second_approver = approved_by
                    row.status = ActionStatus.APPROVED.value
                    session.flush()
                    _record_decision(
                        session, action_id, "second_approval", approved_by, account
                    )
                    pending = _row_to_pending(row)
                    logger.info(
                        "Action %s second approval by %s", action_id, approved_by
                    )
                    return pending
                row.status = ActionStatus.APPROVED.value
                row.approved_at = utcnow()
                row.approved_by = approved_by
                session.flush()
                _record_decision(
                    session,
                    action_id,
                    "approve",
                    approved_by,
                    account_of(session, approved_by),
                )
                pending = _row_to_pending(row)
            logger.info("Action %s approved by %s", action_id, approved_by)
            return pending
        except SQLAlchemyError as e:
            logger.error("DB error approving action %s: %s", action_id, e)
            return None

    def reject_action(
        self,
        action_id: str,
        reason: str,
        rejected_by: str = "analyst",
    ) -> Optional[PendingAction]:
        """Reject a pending action."""
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                row = session.get(ApprovalActionRow, action_id)
                if row is None:
                    logger.warning("Action %s not found", action_id)
                    return None
                if row.status != ActionStatus.PENDING.value or row.reverse_of:
                    # Rejecting a reversal in flight would leave its claim
                    # holding reverse:<id> (only failed rows release a key).
                    logger.warning(
                        "Action %s is not an open approval (status: %s)",
                        action_id,
                        row.status,
                    )
                    return _row_to_pending(row)
                row.status = ActionStatus.REJECTED.value
                row.rejection_reason = reason
                row.approved_by = rejected_by
                row.approved_at = utcnow()
                session.flush()
                _record_decision(
                    session,
                    action_id,
                    "reject",
                    rejected_by,
                    account_of(session, rejected_by),
                )
                pending = _row_to_pending(row)
            logger.info(
                "Action %s rejected by %s: %s",
                action_id,
                rejected_by,
                reason,
            )
            return pending
        except SQLAlchemyError as e:
            logger.error("DB error rejecting action %s: %s", action_id, e)
            return None

    def claim_execution(self, action_id: str) -> bool:
        """Claim an approved row for one run, before any vendor call.

        Sets ``executed_at`` on a row that is approved and has none, in one
        conditional UPDATE: True for exactly one caller.
        ``execute_approved_actions`` skips rows with ``executed_at`` set, so a
        row whose change went out but whose ``mark_executed`` then failed is
        never run again; it stays approved with executed_at set, for a person
        to settle. False on a lost race, a row not approved, or a database
        error: do not execute.
        """
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                result = session.execute(
                    update(ApprovalActionRow)
                    .where(ApprovalActionRow.action_id == action_id)
                    .where(ApprovalActionRow.status == ActionStatus.APPROVED.value)
                    .where(ApprovalActionRow.executed_at.is_(None))
                    .values(executed_at=utcnow())
                )
                return (result.rowcount or 0) == 1
        except SQLAlchemyError as e:
            logger.error("DB error claiming %s for execution: %s", action_id, e)
            return False

    def mark_executed(
        self,
        action_id: str,
        result: Dict,
        *,
        executed_at: Optional[datetime] = None,
        before_state: Optional[Dict] = None,
        after_state: Optional[Dict] = None,
        expires_at: Optional[datetime] = None,
    ) -> Optional[PendingAction]:
        """Mark an action as executed, with what the executor observed."""
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                row = session.get(ApprovalActionRow, action_id)
                if row is None:
                    return None
                if row.status != ActionStatus.APPROVED.value:
                    logger.warning(
                        "Action %s is not approved (status: %s)",
                        action_id,
                        row.status,
                    )
                    return _row_to_pending(row)
                row.status = ActionStatus.EXECUTED.value
                row.executed_at = executed_at or utcnow()
                row.execution_result = result
                if before_state is not None:
                    row.before_state = before_state
                if after_state is not None:
                    row.after_state = after_state
                if expires_at is not None:
                    row.expires_at = expires_at
                session.flush()
                return _row_to_pending(row)
        except SQLAlchemyError as e:
            logger.error("DB error marking action %s executed: %s", action_id, e)
            return None

    def hold_for_person(self, action_id: str, rule: str) -> Optional[PendingAction]:
        """Put an action released without a person back in the approval queue.

        For the dispatcher (W3.1): a row approved with nobody's name on it whose
        autonomy no longer holds (the tier was demoted, the bound broke) waits
        for a person instead of running. Only such a row is touched.
        """
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                row = session.get(ApprovalActionRow, action_id, with_for_update=True)
                if row is None:
                    return None
                if row.status != ActionStatus.APPROVED.value or row.approved_by:
                    return _row_to_pending(row)
                row.status = ActionStatus.PENDING.value
                row.requires_approval = True
                row.approved_at = None
                # The row now waits for a person: its autonomy record says so,
                # and the dispatcher no longer reads it as tier-released.
                params = dict(row.parameters or {})
                record = params.get("autonomy")
                if isinstance(record, dict):
                    record = dict(record)
                    record["effective"] = APPROVE
                    record["reasons"] = [
                        *(record.get("reasons") or []),
                        f"held at dispatch: {rule}",
                    ]
                    params["autonomy"] = record
                    row.parameters = params
                row.reason = f"{row.reason}; {rule}" if row.reason else rule
                session.flush()
                logger.warning("Action %s held for a person: %s", action_id, rule)
                return _row_to_pending(row)
        except SQLAlchemyError as e:
            logger.error("DB error holding action %s: %s", action_id, e)
            return None

    def mark_failed(
        self,
        action_id: str,
        error: str,
    ) -> Optional[PendingAction]:
        """Mark an action as failed."""
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                row = session.get(ApprovalActionRow, action_id)
                if row is None:
                    return None
                row.status = ActionStatus.FAILED.value
                row.executed_at = utcnow()
                row.execution_result = {"error": error}
                session.flush()
                logger.error("Action %s failed: %s", action_id, error)
                return _row_to_pending(row)
        except SQLAlchemyError as e:
            logger.error("DB error marking action %s failed: %s", action_id, e)
            return None

    def record_verification(
        self, action_id: str, verify_status: str
    ) -> Optional[PendingAction]:
        """Record what the executor's verify found (verified/failed/unknown)."""
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                row = session.get(ApprovalActionRow, action_id)
                if row is None:
                    return None
                row.verified_at = utcnow()
                row.verify_status = verify_status
                session.flush()
                return _row_to_pending(row)
        except SQLAlchemyError as e:
            logger.error("DB error recording verification of %s: %s", action_id, e)
            return None

    def count_executed_since(self, action_type: str, since: datetime) -> int:
        """Forward actions of a type executed at or after ``since`` (blast radius).

        Raises on a failed read: a count that could not be taken must not
        read as zero.
        """
        db = get_db_manager()
        with db.session_scope() as session:
            stmt = (
                select(func.count())
                .select_from(ApprovalActionRow)
                .where(ApprovalActionRow.action_type == action_type)
                .where(ApprovalActionRow.status == ActionStatus.EXECUTED.value)
                .where(ApprovalActionRow.reverse_of.is_(None))
                .where(ApprovalActionRow.executed_at >= since)
            )
            return int(session.execute(stmt).scalar_one())

    def list_expired(
        self,
        now: datetime,
        retry_after: timedelta = timedelta(minutes=15),
        limit: int = 100,
    ) -> List[PendingAction]:
        """Executed reversible actions past expires_at and not yet reversed.

        An action whose reversal failed within ``retry_after`` is left out,
        so a target that refuses the undo is retried, not hammered.
        """
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                reverse = ApprovalActionRow.__table__.alias("rev")
                recent_failure = (
                    select(reverse.c.action_id)
                    .where(reverse.c.reverse_of == ApprovalActionRow.action_id)
                    .where(reverse.c.status == ActionStatus.FAILED.value)
                    .where(reverse.c.created_at >= utcnow() - retry_after)
                    .exists()
                )
                stmt = (
                    select(ApprovalActionRow)
                    .where(ApprovalActionRow.status == ActionStatus.EXECUTED.value)
                    .where(ApprovalActionRow.reversed_at.is_(None))
                    .where(ApprovalActionRow.expires_at.is_not(None))
                    .where(ApprovalActionRow.expires_at <= now)
                    .where(
                        ApprovalActionRow.reversibility
                        == Reversibility.REVERSIBLE.value
                    )
                    .where(ApprovalActionRow.reverse_of.is_(None))
                    .where(~recent_failure)
                    .order_by(ApprovalActionRow.expires_at.asc())
                    .limit(limit)
                )
                rows = session.execute(stmt).scalars().all()
                return [_row_to_pending(r) for r in rows]
        except SQLAlchemyError as e:
            logger.error("DB error listing expired actions: %s", e)
            return []

    def begin_reversal(
        self, original_id: str, actor: str, reason: str
    ) -> Optional[PendingAction]:
        """Claim the reversal of ``original_id``: insert its reverse row.

        The row has the original's action_type and target, ``reverse_of`` set,
        ``approved_by`` the actor, and idempotency key ``reverse:<id>``, which
        is unique among non-failed rows: a second concurrent claim gets None,
        as does an action already reversed. ``finish_reversal`` settles it.
        """
        key = f"reverse:{original_id}"
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                original = session.get(ApprovalActionRow, original_id)
                if original is None or original.reversed_at is not None:
                    return None
                now = utcnow()
                held = _nonfailed_by_key(session, key)
                if held is not None:
                    abandoned = held.status == ActionStatus.REJECTED.value or (
                        held.status == ActionStatus.PENDING.value
                        and held.created_at is not None
                        and held.created_at < now - REVERSAL_CLAIM_STALE
                    )
                    if not abandoned:
                        return None
                    # Release the key: a failed row no longer holds it.
                    logger.warning(
                        "Reversal claim %s of %s was abandoned (%s); claiming again",
                        held.action_id,
                        original_id,
                        held.status,
                    )
                    held.status = ActionStatus.FAILED.value
                    held.executed_at = now
                    held.execution_result = {
                        "success": False,
                        "error": "abandoned: the reversal was never settled; "
                        "superseded by a new claim",
                    }
                    session.flush()
                row = ApprovalActionRow(
                    action_id=f"action-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}-rev",
                    action_type=original.action_type,
                    title=f"Reverse: {original.title}"[:2000],
                    description=f"Reversal of {original_id}",
                    target=original.target,
                    confidence=float(original.confidence or 0),
                    reason=reason,
                    evidence=[original_id],
                    created_at=now,
                    created_by=actor,
                    requires_approval=False,
                    status=ActionStatus.PENDING.value,
                    approved_at=now,
                    approved_by=actor,
                    parameters=dict(original.parameters or {}),
                    reversibility=Reversibility.REVERSIBLE.value,
                    idempotency_key=key,
                    reverse_of=original_id,
                )
                session.add(row)
                session.flush()
                return _row_to_pending(row)
        except IntegrityError:
            return None
        except SQLAlchemyError as e:
            logger.error("DB error claiming reversal of %s: %s", original_id, e)
            return None

    def finish_reversal(
        self,
        reverse_id: str,
        *,
        succeeded: bool,
        result: Dict,
        verify_status: Optional[str] = None,
        before_state: Optional[Dict] = None,
        after_state: Optional[Dict] = None,
    ) -> Optional[PendingAction]:
        """Settle a claimed reversal; on success stamp reversed_at on the original."""
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                row = session.get(ApprovalActionRow, reverse_id)
                if row is None or row.reverse_of is None:
                    return None
                now = utcnow()
                row.status = (
                    ActionStatus.EXECUTED.value
                    if succeeded
                    else ActionStatus.FAILED.value
                )
                row.executed_at = now
                row.execution_result = result
                row.before_state = before_state
                row.after_state = after_state
                if verify_status is not None:
                    row.verified_at = now
                    row.verify_status = verify_status
                if succeeded:
                    original = session.get(ApprovalActionRow, row.reverse_of)
                    if original is not None:
                        original.reversed_at = now
                session.flush()
                return _row_to_pending(row)
        except SQLAlchemyError as e:
            logger.error("DB error settling reversal %s: %s", reverse_id, e)
            return None

    def get_stats(self) -> Dict:
        """Get statistics about actions."""
        actions = self.list_actions()
        return {
            "total": len(actions),
            "pending": len(
                [a for a in actions if a.status == ActionStatus.PENDING.value]
            ),
            "approved": len(
                [a for a in actions if a.status == ActionStatus.APPROVED.value]
            ),
            "rejected": len(
                [a for a in actions if a.status == ActionStatus.REJECTED.value]
            ),
            "executed": len(
                [a for a in actions if a.status == ActionStatus.EXECUTED.value]
            ),
            "failed": len(
                [a for a in actions if a.status == ActionStatus.FAILED.value]
            ),
            "requires_approval": len([a for a in actions if a.requires_approval]),
            "by_type": self._count_by_type(actions),
        }

    def _count_by_type(self, actions: List[PendingAction]) -> Dict[str, int]:
        """Count actions by type."""
        counts: Dict[str, int] = {}
        for action in actions:
            counts[action.action_type] = counts.get(action.action_type, 0) + 1
        return counts

    def list_pending_approvals(self) -> List[PendingAction]:
        """List all pending actions requiring approval."""
        return self.list_actions(status=ActionStatus.PENDING, requires_approval=True)


def _text_id(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _case_id_for_action(
    action: PendingAction,
    runs: Dict[str, Any],
    investigations: Dict[str, Optional[str]],
) -> Optional[str]:
    """One case id, in the order #1301 settled. Later sources fill a gap only."""
    params = action.parameters if isinstance(action.parameters, dict) else {}
    direct = _text_id(params.get("case_id"))
    if direct:
        return direct
    if action.workflow_run_id:
        ctx = runs.get(action.workflow_run_id) or {}
        from_run = _text_id(ctx.get("case_id")) if isinstance(ctx, dict) else None
        if from_run:
            return from_run
    investigation_id = _text_id(params.get("investigation_id"))
    if investigation_id:
        return _text_id(investigations.get(investigation_id))
    return None


def _case_lookups(
    actions: List[PendingAction],
) -> tuple[Dict[str, Any], Dict[str, Optional[str]]]:
    """Run trigger contexts and investigation case ids those actions can name."""
    run_ids = {action.workflow_run_id for action in actions if action.workflow_run_id}
    investigation_ids: set[str] = set()
    for action in actions:
        params = action.parameters if isinstance(action.parameters, dict) else {}
        investigation_id = _text_id(params.get("investigation_id"))
        if investigation_id:
            investigation_ids.add(investigation_id)
    runs: Dict[str, Any] = {}
    investigations: Dict[str, Optional[str]] = {}
    if not run_ids and not investigation_ids:
        return runs, investigations
    db = get_db_manager()
    with db.session_scope() as session:
        if run_ids:
            rows = session.query(WorkflowRun).filter(WorkflowRun.run_id.in_(run_ids))
            for row in rows:
                ctx = row.trigger_context
                runs[row.run_id] = ctx if isinstance(ctx, dict) else {}
        if investigation_ids:
            rows = session.query(Investigation).filter(
                Investigation.investigation_id.in_(investigation_ids)
            )
            for row in rows:
                investigations[row.investigation_id] = row.case_id
    return runs, investigations


def _kind_for_action(action: PendingAction) -> str:
    params = action.parameters if isinstance(action.parameters, dict) else {}
    checkpoint = params.get("checkpoint_id")
    if isinstance(checkpoint, str):
        return "checkpoint" if checkpoint.strip() else "approval"
    return "checkpoint" if checkpoint else "approval"


def needs_you(case_id: Optional[str] = None) -> Dict[str, Any]:
    """Pending rows that need a person, oldest first, with no cap.

    Not ``list_pending_approvals`` or ``list_actions``: those are newest-first,
    and ``list_actions`` stops at 500, which hides the oldest asks.
    """
    db = get_db_manager()
    with db.session_scope() as session:
        stmt = (
            select(ApprovalActionRow)
            .where(ApprovalActionRow.status == ActionStatus.PENDING.value)
            .where(ApprovalActionRow.requires_approval.is_(True))
            .order_by(ApprovalActionRow.created_at.asc())
        )
        actions = [
            _row_to_pending(row) for row in session.execute(stmt).scalars().all()
        ]
    runs, investigations = _case_lookups(actions)
    wanted = _text_id(case_id)
    items: List[Dict[str, Any]] = []
    for action in actions:
        resolved = _case_id_for_action(action, runs, investigations)
        if wanted is not None and resolved != wanted:
            continue
        items.append(
            {
                "kind": _kind_for_action(action),
                "source_id": action.action_id,
                "title": action.title,
                "reason": split_decision_rule(action.reason)[0],
                "created_at": action.created_at,
                "reversibility": action.reversibility,
                "case_id": resolved,
            }
        )
    return {"count": len(items), "items": items}


def pending_approval_case_ids() -> set[str]:
    """Case ids that currently need a person.

    Calls ``list_pending_approvals()`` and does not query ``approval_actions``.
    A case id resolves from ``parameters.case_id``, then
    ``workflow_runs.trigger_context.case_id``, then ``investigations.case_id``.
    """
    actions = ApprovalService().list_pending_approvals()
    if not actions:
        return set()
    runs, investigations = _case_lookups(actions)
    found: set[str] = set()
    for action in actions:
        resolved = _case_id_for_action(action, runs, investigations)
        if resolved:
            found.add(resolved)
    return found
