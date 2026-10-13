"""Autonomous response service with approval workflow integration.

Approved actions run through the response policy (``core.response.policy``)
and then the executor the ``ExecutorRegistry`` holds for their type (W2.4).
The registry is built once per process (``core.response.executors.wiring``)
and injected; without one the service has an empty registry, under which
isolate_host is recorded failed (no EDR executor) and other types wait for
manual handling.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from core.agents.builtins import AgentId
from core.autonomy import AutonomyWatchOnly
from core.response.approval_service import (
    ActionStatus,
    ActionType,
    ApprovalService,
    PendingAction,
    Reversibility,
)
from core.response.config import ResponseConfig, decision_rule
from core.response.executors.base import (
    ExecResult,
    ExecutorRegistry,
    PolicyResult,
    TypedAction,
)
from core.response.policy import ActionPolicy, ttl_from_parameters
from core.time import utcnow

logger = logging.getLogger(__name__)

# approved_by / created_by on the reverse rows the expiry sweep writes.
TTL_SWEEP_ACTOR = "system:ttl-sweep"

# Another run holds the row, it is no longer approved, or the claim could not
# be written: in every case this run must not call the vendor.
_NOT_CLAIMED: Dict[str, Any] = {
    "success": False,
    "status": "skipped",
    "error": "not_claimed: the action is already running, done, or unclaimable",
}


def _invalid_reason(error: ValueError) -> str:
    """The first message of a validation error, or the error's text."""
    if isinstance(error, ValidationError):
        errors = error.errors()
        if errors:
            return str(errors[0].get("msg", "invalid"))
    return str(error) or "invalid"


class AutonomousResponseService:
    """Service for managing autonomous threat response with approval workflow."""

    def __init__(
        self,
        approvals: Optional[ApprovalService] = None,
        config: Optional[ResponseConfig] = None,
        executors: Optional[ExecutorRegistry] = None,
        policy: Optional[ActionPolicy] = None,
    ):
        """Initialize autonomous response service.

        ``config`` defaults to the approval service's band so the two never
        compare against different lines; the no-arg form reads Settings.
        ``executors`` is the process's registry (empty when omitted);
        ``policy`` defaults to one reading the approval service's policy
        config, so approve-time and dispatch-time rules agree.
        """
        self.approval_service = approvals or ApprovalService(config=config)
        self.config = config or self.approval_service.config
        self.executors = executors if executors is not None else ExecutorRegistry()
        self.policy = policy or ActionPolicy(
            config_loader=self.approval_service.policy_config
        )

    def correlate_alerts(
        self,
        tempo_flow_alert: Optional[Dict] = None,
        crowdstrike_alert: Optional[Dict] = None,
        splunk_results: Optional[List[Dict]] = None,
    ) -> Dict:
        """
        Correlate alerts from multiple sources and calculate confidence score.

        Args:
            tempo_flow_alert: Alert from Tempo Flow
            crowdstrike_alert: Alert from CrowdStrike
            splunk_results: Results from Splunk queries

        Returns:
            Correlation result with confidence score and reasoning
        """
        confidence = 0.0
        evidence = []
        indicators = []
        reasoning = []

        # Correlate Tempo Flow alerts
        if tempo_flow_alert:
            evidence.append(
                f"Tempo Flow: {tempo_flow_alert.get('finding_id', 'unknown')}"
            )

            severity = tempo_flow_alert.get("severity", "").lower()
            if severity in ["high", "critical"]:
                confidence += 0.15
                reasoning.append(f"High severity detection in Tempo Flow ({severity})")

            # Check for specific attack patterns
            mitre_predictions = tempo_flow_alert.get("mitre_predictions", {})
            if any(t.startswith("T1486") for t in mitre_predictions):  # Ransomware
                confidence += 0.25
                reasoning.append("Ransomware behavior detected (T1486)")
                indicators.append("ransomware")

            if any(t.startswith("T1071") for t in mitre_predictions):  # C2
                confidence += 0.20
                reasoning.append("C2 communication detected (T1071)")
                indicators.append("c2_communication")

            if any(
                t.startswith("T1021") for t in mitre_predictions
            ):  # Lateral movement
                confidence += 0.15
                reasoning.append("Lateral movement detected (T1021)")
                indicators.append("lateral_movement")

        # Correlate CrowdStrike alerts
        if crowdstrike_alert:
            cs_alerts = crowdstrike_alert.get("alerts", [])
            if cs_alerts:
                evidence.append(f"CrowdStrike: {len(cs_alerts)} alert(s)")

                for alert in cs_alerts:
                    severity = alert.get("severity", "").lower()
                    if severity == "critical":
                        confidence += 0.15
                        reasoning.append("Critical severity in CrowdStrike")

                    detection_type = alert.get("detection_type", "").lower()
                    if detection_type == "malware":
                        confidence += 0.20
                        reasoning.append(
                            f"Malware detected: {alert.get('description', '')}"
                        )
                        indicators.append("malware")

                    # Check if already isolated
                    if alert.get("isolated", False):
                        reasoning.append("Host already isolated in CrowdStrike")

        # Correlate Splunk results
        if splunk_results and len(splunk_results) > 0:
            evidence.append(f"Splunk: {len(splunk_results)} event(s)")

            # High volume of events indicates active threat
            if len(splunk_results) > 50:
                confidence += 0.10
                reasoning.append(f"High volume of events ({len(splunk_results)})")

        # Time correlation bonus
        if tempo_flow_alert and crowdstrike_alert:
            # If alerts are within 5 minutes, add correlation bonus
            confidence += 0.10
            reasoning.append("Temporal correlation between multiple sources")

        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)

        return {
            "confidence": confidence,
            "indicators": indicators,
            "evidence": evidence,
            "reasoning": reasoning,
            "recommendation": self._get_recommendation(confidence, indicators),
        }

    def _get_recommendation(self, confidence: float, indicators: List[str]) -> str:
        """Get recommendation based on confidence and indicators."""
        if confidence >= self.config.confidence_threshold:
            return "AUTO-ISOLATE: Confidence threshold met for automatic isolation"
        elif confidence >= self.config.review_threshold:
            return "ISOLATE WITH APPROVAL: High confidence, recommend isolation with quick approval"
        elif confidence >= self.config.monitor_threshold:
            return "MANUAL REVIEW: Moderate confidence, requires analyst review"
        else:
            return "MONITOR: Low confidence, continue monitoring"

    # ------------------------------------------------------------------
    # Policy + registry dispatch (W2.4)
    # ------------------------------------------------------------------

    def _recent_count(self, action_type: str, since: datetime) -> int:
        return self.approval_service.count_executed_since(action_type, since)

    def _typed(
        self, action: PendingAction, *, reverse_of: Optional[str] = None
    ) -> TypedAction:
        """The row as an executor receives it.

        Reversibility is the registry's, not the row's: the row's value was
        the creator's claim, and the registry's is what the executor can undo.

        Raises ``ValueError`` (``ValidationError`` included) for a row that is
        not a valid action, a ttl outside ``(0, MAX_TTL]`` among them. A
        reverse carries no ttl: undoing a change does not expire.
        """
        params = dict(action.parameters or {})
        # The autonomy record is the approval row's, not the executor's input.
        params.pop("autonomy", None)
        params.setdefault("reason", action.reason)
        ttl: Optional[timedelta] = (
            None if reverse_of is not None else ttl_from_parameters(params)
        )
        executor = self.executors.get(action.action_type)
        reversibility = (
            self.executors.reversibility_of(action.action_type)
            if executor is not None
            else action.reversibility
        )
        return TypedAction(
            action_type=action.action_type,
            target=action.target,
            parameters=params,
            reversibility=reversibility,
            idempotency_key=action.idempotency_key,
            ttl=ttl,
            action_id=action.action_id,
            reverse_of=reverse_of,
            requested_by=(action.created_by or "system")[:100],
        )

    def evaluate(self, action: TypedAction) -> PolicyResult:
        """The full policy verdict, with this service's registry and counts.

        A type no executor takes is still screened for protected targets and
        limits (it can only be carried out by hand, or is isolate_host recorded
        failed). A failure to evaluate (a count that could not be read) is a
        refusal.
        """
        registry = (
            self.executors
            if self.executors.get(action.action_type) is not None
            else None
        )
        try:
            return self.policy.evaluate(
                action, registry=registry, recent_count=self._recent_count
            )
        except Exception as e:  # noqa: BLE001
            logger.error("Policy evaluation failed for %s: %s", action.action_type, e)
            return PolicyResult.deny("policy could not be evaluated")

    def _refuse(self, action: PendingAction, reason: str) -> Dict[str, Any]:
        logger.warning("Action %s refused by policy: %s", action.action_id, reason)
        error = f"policy_refused: {reason}"
        self.approval_service.mark_failed(action.action_id, error)
        return {"success": False, "error": error, "status": "failed"}

    def _forced_manual(self) -> bool:
        """The emergency stop: force-manual approval, this process's or stored."""
        svc = self.approval_service
        if getattr(svc, "force_manual_approval", False):
            return True
        try:
            return bool(svc._stored_force_manual_approval())
        except Exception:  # noqa: BLE001
            # Cannot tell whether the stop is on: treat it as on.
            return True

    def _hold(
        self, action: PendingAction, rule: str, reasons: List[str]
    ) -> Dict[str, Any]:
        self.approval_service.hold_for_person(action.action_id, rule)
        logger.warning(
            "Action %s held for a person at dispatch: %s (%s)",
            action.action_id,
            rule,
            "; ".join(reasons),
        )
        return {
            "success": False,
            "status": ActionStatus.PENDING.value,
            "error": f"autonomy_held: {rule}",
            "reasons": list(reasons),
        }

    def _autonomy_recheck(
        self, action: PendingAction
    ) -> tuple[Optional[Dict[str, Any]], Optional[int]]:
        """Hold a row released with no person's name if autonomy no longer holds.

        The tier is decided again at dispatch, with the registry's
        reversibility rather than the row's: force-manual approval (the
        emergency stop, checked first), a demotion, a broken bound or an
        executor that cannot undo the type puts the row back in the approval
        queue. Returns ``(held, ttl_cap)``: ``held`` is the result to return
        when the row is held, else None and the row may proceed (to the
        policy, which always runs); ``ttl_cap`` is the current tier's
        ``max_ttl_seconds``, which the dispatcher holds the action's ttl to.
        """
        if self._forced_manual():
            rule = decision_rule("approval.force_manual", True)
            return (
                self._hold(action, rule, ["force-manual approval is on"]),
                None,
            )
        record = (action.parameters or {}).get("autonomy") or {}
        reversibility = (
            self.executors.reversibility_of(action.action_type)
            if self.executors.get(action.action_type) is not None
            else action.reversibility
        )
        decision = self.approval_service.autonomy_decision(
            action.action_type,
            record.get("category") if isinstance(record, dict) else None,
            reversibility,
            action.confidence,
        )
        if decision is None:
            return None, None
        if decision.autonomous:
            return None, decision.ttl_seconds
        return self._hold(action, decision.rule, list(decision.reasons)), None

    def _dispatch(self, action: PendingAction) -> Optional[Dict[str, Any]]:
        """Run one approved row through the policy and its executor.

        Marks the row executed or failed and returns the execution result.
        None: no executor takes the type and it is not isolate_host, so the
        row is left for manual handling, as before the registry.

        A row is claimed (``ApprovalService.claim_execution`` stamps
        ``executed_at``) before the vendor is called, and a row that cannot be
        claimed is not run. The claim is what keeps a change from going out
        twice: if recording the outcome then fails, the row stays approved
        with ``executed_at`` set, which the loop never dispatches again, and
        the result says the change is unrecorded.
        """
        executor = self.executors.get(action.action_type)
        if executor is None:
            if action.action_type != ActionType.ISOLATE_HOST.value:
                return None
            if not action.approved_by and not action.reverse_of:
                held, _cap = self._autonomy_recheck(action)
                if held is not None:
                    return held
            if not self.approval_service.claim_execution(action.action_id):
                return dict(_NOT_CLAIMED)
            params = action.parameters or {}
            result = self._execute_isolation(
                ip_address=action.target,
                hostname=params.get("hostname"),
                reason=action.reason,
                confidence=action.confidence,
            )
            if result.get("success"):
                if (
                    self.approval_service.mark_executed(action.action_id, result)
                    is None
                ):
                    return self._unrecorded(action, result)
            else:
                self.approval_service.mark_failed(
                    action.action_id, result.get("error", "Unknown error")
                )
            return result

        try:
            typed = self._typed(action)
        except ValueError as e:
            return self._refuse(action, f"invalid action: {_invalid_reason(e)}")

        verdict = self.evaluate(typed)
        if not verdict.allowed:
            return self._refuse(action, "; ".join(verdict.reasons))
        if verdict.requires_approval and not action.approved_by:
            return self._refuse(
                action,
                f"{action.action_type} is irreversible and needs a person's approval",
            )
        if verdict.requires_second_approver:
            second = (action.second_approver or "").strip().casefold()
            first_by = (action.approved_by or "").strip().casefold()
            if not second or second == first_by:
                return self._refuse(
                    action,
                    f"{action.action_type} needs a second approver distinct from the first",
                )
        # Released with no person's name on it: the autonomy tier (W3.1) is
        # decided again, after the policy allowed the action and before the
        # executor sees it.
        if not action.approved_by and not action.reverse_of:
            held, ttl_cap = self._autonomy_recheck(action)
            if held is not None:
                return held
            if ttl_cap:
                typed = self._cap_ttl(typed, executor, ttl_cap)

        # Everything recorded about the run is computed before it runs: a
        # failure here must stop the action, not strand an executed change on
        # a row still marked approved (which the next loop would run again).
        executed_at = utcnow()
        # An undo type (unblock_ip, unisolate_host, enable_user) never expires:
        # the sweep would "reverse" it and re-apply what an analyst lifted.
        expires = typed.reversibility == "reversible" and self._takes_ttl(
            action.action_type
        )
        try:
            columns = typed.to_approval_columns(
                executed_at=executed_at,
                default_ttl=executor.default_ttl if expires else None,
            )
        except (OverflowError, ValueError, TypeError) as e:
            return self._refuse(
                action, f"invalid action: cannot compute expiry ({type(e).__name__})"
            )
        if not self.approval_service.claim_execution(action.action_id):
            return dict(_NOT_CLAIMED)
        try:
            outcome = executor.execute(typed)
        except Exception as e:  # noqa: BLE001
            logger.exception("Executor for %s raised", action.action_type)
            outcome = ExecResult(
                status="failed", error=f"executor error: {type(e).__name__}"
            )

        if not outcome.ok:
            self.approval_service.mark_failed(
                action.action_id, outcome.error or "Unknown error"
            )
            return outcome.to_execution_result()

        expires_at = (
            columns["expires_at"] if expires and outcome.status == "executed" else None
        )
        result = outcome.to_execution_result()
        recorded = self.approval_service.mark_executed(
            action.action_id,
            result,
            executed_at=executed_at,
            before_state=outcome.before_state,
            after_state=outcome.after_state,
            expires_at=expires_at,
        )
        if recorded is None:
            return self._unrecorded(action, result)
        verify_status = self._verify(executor, typed, outcome)
        self.approval_service.record_verification(action.action_id, verify_status)
        return {**result, "verify_status": verify_status}

    @staticmethod
    def _cap_ttl(typed: TypedAction, executor: Any, cap_seconds: int) -> TypedAction:
        """Hold a tier-released action's ttl to the tier's current maximum.

        The row's ttl was capped when it was created; the tier may since have
        been lowered, so the dispatcher caps again. No ttl on the action means
        the executor's default, which is capped the same way.
        """
        cap = timedelta(seconds=int(cap_seconds))
        current = typed.ttl if typed.ttl is not None else executor.default_ttl
        if current is not None and timedelta(0) < current <= cap:
            return typed
        return typed.model_copy(update={"ttl": cap})

    def _takes_ttl(self, action_type: str) -> bool:
        try:
            return self.policy.config.takes_ttl(action_type)
        except Exception:  # noqa: BLE001
            # Unknown: no expiry. A missed expiry leaves a change standing for
            # a person to lift; a wrong one re-applies a lifted block.
            return False

    def _unrecorded(self, action: PendingAction, result: Dict[str, Any]) -> Dict:
        """The vendor changed something and the row could not say so.

        The row keeps its claim (``executed_at``), so it is never dispatched
        again. Reported as a failure: nobody should read it as done.
        """
        logger.critical(
            "Action %s (%s on %s) was carried out but could not be recorded; "
            "it will not be retried. Check the vendor and settle it by hand.",
            action.action_id,
            action.action_type,
            action.target,
        )
        return {
            **result,
            "success": False,
            "status": "failed",
            "error": "executed_unrecorded: the change was made but could not be "
            "recorded; it will not be retried",
        }

    @staticmethod
    def _verify(executor: Any, typed: TypedAction, outcome: ExecResult) -> str:
        try:
            return executor.verify(typed, outcome).status
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "Verify of %s raised: %s", typed.action_type, type(e).__name__
            )
            return "unknown"

    # ------------------------------------------------------------------
    # Proposals from agents and models
    # ------------------------------------------------------------------

    def propose_action(
        self,
        *,
        action_type: str,
        target: str,
        title: str,
        description: str,
        reason: str,
        evidence: List[str],
        proposed_by: str,
        confidence: float = 0.0,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Queue an action an agent or model proposed, if the policy allows it.

        The policy runs before the row exists: a refused proposal is never
        created (W0.5). An allowed one waits for a person whatever its
        confidence (``human_only``); the dispatcher runs the policy again
        before any executor sees it.
        """
        try:
            atype = ActionType(action_type)
        except ValueError:
            atype = ActionType.CUSTOM
        try:
            typed = TypedAction(
                action_type=action_type,
                target=target,
                parameters=dict(parameters or {}),
                requested_by=(proposed_by or "agent")[:100],
                reversibility=(
                    self.executors.reversibility_of(action_type)
                    if self.executors.get(action_type) is not None
                    else "irreversible"
                ),
                ttl=ttl_from_parameters(parameters or {}),
            )
        except ValueError as e:
            return {"status": "refused", "reasons": [_invalid_reason(e)]}
        verdict = self.evaluate(typed)
        if not verdict.allowed:
            logger.warning(
                "Proposal %s on %s by %s refused: %s",
                action_type,
                target,
                proposed_by,
                "; ".join(verdict.reasons),
            )
            return {"status": "refused", "reasons": list(verdict.reasons)}
        try:
            action = self.approval_service.create_action(
                action_type=atype,
                title=title,
                description=description,
                target=target,
                confidence=confidence,
                reason=reason,
                evidence=evidence,
                created_by=proposed_by,
                parameters=dict(parameters or {}),
                reversibility=Reversibility(typed.reversibility),
                human_only=True,
            )
        except AutonomyWatchOnly as e:
            return {"status": "watch", "reasons": [str(e)]}
        return {
            "status": action.status,
            "action_id": action.action_id,
            "requires_second_approver": verdict.requires_second_approver,
        }

    def create_isolation_action(
        self,
        ip_address: str,
        hostname: Optional[str],
        confidence: float,
        reason: str,
        evidence: List[str],
        correlation_data: Dict,
        category: Optional[str] = None,
    ) -> Optional[Dict]:
        """
        Create an isolation action (auto-executes when the approval gate
        approves it, i.e. at or above ``config.confidence_threshold``).

        The policy screens it first: a protected host is refused and no row is
        created; one the policy holds for a person is created ``human_only``.

        Args:
            ip_address: Target IP address
            hostname: Target hostname (optional)
            confidence: Confidence score (0.0-1.0)
            reason: Reason for isolation
            evidence: List of evidence IDs
            correlation_data: Data from correlation analysis
            category: the alert category the autonomy tier is looked up by
                (W3.1); under ``watch`` nothing is recorded and the result's
                status is ``watch``

        Returns:
            Action result
        """
        # Key on the IP when known; an IP-less finding (ip_address == "unknown")
        # keys on hostname instead, so distinct IP-less hosts get distinct rows
        # rather than colliding on the literal string "unknown".
        target_key = (
            ip_address if ip_address and ip_address != "unknown" else f"host:{hostname}"
        )

        try:
            screen = TypedAction(
                action_type=ActionType.ISOLATE_HOST.value,
                target=ip_address or "unknown",
                parameters={"hostname": hostname} if hostname else {},
                reversibility=(
                    self.executors.reversibility_of(ActionType.ISOLATE_HOST.value)
                    if self.executors.get(ActionType.ISOLATE_HOST.value) is not None
                    else "reversible"
                ),
            )
            verdict = self.evaluate(screen)
            if not verdict.allowed:
                logger.warning(
                    "Isolation of %s refused by policy: %s",
                    hostname or ip_address,
                    "; ".join(verdict.reasons),
                )
                return {
                    "status": "refused",
                    "message": "; ".join(verdict.reasons),
                    "confidence": confidence,
                    "reasons": list(verdict.reasons),
                }

            try:
                action, inserted = self.approval_service._put_action(
                    action_type=ActionType.ISOLATE_HOST,
                    title=f"Isolate Host: {hostname or ip_address}",
                    description=f"Network isolation of compromised host based on correlated detections.\n\n"
                    f"Indicators: {', '.join(correlation_data.get('indicators', []))}\n"
                    f"Reasoning: {' | '.join(correlation_data.get('reasoning', []))}",
                    target=ip_address,
                    confidence=confidence,
                    reason=reason,
                    evidence=evidence,
                    created_by=AgentId.AUTO_RESPONDER.value,
                    parameters={"hostname": hostname, "correlation": correlation_data},
                    idempotency_key=f"{ActionType.ISOLATE_HOST.value}:{target_key}",
                    reversibility=Reversibility(screen.reversibility),
                    human_only=verdict.requires_approval
                    or verdict.requires_second_approver,
                    category=category,
                )
            except AutonomyWatchOnly as e:
                logger.info(
                    "Isolation of %s observed only: %s", hostname or ip_address, e
                )
                return {
                    "status": "watch",
                    "message": str(e),
                    "confidence": confidence,
                }

            if not inserted:
                if action.status == ActionStatus.EXECUTED.value:
                    return {
                        "status": "executed",
                        "reused": True,
                        "action_id": action.action_id,
                        "message": f"Host {hostname or ip_address} already isolated",
                        "confidence": action.confidence,
                        "result": action.execution_result,
                    }
                return {
                    "status": action.status,
                    "reused": True,
                    "action_id": action.action_id,
                    "message": f"Isolation already recorded for {hostname or ip_address}",
                    "confidence": action.confidence,
                    "requires_approval": action.requires_approval,
                    "result": action.execution_result,
                }

            if action.status == ActionStatus.APPROVED.value:
                logger.info(
                    f"Action {action.action_id} auto-approved (confidence: {confidence:.2%})"
                )

                execution_result = self._dispatch(action) or {
                    "success": False,
                    "error": "unsupported_action_type",
                }

                if execution_result.get("status") == ActionStatus.PENDING.value:
                    return {
                        "status": "pending_approval",
                        "action_id": action.action_id,
                        "message": "Isolation action held for analyst approval",
                        "confidence": confidence,
                        "requires_approval": True,
                    }

                if execution_result.get("success"):
                    return {
                        "status": "executed",
                        "action_id": action.action_id,
                        "message": f"Host {hostname or ip_address} isolated automatically",
                        "confidence": confidence,
                        "result": execution_result,
                    }

                return {
                    "status": ActionStatus.FAILED.value,
                    "action_id": action.action_id,
                    "message": execution_result.get("message")
                    or f"Isolation of {hostname or ip_address} was not executed",
                    "confidence": confidence,
                    "result": execution_result,
                }
            else:
                logger.info(
                    f"Action {action.action_id} pending approval (confidence: {confidence:.2%})"
                )
                return {
                    "status": "pending_approval",
                    "action_id": action.action_id,
                    "message": "Isolation action created, awaiting analyst approval",
                    "confidence": confidence,
                    "requires_approval": True,
                }

        except Exception as e:
            logger.error(f"Error creating isolation action: {e}")
            return {"error": str(e)}

    def _execute_isolation(
        self, ip_address: str, hostname: Optional[str], reason: str, confidence: float
    ) -> Dict:
        """
        Report that host isolation has no executor.

        Called only when no executor in the registry takes isolate_host. A
        success result would record a containment that never happened.
        """
        logger.info(
            f"Isolation not executed: {hostname or ip_address} "
            f"(confidence: {confidence:.2%}); no EDR executor"
        )
        return {
            "success": False,
            "error": "unsupported_action_type",
            "message": "No EDR executor is configured for host isolation",
        }

    def execute_approved_actions(self) -> List[Dict]:
        """
        Execute all approved actions that haven't been executed yet.

        Each goes through the policy and then the registry's executor for its
        type (``_dispatch``). isolate_host with no executor is recorded failed;
        any other type with no executor is left for manual handling.

        Returns:
            List of execution results
        """
        try:
            # Get approved but not executed actions
            # Only rows something here can run, oldest first: see
            # ApprovalService.list_actions(undispatched=True).
            approved_actions = self.approval_service.list_actions(
                status=ActionStatus.APPROVED,
                action_types=self.executors.action_types()
                | {ActionType.ISOLATE_HOST.value},
                undispatched=True,
            )
            results = []

            for action in approved_actions:
                # Skip if already executed
                if action.executed_at:
                    continue
                # A reverse row is settled by reverse_action, never run forward.
                if action.reverse_of:
                    continue
                # Released by a confidence figure and no person: whoever
                # supplied that figure also chose the outcome.
                # An autonomous row (W3.1) is the exception: the tier released
                # it, and _dispatch decides the tier again before it runs.
                autonomy = (action.parameters or {}).get("autonomy") or {}
                autonomous = (
                    isinstance(autonomy, dict)
                    and autonomy.get("effective") == "autonomous"
                )
                if (
                    not action.requires_approval
                    and not action.approved_by
                    and not autonomous
                ):
                    logger.warning(
                        "Action %s was never decided by a person; not executing",
                        action.action_id,
                    )
                    continue

                try:
                    result = self._dispatch(action)
                except Exception as e:  # noqa: BLE001
                    # One bad row must not stop the queue, nor stay approved
                    # to be dispatched again on the next loop.
                    logger.exception("Dispatch of %s failed", action.action_id)
                    error = f"dispatch error: {type(e).__name__}"
                    try:
                        self.approval_service.mark_failed(action.action_id, error)
                    except Exception:  # noqa: BLE001
                        logger.exception("Could not mark %s failed", action.action_id)
                    result = {"success": False, "error": error, "status": "failed"}
                if result is None:
                    # Unknown action type — leave for another executor or manual handling.
                    continue

                results.append(
                    {
                        "action_id": action.action_id,
                        "action_type": action.action_type,
                        "target": action.target,
                        "result": result,
                    }
                )

            return results

        except Exception as e:
            logger.error(f"Error executing approved actions: {e}")
            return []

    # ------------------------------------------------------------------
    # Reversal: by a person (revert endpoint) or by expiry (TTL sweep)
    # ------------------------------------------------------------------

    @staticmethod
    def _original_result(action: PendingAction) -> ExecResult:
        """The original's ExecResult, rebuilt from its row."""
        stored = action.execution_result or {}
        status = stored.get("status")
        if status not in ("executed", "noop"):
            status = "executed"
        return ExecResult(
            status=status,
            message=str(stored.get("message") or ""),
            external_ref=stored.get("external_ref"),
            before_state=action.before_state,
            after_state=action.after_state,
        )

    def _original_no_longer_in_effect(
        self, executor: Any, original: PendingAction
    ) -> bool:
        """Whether the original's change is observably gone (a takeover check).

        Asks the executor's verify about the current state, the way it checks
        a settled noop: no external_ref, so Defender reads the machine rather
        than the old machine action. Only a definite ``failed`` (the change is
        not in effect) counts; ``unknown`` or an error reverses as before.
        """
        try:
            typed = self._typed(original)
        except ValueError:
            return False
        probe = ExecResult(
            status="noop",
            message="takeover state check",
            before_state=original.before_state,
            after_state=original.after_state,
        )
        return self._verify(executor, typed, probe) == "failed"

    def reverse_action(
        self, action_id: str, *, actor: str, reason: str
    ) -> Dict[str, Any]:
        """Undo an executed reversible action: reverse, then verify.

        Records a reverse row (``reverse_of`` = action_id) on the approval
        audit path and ``reversed_at`` on the original when the reverse ran
        and its verify did not find it failed. ``outcome`` is one of
        ``reversed``, ``failed``, ``not_found``, ``conflict``.
        """
        original = self.approval_service.get_action(action_id)
        if original is None:
            return {"outcome": "not_found", "message": f"no action {action_id}"}
        if original.reverse_of:
            return {
                "outcome": "conflict",
                "message": "a reverse row cannot be reverted",
            }
        if original.status != ActionStatus.EXECUTED.value:
            return {
                "outcome": "conflict",
                "message": f"action is {original.status}, not executed",
            }
        if original.reversed_at:
            return {"outcome": "conflict", "message": "action was already reversed"}
        executor = self.executors.get(original.action_type)
        if executor is None:
            return {
                "outcome": "conflict",
                "message": f"no executor for {original.action_type}",
            }
        if self.executors.reversibility_of(original.action_type) != "reversible":
            return {
                "outcome": "conflict",
                "message": f"{original.action_type} is irreversible",
            }

        try:
            typed = self._typed(original, reverse_of=original.action_id)
        except ValueError:
            return {"outcome": "conflict", "message": "stored action is not valid"}
        # No executor.validate here. It resolves the target afresh (Defender
        # looks the host up by name), and the reverse must act on what the
        # original acted on: the identity recorded in its result
        # (external_ref, before/after state), which reverse() receives. A host
        # renamed since, or a name now ambiguous, must not strand a change.
        # The registry checks that matter for a reverse were made above: an
        # executor holds the type and registered it reversible.

        claim = self.approval_service.begin_reversal(action_id, actor, reason)
        if claim is None:
            return {
                "outcome": "conflict",
                "message": "a reversal of this action is already recorded or in progress",
            }
        logger.info(
            "Reversing %s (%s on %s) for %s: %s",
            action_id,
            original.action_type,
            original.target,
            actor,
            reason,
        )
        already_undone = (
            bool((claim.parameters or {}).get("supersedes"))
            and self._original_no_longer_in_effect(executor, original)
        )
        if already_undone:
            # The superseded claimant may have been slow, not dead: its
            # reverse landed. Running it again would act on a state someone
            # may have set since (W0.13 review).
            outcome = ExecResult(
                status="noop",
                message="original no longer in effect at takeover; not reversed again",
                before_state=original.after_state,
                after_state=original.after_state,
            )
        else:
            try:
                outcome = executor.reverse(typed, self._original_result(original))
            except Exception as e:  # noqa: BLE001
                logger.exception("Reverse of %s raised", action_id)
                outcome = ExecResult(
                    status="failed", error=f"executor error: {type(e).__name__}"
                )

        verify_status: Optional[str] = None
        succeeded = outcome.ok
        result = outcome.to_execution_result()
        if already_undone:
            verify_status = "verified"
            result = {**result, "superseded_claim": claim.parameters["supersedes"]}
        elif succeeded:
            verify_status = self._verify(executor, typed, outcome)
            if verify_status == "failed":
                succeeded = False
                result = {
                    **result,
                    "success": False,
                    "error": "reverse ran but verify found it not in effect",
                }
        result = {**result, "reason": reason, "reversed_by": actor}
        settled = self.approval_service.finish_reversal(
            claim.action_id,
            succeeded=succeeded,
            result=result,
            verify_status=verify_status,
            before_state=outcome.before_state,
            after_state=outcome.after_state,
        )
        logger.info(
            "Reversal %s of %s: %s (verify: %s)",
            claim.action_id,
            action_id,
            "reversed" if succeeded else "failed",
            verify_status,
        )
        superseded = settled is not None and settled.status != (
            ActionStatus.EXECUTED.value if succeeded else ActionStatus.FAILED.value
        )
        return {
            "outcome": "reversed" if succeeded else "failed",
            "action_id": action_id,
            "reverse_action_id": claim.action_id,
            # This claim was taken over while it ran; the outcome is recorded
            # on it as late_outcome, and the takeover's row holds the key.
            "superseded": superseded,
            "verify_status": verify_status,
            "message": outcome.message or (outcome.error or ""),
            "reversed_at": (
                self.approval_service.get_action(action_id).reversed_at  # type: ignore[union-attr]
                if succeeded and settled is not None
                else None
            ),
        }

    def sweep_expired(self, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Reverse every executed reversible action whose expires_at has passed."""
        due = self.approval_service.list_expired(now or utcnow())
        results = []
        for action in due:
            try:
                results.append(
                    self.reverse_action(
                        action.action_id,
                        actor=TTL_SWEEP_ACTOR,
                        reason=f"ttl expired at {action.expires_at}",
                    )
                )
            except Exception as e:  # noqa: BLE001
                logger.error("TTL reversal of %s failed: %s", action.action_id, e)
        return results
