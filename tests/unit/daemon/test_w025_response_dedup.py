"""W0.25: a re-triaged finding is not responded to twice.

The W0.25 backfill predicate re-queues analysis-only rows after an upgrade
(within ``DAEMON_ENRICH_BACKFILL_MAX_AGE_HOURS``). Re-triage is fine; a second
response proposal or escalation for a finding that already has an approval
row is not.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, Mock

import pytest

from services.daemon.config import EscalationConfig, ResponseConfig
from services.daemon.responder import AutonomousResponder

FINDING = {
    "finding_id": "f-dedup",
    "severity": "critical",
    "triage_confidence": 0.99,
    "recommended_action": "isolate",
    "entity_context": {"src_ips": ["10.20.30.40"]},
}


def _responder(already):
    approvals = Mock()
    if isinstance(already, Exception):
        approvals.has_action_for_finding.side_effect = already
    else:
        approvals.has_action_for_finding.return_value = already
    responder = AutonomousResponder(
        ResponseConfig(auto_response_enabled=True),
        EscalationConfig(),
        response_service=Mock(),
        approvals=approvals,
    )
    responder._create_response_action = AsyncMock()
    responder._escalate_finding = AsyncMock()
    return responder, approvals


@pytest.mark.asyncio
async def test_a_finding_with_a_response_row_is_not_proposed_again():
    responder, approvals = _responder(True)

    await responder._evaluate_response(dict(FINDING))

    approvals.has_action_for_finding.assert_called_once_with("f-dedup")
    responder._create_response_action.assert_not_awaited()
    responder._escalate_finding.assert_not_awaited()
    assert responder.stats["already_responded"] == 1


@pytest.mark.asyncio
async def test_a_finding_without_one_is_proposed():
    responder, _ = _responder(False)

    await responder._evaluate_response(dict(FINDING))

    responder._create_response_action.assert_awaited_once()
    assert responder.stats["already_responded"] == 0


@pytest.mark.asyncio
async def test_a_failed_check_behaves_as_before():
    responder, _ = _responder(RuntimeError("db down"))

    await responder._evaluate_response(dict(FINDING))

    responder._create_response_action.assert_awaited_once()


@pytest.mark.external_service
@pytest.mark.database
def test_has_action_for_finding_reads_the_evidence(throwaway_database):
    from core.response.approval_service import ApprovalService
    from core.storage.models import ApprovalAction
    from core.storage.unit_of_work import unit_of_work

    fid = f"f-{uuid.uuid4().hex[:10]}"
    with unit_of_work() as session:
        session.add(
            ApprovalAction(
                action_id=f"act-{uuid.uuid4().hex[:10]}",
                action_type="isolate_host",
                title="t",
                description="d",
                target="10.20.30.40",
                confidence=0.9,
                reason="r",
                evidence=[fid],
                created_by="pytest",
                requires_approval=True,
                status="rejected",
                parameters={},
            )
        )
    service = ApprovalService()
    assert service.has_action_for_finding(fid) is True
    assert service.has_action_for_finding(f"{fid}-other") is False
