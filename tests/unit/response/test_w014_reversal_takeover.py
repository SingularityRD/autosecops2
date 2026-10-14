"""W0.14: a stale reversal claim is taken over only under row locks.

``begin_reversal`` read the stale claim and the original without locking them
and then overwrote the claim's status. A claimant that settled in between had
its executed reversal rewritten as "abandoned" (its outcome lost) while a new
claim was opened on a change that was already undone. The takeover now locks
the claim and the original (in ``finish_reversal``'s order) and re-reads them,
so the settle either lands first and is left untouched, or waits and is
recorded as a late outcome on the superseded claim.

Real Postgres (the ``throwaway_database`` scratch DB of tests/unit/conftest.py).
"""

from __future__ import annotations

import threading
import uuid
from datetime import timedelta

import pytest

from core.time import utcnow

pytestmark = [pytest.mark.external_service, pytest.mark.database]


def _row(**kw):
    from core.storage.models import ApprovalAction

    base = dict(
        action_type="waf_block",
        title="t",
        description="d",
        target="203.0.113.9",
        confidence=0.9,
        reason="r",
        created_by="pytest",
        reversibility="reversible",
        parameters={},
    )
    base.update(kw)
    return ApprovalAction(**base)


@pytest.fixture
def stale_claim(throwaway_database):
    from core.storage.unit_of_work import unit_of_work

    original = f"orig-{uuid.uuid4().hex[:10]}"
    claim = f"{original}-rev-old"
    with unit_of_work() as session:
        session.add(
            _row(
                action_id=original,
                evidence=[],
                requires_approval=True,
                status="executed",
                approved_by="alice",
                created_at=utcnow() - timedelta(days=1),
                executed_at=utcnow() - timedelta(days=1),
            )
        )
    with unit_of_work() as session:
        session.add(
            _row(
                action_id=claim,
                evidence=[original],
                created_by="bob",
                requires_approval=False,
                status="pending",
                approved_by="bob",
                created_at=utcnow() - timedelta(hours=2),
                idempotency_key=f"reverse:{original}",
                reverse_of=original,
            )
        )
    return original, claim


def _settle_while_taking_over(monkeypatch, original, claim):
    """Run ``begin_reversal`` with the stale claimant settling (succeeded)
    right after the takeover has read the claim, before it writes."""
    from core.response import approval_service as mod
    from core.response.approval_service import ApprovalService

    svc = ApprovalService()
    real = mod._nonfailed_by_key
    settled = {}

    def settle():
        settled["row"] = ApprovalService().finish_reversal(
            claim, succeeded=True, result={"success": True}, verify_status="verified"
        )

    worker = threading.Thread(target=settle, daemon=True)

    def interleave(session, key, **kw):
        held = real(session, key, **kw)
        if key == f"reverse:{original}" and not worker.is_alive() and not settled:
            worker.start()
            # Unlocked, the settle commits here; locked, it waits on the claim.
            worker.join(timeout=5)
        return held

    monkeypatch.setattr(mod, "_nonfailed_by_key", interleave)
    new = svc.begin_reversal(original, "carol", "again")
    worker.join(timeout=60)
    assert not worker.is_alive(), "the settle never finished"
    return svc, new, settled.get("row")


def test_a_claim_settling_during_the_takeover_keeps_its_outcome(
    monkeypatch, stale_claim
):
    original, claim = stale_claim
    svc, new, late = _settle_while_taking_over(monkeypatch, original, claim)

    old = svc.get_action(claim)
    assert late is not None
    # The claimant's executed reversal is never lost: either it landed first
    # and the takeover left it alone, or the takeover won the lock and the
    # settle is recorded on the superseded claim.
    if old.status == "executed":
        assert new is None
        assert old.execution_result == {"success": True}
    else:
        assert old.status == "failed"
        assert old.execution_result.get("superseded") is True
        assert old.execution_result["late_outcome"]["succeeded"] is True
        assert new is not None and new.parameters["supersedes"] == claim
    assert svc.get_action(original).reversed_at is not None


def test_a_just_settled_claim_is_left_untouched(monkeypatch, stale_claim):
    """The settle commits after the takeover's first (unlocked) read of the
    original: the locked re-read sees it, and nothing is overwritten."""
    from core.response import approval_service as mod
    from core.response.approval_service import ApprovalService

    original, claim = stale_claim
    real = mod._nonfailed_by_key
    done = []

    def settle_first(session, key, **kw):
        if not done:
            done.append(
                ApprovalService().finish_reversal(
                    claim, succeeded=True, result={"success": True}
                )
            )
        return real(session, key, **kw)

    monkeypatch.setattr(mod, "_nonfailed_by_key", settle_first)
    svc = ApprovalService()
    assert svc.begin_reversal(original, "carol", "again") is None
    old = svc.get_action(claim)
    assert old.status == "executed"
    assert old.execution_result == {"success": True}
    assert svc.get_action(original).reversed_at is not None
