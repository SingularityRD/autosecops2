"""W0.25 adapt(upstream d2e5f2b6): every approval timestamp is stamped as UTC.

Upstream marked ``created_at``/``approved_at``/``executed_at`` as UTC and built
the action id from the UTC clock. This fork also serialises ``expires_at``,
``verified_at`` and ``reversed_at`` (through ``_iso``) and builds a reversal
row id (``…-rev``); both used the naive local clock / bare ``isoformat()``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest

from core.response import approval_service
from core.response.approval_service import _row_to_pending
from core.storage.models import ApprovalAction

NAIVE = datetime(2099, 1, 1, 8, 0, 0)


def _row(**kw) -> ApprovalAction:
    base = dict(
        action_id="utc-row",
        action_type="block_ip",
        title="t",
        description="d",
        target="203.0.113.9",
        confidence=0.9,
        reason="r",
        evidence=[],
        created_by="pytest",
        requires_approval=True,
        status="executed",
        created_at=NAIVE,
        parameters={},
    )
    base.update(kw)
    return ApprovalAction(**base)


def test_fork_lifecycle_fields_are_stamped_utc():
    pending = _row_to_pending(
        _row(
            expires_at=NAIVE + timedelta(hours=1),
            verified_at=NAIVE + timedelta(minutes=3),
            reversed_at=NAIVE + timedelta(minutes=4),
        )
    )
    assert pending.expires_at == "2099-01-01T09:00:00+00:00"
    assert pending.verified_at == "2099-01-01T08:03:00+00:00"
    assert pending.reversed_at == "2099-01-01T08:04:00+00:00"


def test_missing_lifecycle_fields_stay_none():
    pending = _row_to_pending(_row())
    assert pending.expires_at is None
    assert pending.verified_at is None
    assert pending.reversed_at is None


@pytest.mark.external_service
@pytest.mark.database
def test_reversal_id_comes_from_the_utc_clock(throwaway_database, monkeypatch):
    from core.storage.unit_of_work import unit_of_work

    original = f"orig-{uuid.uuid4().hex[:10]}"
    with unit_of_work() as session:
        session.add(
            _row(
                action_id=original,
                action_type="waf_block",
                reversibility="reversible",
                approved_by="alice",
                created_at=datetime(2026, 1, 1),
                executed_at=datetime(2026, 1, 1),
            )
        )
    fixed = datetime(2099, 3, 4, 5, 6, 7, 890000)
    monkeypatch.setattr(approval_service, "utcnow", lambda: fixed)
    row = approval_service.ApprovalService().begin_reversal(original, "carol", "undo")
    assert row is not None
    assert row.action_id == "action-20990304-050607-890000-rev"
