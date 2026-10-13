"""The two-person rule's distinct-role condition and the SoD report (W3.2).

DB-backed: the throwaway database (tests/unit/conftest.py) plus
``61_approval_decisions.sql``, which create_all does not build.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from core.response import segregation
from core.response.approval_service import (
    ActionStatus,
    ActionType,
    ApprovalService,
    SecondApproverConflict,
    SecondApproverRoleConflict,
    second_approver_detail,
)
from core.response.config import ResponseConfig
from core.response.policy import PolicyConfig
from core.storage.connection import get_db_manager
from core.storage.models import ApprovalAction as Row
from core.storage.models import Role, User
from core.time import utcnow

pytestmark = pytest.mark.external_service

INIT_SQL = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "61_approval_decisions.sql"
)
TAG = uuid.uuid4().hex[:6]


def _name(base: str) -> str:
    return f"{base}-{TAG}"


@pytest.fixture(scope="module")
def people(throwaway_database):
    """Two senior analysts and a manager, and the decisions table."""
    with get_db_manager().engine.begin() as conn:
        conn.execute(text(INIT_SQL.read_text(encoding="utf-8")))
    with get_db_manager().session_scope() as s:
        for role_id, name in (
            ("r-senior-" + TAG, "Senior " + TAG),
            ("r-mgr-" + TAG, "Manager " + TAG),
        ):
            s.add(Role(role_id=role_id, name=name, description="", permissions={}))
        s.flush()
        for user, role_id in (
            ("alice", "r-senior-" + TAG),
            ("bob", "r-senior-" + TAG),
            ("mallory", "r-mgr-" + TAG),
        ):
            s.add(
                User(
                    user_id=f"u-{user}-{TAG}",
                    username=_name(user),
                    email=f"{user}-{TAG}@test.local",
                    password_hash="x",
                    full_name=user,
                    role_id=role_id,
                )
            )
    return {
        "alice": _name("alice"),
        "bob": _name("bob"),
        "mallory": _name("mallory"),
    }


def _svc(**raw) -> ApprovalService:
    svc = ApprovalService(
        config=ResponseConfig(), policy_config=PolicyConfig.from_mapping(raw)
    )
    svc.force_manual_approval = False
    return svc


def _create(svc, action_type=ActionType.DISABLE_USER, created_by="pytest"):
    return svc.create_action(
        action_type=action_type,
        title="t",
        description="d",
        target=f"user-{uuid.uuid4().hex[:6]}@example.com",
        confidence=0.99,
        reason="r",
        evidence=["ev"],
        created_by=created_by,
    )


def _decisions(action_id):
    with get_db_manager().session_scope() as s:
        return [
            tuple(r)
            for r in s.execute(
                text(
                    "SELECT step, actor, actor_role_id FROM approval_decisions "
                    "WHERE action_id = :a ORDER BY id"
                ),
                {"a": action_id},
            ).all()
        ]


class TestConfig:
    def test_distinct_role_types_are_four_eyes_types_too(self):
        cfg = PolicyConfig.from_mapping(
            {"distinct_role_types": ["block_ip", "DISABLE_USER"]}
        )
        assert cfg.needs_distinct_role("block_ip")
        assert cfg.needs_second_approver("block_ip")
        assert cfg.needs_distinct_role("disable_user")
        assert not cfg.needs_distinct_role("revoke_sessions")

    def test_off_by_default(self):
        assert PolicyConfig().distinct_role_types == frozenset()
        assert not PolicyConfig.from_mapping({}).needs_distinct_role("disable_user")

    def test_the_conflict_is_a_second_approver_conflict(self):
        e = SecondApproverRoleConflict("x")
        assert isinstance(e, SecondApproverConflict)
        assert "different role" in second_approver_detail(e)
        assert "different person" in second_approver_detail(SecondApproverConflict("x"))


class TestDistinctRole:
    def test_same_role_second_approval_is_refused_when_configured(self, people):
        svc = _svc(distinct_role_types=["disable_user"])
        row = _create(svc)
        svc.approve_action(row.action_id, people["alice"])
        with pytest.raises(SecondApproverRoleConflict):
            svc.approve_action(row.action_id, people["bob"])
        still = svc.get_action(row.action_id)
        assert still.status == ActionStatus.PENDING.value
        assert still.second_approver is None
        assert [d[0] for d in _decisions(row.action_id)] == ["first_approval"]

    def test_a_different_role_completes_the_approval(self, people):
        svc = _svc(distinct_role_types=["disable_user"])
        row = _create(svc)
        svc.approve_action(row.action_id, people["alice"])
        done = svc.approve_action(row.action_id, people["mallory"].upper())
        assert done.status == ActionStatus.APPROVED.value
        assert _decisions(row.action_id) == [
            ("first_approval", people["alice"], "r-senior-" + TAG),
            ("second_approval", people["mallory"].upper(), "r-mgr-" + TAG),
        ]

    def test_without_the_condition_the_same_role_may_approve(self, people):
        svc = _svc()
        row = _create(svc)
        svc.approve_action(row.action_id, people["alice"])
        done = svc.approve_action(row.action_id, people["bob"])
        assert done.status == ActionStatus.APPROVED.value

    def test_the_same_person_is_still_refused(self, people):
        svc = _svc(distinct_role_types=["disable_user"])
        row = _create(svc)
        svc.approve_action(row.action_id, people["alice"])
        with pytest.raises(SecondApproverConflict):
            svc.approve_action(row.action_id, people["alice"].upper())

    @pytest.mark.parametrize("second", ["analyst", "agent", ""])
    def test_an_approver_with_no_role_is_refused(self, people, second):
        svc = _svc(distinct_role_types=["disable_user"])
        row = _create(svc)
        svc.approve_action(row.action_id, people["alice"])
        with pytest.raises(SecondApproverRoleConflict):
            svc.approve_action(row.action_id, second or "nobody")

    def test_the_first_approvers_recorded_role_counts(self, people):
        svc = _svc(distinct_role_types=["disable_user"])
        row = _create(svc)
        svc.approve_action(row.action_id, people["mallory"])
        # Mallory is moved to the senior role after approving as manager...
        with get_db_manager().session_scope() as s:
            s.query(User).filter(User.username == people["mallory"]).update(
                {"role_id": "r-senior-" + TAG}
            )
        try:
            # ...a senior analyst may still second it: the decision was a manager's.
            done = svc.approve_action(row.action_id, people["bob"])
            assert done.status == ActionStatus.APPROVED.value
        finally:
            with get_db_manager().session_scope() as s:
                s.query(User).filter(User.username == people["mallory"]).update(
                    {"role_id": "r-mgr-" + TAG}
                )

    def test_configurable_per_action_class(self, people):
        svc = _svc(distinct_role_types=["revoke_sessions"])
        same_ok = _create(svc, ActionType.DISABLE_USER)
        svc.approve_action(same_ok.action_id, people["alice"])
        assert svc.approve_action(same_ok.action_id, people["bob"]).status == "approved"
        refused = _create(svc, ActionType.REVOKE_SESSIONS)
        svc.approve_action(refused.action_id, people["alice"])
        with pytest.raises(SecondApproverRoleConflict):
            svc.approve_action(refused.action_id, people["bob"])

    def test_single_approvals_and_rejections_are_recorded(self, people):
        svc = _svc()
        svc.force_manual_approval = True
        approved = _create(svc, ActionType.BLOCK_IP)
        svc.approve_action(approved.action_id, people["alice"])
        rejected = _create(svc, ActionType.BLOCK_IP)
        svc.reject_action(rejected.action_id, "no", people["bob"])
        assert _decisions(approved.action_id) == [
            ("approve", people["alice"], "r-senior-" + TAG)
        ]
        assert _decisions(rejected.action_id) == [
            ("reject", people["bob"], "r-senior-" + TAG)
        ]


def _row(action_type="block_ip", status="executed", **kw):
    now = utcnow()
    values = dict(
        action_id=f"sod-{uuid.uuid4().hex[:10]}",
        action_type=action_type,
        title="t",
        description="d",
        target="198.51.100.9",
        confidence=0.9,
        reason="r",
        evidence=[],
        created_at=now,
        created_by="pytest",
        requires_approval=True,
        status=status,
        parameters={},
        reversibility="reversible",
        executed_at=now if status == "executed" else None,
    )
    values.update(kw)
    with get_db_manager().session_scope() as s:
        s.add(Row(**values))
    return values["action_id"]


def _report(policy=None, **kw):
    with get_db_manager().session_scope() as s:
        report = segregation.build_report(
            s,
            policy
            or PolicyConfig.from_mapping({"distinct_role_types": ["disable_user"]}),
            **kw,
        )
    return {r["action_id"]: r for r in report["rows"]}, report


class TestReport:
    def test_each_violation_is_found(self, people):
        a, b, m = people["alice"], people["bob"], people["mallory"]
        clean = _row(approved_by=a)
        self_approved = _row(created_by=a, approved_by=a.upper())
        missing = _row("disable_user", approved_by=a)
        same_role = _row("disable_user", approved_by=a, second_approver=b)
        unknown = _row("disable_user", approved_by=a, second_approver="ghost")
        same_person = _row("disable_user", approved_by=a, second_approver=a.upper())
        unapproved = _row(approved_by=None)
        distinct_ok = _row("disable_user", approved_by=a, second_approver=m)
        rows, report = _report()

        assert rows[clean]["violations"] == []
        assert rows[clean]["approved_role"] == "Senior " + TAG
        assert rows[clean]["executed_by"] == segregation.DISPATCHER
        assert rows[self_approved]["violations"] == ["self_approval"]
        assert rows[missing]["violations"] == ["missing_second_approver"]
        assert rows[same_role]["violations"] == ["same_role"]
        assert rows[unknown]["violations"] == ["unknown_role"]
        assert "same_person" in rows[same_person]["violations"]
        assert rows[unapproved]["violations"] == ["executed_without_approval"]
        assert rows[distinct_ok]["violations"] == []
        assert rows[distinct_ok]["second_role"] == "Manager " + TAG
        assert report["summary"]["by_kind"]["same_role"] >= 1
        assert set(report["summary"]["by_kind"]) == set(segregation.VIOLATIONS)

    def test_recorded_roles_win_over_current_ones(self, people):
        svc = _svc(distinct_role_types=["disable_user"])
        row = _create(svc)
        svc.approve_action(row.action_id, people["alice"])
        svc.approve_action(row.action_id, people["mallory"])
        rows, _ = _report()
        assert rows[row.action_id]["role_source"] == "recorded"
        assert rows[row.action_id]["violations"] == []
        legacy = _row(
            "disable_user",
            approved_by=people["alice"],
            second_approver=people["mallory"],
        )
        rows, _ = _report()
        assert rows[legacy]["role_source"] == "current"

    def test_reverse_rows_name_who_reverted(self, people):
        original = _row(approved_by=people["alice"])
        reverse = _row(
            approved_by=people["bob"],
            created_by=people["bob"],
            reverse_of=original,
            requires_approval=False,
        )
        rows, _ = _report()
        assert rows[reverse]["executed_by"] == people["bob"]
        assert rows[reverse]["violations"] == []

    def test_filters(self, people):
        bad = _row(approved_by=None)
        rows, report = _report(violations_only=True)
        assert bad in rows
        assert all(r["violations"] for r in report["rows"])
        rows, _ = _report(action_type="disable_user")
        assert bad not in rows
        rows, _ = _report(since=utcnow())
        assert bad not in rows

    def test_csv_cells_cannot_be_formulas(self, people):
        rid = _row(approved_by=None, target='=HYPERLINK("http://x")', created_by="+cmd")
        _, report = _report()
        csv_text = segregation.to_csv(report)
        assert csv_text.splitlines()[0].split(",") == list(segregation.CSV_COLUMNS)
        line = next(line for line in csv_text.splitlines() if rid in line)
        assert "'=HYPERLINK" in line and "'+cmd" in line
        assert "executed_without_approval" in line
