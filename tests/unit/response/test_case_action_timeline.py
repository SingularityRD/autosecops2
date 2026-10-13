"""GET /api/cases/{id}/actions/timeline: a case's response actions and lifecycle (W2.8)."""

from datetime import datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.response.action_timeline import summarize_state
from core.storage.models import ApprovalAction, Case, Investigation, WorkflowRun
from core.storage.unit_of_work import unit_of_work

T0 = datetime(2099, 2, 1, 8, 0, 0)
CASE = "tl-case"


def _approval(action_id: str, created_at: datetime, **kw) -> ApprovalAction:
    return ApprovalAction(
        action_id=action_id,
        action_type=kw.pop("action_type", "block_ip"),
        title=kw.pop("title", action_id),
        description="d",
        target=kw.pop("target", "10.0.0.9"),
        confidence=kw.pop("confidence", 0.9),
        reason=kw.pop("reason", "because"),
        evidence=[],
        created_by=kw.pop("created_by", "containment_agent"),
        requires_approval=kw.pop("requires_approval", True),
        status=kw.pop("status", "pending"),
        created_at=created_at,
        parameters=kw.pop("parameters", {}),
        **kw,
    )


# --- pure helpers -----------------------------------------------------------


@pytest.mark.unit
def test_summarize_state_is_bounded_and_flat():
    assert summarize_state(None) is None
    assert summarize_state({}) is None
    assert summarize_state(["not", "a", "dict"]) is None
    rows = summarize_state(
        {
            "isolated": False,
            "policy": {"a": 1, "b": 2},
            "ips": [1, 2, 3],
            "note": None,
            "long": "x" * 500,
        }
    )
    by_key = {row["key"]: row["value"] for row in rows}
    assert by_key["isolated"] == "false"
    assert by_key["policy"] == "{2 keys}"
    assert by_key["ips"] == "[3 items]"
    assert by_key["note"] == "null"
    assert len(by_key["long"]) == 120 and by_key["long"].endswith("…")

    many = summarize_state({f"k{i:02d}": i for i in range(20)})
    assert len(many) == 13
    assert many[-1] == {"key": "…", "value": "8 more"}


# --- the route --------------------------------------------------------------


@pytest.fixture
def client():
    from services.api.routers.cases import router

    app = FastAPI()
    app.include_router(router, prefix="/api/cases")
    return TestClient(app)


@pytest.fixture
def seeded(throwaway_database):
    with unit_of_work() as session:
        session.add_all(
            [
                Case(case_id=CASE, title="timeline", status="open"),
                Case(case_id="tl-other", title="other", status="open"),
                WorkflowRun(
                    run_id="tl-run",
                    workflow_id="tl-wf",
                    workflow_name="Timeline",
                    status="completed",
                    trigger_context={"case_id": CASE},
                    started_at=T0,
                ),
                Investigation(
                    investigation_id="tl-inv",
                    case_id=CASE,
                    workflow_id="tl-wf",
                    trigger_type="manual",
                    trigger_ids=[],
                    workdir="/tmp/tl",
                ),
            ]
        )
        session.flush()
        session.add_all(
            [
                # Executed, verified, expiring, reversible: the Revert candidate.
                _approval(
                    "tl-exec",
                    T0,
                    title="Block 10.0.0.9",
                    reason="C2 beacon seen.; response.auto_approve_threshold=0.90 met (0.95)",
                    status="executed",
                    parameters={"case_id": CASE},
                    approved_at=T0 + timedelta(minutes=1),
                    approved_by="alice",
                    second_approver="bob",
                    executed_at=T0 + timedelta(minutes=2),
                    execution_result={
                        "success": True,
                        "status": "succeeded",
                        "message": "rule 42 added",
                    },
                    verified_at=T0 + timedelta(minutes=3),
                    verify_status="verified",
                    expires_at=T0 + timedelta(hours=24),
                    before_state={"blocked": False},
                    after_state={"blocked": True, "rule": {"id": 42}},
                ),
                # Executed but irreversible.
                _approval(
                    "tl-irrev",
                    T0 + timedelta(minutes=10),
                    action_type="disable_user",
                    status="executed",
                    reversibility="irreversible",
                    workflow_run_id="tl-run",
                    approved_at=T0 + timedelta(minutes=11),
                    approved_by="alice",
                    executed_at=T0 + timedelta(minutes=12),
                ),
                # Executed reversible, already reverted by tl-undo below.
                _approval(
                    "tl-done",
                    T0 + timedelta(minutes=20),
                    status="executed",
                    parameters={"investigation_id": "tl-inv"},
                    approved_at=T0 + timedelta(minutes=21),
                    approved_by="alice",
                    executed_at=T0 + timedelta(minutes=22),
                    reversed_at=T0 + timedelta(minutes=40),
                ),
                # The revert row carries no case id of its own.
                _approval(
                    "tl-undo",
                    T0 + timedelta(minutes=39),
                    status="executed",
                    reverse_of="tl-done",
                    created_by="carol",
                    executed_at=T0 + timedelta(minutes=40),
                ),
                _approval(
                    "tl-rejected",
                    T0 + timedelta(minutes=30),
                    status="rejected",
                    parameters={"case_id": CASE},
                    approved_at=T0 + timedelta(minutes=31),
                    approved_by="dave",
                    rejection_reason="wrong host",
                ),
                _approval(
                    "tl-failed",
                    T0 + timedelta(minutes=50),
                    status="failed",
                    parameters={"case_id": CASE},
                    executed_at=T0 + timedelta(minutes=51),
                    execution_result={"success": False, "error": "EDR timeout"},
                ),
                _approval(
                    "tl-pending",
                    T0 + timedelta(minutes=60),
                    parameters={"case_id": CASE},
                ),
                # Names another case directly; the run's case only fills a gap.
                _approval(
                    "tl-elsewhere",
                    T0 + timedelta(minutes=70),
                    workflow_run_id="tl-run",
                    parameters={"case_id": "tl-other"},
                ),
            ]
        )
    yield
    with unit_of_work() as session:
        session.query(ApprovalAction).filter(
            ApprovalAction.reverse_of.like("tl-%")
        ).delete(synchronize_session=False)
        session.query(ApprovalAction).filter(
            ApprovalAction.action_id.like("tl-%")
        ).delete(synchronize_session=False)
        session.query(Investigation).filter(
            Investigation.investigation_id == "tl-inv"
        ).delete(synchronize_session=False)
        session.query(WorkflowRun).filter(WorkflowRun.run_id == "tl-run").delete(
            synchronize_session=False
        )
        session.query(Case).filter(Case.case_id.in_([CASE, "tl-other"])).delete(
            synchronize_session=False
        )


def _by_id(body: dict) -> dict:
    return {item["action_id"]: item for item in body["actions"]}


@pytest.mark.unit
@pytest.mark.external_service
@pytest.mark.database
def test_timeline_resolves_the_case_and_orders_newest_first(client, seeded):
    res = client.get(f"/api/cases/{CASE}/actions/timeline")
    assert res.status_code == 200
    body = res.json()
    ids = [item["action_id"] for item in body["actions"]]
    assert ids == [
        "tl-pending",
        "tl-failed",
        "tl-undo",
        "tl-rejected",
        "tl-done",
        "tl-irrev",
        "tl-exec",
    ]
    assert body["case_id"] == CASE
    assert body["count"] == 7
    assert body["truncated"] is False
    assert "tl-elsewhere" not in ids

    other = client.get("/api/cases/tl-other/actions/timeline").json()
    assert [item["action_id"] for item in other["actions"]] == ["tl-elsewhere"]


@pytest.mark.unit
@pytest.mark.external_service
@pytest.mark.database
def test_timeline_carries_each_lifecycle_column(client, seeded):
    items = _by_id(client.get(f"/api/cases/{CASE}/actions/timeline").json())

    ex = items["tl-exec"]
    assert ex["proposed_by"] == "containment_agent"
    assert ex["proposed_at"] == "2099-02-01T08:00:00Z"
    assert ex["reason"] == "C2 beacon seen."
    assert ex["policy"] == {
        "requires_approval": True,
        "decision_rule": "response.auto_approve_threshold=0.90 met (0.95)",
    }
    assert ex["approved_by"] == "alice"
    assert ex["second_approver"] == "bob"
    assert ex["executed_at"] == "2099-02-01T08:02:00Z"
    assert ex["execution"]["message"] == "rule 42 added"
    assert ex["verify_status"] == "verified"
    assert ex["verified_at"] == "2099-02-01T08:03:00Z"
    assert ex["expires_at"] == "2099-02-02T08:00:00Z"
    assert ex["before_state"] == [{"key": "blocked", "value": "false"}]
    assert ex["after_state"] == [
        {"key": "blocked", "value": "true"},
        {"key": "rule", "value": "{1 keys}"},
    ]
    assert ex["can_revert"] is True
    assert [e["kind"] for e in ex["events"]] == [
        "proposed",
        "approved",
        "executed",
        "verified",
    ]
    assert ex["events"][1]["actor"] == "alice + bob"
    assert ex["events"][3]["detail"] == "verified"

    rej = items["tl-rejected"]
    assert rej["approved_by"] is None and rej["approved_at"] is None
    assert rej["rejection_reason"] == "wrong host"
    assert rej["events"][-1] == {
        "kind": "rejected",
        "at": "2099-02-01T08:31:00Z",
        "actor": "dave",
        "detail": "wrong host",
    }
    assert rej["can_revert"] is False

    failed = items["tl-failed"]
    assert failed["events"][-1]["kind"] == "failed"
    assert failed["events"][-1]["detail"] == "EDR timeout"
    assert failed["can_revert"] is False

    assert items["tl-pending"]["events"] == [
        {
            "kind": "proposed",
            "at": "2099-02-01T09:00:00Z",
            "actor": "containment_agent",
            "detail": None,
        }
    ]
    assert items["tl-pending"]["can_revert"] is False


@pytest.mark.unit
@pytest.mark.external_service
@pytest.mark.database
def test_revert_state_is_derived_from_the_row(client, seeded):
    items = _by_id(client.get(f"/api/cases/{CASE}/actions/timeline").json())
    # Irreversible: never offered.
    assert items["tl-irrev"]["can_revert"] is False
    # Already reverted: reversed_at set and the undoing row is linked.
    done = items["tl-done"]
    assert done["can_revert"] is False
    assert done["reverted_by"] == "tl-undo"
    assert done["events"][-1]["kind"] == "reversed"
    # The revert row itself belongs to the case through reverse_of, and is not revertible.
    undo = items["tl-undo"]
    assert undo["reverse_of"] == "tl-done"
    assert undo["can_revert"] is False


@pytest.mark.unit
@pytest.mark.external_service
@pytest.mark.database
def test_unknown_case_is_404_and_empty_case_is_empty(client, seeded):
    assert client.get("/api/cases/tl-missing/actions/timeline").status_code == 404
    with unit_of_work() as session:
        session.add(Case(case_id="tl-empty", title="empty", status="open"))
    try:
        body = client.get("/api/cases/tl-empty/actions/timeline").json()
        assert body == {
            "case_id": "tl-empty",
            "count": 0,
            "truncated": False,
            "actions": [],
        }
    finally:
        with unit_of_work() as session:
            session.query(Case).filter(Case.case_id == "tl-empty").delete(
                synchronize_session=False
            )


@pytest.mark.unit
def test_route_is_read_only_and_auth_required():
    """GET only, and mounted behind auth like the rest of the cases router."""
    from core.routing import Auth
    from services.api.routers import cases

    assert cases.ROUTER_META.auth is Auth.REQUIRED
    methods = {
        method
        for route in cases.router.routes
        if getattr(route, "path", "") == "/{case_id}/actions/timeline"
        for method in route.methods
    }
    assert methods == {"GET"}
