"""API envelopes and computed payloads for the cases router.

Entity rows reuse the dump schemas; each list wrapper and each computed dict
is its own model so OpenAPI records the real JSON. Lives here rather than
under ``services/api/routers/`` because every module there must export a
``router``.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel

from core.storage.schemas.case import CaseSchema
from core.storage.schemas.case_entities import (
    CaseClosureInfoSchema,
    CaseCommentSchema,
    CaseEscalationSchema,
    CaseEvidenceSchema,
    CaseIOCSchema,
    CaseRelationshipSchema,
    CaseTaskSchema,
    CaseWatcherSchema,
)


class CaseSuccessResponse(BaseModel):
    """Mutation that only reports whether it landed."""

    success: bool


class CaseQueueItem(BaseModel):
    """One row of the case queue.

    ``case_id`` and ``title`` stay so callers that only need a picker
    (the workflow start dialog) can keep reading the list.
    """

    case_id: str
    title: str
    priority: Optional[str] = None
    assignee: Optional[str] = None
    combined_state: str
    workflow_id: Optional[str] = None
    findings_count: int = 0
    iteration_count: Optional[int] = None
    cost_usd: Optional[float] = None
    max_cost_usd: Optional[float] = None
    budget_health: Optional[str] = None
    comment_count: int = 0
    last_activity: Optional[datetime] = None
    age_seconds: float
    sla_seconds_left: Optional[float] = None
    health_status: Optional[str] = None
    needs_you: bool = False
    description: Optional[str] = None
    sla_paused: bool = False


class CaseQueueStrip(BaseModel):
    """Counts for the queue strip. Independent of the page filters."""

    by_state: dict[str, int]
    sla_at_risk: int
    closed_today: int
    agent_closure_share: float
    needs_you: int


class CaseListResponse(BaseModel):
    cases: list[CaseQueueItem]
    total: int
    limit: int
    offset: int
    has_more: bool
    strip: CaseQueueStrip


class CaseInvestigationRef(BaseModel):
    """One run on the case page: an investigation, or a run started on the case
    with no investigation row (``investigation_id`` null). Newest first."""

    investigation_id: Optional[str] = None
    status: str
    workflow_id: str
    run_id: str
    live: bool = False
    cost_usd: float = 0
    max_cost_usd: float = 0
    budget_health: str = "healthy"
    iteration_count: int = 0
    created_at: Optional[str] = None


class CaseClosureView(BaseModel):
    """What the closed summary shows. ``verdict`` is the stated reason."""

    closure_category: str
    closed_by: str
    closed_by_kind: str
    closed_at: Optional[str] = None
    verdict: str = ""


class CaseLinkedFinding(BaseModel):
    """One finding the case already links, and the source door when one exists."""

    finding_id: str
    title: Optional[str] = None
    description: Optional[str] = None
    source_link: Optional[str] = None
    entities: list[str] = []


class CaseDetailResponse(CaseSchema):
    """``GET /cases/{id}`` — the case, its combined state, and the runs on it."""

    combined_state: str
    investigations: list[CaseInvestigationRef] = []
    closure: Optional[CaseClosureView] = None
    linked_findings: list[CaseLinkedFinding] = []


class CaseRecordRow(BaseModel):
    id: str
    at: str
    kind: str
    source: str
    chained: bool
    text: str


class CaseSubjectValue(BaseModel):
    ref: int
    field: str = "value"
    value: str = ""


class CaseRecordResponse(BaseModel):
    """The merged record. ``run_id`` is absent when the case has no run."""

    run_id: Optional[str] = None
    investigation_id: Optional[str] = None
    rows: list[CaseRecordRow] = []
    # W0.30: subject-written values the rows name as [subject value N]; the
    # console renders them as plain text in their own box.
    subject_values: list[CaseSubjectValue] = []


class CasePurgeResponse(BaseModel):
    success: bool
    deleted: int
    killed_investigations: int = 0
    message: str


class CaseReportResponse(BaseModel):
    success: bool
    filename: str
    path: str
    case_id: str


class CaseSummaryResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    by_priority: dict[str, int]


class CaseCommentsResponse(BaseModel):
    comments: list[CaseCommentSchema]


class CaseWatchersResponse(BaseModel):
    watchers: list[CaseWatcherSchema]


class CaseEvidenceListResponse(BaseModel):
    evidence: list[CaseEvidenceSchema]


class CaseIOCListResponse(BaseModel):
    iocs: list[CaseIOCSchema]


class CaseIOCBulkResponse(BaseModel):
    added: int


class CaseIOCExportResponse(BaseModel):
    format: str
    content: Any


class CaseTasksResponse(BaseModel):
    tasks: list[CaseTaskSchema]


class CaseRelationshipsResponse(BaseModel):
    relationships: list[CaseRelationshipSchema]


class CaseCloseResponse(BaseModel):
    success: bool
    closure: CaseClosureInfoSchema


class CaseEscalationsResponse(BaseModel):
    escalations: list[CaseEscalationSchema]


class CaseMergeResponse(BaseModel):
    success: bool
    target_case: Optional[CaseSchema] = None
    findings_moved: Optional[int] = None
    source_case_status: str
    message: str


class CaseSearchResponse(BaseModel):
    results: list[CaseSchema]
    total: int
    limit: int
    offset: int
    has_more: bool


class CaseActionStateRow(BaseModel):
    """One key of an action's observed before/after state, value as text."""

    key: str
    value: str


class CaseActionEvent(BaseModel):
    """One dated step of an action's lifecycle.

    ``kind``: proposed, approved, rejected, executed, failed, verified,
    reversed. ``detail`` is the rejection reason, execution message or error,
    or the verify status.
    """

    kind: str
    at: Optional[str] = None
    actor: Optional[str] = None
    detail: Optional[str] = None


class CaseActionPolicy(BaseModel):
    """What the approval gate recorded: whether a person had to approve, and
    the decision rule stored on the reason (``field=value [met|not met (x)]``)."""

    requires_approval: bool
    decision_rule: Optional[str] = None


class CaseActionExecution(BaseModel):
    success: Optional[bool] = None
    status: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None


class CaseActionTimelineItem(BaseModel):
    """A response action on the case and its lifecycle (W0.5 columns).

    ``can_revert`` is the row's state only (executed, reversible, not yet
    reversed, not itself a revert); whether the caller may revert is RBAC's.
    """

    action_id: str
    action_type: str
    title: str
    target: str
    status: str
    reversibility: str
    can_revert: bool
    proposed_at: Optional[str] = None
    proposed_by: Optional[str] = None
    confidence: Optional[float] = None
    reason: str = ""
    policy: CaseActionPolicy
    approved_at: Optional[str] = None
    approved_by: Optional[str] = None
    second_approver: Optional[str] = None
    rejection_reason: Optional[str] = None
    executed_at: Optional[str] = None
    execution: Optional[CaseActionExecution] = None
    verified_at: Optional[str] = None
    verify_status: Optional[str] = None
    expires_at: Optional[str] = None
    reversed_at: Optional[str] = None
    reverse_of: Optional[str] = None
    reverted_by: Optional[str] = None
    before_state: Optional[list[CaseActionStateRow]] = None
    after_state: Optional[list[CaseActionStateRow]] = None
    events: list[CaseActionEvent] = []


class CaseActionTimelineResponse(BaseModel):
    """Newest first. ``truncated`` when the case had more than the cap."""

    case_id: str
    count: int
    truncated: bool = False
    actions: list[CaseActionTimelineItem] = []
