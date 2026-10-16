"""What the setup wizard reports: real readiness, and progress kept on the server.

Readiness (W0.33, KS-10). The wizard used to say "AutoSecOps is ready" on an
empty install. ``build_readiness`` names each piece an install needs and says
which are missing. Two are **required** -- without them nothing gets
investigated -- and two are **recommended**:

* ``data`` (required): an alert source -- an enabled integration in an alert
  category, an enabled Federation source, alerts already ingested, or demo
  data;
* ``model`` (required): a model agents can route to -- an active default
  provider row, or a routable key in the model gateway;
* ``executor`` (recommended): an integration that can carry out a response
  action (``core.response.executors.wiring.EXECUTOR_SOURCES``); without one
  AutoSecOps investigates and recommends but cannot act;
* ``notify`` (recommended): a Slack or PagerDuty route, so a decision that
  needs a person reaches one.

Progress (W0.33, KS-09). The furthest step reached, the steps continued past
and whether setup was finished or put off live in one ``system_config`` row,
``setup.progress``, written through ``ConfigService`` so every change has an
audit row naming who made it. A second administrator or another browser picks
up where the first left off.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator

PROGRESS_KEY = "setup.progress"
STEP_COUNT = 5

# Integration descriptor categories that produce alerts. Matches the wizard's
# DATA_SOURCE_CATEGORIES (clients/web/src/screens/setup/setupSteps.ts), plus the
# plain "EDR" some descriptors use.
ALERT_SOURCE_CATEGORIES = frozenset(
    {
        "SIEM",
        "EDR",
        "EDR/XDR",
        "Cloud Security",
        "Network Security",
        "Data Pipeline",
        "Detection & AI",
    }
)

SetupStatus = Literal["in_progress", "deferred", "completed"]


def _item(
    item_id: str, label: str, required: bool, ready: bool, detail: str, href: str
) -> Dict[str, Any]:
    return {
        "id": item_id,
        "label": label,
        "required": required,
        "ready": ready,
        "detail": detail,
        "href": href,
    }


def build_readiness(
    *,
    demo_mode: bool,
    enabled_integrations: Iterable[str],
    categories: Dict[str, str],
    federation_sources: int,
    alerts: int,
    provider_ready: bool,
    gateway_routable: Optional[bool],
    executor_integrations: Iterable[str],
    notify_route: bool,
) -> Dict[str, Any]:
    """The readiness verdict from facts the caller has read.

    ``gateway_routable`` is None when the model gateway could not be asked.
    """
    enabled = list(enabled_integrations)
    alert_sources = [i for i in enabled if categories.get(i) in ALERT_SOURCE_CATEGORIES]
    if demo_mode:
        data = (True, "Demo data is on")
    elif alert_sources:
        n = len(alert_sources)
        data = (True, f"{n} alert source{'s' if n != 1 else ''} connected")
    elif federation_sources:
        data = (True, f"{federation_sources} collection source(s) on")
    elif alerts:
        data = (True, "Alerts have been ingested")
    else:
        data = (False, "No alert source connected and no alerts ingested")

    if provider_ready or gateway_routable:
        model = (True, "A model is ready for agents")
    elif gateway_routable is None:
        model = (False, "No model provider, and the model gateway could not be reached")
    else:
        model = (False, "No model provider with a working key")

    executors = sorted(set(enabled) & set(executor_integrations))
    executor = (
        (True, f"{len(executors)} response integration(s) connected")
        if executors
        else (
            False,
            "No response integration connected: AutoSecOps can investigate and "
            "recommend, but cannot act",
        )
    )
    notify = (
        (True, "Slack or PagerDuty route is set")
        if notify_route
        else (
            False,
            "No Slack or PagerDuty route: nobody is told when a decision waits",
        )
    )

    integrations = "/settings?section=integrations"
    items = [
        _item("data", "Alert source", True, data[0], data[1], integrations),
        _item(
            "model", "AI model", True, model[0], model[1], "/settings?section=ai-config"
        ),
        _item(
            "executor",
            "Response actions",
            False,
            executor[0],
            executor[1],
            integrations,
        ),
        _item("notify", "Notifications", False, notify[0], notify[1], integrations),
    ]
    missing = [i["id"] for i in items if i["required"] and not i["ready"]]
    return {
        "ready": not missing,
        "missing": missing,
        "recommended_missing": [
            i["id"] for i in items if not i["required"] and not i["ready"]
        ],
        "items": items,
    }


class SetupProgressWrite(BaseModel):
    """What the wizard saves. Steps are numbered 1..STEP_COUNT."""

    furthest: int = Field(1, ge=1, le=STEP_COUNT)
    passed: List[int] = Field(default_factory=list, max_length=STEP_COUNT)
    status: SetupStatus = "in_progress"

    @field_validator("passed")
    @classmethod
    def _steps_in_range(cls, value: List[int]) -> List[int]:
        if any(n < 1 or n > STEP_COUNT for n in value):
            raise ValueError(f"steps are numbered 1 to {STEP_COUNT}")
        return sorted(set(value))


def read_progress(value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The stored row as the wizard reads it; anything malformed is "not started"."""
    base: Dict[str, Any] = {
        "furthest": 1,
        "passed": [],
        "status": "in_progress",
        "started": False,
        "updated_by": None,
        "updated_at": None,
        "completed_by": None,
        "completed_at": None,
    }
    if not isinstance(value, dict):
        return base
    try:
        parsed = SetupProgressWrite.model_validate(
            {k: value.get(k) for k in ("furthest", "passed", "status") if k in value}
        )
    except ValueError:
        return base
    base.update(parsed.model_dump(), started=True)
    for key in ("updated_by", "updated_at", "completed_by", "completed_at"):
        if isinstance(value.get(key), str):
            base[key] = value[key]
    return base


def next_progress(
    previous: Optional[Dict[str, Any]],
    write: SetupProgressWrite,
    *,
    actor: str,
    now: str,
    ready: bool,
) -> Dict[str, Any]:
    """The row to store. "completed" is only recorded when the install is ready;
    an install that is not is recorded as "deferred", so the record never claims
    a setup that is not done."""
    status: SetupStatus = write.status
    if status == "completed" and not ready:
        status = "deferred"
    stored: Dict[str, Any] = {
        "furthest": write.furthest,
        "passed": write.passed,
        "status": status,
        "updated_by": actor,
        "updated_at": now,
        "completed_by": None,
        "completed_at": None,
    }
    if status == "completed":
        prior = read_progress(previous)
        if prior["status"] == "completed" and prior["completed_at"]:
            stored["completed_by"] = prior["completed_by"]
            stored["completed_at"] = prior["completed_at"]
        else:
            stored["completed_by"] = actor
            stored["completed_at"] = now
    return stored
