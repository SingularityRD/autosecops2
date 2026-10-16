"""The response policy, managed from the console (W0.36, SOC4-11 / KS-19).

``GET /api/response/policy``   settings.read   the stored policy, its defaults, the effect
``PUT /api/response/policy``   settings.write  replace the editable keys, with a reason

Editable: ``protected_targets``, ``protected_tags``, ``asset_tags``,
``hourly_limits``, ``default_hourly_limit`` and ``four_eyes_types`` of the
``response.policy`` system config row (``core/response/policy.py``). The other
keys of that row are kept as they are: ``distinct_role_types`` has its own route
(``PUT /api/response/four-eyes/{type}``), ``subdomain_matching_types`` and
``undo_types`` stay a database matter.

Protected tags and four-eyes types only add to the built-in sets
(``PolicyConfig.from_mapping``): no request here can unprotect a domain
controller or take ``disable_user`` out of the two-person rule. Every accepted
change is written through ``ConfigService.set_system_config``, which records a
``config_audit_log`` row with the user, the reason and the old and new value.
The daemon and the approval flow read the row at each decision, so a change
applies without a restart.
"""

from __future__ import annotations

import re
from typing import Annotated, Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from core.auth.permissions import require_permission
from core.response.approval_service import ActionType
from core.response.policy import (
    _EMPTY_TARGETS,
    DEFAULT_FOUR_EYES_TYPES,
    DEFAULT_HOURLY_LIMIT,
    DEFAULT_HOURLY_LIMITS,
    DEFAULT_PROTECTED_TAGS,
    PolicyConfig,
    identify,
)
from core.response.policy_store import PolicyConflict, read_policy, update_policy
from core.routing import Auth, RouterMeta
from core.storage.models import User

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/response",
    tags=["response"],
    auth=Auth.REQUIRED,
)

EDITABLE_KEYS = (
    "protected_targets",
    "protected_tags",
    "asset_tags",
    "hourly_limits",
    "default_hourly_limit",
    "four_eyes_types",
)
ACTION_TYPES = sorted(t.value for t in ActionType if t is not ActionType.WORKFLOW_PHASE)
MAX_ENTRIES = 5000
MAX_TARGET_LENGTH = 253
MAX_HOURLY_LIMIT = 1000
MAX_TAGS = 200  # protected_tags
MAX_TAGS_PER_ASSET = 32
# The whole request body. The policy row is read at every response decision,
# so it stays small whatever the per-field bounds would allow together.
MAX_BODY_BYTES = 1024 * 1024
_TAG = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

Limit = Annotated[int, Field(strict=True, ge=0, le=MAX_HOURLY_LIMIT)]
# Generous outer bounds so a huge string is refused before it is parsed; the
# exact rules (253-character names, 64-character tags) give the clearer 422.
Name = Annotated[str, Field(max_length=1024)]
Tag = Annotated[str, Field(max_length=256)]


class PolicyDefaults(BaseModel):
    protected_tags: List[str]
    four_eyes_types: List[str]
    hourly_limits: Dict[str, int]
    default_hourly_limit: int


class EffectivePolicy(BaseModel):
    """What ``ActionPolicy`` applies: the stored values merged with the defaults."""

    protected_tags: List[str]
    four_eyes_types: List[str]
    distinct_role_types: List[str]
    hourly_limits: Dict[str, int]
    default_hourly_limit: int


class ResponsePolicyView(BaseModel):
    protected_targets: List[str]
    protected_tags: List[str]
    asset_tags: Dict[str, List[str]]
    hourly_limits: Dict[str, int]
    default_hourly_limit: int
    four_eyes_types: List[str]
    defaults: PolicyDefaults
    effective: EffectivePolicy
    action_types: List[str]
    # Send it back with PUT: a policy changed since it was read answers 409.
    version: str


class ResponsePolicyUpdate(BaseModel):
    """The editable keys, whole: a key left out is reset to its default."""

    model_config = ConfigDict(extra="forbid")

    protected_targets: List[Name] = Field(default_factory=list, max_length=MAX_ENTRIES)
    protected_tags: List[Tag] = Field(default_factory=list, max_length=MAX_TAGS)
    asset_tags: Dict[
        Name, Annotated[List[Tag], Field(max_length=MAX_TAGS_PER_ASSET)]
    ] = Field(default_factory=dict, max_length=MAX_ENTRIES)
    hourly_limits: Dict[Name, Limit] = Field(default_factory=dict, max_length=100)
    default_hourly_limit: Limit = DEFAULT_HOURLY_LIMIT
    four_eyes_types: List[Name] = Field(default_factory=list, max_length=100)
    reason: str = Field(..., min_length=1, max_length=2000)
    # The version GET returned; required so a stale copy cannot overwrite.
    version: str = Field(..., min_length=1, max_length=128)


def _invalid(message: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, message)


def _target(value: str, field: str) -> str:
    text = value.strip()
    if not text:
        raise _invalid(f"{field}: an entry is blank")
    if len(text) > MAX_TARGET_LENGTH or _CONTROL.search(text):
        raise _invalid(f"{field}: {text[:40]!r} is not a host, address or account")
    ident = identify(text)
    if ident is None or ident.name in _EMPTY_TARGETS:
        raise _invalid(f"{field}: {text!r} names nothing")
    return text


def _tags(values: List[str], field: str) -> List[str]:
    out = set()
    for value in values:
        tag = value.strip().casefold()
        if not _TAG.match(tag):
            raise _invalid(
                f"{field}: {value[:40]!r} is not a tag (a-z, 0-9, _ . : -; "
                "at most 64 characters)"
            )
        out.add(tag)
    return sorted(out)


def _types(values: List[str], field: str) -> List[str]:
    out = set()
    for value in values:
        kind = value.strip().casefold()
        if kind not in ACTION_TYPES:
            raise _invalid(f"{field}: unknown action type {value[:40]!r}")
        out.add(kind)
    return sorted(out)


def normalise_update(body: ResponsePolicyUpdate) -> Dict[str, Any]:
    """The editable keys as they will be stored; 422 on the first bad entry."""
    targets: Dict[str, str] = {}
    for value in body.protected_targets:
        text = _target(value, "protected_targets")
        targets.setdefault(text.casefold(), text)
    asset_tags: Dict[str, List[str]] = {}
    for target, tags in body.asset_tags.items():
        text = _target(target, "asset_tags")
        if not tags:
            raise _invalid(f"asset_tags: {text!r} has no tags")
        merged = set(asset_tags.get(text, [])) | set(_tags(tags, "asset_tags"))
        asset_tags[text] = sorted(merged)
    limits: Dict[str, int] = {}
    for kind, limit in body.hourly_limits.items():
        limits[_types([kind], "hourly_limits")[0]] = limit
    return {
        "protected_targets": sorted(targets.values(), key=str.casefold),
        "protected_tags": _tags(body.protected_tags, "protected_tags"),
        "asset_tags": dict(sorted(asset_tags.items())),
        "hourly_limits": dict(sorted(limits.items())),
        "default_hourly_limit": body.default_hourly_limit,
        "four_eyes_types": _types(body.four_eyes_types, "four_eyes_types"),
    }


def _list(raw: Dict[str, Any], key: str) -> List[str]:
    value = raw.get(key) or []
    if isinstance(value, str):
        value = [value]
    return [str(v) for v in value]


def view(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    raw = raw or {}
    policy = PolicyConfig.from_mapping(raw)
    asset_tags = raw.get("asset_tags") or {}
    return {
        "protected_targets": _list(raw, "protected_targets"),
        "protected_tags": _list(raw, "protected_tags"),
        "asset_tags": {
            str(k): [str(t) for t in ([v] if isinstance(v, str) else v or [])]
            for k, v in asset_tags.items()
        },
        "hourly_limits": {
            str(k): int(v) for k, v in (raw.get("hourly_limits") or {}).items()
        },
        "default_hourly_limit": int(
            raw.get("default_hourly_limit", DEFAULT_HOURLY_LIMIT)
        ),
        "four_eyes_types": _list(raw, "four_eyes_types"),
        "defaults": {
            "protected_tags": sorted(DEFAULT_PROTECTED_TAGS),
            "four_eyes_types": sorted(DEFAULT_FOUR_EYES_TYPES),
            "hourly_limits": dict(sorted(DEFAULT_HOURLY_LIMITS.items())),
            "default_hourly_limit": DEFAULT_HOURLY_LIMIT,
        },
        "effective": {
            "protected_tags": sorted(policy.protected_tags),
            "four_eyes_types": sorted(policy.four_eyes_types),
            "distinct_role_types": sorted(policy.distinct_role_types),
            "hourly_limits": dict(sorted(policy.hourly_limits.items())),
            "default_hourly_limit": policy.default_hourly_limit,
        },
        "action_types": ACTION_TYPES,
    }


def _read() -> tuple[Dict[str, Any], str]:
    try:
        return read_policy()
    except Exception:  # noqa: BLE001
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The response policy could not be read",
        ) from None


def _view(raw: Dict[str, Any], version: str) -> Dict[str, Any]:
    try:
        return {**view(raw), "version": version}
    except (TypeError, ValueError, AttributeError):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The stored response policy is malformed; the policy refuses every "
            "action until it is replaced",
        ) from None


async def body_cap(request: Request) -> None:
    """413 for a body over ``MAX_BODY_BYTES`` (declared or actual)."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(413, f"The policy is limited to {MAX_BODY_BYTES} bytes")
    if len(await request.body()) > MAX_BODY_BYTES:
        raise HTTPException(413, f"The policy is limited to {MAX_BODY_BYTES} bytes")


CONFLICT = (
    "The response policy was changed by someone else since you loaded it. "
    "Reload it, review the change and save again."
)


@router.get("/policy", response_model=ResponsePolicyView)
def get_response_policy(
    user: User = Depends(require_permission("settings.read")),
) -> Dict[str, Any]:
    """Protected assets, hourly limits and four-eyes types, stored and in effect."""
    return _view(*_read())


@router.put(
    "/policy", response_model=ResponsePolicyView, dependencies=[Depends(body_cap)]
)
def put_response_policy(
    body: ResponsePolicyUpdate,
    user: User = Depends(require_permission("settings.write")),
) -> Dict[str, Any]:
    """Replace the editable keys. Audited (who, reason, old and new value).

    Read, compared with ``version``, changed and written in one transaction
    under a row lock: 409 when the policy changed since the caller read it.
    """
    reason = body.reason.strip()
    if not reason:
        raise _invalid("A reason is required")
    updates = normalise_update(body)

    def change(raw: Dict[str, Any]) -> Dict[str, Any]:
        new = {k: v for k, v in raw.items() if k not in EDITABLE_KEYS}
        new.update(updates)
        return new

    try:
        new, version, _written = update_policy(
            user.username, reason, change, expected_version=body.version
        )
    except PolicyConflict:
        raise HTTPException(status.HTTP_409_CONFLICT, CONFLICT) from None
    except Exception:  # noqa: BLE001
        # The database refused the read or the write: unavailable, not "saved".
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Could not save the response policy"
        ) from None
    return _view(new, version)
