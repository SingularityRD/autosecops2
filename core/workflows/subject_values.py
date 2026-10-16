"""Subject-written values beside agent prose (W0.30 round 6).

The agent layer never puts text a monitored party could have written into the
prose it sends (checkpoint questions, status reasons, reports, case files). Each
such value is a fixed ASCII marker in the prose, ``[subject value N]``, and the
value travels beside it as a row ``{ref, field, value}`` (already display-safe:
controls, bidi characters and newlines neutralised).

A UI renders those rows as plain text in their own box. A plain-text consumer
here gets the prose plus a trailing block: a fixed header line, then one
``[N] field = "<JSON>"`` line per value. JSON escaping is real in that block,
because nothing re-renders it. Where the stored text is markdown (a run's
summary, a case file), the block goes inside a fenced code block, which markdown
renders literally; a value cannot end the fence, since it cannot start a line.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, List

from pydantic import BaseModel, Field

from core.response.checkpoints import display_safe

HEADER = "Written by the subject (untrusted):"


class SubjectValue(BaseModel):
    ref: int = Field(..., ge=1)
    field: str = Field("value", max_length=64)
    value: str = Field("", max_length=8000)


def _rows(values: Iterable[SubjectValue]) -> List[SubjectValue]:
    """In ref order; an exact repeat is dropped, never a different row. The agent
    layer numbers one body's refs once (core/outbound.ts), so two rows sharing a
    ref is a defect to show, not a value to lose."""
    seen = set()
    out = []
    for v in values:
        key = (v.ref, v.field, v.value)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return sorted(out, key=lambda v: v.ref)


def subject_block(values: Iterable[SubjectValue]) -> str:
    """The header line and one line per value; empty when there are none."""
    rows = _rows(values)
    if not rows:
        return ""
    lines = [HEADER]
    for row in rows:
        field = display_safe(row.field) or "value"
        shown = json.dumps(display_safe(row.value), ensure_ascii=False)
        lines.append(f"[{row.ref}] {field} = {shown}")
    return "\n".join(lines)


def with_plain_block(text: str, values: Iterable[SubjectValue]) -> str:
    block = subject_block(values)
    return f"{text}\n\n{block}" if block else text


def with_markdown_block(text: str, values: Iterable[SubjectValue]) -> str:
    block = subject_block(values)
    return f"{text}\n\n```text\n{block}\n```" if block else text


def as_dicts(values: Iterable[SubjectValue]) -> List[dict]:
    return [v.model_dump() for v in _rows(values)]


# A block as this module writes it: optionally fenced, the header, then one
# "[N] field = ..." line per value. Matched also when the text it trails was
# flattened onto one line (header to end of line), cut short (no closing fence),
# indented or quoted ("> "), or the header was re-spaced or re-cased on the way
# (round 9: matched on words, any whitespace, any case).
_HEADER_WORDS = r"written\s+by\s+the\s+subject\s*\(\s*untrusted\s*\)\s*:"
_BLOCK = re.compile(
    r"[ \t]*\n*(?:[ \t>]*```text[ \t]*\n)?[ \t>]*"
    + _HEADER_WORDS
    + r"[^\n]*(?:\n[ \t>]*\[\d+\] [^\n]*)*(?:\n[ \t>]*```)?",
    re.IGNORECASE,
)
# Fail-safe: a value line wherever it stands -- its header lost to a front cut, or
# split into another field -- is dropped whole.
_VALUE_LINE = re.compile(r'^[ \t]*>?[ \t]*\[\d+\] \S+ = ".*(?:\n|$)', re.MULTILINE)
WITHHELD = "[subject value withheld]"


def for_model(text: Any) -> Any:
    """``text`` as a model may read it: every subject block removed, so only the
    ``[subject value N]`` markers remain (W0.30). People see the values in the
    block or the console's box; models never do. Non-strings pass through."""
    if not isinstance(text, str) or ("[" not in text and "subject" not in text.lower()):
        return text
    return _VALUE_LINE.sub("", _BLOCK.sub("", text))


def _own_rows(value: dict) -> List[tuple]:
    """The subject_values rows that scope ``value``: its own, or those of a
    direct child (an approval row keeps them in ``parameters``)."""
    holders = [value] + [v for v in value.values() if isinstance(v, dict)]
    rows: dict = {}
    for holder in holders:
        for row in holder.get("subject_values") or []:
            if (
                isinstance(row, dict)
                and isinstance(row.get("value"), str)
                and row["value"]
            ):
                rows.setdefault(row.get("ref"), row["value"])
    # Longest first, so a value inside another is not split.
    return sorted(rows.items(), key=lambda pair: -len(pair[1]))


# Long values are masked wherever they occur; short ones only as a whole token, so a
# value "WS0" never turns "WS01" into "[subject value 1]1" (round 10). A token is a
# run of Unicode letters and digits: ".", "-", "_" and everything else are edges
# (round 11). A short value is masked only when it is at least 3 characters and
# holds a non-letter (a digit or punctuation) -- "WS0", "10.0", "a_b" -- so a short
# dictionary or stop word ("the", "ok") the subject happened to write does not
# blank out the same word in a model's prose; the position mask (subject_paths) is
# what covers a gated call's arguments regardless.
_SUBSTRING_MIN = 8
_SHORT_MIN = 3


def _short_maskable(value: str) -> bool:
    return len(value) >= _SHORT_MIN and not value.isalpha()


def _mask(text: str, known: List[tuple]) -> str:
    for ref, raw in known:
        marker = f"[subject value {ref}]" if isinstance(ref, int) else WITHHELD
        if text == raw:
            return marker
        for spelled in dict.fromkeys((raw, json.dumps(raw, ensure_ascii=False)[1:-1])):
            if not spelled or spelled not in text:
                continue
            if len(spelled) >= _SUBSTRING_MIN:
                text = text.replace(spelled, marker)
            elif _short_maskable(spelled):
                pattern = rf"(?<![^\W_]){re.escape(spelled)}(?![^\W_])"
                text = re.sub(pattern, marker, text)
    return text


WITHHELD_NOTE = (
    "[withheld from the model: this approval's arguments hold text the subject "
    "wrote, and where in them it sits was not recorded]"
)


def _markers(refs: Any) -> str:
    refs = [r for r in (refs or []) if isinstance(r, int)]
    return " ".join(f"[subject value {r}]" for r in refs) or WITHHELD


def _set_leaf(node: Any, path: List[Any], marker: str) -> bool:
    """Replace the leaf at ``path`` with ``marker``; False when the path is not
    there (the row is then not trusted to be masked)."""
    if not path:
        return False
    for step in path[:-1]:
        try:
            node = node[step]
        except (KeyError, IndexError, TypeError):
            return False
    last = path[-1]
    try:
        node[last]
    except (KeyError, IndexError, TypeError):
        return False
    node[last] = marker
    return True


def _masked_args(params: dict) -> Any:
    """The bound arguments with every subject-derived leaf replaced by its
    marker, by position (``subject_paths``); None when that cannot be done."""
    paths = params.get("subject_paths")
    if not isinstance(paths, list) or not paths:
        return None
    try:
        args = json.loads(params.get("args_canonical") or "")
    except (TypeError, ValueError):
        return None
    for entry in paths:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), list):
            return None
        if not _set_leaf(args, entry["path"], _markers(entry.get("refs"))):
            return None
    return args


def _approval_view(row: dict) -> dict:
    """An approval row as a model may read it (W0.30 round 11).

    A gated call whose arguments a guard filled with subject text carries
    ``subject_paths``: those leaves are masked by position, and the model's
    ``args_canonical``, ``args_targets`` and description are rebuilt from the
    masked arguments -- the stored text, display-escaped and cut, is never
    passed through. A row with subject values and arguments but no usable paths
    fails closed: arguments, targets and description are withheld."""
    params = row.get("parameters")
    if not isinstance(params, dict) or not params.get("subject_values"):
        return row
    if "args_canonical" not in params:
        return row
    from core.response.checkpoints import (
        canonical_args,
        target_fields,
        tool_call_prompt,
    )

    args = _masked_args(params)
    if args is None:
        kept = {
            k: v
            for k, v in params.items()
            if k
            not in ("args_canonical", "args_targets", "args_summary", "subject_paths")
        }
        kept["args_withheld"] = WITHHELD_NOTE
        return {**row, "parameters": kept, "description": WITHHELD_NOTE}
    tool = str(params.get("tool") or "")
    question = str(row.get("description") or "").split("\n\nTool: ", 1)[0]
    return {
        **row,
        "description": f"{question}\n\n{tool_call_prompt(tool, args)}",
        "parameters": {
            **params,
            "args_canonical": canonical_args(args),
            "args_targets": target_fields(args),
        },
    }


def _looks_like_approval(value: dict) -> bool:
    params = value.get("parameters")
    return isinstance(params, dict) and "args_canonical" in params


def _deep(value: Any, known: List[tuple], key: Any = None) -> Any:
    if isinstance(value, str):
        return _mask(for_model(value), known)
    if key == "subject_values" and isinstance(value, list):
        return [
            {**row, "value": WITHHELD} if isinstance(row, dict) else row
            for row in value
        ]
    if isinstance(value, list):
        return [_deep(v, known) for v in value]
    if isinstance(value, tuple):
        return tuple(_deep(v, known) for v in value)
    if isinstance(value, bytes):
        try:
            return _deep(value.decode("utf-8"), known, key)
        except UnicodeDecodeError:
            return value
    if isinstance(value, dict):
        # An approval row: masked by position first (round 11); value matching
        # below stays as a second pass.
        if _looks_like_approval(value):
            value = _approval_view(value)
        # A dict that carries its own rows is its own scope (round 10): one
        # approval's refs never mask another's text, whatever their numbers.
        scoped = _own_rows(value) or known
        return {k: _deep(v, scoped, k) for k, v in value.items()}
    return value


def for_model_deep(value: Any) -> Any:
    """:func:`for_model` over every string in a JSON-shaped value, for a model.

    An approval row hands a model its ``subject_values`` and, inside a gated
    call's ``args_canonical`` / ``parameters`` / ``dispatched_arguments``, the
    subject's text resolved. Every row's value becomes the withheld marker (ref
    and field kept), and every string under the object that owns those rows has
    each of them replaced by its ``[subject value N]`` marker -- scoped per
    object, so a list of approvals masks each with its own. A new object: what
    is stored, and the digest the approval binds, are untouched."""
    return _deep(value, [])
