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
# value "WS0" never turns "WS01" into "[subject value 1]1" (round 10).
_SUBSTRING_MIN = 8
_TOKEN_EDGE = r"A-Za-z0-9_.\-"


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
            else:
                pattern = (
                    rf"(?<![{_TOKEN_EDGE}]){re.escape(spelled)}(?![{_TOKEN_EDGE}])"
                )
                text = re.sub(pattern, marker, text)
    return text


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
    if isinstance(value, dict):
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
