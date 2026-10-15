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
# flattened onto one line (header to end of line) or cut short (no closing fence).
_BLOCK = re.compile(
    r"[ \t]*\n*(?:```text\n)?"
    + re.escape(HEADER)
    + r"[^\n]*(?:\n\[\d+\] [^\n]*)*(?:\n```)?"
)


def for_model(text: Any) -> Any:
    """``text`` as a model may read it: every subject block removed, so only the
    ``[subject value N]`` markers remain (W0.30). People see the values in the
    block or the console's box; models never do. Non-strings pass through."""
    if not isinstance(text, str) or HEADER not in text:
        return text
    return _BLOCK.sub("", text)


def for_model_deep(value: Any) -> Any:
    """:func:`for_model` over every string in a JSON-shaped value."""
    if isinstance(value, str):
        return for_model(value)
    if isinstance(value, list):
        return [for_model_deep(v) for v in value]
    if isinstance(value, tuple):
        return tuple(for_model_deep(v) for v in value)
    if isinstance(value, dict):
        return {k: for_model_deep(v) for k, v in value.items()}
    return value
