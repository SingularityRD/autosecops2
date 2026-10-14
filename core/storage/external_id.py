"""The external id a finding is stored and looked up under (W0.12b)."""

from __future__ import annotations

from typing import Any


def normalize_external_id(value: Any) -> Any:
    """The external id to store and look up: None when there is none.

    A blank one ("" or whitespace) names nothing, so it is stored as NULL,
    which the uniq_findings_source_extid index (``external_id IS NOT NULL``)
    leaves out. Stored as "", every blank-id finding of a source would collide
    on the index with the first one, and a lookup that skipped blanks would
    never find the row it collides with.
    """
    if isinstance(value, str) and not value.strip():
        return None
    return value
