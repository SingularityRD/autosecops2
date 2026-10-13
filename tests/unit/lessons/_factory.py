"""Shared builders for the lesson tests (W3.11)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.lessons.model import Lesson, validate_scope

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)

# In the v1 corpus this address appears only on benign Entra alerts that the
# committed stub cassette calls malicious: a lesson about it removes false
# positives and costs no recall.
SCANNER_IP = "198.51.100.157"
GOOD_SCOPE = {"data_source": "entra", "src_ips": [SCANNER_IP], "max_severity": "high"}
# A whole rule: its benign and malicious twins both match, so recall falls.
RULE_SCOPE = {
    "data_source": "okta",
    "rule_name": "Session reused from different network",
    "max_severity": "high",
}


def make_lesson(scope=None, **kw) -> Lesson:
    fields = dict(
        id=kw.pop("id", "l-1"),
        lesson="Our scanner",
        effect="benign_hint",
        applies_to=validate_scope(scope or GOOD_SCOPE),
        created_by="ayse",
        created_at=NOW,
        expires_at=NOW + timedelta(days=30),
        status="active",
        provenance="analyst",
    )
    fields.update(kw)
    return Lesson(**fields)
