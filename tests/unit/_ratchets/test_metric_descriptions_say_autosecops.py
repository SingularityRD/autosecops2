"""Metric descriptions are operator-visible (/metrics, dashboards): they name
the product AutoSecOps, never its upstream name."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
_DESCRIPTION = re.compile(r"description\s*=\s*[\"'][^\"']*\bVigil\b")


def test_no_metric_description_says_vigil():
    offenders = []
    for base in ("core", "services"):
        for path in (ROOT / base).rglob("*.py"):
            if "node_modules" in path.parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if "create_observable_gauge" not in text and "Gauge(" not in text:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if _DESCRIPTION.search(line):
                    offenders.append(f"{path.relative_to(ROOT)}:{lineno}")
    assert offenders == []
