"""Findings stored before W0.29 keep ``data_source = "loglm"`` and their tier.

The third-party connector is gone, but its rows are still cited by verdicts; a
case distilled from them must keep grading them as our own telemetry.
"""

import pytest

from core.memory.source_tier import InvestigationKind, SourceTier, resolve_source_tier

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("name", ["loglm", "LogLM", " loglm "])
def test_legacy_loglm_rows_stay_telemetry_on_a_case(name):
    assert resolve_source_tier(name, InvestigationKind.CASE) is SourceTier.TELEMETRY
