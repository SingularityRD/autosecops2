"""W4.2 chaos scenarios as opt-in tests.

    CHAOS_TESTS=1 pytest -c tests/pytest.ini -o addopts= -m chaos tests/perf
    CHAOS_TESTS=1 CHAOS_TARGET=staging pytest ... -m chaos tests/perf   # staging

Each test injects one fault under load and asserts: no accepted finding lost,
no duplicate row, every finding settled within the scenario's recovery bound,
plus the scenario's own checks (tests/perf/chaos.py). A scenario the target
cannot apply (no ``CHAOS_CMD_*`` on staging, no W3.9 for the standby case) is
skipped, never faked. Results are also written to
``$PERF_OUT_DIR/chaos-<scenario>-<run>.json``.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict

import pytest

from tests.perf import chaos
from tests.perf.conftest import perf_out_dir

pytestmark = [pytest.mark.chaos, pytest.mark.external_service, pytest.mark.integration]

SCENARIOS = list(chaos.scenarios())


@pytest.fixture(scope="module")
def target(request):
    if os.environ.get("CHAOS_TARGET") == "staging":
        t = chaos.StagingTarget()
        missing = t.missing()
        if missing:
            pytest.skip(f"staging target needs {', '.join(missing)}")
        return t
    return chaos.LocalTarget(request.getfixturevalue("local_stack"))


@pytest.mark.parametrize("name", SCENARIOS)
def test_chaos_scenario(target, name):
    res = chaos.run_scenario(
        target,
        chaos.scenarios()[name],
        rate=float(os.environ.get("CHAOS_RATE", "1")),
        pre=float(os.environ.get("CHAOS_PRE", "15")),
        fault=float(os.environ.get("CHAOS_FAULT", "30")),
        post=float(os.environ.get("CHAOS_POST", "15")),
    )
    out = perf_out_dir() / f"chaos-{name}-{res.run_id}.json"
    out.write_text(json.dumps(asdict(res), indent=2, default=str), encoding="utf-8")
    if res.status == "SKIP":
        pytest.skip("; ".join(res.reasons))
    assert res.status == "PASS", f"{res.status}: {res.reasons} (details {out})"
