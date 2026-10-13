"""W4.2 chaos scenarios as opt-in tests.

    CHAOS_TESTS=1 pytest -c tests/pytest.ini -o addopts= -m chaos tests/perf
    CHAOS_TESTS=1 CHAOS_TARGET=staging pytest ... -m chaos tests/perf   # staging

Each test injects one fault under load and asserts: no accepted finding lost,
no duplicate row, every finding settled within the scenario's recovery bound,
plus the scenario's own checks (tests/perf/chaos.py). A scenario the target
cannot apply (no ``CHAOS_CMD_*`` on staging, no W3.9 for the standby case) is
skipped, never faked. Results are also written to
``$PERF_OUT_DIR/chaos-<scenario>-<run>.json``.

Locally, ``daemon_kill_standby`` runs on its own two-daemon stack with leader
election whenever W3.9 is in the checkout (``CHAOS_STANDBY=0`` turns that
off; ``CHAOS_STANDBY=1`` puts every scenario on a two-daemon stack).

``pg_restart`` is a strict xfail while W0.12 (durable webhook ingest,
``core/ingestion/spool.py``) is missing -- the known W4.1 data-loss finding --
and a hard failure (lost must be 0) once W0.12 is merged.
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


def _staging():
    t = chaos.StagingTarget()
    missing = t.missing()
    if missing:
        pytest.skip(f"staging target needs {', '.join(missing)}")
    return t


@pytest.fixture(scope="module")
def target(request):
    if os.environ.get("CHAOS_TARGET") == "staging":
        return _staging()
    return chaos.LocalTarget(request.getfixturevalue("local_stack"))


@pytest.fixture(scope="module")
def standby_target(request):
    """Target for daemon_kill_standby: a two-daemon local stack when W3.9 is in."""
    if os.environ.get("CHAOS_TARGET") == "staging":
        return _staging()
    if os.environ.get("CHAOS_STANDBY") in ("1", "true", "0", "false"):
        # Explicit choice: the shared stack (two daemons or one) decides.
        return request.getfixturevalue("target")
    if not chaos.leader_election_merged():
        return request.getfixturevalue("target")  # reports SKIP
    return chaos.LocalTarget(request.getfixturevalue("local_standby_stack"))


@pytest.mark.parametrize("name", SCENARIOS)
def test_chaos_scenario(request, name):
    scenario = chaos.scenarios()[name]
    if name == "daemon_kill_standby":
        target = request.getfixturevalue("standby_target")
    else:
        target = request.getfixturevalue("target")
    if scenario.known_open() and os.environ.get("CHAOS_TARGET") != "staging":
        request.applymarker(pytest.mark.xfail(reason=scenario.known_issue, strict=True))
    res = chaos.run_scenario(
        target,
        scenario,
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
    if scenario.takeover:
        assert res.takeover_seconds is not None, res.reasons
        assert res.takeover_seconds <= res.takeover_bound
