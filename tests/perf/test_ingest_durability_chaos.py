"""W0.12 regression: the W4.1 chaos findings on ingest durability, under load.

    CHAOS_TESTS=1 python -m pytest -c tests/pytest.ini -o addopts= \\
        -p no:cacheprovider --asyncio-mode=auto -m chaos -q \\
        tests/perf/test_ingest_durability_chaos.py

Against the local stack (tests/perf/stack.py, a private Postgres/Redis), each
scenario asserts 0 accepted findings lost, 0 duplicate or unexpected rows, 0
unsettled (tests/perf/chaos.py run_scenario):

* ``pg_restart``: PostgreSQL down for the fault window. W4.1 lost 30/30
  acknowledged findings here (docs/wp/w4.1.md finding 1).
* ``daemon_kill``: the daemon SIGKILLed under a faster load.
* ``pg_down_daemon_kill``: the daemon is SIGKILLed at the end of a database
  outage, while every finding acknowledged during the outage is waiting in
  its spool, and started again only after the database is back: everything it
  acknowledged is replayed from disk (finding 3), and replay makes no
  duplicate row.
* ``redis_restart``: also checks that the LLM worker reconnected instead of
  exiting (finding 2): no "worker exited" event from the stack supervisor.

Opt-in and ``external_service`` like the rest of tests/perf (the WP gates do
not collect it). Results land in ``$PERF_OUT_DIR/w012-<scenario>-<run>.json``.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict

import pytest

from tests.perf import chaos
from tests.perf.conftest import perf_out_dir

pytestmark = [pytest.mark.chaos, pytest.mark.external_service, pytest.mark.integration]

_W41 = chaos.scenarios()

SCENARIOS = {
    "pg_restart": (_W41["pg_restart"], 2.0),
    "daemon_kill": (_W41["daemon_kill"], 5.0),
    "pg_down_daemon_kill": (
        chaos.Scenario(
            "pg_down_daemon_kill",
            ["pg_stop"],
            ["daemon_kill", "pg_start", "daemon_start"],
            float(os.environ.get("CHAOS_RECOVERY_PG_DOWN_DAEMON_KILL", "300")),
            "daemon SIGKILLed with a database outage's findings in its spool",
        ),
        2.0,
    ),
    "redis_restart": (_W41["redis_restart"], 1.0),
}


@pytest.fixture(scope="module")
def target(request):
    return chaos.LocalTarget(request.getfixturevalue("local_stack"))


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_ingest_durability(target, name):
    scenario, rate = SCENARIOS[name]
    res = chaos.run_scenario(
        target,
        scenario,
        rate=float(os.environ.get("CHAOS_RATE", rate)),
        pre=float(os.environ.get("CHAOS_PRE", "10")),
        fault=float(os.environ.get("CHAOS_FAULT", "30")),
        post=float(os.environ.get("CHAOS_POST", "10")),
    )
    out = perf_out_dir() / f"w012-{name}-{res.run_id}.json"
    out.write_text(json.dumps(asdict(res), indent=2, default=str), encoding="utf-8")
    if res.status == "SKIP":
        pytest.skip("; ".join(res.reasons))
    acc = res.accounting
    assert res.status == "PASS", f"{res.status}: {res.reasons} (details {out})"
    assert acc["lost"] == 0, acc
    assert acc["duplicate_rows"] == 0 and acc["unexpected_rows"] == 0, acc
    assert acc["stored"] == acc["accepted"] > 0, acc
    if name == "redis_restart":
        exits = [e for e in res.target_events if "worker exited" in e]
        assert not exits, f"LLM worker exited instead of reconnecting: {exits}"
