"""W4.1 smoke: a small sustained + burst load against a local stack.

This is a smoke test of the load tooling and of the ingest path, not a
capacity measurement: the local stack shares a small machine with everything
else running on it. The SLO table is compared and written to the report but
only loss and settlement are asserted; the capacity run is on staging
(docs/operations/load-chaos-runbook.md).

    LOAD_TESTS=1 pytest -c tests/pytest.ini -o addopts= -m load tests/perf
"""

from __future__ import annotations

import asyncio
import os

import pytest

from tests.perf import loadgen
from tests.perf.conftest import perf_out_dir

pytestmark = [pytest.mark.load, pytest.mark.external_service, pytest.mark.integration]


def _profile() -> loadgen.Profile:
    return loadgen.Profile(
        rate=float(os.environ.get("LOAD_RATE", "1")),
        duration=float(os.environ.get("LOAD_DURATION", "60")),
        burst_rate=float(os.environ.get("LOAD_BURST_RATE", "5")),
        burst_duration=float(os.environ.get("LOAD_BURST_DURATION", "10")),
        burst_every=float(os.environ.get("LOAD_BURST_EVERY", "60")),
        burst_offset=float(os.environ.get("LOAD_BURST_OFFSET", "25")),
        api_fraction=float(os.environ.get("LOAD_API_FRACTION", "0.1")),
        rules_fraction=float(os.environ.get("LOAD_RULES_FRACTION", "0.3")),
    )


def test_load_smoke(local_stack):
    ep = local_stack.endpoints
    run_id = loadgen.new_run_id()
    engine = loadgen.make_engine(ep.db_url)
    loadgen.seed_rules_lane(engine, run_id)
    profile = _profile()
    log = asyncio.run(
        loadgen.run_load(
            profile,
            loadgen.Target(
                webhooks=ep.webhooks,
                webhook_token=ep.webhook_token,
                api_base=ep.api_base,
                api_token=ep.api_token,
            ),
            loadgen.load_corpus(loadgen.DEFAULT_CORPUS),
            run_id,
            api_read_rps=0.5,
        )
    )
    report = loadgen.build_report(
        engine,
        run_id,
        "local smoke (not capacity)",
        profile,
        log,
        settle_timeout=float(os.environ.get("LOAD_SETTLE_TIMEOUT", "600")),
        notes=[
            "Local smoke on a shared 2-CPU machine with a stub model; "
            "not a capacity measurement.",
            f"Enrichment backfill interval {local_stack.backfill_interval}s: "
            "API-ingested findings wait for the sweep.",
        ],
    )
    out = perf_out_dir() / f"load-smoke-{run_id}"
    loadgen.write_report(report, out)
    acc = report.accounting
    assert acc.accepted == acc.sent, log.summary()
    assert not acc.lost, f"lost: {acc.lost[:10]} (report {out}.md)"
    assert acc.duplicate_rows == 0 and not acc.unexpected
    assert not acc.unsettled, f"unsettled: {acc.unsettled[:10]} (report {out}.md)"
    lanes = {k: v.count for k, v in report.lanes.items() if v.count}
    assert lanes.get("rules"), f"rules lane never exercised: {lanes}"
    assert lanes.get("small_model"), f"small-model lane never exercised: {lanes}"
