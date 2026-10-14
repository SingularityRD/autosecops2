"""Opt-in gates for the load (W4.1) and chaos (W4.2) tests.

``load`` and ``chaos`` tests start a whole stack and run for minutes, so they
are skipped unless asked for:

    LOAD_TESTS=1  pytest -c tests/pytest.ini -o addopts= -m load  tests/perf
    CHAOS_TESTS=1 pytest -c tests/pytest.ini -o addopts= -m chaos tests/perf

``CHAOS_TARGET=staging`` points the chaos tests at an existing install instead
of a local stack (docs/operations/load-chaos-runbook.md). Both kinds are also
``external_service``, so the WP gates (``-m "not external_service"``) never
collect them; the unit tests in this folder run everywhere.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_OPT_IN = {"load": "LOAD_TESTS", "chaos": "CHAOS_TESTS"}


def pytest_collection_modifyitems(config, items):
    for item in items:
        for marker, var in _OPT_IN.items():
            if marker in item.keywords and os.environ.get(var) not in ("1", "true"):
                item.add_marker(pytest.mark.skip(reason=f"opt-in: set {var}=1"))


def perf_out_dir() -> Path:
    out = Path(os.environ.get("PERF_OUT_DIR", "/tmp/autosecops-perf"))
    out.mkdir(parents=True, exist_ok=True)
    return out


def _start_stack(tmp_path_factory, name: str, standby: bool):
    from tests.perf.stack import LocalStack, StackError

    reason = LocalStack.unavailable()
    if reason:
        if os.environ.get("CI") or os.environ.get("PERF_REQUIRED"):
            pytest.fail(reason)
        pytest.skip(reason)
    if standby and not LocalStack.leader_election_supported():
        standby = False
    stack = LocalStack(
        tmp_path_factory.mktemp(name),
        daemons=2 if standby else 1,
        leader_election=standby,
    )
    try:
        stack.start()
    except StackError as e:
        stack.stop()
        pytest.fail(f"local stack did not start: {e}")
    return stack


@pytest.fixture(scope="session")
def local_stack(tmp_path_factory):
    stack = _start_stack(
        tmp_path_factory,
        "perf-stack",
        os.environ.get("CHAOS_STANDBY") in ("1", "true"),
    )
    try:
        yield stack
    finally:
        stack.stop()


@pytest.fixture(scope="module")
def local_standby_stack(tmp_path_factory):
    """Two daemons with W3.9 leader election, for daemon_kill_standby."""
    stack = _start_stack(tmp_path_factory, "perf-standby-stack", True)
    try:
        yield stack
    finally:
        stack.stop()
