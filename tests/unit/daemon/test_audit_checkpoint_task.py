"""The daemon schedules the signed audit checkpoint, and 0 turns it off."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.config import get_settings
from services.daemon.config import SchedulerConfig
from services.daemon.scheduler import TaskScheduler

pytestmark = pytest.mark.unit


@pytest.fixture
def interval(monkeypatch):
    def set_interval(seconds):
        monkeypatch.setattr(
            get_settings(), "audit_checkpoint_interval_seconds", seconds
        )

    return set_interval


def _task(scheduler):
    return next((t for t in scheduler._tasks if t.name == "audit_checkpoint"), None)


def test_registered_at_the_configured_interval(interval):
    interval(7200)
    task = _task(TaskScheduler(SchedulerConfig()))
    assert task is not None and task.interval == 7200 and task.enabled


def test_zero_turns_it_off(interval):
    interval(0)
    assert _task(TaskScheduler(SchedulerConfig())) is None


def test_interval_has_a_floor(interval):
    interval(5)
    assert _task(TaskScheduler(SchedulerConfig())).interval == 60


@pytest.mark.asyncio
async def test_task_writes_a_checkpoint_off_the_loop(interval):
    interval(3600)
    scheduler = TaskScheduler(SchedulerConfig())
    manager = MagicMock()
    with (
        patch("services.daemon.scheduler.get_db_manager", return_value=manager),
        patch(
            "core.audit.checkpoint.run_checkpoint",
            return_value=SimpleNamespace(id=42),
        ) as run,
    ):
        assert await scheduler._run_audit_checkpoint() == 42
    run.assert_called_once_with(manager.engine)


@pytest.mark.asyncio
async def test_a_skipped_first_checkpoint_with_a_key_is_retried_soon(interval):
    """W0.44: the daemon can start before audit_chain exists. With a key the
    task asks to run again next minute (bounded), not an interval later."""
    from services.daemon import scheduler as sched

    interval(3600)
    scheduler = TaskScheduler(SchedulerConfig())
    with (
        patch("services.daemon.scheduler.get_db_manager", return_value=MagicMock()),
        patch("core.audit.checkpoint.run_checkpoint", return_value=None),
        patch("core.audit.checkpoint.signing_key_from_secrets", return_value=object()),
    ):
        results = [
            await scheduler._run_audit_checkpoint()
            for _ in range(sched._CHECKPOINT_START_RETRIES + 2)
        ]
    assert (
        results[: sched._CHECKPOINT_START_RETRIES]
        == [sched.RETRY_SOON] * sched._CHECKPOINT_START_RETRIES
    )
    assert results[-2:] == [None, None]


@pytest.mark.asyncio
async def test_no_key_is_not_retried(interval):
    from services.daemon import scheduler as sched

    interval(3600)
    scheduler = TaskScheduler(SchedulerConfig())
    with (
        patch("services.daemon.scheduler.get_db_manager", return_value=MagicMock()),
        patch("core.audit.checkpoint.run_checkpoint", return_value=None),
        patch("core.audit.checkpoint.signing_key_from_secrets", return_value=None),
    ):
        assert await scheduler._run_audit_checkpoint() is None


@pytest.mark.asyncio
async def test_a_retry_soon_task_keeps_no_last_run(interval):
    """The loop leaves last_run unset, so the next minute's check runs it again."""
    from services.daemon import scheduler as sched

    interval(0)
    scheduler = TaskScheduler(SchedulerConfig())
    calls = []

    async def func():
        calls.append(1)
        return sched.RETRY_SOON

    scheduler._tasks = [
        sched.ScheduledTask(name="t", func=func, interval=3600, run_on_start=True)
    ]
    scheduler._init_services = lambda: None
    stop = __import__("asyncio").Event()

    async def no_rates():
        return None

    with (
        patch("services.daemon.scheduler.refresh_gateway_rates", no_rates),
        patch("services.daemon.scheduler.run_gateway_rates_refresher", no_rates),
    ):
        import asyncio

        runner = asyncio.ensure_future(scheduler.run(stop))
        await asyncio.sleep(0.1)
        stop.set()
        await asyncio.wait_for(runner, timeout=5)
    # Started once, then the loop ran it again at once (last_run still None).
    assert len(calls) >= 2
    assert scheduler._tasks[0].last_run is None
