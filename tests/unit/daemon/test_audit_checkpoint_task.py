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
