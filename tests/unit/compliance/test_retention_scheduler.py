"""The daemon only schedules the retention purge when RETENTION_PURGE_ENABLED."""

from __future__ import annotations

import pytest

from core.config import get_settings
from services.daemon.config import SchedulerConfig
from services.daemon.scheduler import TaskScheduler

pytestmark = pytest.mark.unit


@pytest.fixture
def fresh_settings(monkeypatch):
    monkeypatch.delenv("RETENTION_PURGE_ENABLED", raising=False)
    monkeypatch.delenv("RETENTION_PURGE_INTERVAL", raising=False)
    get_settings.cache_clear()
    yield monkeypatch
    monkeypatch.delenv("RETENTION_PURGE_ENABLED", raising=False)
    monkeypatch.delenv("RETENTION_PURGE_INTERVAL", raising=False)
    get_settings.cache_clear()


def _names(scheduler):
    return [t.name for t in scheduler._tasks]


def test_off_by_default_and_a_dry_run_when_switched_on(fresh_settings):
    settings = get_settings()
    assert settings.retention_purge_enabled is False
    assert settings.retention_purge_dry_run is True
    assert "retention_purge" not in _names(TaskScheduler(SchedulerConfig()))


def test_registered_when_enabled_never_more_than_hourly(fresh_settings):
    fresh_settings.setenv("RETENTION_PURGE_ENABLED", "true")
    fresh_settings.setenv("RETENTION_PURGE_INTERVAL", "60")
    get_settings.cache_clear()

    scheduler = TaskScheduler(SchedulerConfig())
    [task] = [t for t in scheduler._tasks if t.name == "retention_purge"]

    assert task.enabled and not task.run_on_start
    assert task.interval == 3600


async def test_the_task_returns_nothing_when_the_flag_is_off(fresh_settings):
    scheduler = TaskScheduler(SchedulerConfig())
    assert await scheduler._run_retention_purge() is None
