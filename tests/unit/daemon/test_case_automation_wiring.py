"""Case automation runs in the daemon, once, and stops with it.

The SLA monitor, stale-case detector, digest, notification dispatcher and
webhook sender used to sit in ``CaseAutomationService.start()``, which nothing
called. They are now a daemon component; the API process must not start them
too (it can run several workers, each of which would run every loop).
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

from core.cases import case_automation_service as automation
from core.config import get_settings
from services.daemon import main as daemon_main

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]


def test_the_daemon_builds_it_when_enabled(monkeypatch):
    monkeypatch.setenv("CASE_AUTOMATION_ENABLED", "true")
    get_settings.cache_clear()
    assert isinstance(
        daemon_main.build_case_automation(), automation.CaseAutomationService
    )


def test_it_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("CASE_AUTOMATION_ENABLED", "false")
    get_settings.cache_clear()
    assert daemon_main.build_case_automation() is None


def test_the_daemon_starts_it_as_a_component():
    source = (REPO / "services/daemon/main.py").read_text(encoding="utf-8")
    assert "self._case_automation = build_case_automation()" in source
    assert 'start("case_automation", self._case_automation' in source


def _names_used(path: Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.ImportFrom):
            names.update(a.name for a in node.names)
    return names


def test_the_api_process_never_starts_it():
    forbidden = {
        "CaseAutomationService",
        "automation_service",
        "CaseNotificationDispatcher",
        "WebhookSender",
        "deliver_due",
        "dispatch_pending",
    }
    offenders = []
    for path in sorted((REPO / "services" / "api").rglob("*.py")):
        hit = forbidden & _names_used(path)
        if hit:
            offenders.append(f"{path.relative_to(REPO)}: {sorted(hit)}")
    assert offenders == []


class _Dispatcher:
    def __init__(self):
        self.calls = 0

    def dispatch_pending(self):
        self.calls += 1
        return {}


class _Sender:
    def __init__(self):
        self.calls = 0

    async def deliver_due(self):
        self.calls += 1
        return {}


@pytest.mark.asyncio
async def test_run_drives_the_dispatcher_and_sender_and_stops_on_shutdown(
    monkeypatch,
):
    dispatcher, sender = _Dispatcher(), _Sender()
    svc = automation.CaseAutomationService(dispatcher=dispatcher, webhook_sender=sender)
    # No database here: the loops that query it are replaced.
    monkeypatch.setattr(svc, "check_sla_deadlines", lambda: 0)
    monkeypatch.setattr(svc, "_update_case_metrics", lambda: None)
    monkeypatch.setattr(svc, "detect_stale_cases", lambda: 0)
    monkeypatch.setattr(svc, "_generate_daily_digest", lambda: None)

    shutdown = asyncio.Event()
    task = asyncio.create_task(svc.run(shutdown))
    for _ in range(50):
        await asyncio.sleep(0.01)
        if dispatcher.calls and sender.calls:
            break
    shutdown.set()
    await asyncio.wait_for(task, timeout=5)

    assert dispatcher.calls >= 1 and sender.calls >= 1
    assert svc.running is False
