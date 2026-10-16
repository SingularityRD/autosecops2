"""Executors follow the stored config without a restart (W0.37, gap T6 / KS-18).

``LiveExecutorRegistry`` is what the API lifespan and the daemon now build. An
executor enabled, disabled or re-keyed in Settings takes effect in every
process within ``reload_seconds``: the multi-process test runs two separate
Python processes that share only the config store, as the API and daemon
containers share Postgres and the secret file.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from core.response.executors.base import ExecutorRegistry, TypedAction
from core.response.executors.wiring import (
    EXECUTOR_SOURCES,
    LiveExecutorRegistry,
    _digest,
)

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]

PAN = {"hostname": "fw.example.test", "api_key": "pan-key-not-real"}
ENTRA = {"tenant_id": "t", "client_id": "c", "client_secret": "entra-secret-not-real"}


class _Store:
    """The shared config store: what each process reads on refresh."""

    def __init__(self) -> None:
        self.enabled: set[str] = set()
        self.configs: dict[str, dict] = {}
        self.reads = 0
        self.fail = False

    def is_enabled(self, integration_id: str) -> bool:
        self.reads += 1
        if self.fail:
            raise ConnectionError("db down")
        return integration_id in self.enabled

    def config_for(self, integration_id: str) -> dict:
        return dict(self.configs.get(integration_id, {}))


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _live(store: _Store, clock: _Clock, reload_seconds: float = 10.0):
    return LiveExecutorRegistry(
        EXECUTOR_SOURCES,
        enabled=store.is_enabled,
        config_for=store.config_for,
        reload_seconds=reload_seconds,
        clock=clock,
    )


def test_enabling_an_executor_makes_it_available_without_a_restart():
    store, clock = _Store(), _Clock()
    registry = _live(store, clock)
    assert registry.get("block_ip") is None
    assert "waf_block" in registry.action_types()  # Cloudflare is always there

    store.enabled.add("palo-alto")
    store.configs["palo-alto"] = PAN
    # within the reload window the old set still answers
    assert registry.get("block_ip") is None
    clock.now += 10.0
    assert registry.get("block_ip") is not None
    assert registry.action_types_for("palo-alto") == {"block_ip", "unblock_ip"}
    assert registry.reversibility_of("block_ip") == "reversible"


def test_disabling_an_executor_makes_it_unavailable():
    store, clock = _Store(), _Clock()
    store.enabled.add("azure-ad")
    store.configs["azure-ad"] = ENTRA
    registry = _live(store, clock)
    assert registry.get("disable_user") is not None

    store.enabled.discard("azure-ad")
    clock.now += 10.0
    assert registry.get("disable_user") is None
    assert registry.action_types_for("azure-ad") == frozenset()
    verdict = registry.validate(
        TypedAction(action_type="disable_user", target="a@b.c")
    )
    assert verdict.allowed is False
    assert "no executor" in verdict.reasons[0]


def test_new_credentials_rebuild_the_executor():
    store, clock = _Store(), _Clock()
    store.enabled.add("palo-alto")
    store.configs["palo-alto"] = PAN
    registry = _live(store, clock)
    before = registry.get("block_ip")

    store.configs["palo-alto"] = {**PAN, "api_key": "rotated-key"}
    clock.now += 10.0
    after = registry.get("block_ip")
    assert after is not None and after is not before
    assert registry.generation == 2


def test_an_unchanged_config_keeps_the_same_executor_objects():
    store, clock = _Store(), _Clock()
    store.enabled.add("palo-alto")
    store.configs["palo-alto"] = PAN
    registry = _live(store, clock)
    first = registry.get("block_ip")
    for _ in range(3):
        clock.now += 10.0
        assert registry.get("block_ip") is first
    assert registry.generation == 1


def test_reads_are_throttled_and_invalidate_forces_one():
    store, clock = _Store(), _Clock()
    registry = _live(store, clock)
    reads = store.reads
    for _ in range(20):
        registry.get("block_ip")
    assert store.reads == reads  # nothing re-read inside the window

    store.enabled.add("palo-alto")
    store.configs["palo-alto"] = PAN
    registry.invalidate()  # what the API's save handler calls
    assert registry.get("block_ip") is not None


def test_an_unreadable_config_keeps_the_current_executors():
    store, clock = _Store(), _Clock()
    store.enabled.add("palo-alto")
    store.configs["palo-alto"] = PAN
    registry = _live(store, clock)

    store.fail = True
    clock.now += 10.0
    assert registry.get("block_ip") is not None

    store.fail = False
    store.enabled.clear()
    clock.now += 10.0
    assert registry.get("block_ip") is None


def test_the_registry_keeps_a_digest_not_the_credentials():
    store, clock = _Store(), _Clock()
    store.enabled.update({"palo-alto", "azure-ad"})
    store.configs.update({"palo-alto": PAN, "azure-ad": ENTRA})
    registry = _live(store, clock)
    held = repr(
        {k: v for k, v in vars(registry).items() if k not in ("_by_type", "_lock")}
    )
    for secret in (PAN["api_key"], ENTRA["client_secret"]):
        assert secret not in held
    assert len(_digest(PAN)) == 64


def test_it_is_an_executor_registry_for_the_response_service():
    from core.response.autonomous_response_service import AutonomousResponseService

    store, clock = _Store(), _Clock()
    registry = _live(store, clock)
    assert isinstance(registry, ExecutorRegistry)
    service = AutonomousResponseService(executors=registry)
    assert service.executors is registry


def test_api_and_daemon_build_the_live_registry():
    for path in ("services/api/main.py", "services/daemon/main.py"):
        text = (REPO / path).read_text(encoding="utf-8")
        assert "LiveExecutorRegistry()" in text, path
        assert "build_executor_registry()" not in text, path


# --------------------------------------------------------------- two processes

_CHILD = textwrap.dedent(
    """
    import json, sys
    sys.path.insert(0, sys.argv[2])
    from core.response.executors.wiring import EXECUTOR_SOURCES, LiveExecutorRegistry

    path = sys.argv[1]

    def load():
        with open(path) as f:
            return json.load(f)

    registry = LiveExecutorRegistry(
        EXECUTOR_SOURCES,
        enabled=lambda i: i in load()["enabled"],
        config_for=lambda i: load()["configs"].get(i, {}),
        reload_seconds=0.2,
    )
    print("ready", flush=True)
    for line in sys.stdin:
        print(json.dumps(sorted(registry.action_types())), flush=True)
    """
)


def _write(path: Path, enabled: list[str], configs: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"enabled": enabled, "configs": configs}))
    tmp.replace(path)


def _ask(proc: subprocess.Popen) -> set[str]:
    proc.stdin.write("?\n")
    proc.stdin.flush()
    return set(json.loads(proc.stdout.readline()))


def test_two_processes_follow_one_store_without_a_restart(tmp_path):
    store = tmp_path / "integrations.json"
    _write(store, [], {})
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD, str(store), str(REPO)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            cwd=str(tmp_path),
        )
        for _ in ("api", "daemon")
    ]
    try:
        for proc in procs:
            assert proc.stdout.readline().strip() == "ready"
            assert "isolate_host" not in _ask(proc)

        _write(
            store,
            ["microsoft-defender"],
            {"microsoft-defender": {"tenant_id": "t", "client_id": "c", "client_secret": "s"}},
        )
        time.sleep(0.3)
        for proc in procs:
            assert {"isolate_host", "unisolate_host"} <= _ask(proc)

        _write(store, [], {})
        time.sleep(0.3)
        for proc in procs:
            assert "isolate_host" not in _ask(proc)
    finally:
        for proc in procs:
            proc.stdin.close()
            proc.wait(timeout=30)


# ------------------------------------------------------------------- Postgres


@pytest.mark.external_service
def test_a_saved_row_reaches_a_second_registry_through_postgres(monkeypatch):
    """The real store: integration_configs rows plus the secret channel."""
    from core.storage.config_service import ConfigService

    monkeypatch.setenv("PALO_ALTO_API_KEY", "pan-key-not-real")
    service = ConfigService(user_id="w037-test")
    # a row of its own, so the table (not integrations_config.json) is the store
    assert service.set_integration_config("w037-placeholder", {}, enabled=False)
    api = LiveExecutorRegistry(reload_seconds=0)
    daemon = LiveExecutorRegistry(reload_seconds=0)
    try:
        assert api.get("block_ip") is None and daemon.get("block_ip") is None

        assert service.set_integration_config(
            "palo-alto", {"hostname": "fw.example.test"}, enabled=True
        )
        assert api.get("block_ip") is not None
        assert daemon.get("block_ip") is not None

        assert service.set_integration_config(
            "palo-alto", {"hostname": "fw.example.test"}, enabled=False
        )
        assert api.get("block_ip") is None
        assert daemon.get("block_ip") is None
    finally:
        service.set_integration_config("palo-alto", {}, enabled=False)
