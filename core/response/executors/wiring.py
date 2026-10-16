"""Building the process's ``ExecutorRegistry`` (W2.4).

There is no module-level registry (tests/unit/_ratchets/test_no_ambient_state.py):
the API lifespan (``services/api/main.py``) and the daemon
(``services/daemon/main.py``) each build a ``LiveExecutorRegistry`` at startup
and inject it.

A ``LiveExecutorRegistry`` follows the stored configuration (W0.37). Each
lookup re-reads the enabled set and every executor integration's resolved
settings once ``reload_seconds`` have passed since the last read, and rebuilds
the registry when a digest of them changed. Turning an executor on, off or
changing its credentials in Settings therefore takes effect in every process
(API, daemon) without a restart: at once in the API process that saved it
(``invalidate``), within ``reload_seconds`` elsewhere. Both stores are shared
between processes: ``integration_configs`` in Postgres, and the encrypted
secret file, which every process re-reads when its mtime moves.

Executors plug in by naming a module in ``EXECUTOR_SOURCES``. The module
exports ``build_executor(config) -> Executor | None``, where ``config`` is the
integration's resolved settings: the stored integration config with every
descriptor field resolved through ``core.integrations._base.config``, so secret
fields (Entra's ``client_secret``) come from the secret store. The stored JSON
never holds a secret (``integration_secrets.split_secrets`` strips them), so a
factory handed the raw config would be missing its credentials.
``integration_id`` is the descriptor id (``microsoft-defender``, ``azure-ad``,
``palo-alto``): the key ``enabled_integrations`` and the secret store use. A source
whose module is not installed is skipped; one whose integration is disabled is
skipped unless ``always`` (the executor then reads its settings per call and
fails the action itself while disabled, as Cloudflare does). A factory that
raises, or an executor that conflicts with one already registered, is logged
and left out: one broken integration does not take the others down.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Dict, Optional

from core.response.executors.base import (
    Executor,
    ExecutorConflict,
    ExecutorRegistry,
    PolicyResult,
    TypedAction,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExecutorSource:
    """Where one integration's executor comes from."""

    integration_id: str
    module: str
    always: bool = False


EXECUTOR_SOURCES: tuple[ExecutorSource, ...] = (
    ExecutorSource("cloudflare", "core.integrations.cloudflare.executor", always=True),
    ExecutorSource(
        "microsoft-defender", "core.integrations.microsoft_defender.executor"
    ),
    ExecutorSource("azure-ad", "core.integrations.azure_ad.executor"),
    ExecutorSource("palo-alto", "core.integrations.palo_alto.executor"),
)


def _is_enabled(integration_id: str) -> bool:
    from core.config import is_integration_enabled

    return is_integration_enabled(integration_id)


def resolved_integration_config(integration_id: str) -> Dict[str, Any]:
    """The stored config with descriptor fields resolved, secrets included.

    Keys the descriptor does not declare (an executor's own settings, such as
    ``protected_users``) pass through from the stored config; a declared field
    takes its resolved value when it has one.
    """
    from core.config import get_integration_config
    from core.integrations._base.config import resolve
    from core.integrations._base.descriptor import get_descriptor

    config: Dict[str, Any] = dict(get_integration_config(integration_id) or {})
    descriptor = get_descriptor(integration_id)
    if descriptor is not None:
        for key, value in resolve(descriptor).items():
            if value is not None and value != "":
                config[key] = value
    return config


def _import(module: str) -> Optional[Any]:
    try:
        return importlib.import_module(module)
    except ModuleNotFoundError as e:
        # The executor's own module is absent: not installed in this build.
        if e.name and module.startswith(e.name):
            logger.debug("No executor module %s", module)
            return None
        raise


def build_executor_registry(
    sources: Iterable[ExecutorSource] = EXECUTOR_SOURCES,
    *,
    enabled: Callable[[str], bool] = _is_enabled,
    config_for: Callable[[str], Dict[str, Any]] = resolved_integration_config,
    built: Optional[Dict[str, frozenset[str]]] = None,
) -> ExecutorRegistry:
    """A registry holding every available, enabled executor.

    ``built``, when given, receives integration_id -> the action types its
    executor registered.
    """
    registry = ExecutorRegistry()
    for source in sources:
        try:
            if not source.always and not enabled(source.integration_id):
                continue
            module = _import(source.module)
            if module is None:
                continue
            factory = getattr(module, "build_executor", None)
            if factory is None:
                logger.error("%s has no build_executor; skipped", source.module)
                continue
            executor: Optional[Executor] = factory(config_for(source.integration_id))
            if executor is None:
                continue
            registry.register(executor)
            if built is not None:
                built[source.integration_id] = frozenset(executor.action_types)
            logger.info(
                "Registered %s executor for %s",
                source.integration_id,
                sorted(executor.action_types),
            )
        except ExecutorConflict as e:
            logger.error("Executor for %s not registered: %s", source.integration_id, e)
        except Exception as e:  # noqa: BLE001
            logger.error(
                "Executor for %s failed to build: %s", source.integration_id, e
            )
    return registry


# How stale a process's executors may be after a change saved by another
# process. Each re-read is one integration_configs query per executor source.
RELOAD_SECONDS = 10.0


def _digest(value: Any) -> str:
    """A digest of a config, so the registry keeps no copy of its secrets."""
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class LiveExecutorRegistry(ExecutorRegistry):
    """An ``ExecutorRegistry`` that rebuilds itself when the stored config changes.

    Every lookup (``get``, ``for_type``, ``action_types``, ``validate``) first
    calls ``refresh``. ``reversibility_of`` does not: callers ask it right after
    ``get`` found the type, and must get the answer for that same set. A refresh within ``reload_seconds`` of
    the last one does nothing; otherwise it reads each source's enabled flag and
    resolved config, and when their digest differs from the one the current
    executors were built from, builds a new set with ``build_executor_registry``
    and swaps it in whole. A lookup sees the old set or the new one, never a mix.
    An executor already handed out keeps running the action it was given.

    A read that raises keeps the current executors; the next lookup tries
    again. ``register`` on this registry is for tests: a rebuild replaces it.
    """

    def __init__(
        self,
        sources: Iterable[ExecutorSource] = EXECUTOR_SOURCES,
        *,
        enabled: Callable[[str], bool] = _is_enabled,
        config_for: Callable[[str], Dict[str, Any]] = resolved_integration_config,
        reload_seconds: float = RELOAD_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__()
        self._sources = tuple(sources)
        self._enabled = enabled
        self._config_for = config_for
        self.reload_seconds = max(0.0, float(reload_seconds))
        self._clock = clock
        self._lock = threading.Lock()
        self._digest: Optional[str] = None
        self._checked_at: Optional[float] = None
        self._built: Dict[str, frozenset[str]] = {}
        self.generation = 0
        self.refresh(force=True)

    def _read(self) -> tuple[Dict[str, bool], Dict[str, Dict[str, Any]]]:
        enabled: Dict[str, bool] = {}
        configs: Dict[str, Dict[str, Any]] = {}
        for source in self._sources:
            if source.always:
                continue
            on = bool(self._enabled(source.integration_id))
            enabled[source.integration_id] = on
            if on:
                configs[source.integration_id] = dict(
                    self._config_for(source.integration_id) or {}
                )
        return enabled, configs

    def invalidate(self) -> None:
        """Re-read the config on the next lookup, whatever ``reload_seconds`` says."""
        self._checked_at = None

    def refresh(self, *, force: bool = False) -> bool:
        """Rebuild when the stored config changed; True when it rebuilt."""
        now = self._clock()
        checked = self._checked_at
        if not force and checked is not None and now - checked < self.reload_seconds:
            return False
        with self._lock:
            checked = self._checked_at
            if (
                not force
                and checked is not None
                and self._clock() - checked < self.reload_seconds
            ):
                return False
            try:
                enabled, configs = self._read()
            except Exception as e:  # noqa: BLE001
                logger.error(
                    "Executor config could not be read (%s); keeping the current "
                    "executors",
                    type(e).__name__,
                )
                self._checked_at = now
                return False
            digest = _digest({"enabled": enabled, "configs": configs})
            self._checked_at = now
            if digest == self._digest:
                return False
            built: Dict[str, frozenset[str]] = {}
            fresh = build_executor_registry(
                self._sources,
                enabled=lambda i: enabled.get(i, False),
                config_for=lambda i: configs.get(i, {}),
                built=built,
            )
            # one assignment: a concurrent lookup reads the old dict or the new
            self._by_type = fresh._by_type
            self._built = built
            self._digest = digest
            self.generation += 1
            if self.generation > 1:
                logger.info(
                    "Executor configuration changed; executors now cover %s",
                    sorted(self._by_type),
                )
            return True

    def action_types_for(self, integration_id: str) -> frozenset[str]:
        """The action types the integration's executor covers now; empty if none."""
        self.refresh()
        return self._built.get(integration_id, frozenset())

    def get(self, action_type: str) -> Optional[Executor]:
        self.refresh()
        return super().get(action_type)

    def for_type(self, action_type: str) -> Executor:
        self.refresh()
        return super().for_type(action_type)

    def action_types(self) -> frozenset[str]:
        self.refresh()
        return super().action_types()

    def validate(self, action: TypedAction) -> PolicyResult:
        self.refresh()
        return super().validate(action)


def registry_snapshot(registry: ExecutorRegistry) -> Dict[str, Dict[str, Any]]:
    """action_type -> executor class, reversibility and default ttl (seconds)."""
    out: Dict[str, Dict[str, Any]] = {}
    for action_type in sorted(registry.action_types()):
        executor = registry.for_type(action_type)
        ttl = executor.default_ttl
        out[action_type] = {
            "executor": type(executor).__name__,
            "reversibility": registry.reversibility_of(action_type),
            "default_ttl_seconds": int(ttl.total_seconds()) if ttl else None,
        }
    return out


__all__ = [
    "EXECUTOR_SOURCES",
    "ExecutorSource",
    "LiveExecutorRegistry",
    "RELOAD_SECONDS",
    "build_executor_registry",
    "registry_snapshot",
    "resolved_integration_config",
]
