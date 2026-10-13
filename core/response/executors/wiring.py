"""Building the process's ``ExecutorRegistry`` (W2.4).

There is no module-level registry (tests/unit/_ratchets/test_no_ambient_state.py):
the API lifespan (``services/api/main.py``) and the daemon
(``services/daemon/main.py``) each call ``build_executor_registry()`` once at
startup and inject the result.

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

import importlib
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Dict, Optional

from core.response.executors.base import Executor, ExecutorConflict, ExecutorRegistry

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
) -> ExecutorRegistry:
    """A registry holding every available, enabled executor."""
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
    "build_executor_registry",
    "registry_snapshot",
    "resolved_integration_config",
]
