"""Keep the ARQ LLM worker running across Redis outages (W0.12).

ARQ's ``Worker.run`` returns when the worker is told to stop (SIGTERM/SIGINT)
and raises when its Redis connection fails, at start (``create_pool`` gives up
after its own retries) or while polling. Raising used to end the process, and
triage stopped until something restarted it, which Compose and systemd
installs do not always do. Here a Redis failure builds a fresh worker on a
fresh event loop after a backoff (1 s doubling to 30 s, reset after a minute
of healthy running); any other error still ends the process.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Optional, Tuple, Type

logger = logging.getLogger(__name__)

BACKOFF_START = 1.0
BACKOFF_MAX = 30.0
# A worker that ran this long before failing was healthy: start over at 1 s.
HEALTHY_AFTER = 60.0


def redis_errors() -> Tuple[Type[BaseException], ...]:
    """Exceptions that mean "Redis is unreachable", not a bug."""
    errors: list = [ConnectionError, TimeoutError, OSError]
    try:
        import redis.exceptions as rex

        errors += [rex.ConnectionError, rex.TimeoutError, rex.BusyLoadingError]
    except ImportError:  # pragma: no cover - redis is a dependency
        pass
    return tuple(errors)


def _drain_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Cancel what the failed worker left on its loop (e.g. the rates
    refresher, whose on_shutdown never ran) and close the loop."""
    try:
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    except Exception:  # noqa: BLE001 - best effort on a dead worker's loop
        logger.debug("LLM worker loop cleanup failed", exc_info=True)
    finally:
        loop.close()


def run_forever(
    settings_cls: Any,
    *,
    create_worker: Optional[Callable[[Any], Any]] = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    max_restarts: Optional[int] = None,
) -> int:
    """Run the worker until it is told to stop; reconnect on Redis loss.

    Returns the number of reconnects (for tests; ``max_restarts`` bounds them
    there). A non-Redis exception propagates.
    """
    if create_worker is None:
        from arq.worker import create_worker as arq_create_worker

        create_worker = arq_create_worker
    transient = redis_errors()
    backoff = BACKOFF_START
    restarts = 0
    while True:
        # Python 3.12+ dropped implicit loop creation; ARQ's Worker needs one.
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        started = clock()
        try:
            worker = create_worker(settings_cls)
            worker.run()
            return restarts  # stopped on a signal: a normal exit
        except transient as exc:
            if clock() - started >= HEALTHY_AFTER:
                backoff = BACKOFF_START
            logger.error(
                "LLM worker lost Redis (%s: %s); reconnecting in %.0fs",
                type(exc).__name__,
                exc,
                backoff,
            )
        finally:
            _drain_loop(loop)
            asyncio.set_event_loop(None)
        restarts += 1
        if max_restarts is not None and restarts > max_restarts:
            return restarts
        sleep(backoff)
        backoff = min(backoff * 2, BACKOFF_MAX)
