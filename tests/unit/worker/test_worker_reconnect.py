"""The LLM worker reconnects on Redis loss instead of exiting (W0.12, W4.1
finding 2: it exited with code 1 on every Redis restart)."""

from __future__ import annotations

import asyncio

import pytest
import redis.exceptions

from services.worker import supervise

pytestmark = pytest.mark.unit


class _Worker:
    def __init__(self, outcome):
        self.outcome = outcome

    def run(self):
        # ARQ builds its worker on the current loop; one must be set.
        loop = asyncio.get_event_loop()
        assert not loop.is_closed()
        if isinstance(self.outcome, BaseException):
            raise self.outcome


def _factory(outcomes, made):
    def create(settings_cls):
        worker = _Worker(outcomes.pop(0))
        made.append(worker)
        return worker

    return create


def test_redis_loss_reconnects_with_growing_backoff():
    made, sleeps = [], []
    outcomes = [
        redis.exceptions.ConnectionError("Error 111 connecting"),
        redis.exceptions.TimeoutError("timeout"),
        ConnectionRefusedError(111, "refused"),
        None,  # Redis back; then stopped by SIGTERM
    ]
    restarts = supervise.run_forever(
        object, create_worker=_factory(outcomes, made), sleep=sleeps.append
    )
    assert restarts == 3
    assert len(made) == 4
    assert sleeps == [1.0, 2.0, 4.0]


def test_backoff_is_capped():
    sleeps = []
    outcomes = [redis.exceptions.ConnectionError("down")] * 10 + [None]
    supervise.run_forever(
        object, create_worker=_factory(outcomes, []), sleep=sleeps.append
    )
    assert max(sleeps) == supervise.BACKOFF_MAX
    assert sleeps[-1] == supervise.BACKOFF_MAX


def test_backoff_resets_after_a_healthy_run():
    sleeps = []
    now = [0.0]

    def clock():
        return now[0]

    class _Slow(_Worker):
        def run(self):
            now[0] += 120.0  # ran two minutes, then lost Redis
            super().run()

    outcomes = [
        redis.exceptions.ConnectionError("a"),
        redis.exceptions.ConnectionError("b"),
        redis.exceptions.ConnectionError("c"),
        None,
    ]

    def create(settings_cls):
        o = outcomes.pop(0)
        return _Slow(o) if len(outcomes) == 1 else _Worker(o)

    supervise.run_forever(
        object, create_worker=create, sleep=sleeps.append, clock=clock
    )
    assert sleeps == [1.0, 2.0, 1.0]


def test_other_errors_still_end_the_process():
    with pytest.raises(ValueError):
        supervise.run_forever(
            object,
            create_worker=_factory([ValueError("bug")], []),
            sleep=lambda s: None,
        )


def test_each_attempt_gets_a_fresh_loop_and_leftover_tasks_are_cancelled():
    loops = []
    cancelled = []

    class _Leaky(_Worker):
        def run(self):
            loop = asyncio.get_event_loop()
            loops.append(loop)

            async def refresher():
                try:
                    await asyncio.sleep(3600)
                except asyncio.CancelledError:
                    cancelled.append(True)
                    raise

            loop.create_task(refresher())
            loop.run_until_complete(asyncio.sleep(0))
            super().run()

    outcomes = [redis.exceptions.ConnectionError("x"), None]

    def create(settings_cls):
        return _Leaky(outcomes.pop(0))

    supervise.run_forever(object, create_worker=create, sleep=lambda s: None)
    assert len(loops) == 2 and loops[0] is not loops[1]
    assert all(loop.is_closed() for loop in loops)
    assert cancelled == [True, True]


def test_main_uses_the_supervisor(monkeypatch):
    import services.worker.__main__ as entry

    called = {}
    monkeypatch.setattr(entry, "validate_settings_or_exit", lambda: None)
    monkeypatch.setattr(
        supervise, "run_forever", lambda settings: called.setdefault("s", settings)
    )
    entry.main()
    from services.worker.jobs import WorkerSettings

    assert called["s"] is WorkerSettings
