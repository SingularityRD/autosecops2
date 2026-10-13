"""A real SOCDaemon process whose only component writes rows: used by
test_daemon_leader_election.py to run two replicas against one Postgres.

Everything but ``_init_components`` is the production path in
services/daemon/main.py: the election, the standby, the fence, the heartbeat,
the exit code on demotion. The writer inserts one row every 50 ms through the
platform engine (fenced), tagged with this process's instance id.

stdout protocol (one line each, flushed): ``LEADER <instance_id>`` when this
process starts leading, ``WRITE_FAILED <error class>`` per refused write.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sqlalchemy import text  # noqa: E402

from services.daemon.main import SOCDaemon  # noqa: E402


class Writer:
    def __init__(self, instance_id: str) -> None:
        self.instance_id = instance_id

    def _write(self) -> None:
        from core.storage.connection import get_db_manager

        with get_db_manager().session_scope() as session:
            session.execute(
                text("INSERT INTO leader_writes (writer) VALUES (:w)"),
                {"w": self.instance_id},
            )

    async def run(self, shutdown: asyncio.Event) -> None:
        while not shutdown.is_set():
            try:
                await asyncio.to_thread(self._write)
            except Exception as exc:  # noqa: BLE001 - reported, not fatal
                print(f"WRITE_FAILED {type(exc).__name__}", flush=True)
            await asyncio.sleep(0.05)


class HarnessDaemon(SOCDaemon):
    async def _init_components(self) -> None:
        # The scheduler slot is just a component the run loop starts.
        self._scheduler = Writer(self._leadership.instance_id)
        print(f"LEADER {self._leadership.instance_id}", flush=True)


def main() -> None:
    from services.daemon.config import DaemonConfig

    config = DaemonConfig.from_env()
    config.metrics.enabled = False
    config.polling.webhook_enabled = False
    asyncio.run(HarnessDaemon(config).run())


if __name__ == "__main__":
    main()
