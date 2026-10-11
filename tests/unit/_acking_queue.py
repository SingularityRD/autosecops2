"""A stand-in for ``FindingProcessor.input_queue`` that reports every put as stored.

Federation and Kafka producers wait for the processor's per-item ack before
they advance a cursor or offset, so a bare ``asyncio.Queue`` would hang them.
"""

from __future__ import annotations

import asyncio
from typing import Any

from core.ingestion.ack import settle_ack


class AckingQueue(asyncio.Queue):
    def __init__(self, *args: Any, stored: bool = True, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._stored = stored

    def put_nowait(self, item: Any) -> None:
        # Queue.put ends in put_nowait, and the hand-off tries put_nowait first.
        super().put_nowait(item)
        settle_ack(item.get("ack"), self._stored)
