"""QRadar federation adapter (W0.41): offenses by id.

The cursor is ``{"after_id": N}``, the highest offense id read. On the first
run it is set to the newest offense id and nothing is read (federation does
not backfill on enable). Each tick reads the offenses above it, lowest id
first, up to ``max_items``; a full batch is truncated and the runner reads on.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.config import is_integration_enabled
from core.federation.contract import FederationAdapter, FetchResult, register_adapter
from core.integrations.qradar.ingestion import (
    build_client,
    qradar_config,
    transform_offense,
)

logger = logging.getLogger(__name__)


class QRadarAdapter:
    name = "qradar"
    integration_id = "qradar"

    def is_configured(self) -> bool:
        return is_integration_enabled(self.integration_id)

    def default_interval(self) -> int:
        return 120

    async def fetch(
        self, *, since: Any, cursor: Dict[str, Any], max_items: int
    ) -> FetchResult:
        if not self.is_configured():
            return FetchResult(findings=[], cursor=dict(cursor or {}))
        config = qradar_config()
        client = build_client(config)
        if client is None:
            return FetchResult(findings=[], cursor=dict(cursor or {}))
        try:
            after = _after_id(cursor)
            if after is None:
                newest = await client.newest_offense_id()
                return FetchResult(findings=[], cursor={"after_id": newest})
            offenses = await client.offenses_after(
                after, max_items, config.get("offense_filter")
            )
        finally:
            await client.close()
        findings = []
        dropped = 0
        newest = after
        for offense in offenses[:max_items]:
            offense_id = offense.get("id")
            if isinstance(offense_id, int) and not isinstance(offense_id, bool):
                newest = max(newest, offense_id)
            finding = transform_offense(offense)
            if finding is None:
                dropped += 1
                continue
            findings.append(finding)
        return FetchResult(
            findings=findings,
            cursor={"after_id": newest},
            dropped=dropped,
            truncated=len(offenses) >= max_items,
        )


def _after_id(cursor: Optional[Dict[str, Any]]) -> Optional[int]:
    raw = (cursor or {}).get("after_id")
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.isdigit():
        return int(raw)
    return None


def _factory() -> FederationAdapter:
    return QRadarAdapter()


register_adapter("qradar", _factory)
