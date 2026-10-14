"""Spool replay against a real findings table and its unique index (W0.12b r6).

``uniq_findings_source_extid`` is ``UNIQUE (data_source, external_id) WHERE
external_id IS NOT NULL``. Round 6 found two ways a spooled finding could hit
it forever while the daemon took the collision for an outage (never counted,
never quarantined, holding its spool slot and pausing the feeder):

* an empty external id was inserted as "" but never looked up, so a second
  blank-id finding of the same source collided with the first;
* any 23505 the in-place retry does not resolve as "already stored".

The index, the driver's error and its SQLSTATE are the thing under test, so
the store goes through the real ``DatabaseService`` on the throwaway database.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List

import pytest

from core.ingestion.handoff import envelope
from core.ingestion.ingestion_service import IngestionService
from core.ingestion.spool import DEAD_DIR, IngestSpool
from services.daemon.config import ProcessingConfig
from services.daemon.processor import _SPOOL_POISON_ATTEMPTS, FindingProcessor

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]


def _source() -> str:
    return f"w012b-r6-{uuid.uuid4().hex[:10]}"


def _db():
    from core.storage.service import DatabaseService

    return DatabaseService()


def _processor(monkeypatch, db, spool: IngestSpool) -> FindingProcessor:
    monkeypatch.setattr("services.daemon.processor._STORE_RETRY_BACKOFF", 0)
    monkeypatch.setattr("services.daemon.processor._SPOOL_BACKOFF_BASE", 0.01)
    monkeypatch.setattr("services.daemon.processor._SPOOL_BACKOFF_MAX", 0.02)
    service = IngestionService.__new__(IngestionService)
    service.use_database = True
    service.db_service = db
    service.stats = {"findings_imported": 0, "findings_skipped": 0}
    service.stats["findings_errors"] = 0
    monkeypatch.setattr(
        "core.ingestion.ingestion_service.IngestionService", lambda: service
    )
    processor = FindingProcessor(
        ProcessingConfig(
            auto_triage_enabled=False,
            auto_enrich_enabled=False,
            max_concurrent_tasks=2,
            enrich_backfill_enabled=False,
        )
    )
    processor._data_service = db
    processor._init_services = lambda: None  # type: ignore[method-assign]
    processor.attach_spool(spool)
    enriched: List[str] = []

    async def spawn(finding, source=None):
        enriched.append(finding["finding_id"])

    processor._spawn_enrich = spawn  # type: ignore[method-assign]
    processor.enriched = enriched  # type: ignore[attr-defined]
    return processor


async def _drain(processor: FindingProcessor, spool: IngestSpool, rounds: int):
    for _ in range(rounds):
        for entry in spool.claim(100):
            item = envelope(entry.finding, entry.source)
            item["spool"] = entry
            await processor._process_item(item)
        if len(spool) == 0:
            return


def _finding(finding_id: str, source: str, external_id: Any) -> Dict[str, Any]:
    return {
        "finding_id": finding_id,
        "data_source": source,
        "external_id": external_id,
        "title": "w012b round 6",
        "severity": "low",
    }


def _stored_external_ids(source: str) -> Dict[str, Any]:
    from core.storage.connection import get_db_manager
    from core.storage.models import Finding

    with get_db_manager().session_scope() as session:
        rows = session.query(Finding).filter(Finding.data_source == source).all()
        return {row.finding_id: row.external_id for row in rows}


@pytest.mark.asyncio
@pytest.mark.parametrize("blank", ["", "  "])
async def test_blank_external_ids_of_one_source_all_store(monkeypatch, tmp_path, blank):
    source = _source()
    ids = [f"{source}-{i}" for i in range(3)]
    spool = IngestSpool(tmp_path)
    spool.open()
    processor = _processor(monkeypatch, _db(), spool)
    spool.append([_finding(fid, source, blank) for fid in ids], "webhook")

    await _drain(processor, spool, _SPOOL_POISON_ATTEMPTS + 1)

    assert len(spool) == 0
    # None of them collided: all stored, with no external id (NULL), triaged.
    assert _stored_external_ids(source) == {fid: None for fid in ids}
    assert sorted(processor.enriched) == sorted(ids)
    assert processor.stats["spool_store_outages"] == 0
    assert processor.stats["spool_quarantined"] == 0


@pytest.mark.asyncio
async def test_a_repeated_external_id_is_already_stored_not_a_collision(
    monkeypatch, tmp_path
):
    source = _source()
    spool = IngestSpool(tmp_path)
    spool.open()
    processor = _processor(monkeypatch, _db(), spool)
    first, again = f"{source}-a", f"{source}-b"  # a resend under a new id
    spool.append([_finding(first, source, "ext-1")], "webhook")
    spool.append([_finding(again, source, "ext-1")], "webhook")

    await _drain(processor, spool, 2)

    assert len(spool) == 0
    assert _stored_external_ids(source) == {first: "ext-1"}
    assert processor.enriched == [first]
    assert processor.stats["spool_replay_skipped"] == 1
    assert processor.stats["spool_quarantined"] == 0


@pytest.mark.asyncio
async def test_a_unique_violation_that_never_resolves_is_quarantined(
    monkeypatch, tmp_path
):
    """The real 23505 from uniq_findings_source_extid, with a lookup that never
    finds the row it collides with: quarantined after the poison attempts,
    instead of waiting in the spool forever as an "outage"."""
    source = _source()
    db = _db()
    stored, colliding = f"{source}-stored", f"{source}-colliding"
    spool = IngestSpool(tmp_path)
    spool.open()
    processor = _processor(monkeypatch, db, spool)
    spool.append([_finding(stored, source, "ext-x")], "webhook")
    await _drain(processor, spool, 1)
    assert _stored_external_ids(source) == {stored: "ext-x"}

    # Whatever makes the lookup miss (a type or collation mismatch, a source
    # normalised differently): the insert still hits the index.
    db.get_finding_by_external_id = lambda *_a: None  # type: ignore[method-assign]
    spool.append(
        [_finding(colliding, source, "ext-x"), _finding(f"{source}-ok", source, "y")],
        "webhook",
    )
    await _drain(processor, spool, _SPOOL_POISON_ATTEMPTS + 1)

    assert len(spool) == 0  # nothing holds a slot or the pending count
    assert _stored_external_ids(source) == {stored: "ext-x", f"{source}-ok": "y"}
    assert processor.stats["spool_quarantined"] == 1
    assert processor.stats["spool_store_outages"] == 0
    [dead] = list((tmp_path / DEAD_DIR).glob("seg-*.jsonl"))
    text = dead.read_text()
    assert colliding in text
    assert "conflict" in text
