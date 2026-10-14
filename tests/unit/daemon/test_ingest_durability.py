"""W0.12 ingest durability in the processor: the spool is drained, replayed,
never dropped from; the backfill leaves in-flight findings alone.

Regression tests for the W4.1 chaos findings (docs/wp/w0.12.md):
pg_restart lost every acknowledged finding, a daemon kill lost the in-memory
queue, and the backfill re-triaged findings still in flight.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import pytest

from core.ingestion.handoff import envelope
from core.ingestion.spool import DEAD_DIR, IngestSpool
from services.daemon.config import ProcessingConfig
from services.daemon.processor import _SPOOL_POISON_ATTEMPTS, FindingProcessor

pytestmark = pytest.mark.unit


class _Db:
    """A findings table with an on/off switch, idempotent by finding_id."""

    def __init__(self) -> None:
        self.up = True
        self.rows: Dict[str, Dict[str, Any]] = {}
        self.inserts: List[str] = []

    def ingest_finding(self, finding: Dict[str, Any]) -> bool:
        if not self.up:
            raise ConnectionError("could not connect to server: Connection refused")
        fid = finding["finding_id"]
        if fid not in self.rows:
            self.rows[fid] = dict(finding)
            self.inserts.append(fid)
        return True

    def get_finding(self, finding_id: str):
        if not self.up:
            return None
        return self.rows.get(finding_id)


def _processor(monkeypatch, db: _Db, spool: IngestSpool) -> FindingProcessor:
    monkeypatch.setattr("services.daemon.processor._STORE_RETRY_BACKOFF", 0)
    monkeypatch.setattr("services.daemon.processor._SPOOL_BACKOFF_BASE", 0.01)
    monkeypatch.setattr("services.daemon.processor._SPOOL_BACKOFF_MAX", 0.02)
    monkeypatch.setattr("core.ingestion.ingestion_service.IngestionService", lambda: db)
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

    async def db_answers() -> bool:
        return db.up

    processor._database_answers = db_answers  # type: ignore[method-assign]
    return processor


def _open(path) -> IngestSpool:
    spool = IngestSpool(path)
    spool.open()
    return spool


async def _until(predicate, timeout: float = 10.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.02)


@pytest.mark.asyncio
async def test_database_outage_loses_no_acknowledged_finding(monkeypatch, tmp_path):
    """W4.1 pg_restart: 30/30 acknowledged findings were lost. Now 0."""
    db = _Db()
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    shutdown = asyncio.Event()
    run = asyncio.create_task(processor.run(shutdown))
    try:
        db.up = False
        ids = [f"pg-{i}" for i in range(30)]
        for fid in ids:  # what the webhook acknowledged during the outage
            spool.append([{"finding_id": fid}], "webhook")
        await asyncio.sleep(0.3)
        assert db.inserts == []
        assert len(spool) == 30
        assert processor.stats["store_dropped"] == 0

        db.up = True
        await _until(lambda: len(spool) == 0)
        assert sorted(db.inserts) == sorted(ids)  # all stored, once each
        assert processor.stats["processed"] == 30
        assert processor.stats["store_retried"] >= 1
        assert processor.stats["spool_quarantined"] == 0
    finally:
        shutdown.set()
        await run
    assert not list(tmp_path.glob("seg-*.jsonl"))


@pytest.mark.asyncio
async def test_a_killed_daemons_spool_is_replayed_once(monkeypatch, tmp_path):
    """W4.1 finding 3: queued-in-memory findings died with the daemon."""
    db = _Db()
    first = _open(tmp_path)
    first.append([{"finding_id": "k-1"}, {"finding_id": "k-2"}], "webhook")
    first.append([{"finding_id": "k-3"}], "webhook")
    # k-1 was stored before the kill but its segment was not finished.
    db.ingest_finding({"finding_id": "k-1"})
    first.close()  # SIGKILL: nothing else happens

    spool = IngestSpool(tmp_path)
    assert spool.open() == 3
    processor = _processor(monkeypatch, db, spool)
    shutdown = asyncio.Event()
    run = asyncio.create_task(processor.run(shutdown))
    try:
        await _until(lambda: len(spool) == 0)
    finally:
        shutdown.set()
        await run
    assert db.inserts == ["k-1", "k-2", "k-3"]  # no duplicate row
    # k-1 was already stored: not triaged a second time by the replay.
    assert processor.enriched == ["k-2", "k-3"]
    assert processor.stats["spool_replay_skipped"] == 1


@pytest.mark.asyncio
async def test_shutdown_mid_outage_keeps_everything_for_the_next_start(
    monkeypatch, tmp_path
):
    db = _Db()
    db.up = False
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    shutdown = asyncio.Event()
    run = asyncio.create_task(processor.run(shutdown))
    spool.append([{"finding_id": f"s-{i}"} for i in range(5)], "webhook")
    await asyncio.sleep(0.2)
    shutdown.set()
    await run
    spool.close()

    again = IngestSpool(tmp_path)
    assert again.open() == 5


@pytest.mark.asyncio
async def test_a_finding_the_store_refuses_is_quarantined_not_dropped(
    monkeypatch, tmp_path
):
    db = _Db()

    def refuse(finding):
        if finding["finding_id"] == "poison":
            return False  # e.g. a row the database rejects every time
        return _Db.ingest_finding(db, finding)

    db.ingest_finding = refuse  # type: ignore[method-assign]
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    spool.append([{"finding_id": "poison"}, {"finding_id": "fine"}], "webhook")
    for _ in range(_SPOOL_POISON_ATTEMPTS + 2):
        for entry in spool.claim(10):
            item = envelope(entry.finding, entry.source)
            item["spool"] = entry
            await processor._process_item(item)
        if len(spool) == 0:
            break
    assert len(spool) == 0
    assert db.inserts == ["fine"]
    assert processor.stats["spool_quarantined"] == 1
    [dead] = list((tmp_path / DEAD_DIR).glob("seg-*.jsonl"))
    assert '"poison"' in dead.read_text()


@pytest.mark.asyncio
async def test_no_quarantine_while_the_database_is_down(monkeypatch, tmp_path):
    db = _Db()
    db.up = False
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    spool.append([{"finding_id": "x"}], "webhook")
    for _ in range(_SPOOL_POISON_ATTEMPTS * 3):
        [entry] = spool.claim(1)
        await processor._process_item(
            {**envelope(entry.finding, "webhook"), "spool": entry}
        )
    assert len(spool) == 1
    assert processor.stats["spool_quarantined"] == 0


@pytest.mark.asyncio
async def test_cancelled_mid_store_gives_the_entry_back(monkeypatch, tmp_path):
    db = _Db()
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    started = asyncio.Event()

    async def hang(_finding):
        started.set()
        await asyncio.sleep(3600)

    processor._store_with_retry = hang  # type: ignore[method-assign]
    spool.append([{"finding_id": "c"}], "webhook")
    [entry] = spool.claim(1)
    task = asyncio.create_task(
        processor._process_item({**envelope(entry.finding, "webhook"), "spool": entry})
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert [e.finding_id for e in spool.claim(1)] == ["c"]
    assert not processor._inflight


# -- backfill (W4.1 finding 5) ---------------------------------------------------


class _Sweep:
    def __init__(self, rows):
        self.rows = rows

    def get_findings_missing_enrichment(self, limit, max_age_hours):
        return list(self.rows)


@pytest.mark.asyncio
async def test_backfill_skips_findings_in_flight(monkeypatch):
    processor = FindingProcessor(
        ProcessingConfig(
            auto_triage_enabled=True,
            auto_enrich_enabled=False,
            enrich_backfill_interval=0,
        )
    )
    processor._data_service = _Sweep([{"finding_id": "busy"}, {"finding_id": "idle"}])
    processor._settling_decisions = lambda ids, tenant: {}
    spawned: List[str] = []
    shutdown = asyncio.Event()

    async def spawn(finding, source=None):
        spawned.append(finding["finding_id"])
        shutdown.set()

    processor._spawn_enrich = spawn  # type: ignore[method-assign]
    processor._inflight["busy"] += 1  # waiting on the model right now

    await asyncio.wait_for(processor._backfill_loop(shutdown), timeout=10)

    assert spawned == ["idle"]
    assert processor.stats["backfill_skipped_inflight"] >= 1


@pytest.mark.asyncio
async def test_inflight_lasts_until_the_enrich_task_ends(monkeypatch):
    processor = FindingProcessor(
        ProcessingConfig(auto_triage_enabled=False, auto_enrich_enabled=False)
    )
    release = asyncio.Event()

    async def slow(finding, source=None):
        await release.wait()

    processor._enrich_in_background = slow  # type: ignore[method-assign]
    await processor._spawn_enrich({"finding_id": "t"}, "webhook")
    assert processor._inflight["t"] == 1
    release.set()
    await asyncio.gather(*list(processor._enrich_tasks))
    await asyncio.sleep(0)
    assert "t" not in processor._inflight


# -- the daemon opens the spool (leader only) -----------------------------------


def _daemon(spool_cfg):
    from services.daemon.config import DaemonConfig
    from services.daemon.main import SOCDaemon

    daemon = SOCDaemon.__new__(SOCDaemon)
    daemon.config = DaemonConfig()
    daemon.config.spool = spool_cfg
    return daemon


@pytest.mark.asyncio
async def test_daemon_opens_the_spool_and_replays(tmp_path):
    from services.daemon.config import IngestSpoolConfig

    left = _open(tmp_path / "spool")
    left.append([{"finding_id": "left-over"}], "webhook")
    left.close()

    daemon = _daemon(
        IngestSpoolConfig(directory=str(tmp_path / "spool"), max_findings=9)
    )
    spool = await daemon._open_spool()
    try:
        assert spool is not None and spool.is_open
        assert spool.max_findings == 9
        assert [e.finding_id for e in spool.claim(5)] == ["left-over"]
    finally:
        spool.close()


@pytest.mark.asyncio
async def test_daemon_without_a_usable_spool_falls_back_to_ack_on_store(tmp_path):
    from services.daemon.config import IngestSpoolConfig

    held = _open(tmp_path)  # another live process owns this directory
    try:
        daemon = _daemon(IngestSpoolConfig(directory=str(tmp_path)))
        assert await daemon._open_spool() is None
    finally:
        held.close()
    assert await _daemon(IngestSpoolConfig(enabled=False))._open_spool() is None


def test_default_directory_is_under_the_state_directory(monkeypatch, tmp_path):
    from services.daemon.config import IngestSpoolConfig

    monkeypatch.setenv("VIGIL_DIR", str(tmp_path))
    assert IngestSpoolConfig().resolved_directory() == tmp_path / "spool" / "webhook"
    assert IngestSpoolConfig(directory="/x/y").resolved_directory().as_posix() == "/x/y"


def test_settings_reach_the_config(monkeypatch):
    from core.config import get_settings
    from services.daemon.config import DaemonConfig

    monkeypatch.setenv("DAEMON_INGEST_SPOOL_ENABLED", "false")
    monkeypatch.setenv("DAEMON_INGEST_SPOOL_DIR", "/data/spool")
    monkeypatch.setenv("DAEMON_INGEST_SPOOL_MAX_FINDINGS", "123")
    monkeypatch.setenv("DAEMON_INGEST_SPOOL_MAX_MB", "7")
    get_settings.cache_clear()
    try:
        cfg = DaemonConfig.from_env().spool
    finally:
        get_settings.cache_clear()
    assert (cfg.enabled, cfg.directory, cfg.max_findings, cfg.max_mb) == (
        False,
        "/data/spool",
        123,
        7,
    )


def test_a_standby_reports_its_waiting_spool_without_opening_it(tmp_path, caplog):
    import logging

    from services.daemon.config import IngestSpoolConfig

    held = _open(tmp_path)
    held.append([{"finding_id": "w"}], "webhook")
    daemon = _daemon(IngestSpoolConfig(directory=str(tmp_path)))
    caplog.set_level(logging.WARNING)
    daemon._report_waiting_spool()
    held.close()
    assert "1 ingest spool segment(s) on this pod wait until it leads" in caplog.text
