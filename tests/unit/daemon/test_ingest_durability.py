"""W0.12 ingest durability in the processor: the spool is drained, replayed,
never dropped from; the backfill leaves in-flight findings alone.

Regression tests for the W4.1 chaos findings (docs/wp/w0.12.md):
pg_restart lost every acknowledged finding, a daemon kill lost the in-memory
queue, and the backfill re-triaged findings still in flight.
"""

from __future__ import annotations

import asyncio
import os
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from core.exceptions import default_on_error
from core.ingestion.handoff import envelope
from core.ingestion.ingestion_service import IngestionService
from core.ingestion.spool import DEAD_DIR, IngestSpool
from services.daemon.config import ProcessingConfig
from services.daemon.processor import _SPOOL_POISON_ATTEMPTS, FindingProcessor

pytestmark = pytest.mark.unit


class _PgError(Exception):
    """A driver error carrying its SQLSTATE, as psycopg does."""

    def __init__(self, message: str, sqlstate: str) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


class _Db:
    """A findings table with an on/off switch, idempotent by finding_id.

    Used as the DatabaseService behind a real ``IngestionService``: its
    methods are wrapped in ``@default_on_error`` like the real ones, so an
    error reads as "not found"/"not created" unless the store unwraps them.
    """

    def __init__(self) -> None:
        self.up = True
        self.rows: Dict[str, Dict[str, Any]] = {}
        self.inserts: List[str] = []
        # The database answers but refuses every write with this.
        self.reject: Optional[Exception] = None
        # Per-finding write refusals (a row the database rejects).
        self.refuse: Dict[str, Exception] = {}
        # The next N lookups fail (a blip, a pool timeout).
        self.lookup_failures = 0

    @default_on_error(None)
    def get_finding(self, finding_id: str):
        if not self.up:
            raise ConnectionError("could not connect to server: Connection refused")
        if self.lookup_failures:
            self.lookup_failures -= 1
            raise _PgError("canceling statement due to statement timeout", "57014")
        row = self.rows.get(finding_id)
        return SimpleNamespace(**row) if row is not None else None

    @default_on_error(None)
    def get_finding_by_external_id(self, data_source: str, external_id: str):
        return None

    @default_on_error(None)
    def create_finding(self, finding_id: str, **_kw):
        if not self.up:
            raise ConnectionError("could not connect to server: Connection refused")
        if self.reject is not None:
            raise self.reject
        if finding_id in self.refuse:
            raise self.refuse[finding_id]
        if finding_id in self.rows:
            raise _PgError("duplicate key value", "23505")
        self.rows[finding_id] = {"finding_id": finding_id, "ai_enrichment": None}
        self.inserts.append(finding_id)
        return self.rows[finding_id]

    def store(self, finding_id: str, *, triaged: bool) -> None:
        """A row the previous process stored (and maybe triaged)."""
        self.rows[finding_id] = {
            "finding_id": finding_id,
            "ai_enrichment": {"ai_triage": {"verdict": "x"}} if triaged else None,
        }
        self.inserts.append(finding_id)


def _ingestion(db: _Db) -> IngestionService:
    service = IngestionService.__new__(IngestionService)
    service.use_database = True
    service.db_service = db
    service.stats = {
        "findings_imported": 0,
        "findings_skipped": 0,
        "findings_errors": 0,
    }
    return service


def _processor(monkeypatch, db: _Db, spool: IngestSpool) -> FindingProcessor:
    monkeypatch.setattr("services.daemon.processor._STORE_RETRY_BACKOFF", 0)
    monkeypatch.setattr("services.daemon.processor._SPOOL_BACKOFF_BASE", 0.01)
    monkeypatch.setattr("services.daemon.processor._SPOOL_BACKOFF_MAX", 0.02)
    service = _ingestion(db)
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
    processor._settling_decisions = lambda ids, tenant: {}  # no decision recorded
    processor.attach_spool(spool)
    enriched: List[str] = []

    async def spawn(finding, source=None):
        fid = finding["finding_id"]
        enriched.append(fid)
        if fid in db.rows:  # the triage this run writes back
            db.rows[fid]["ai_enrichment"] = {"ai_triage": {"verdict": "x"}}

    processor._spawn_enrich = spawn  # type: ignore[method-assign]
    processor.enriched = enriched  # type: ignore[attr-defined]

    async def db_answers() -> bool:
        return db.up

    processor._database_answers = db_answers  # type: ignore[method-assign]
    return processor


async def _drain_once(processor: FindingProcessor, spool: IngestSpool) -> None:
    for entry in spool.claim(100):
        item = envelope(entry.finding, entry.source)
        item["spool"] = entry
        await processor._process_item(item)


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
    # k-1 was stored and triaged before the kill, but the kill came before
    # its spool entry was marked done.
    db.store("k-1", triaged=True)
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

    # A row the database rejects every time (invalid byte sequence).
    db.refuse["poison"] = _PgError("invalid byte sequence for encoding", "22021")
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

    processor._store_spooled = hang  # type: ignore[method-assign]
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


# -- W0.12b: replay never triages twice; write rejection is an outage ---------


@pytest.mark.asyncio
async def test_replay_triages_only_what_the_killed_daemon_had_not_stored(
    monkeypatch, tmp_path
):
    """Verifier probe: x1 stored + done before the kill; replay enriches x2 only."""
    db = _Db()
    first = _open(tmp_path)
    first.append([{"finding_id": "x1"}, {"finding_id": "x2"}], "webhook")
    processor = _processor(monkeypatch, db, first)
    [x1, _x2] = first.claim(2)
    first.release(_x2)
    await processor._process_item({**envelope(x1.finding, "webhook"), "spool": x1})
    assert processor.enriched == ["x1"]
    first.close()  # SIGKILL with x2 still in the half-done segment

    spool = IngestSpool(tmp_path)
    assert spool.open() == 1  # x1 is marked done, not replayed
    again = _processor(monkeypatch, db, spool)
    await _drain_once(again, spool)
    assert again.enriched == ["x2"]
    assert db.inserts == ["x1", "x2"]
    assert len(spool) == 0
    assert not list(tmp_path.glob("seg-*"))  # segment and its done marks gone


@pytest.mark.asyncio
async def test_a_lookup_error_on_replay_is_a_retry_not_a_second_triage(
    monkeypatch, tmp_path
):
    """W0.12 replay asked DatabaseDataService.get_finding, which answers None
    on an error (and for 10 s after one); the store then said "already
    exists" and the finding was triaged again."""
    db = _Db()
    first = _open(tmp_path)
    first.append([{"finding_id": "y"}], "webhook")
    db.store("y", triaged=True)  # stored + triaged, killed before done
    first.close()

    spool = IngestSpool(tmp_path)
    assert spool.open() == 1
    processor = _processor(monkeypatch, db, spool)
    db.lookup_failures = 2  # the first lookups time out
    await _drain_once(processor, spool)
    assert len(spool) == 0
    assert processor.enriched == []
    assert processor.stats["spool_replay_skipped"] == 1
    assert processor.stats["spool_quarantined"] == 0
    assert db.inserts == ["y"]


@pytest.mark.asyncio
async def test_a_stored_but_untriaged_finding_is_triaged_once(monkeypatch, tmp_path):
    db = _Db()
    db.store("u", triaged=False)  # killed between the store and the triage
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    spool.append([{"finding_id": "u"}], "webhook")
    await _drain_once(processor, spool)
    assert processor.enriched == ["u"]
    assert processor.stats["spool_existing_enriched"] == 1

    spool.append([{"finding_id": "u"}], "webhook")  # a resend: now triaged
    await _drain_once(processor, spool)
    assert processor.enriched == ["u"]
    assert processor.stats["spool_replay_skipped"] == 1


@pytest.mark.asyncio
async def test_a_replayed_finding_a_recorded_decision_settled_is_not_routed(
    monkeypatch, tmp_path
):
    """W0.15 round 2: the spool replay applies the backfill's settled check."""
    from core.lanes.alert_lanes import LANE_RULES, LaneDecision

    db = _Db()
    db.store("s", triaged=False)  # decided (rules), killed before the write
    db.store("u", triaged=False)  # no decision recorded: triaged as before
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    asked = []

    def lookup(ids, tenant):
        asked.append(list(ids))
        return {
            i: LaneDecision(
                finding_id=i, tenant_id=tenant, lane=LANE_RULES, reason="r", risk=0.1
            )
            for i in ids
            if i == "s"
        }

    processor._settling_decisions = lookup
    spool.append([{"finding_id": "s"}, {"finding_id": "u"}], "webhook")
    await _drain_once(processor, spool)
    assert processor.enriched == ["u"]
    assert sorted(asked) == [["s"], ["u"]]
    assert processor.stats["spool_replay_settled"] == 1
    assert processor.stats["spool_existing_enriched"] == 1
    assert len(spool) == 0


@pytest.mark.asyncio
async def test_a_replay_leaves_an_unknown_decision_to_the_backfill(
    monkeypatch, tmp_path
):
    db = _Db()
    db.store("q", triaged=False)
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)

    def down(ids, tenant):
        raise ConnectionError("database unavailable")

    processor._settling_decisions = down
    spool.append([{"finding_id": "q"}], "webhook")
    await _drain_once(processor, spool)
    # Backfill off (this helper): routed as before rather than never.
    assert processor.enriched == ["q"]

    db.store("p", triaged=False)
    processor.config.enrich_backfill_enabled = True
    processor.config.auto_triage_enabled = True
    spool.append([{"finding_id": "p"}], "webhook")
    await _drain_once(processor, spool)
    assert processor.enriched == ["q"]  # the backfill looks again
    assert processor.stats["spool_replay_settled"] == 1


@pytest.mark.asyncio
async def test_a_stored_finding_being_triaged_here_is_not_triaged_again(
    monkeypatch, tmp_path
):
    db = _Db()
    db.store("busy", triaged=False)
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    processor._inflight["busy"] += 1  # its triage is running right now
    spool.append([{"finding_id": "busy"}], "webhook")
    await _drain_once(processor, spool)
    assert processor.enriched == []
    assert len(spool) == 0


def _wrapped(sqlstate: str, message: str) -> Exception:
    from sqlalchemy.exc import OperationalError

    return OperationalError("INSERT INTO findings", {}, _PgError(message, sqlstate))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        _PgError("cannot execute INSERT in a read-only transaction", "25006"),
        _PgError('could not extend file "base/1/2": No space left on device', "53100"),
        _PgError("permission denied for table findings", "42501"),
        _wrapped("25006", "cannot execute INSERT in a read-only transaction"),
        RuntimeError("cannot execute INSERT in a read-only transaction"),
    ],
    ids=["read-only", "disk-full", "permission", "wrapped-read-only", "no-sqlstate"],
)
async def test_a_database_that_rejects_writes_is_an_outage_not_poison(
    monkeypatch, tmp_path, error
):
    """W0.12 quarantined everything after 5 tries when the database answered
    SELECT 1 but refused writes (read-only after a failover, disk full)."""
    db = _Db()
    db.reject = error  # up: SELECT 1 and lookups answer
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    spool.append([{"finding_id": "a"}, {"finding_id": "b"}], "webhook")
    for _ in range(_SPOOL_POISON_ATTEMPTS * 3):
        await _drain_once(processor, spool)
    assert len(spool) == 2
    assert processor.stats["spool_quarantined"] == 0
    assert processor.stats["spool_store_outages"] >= _SPOOL_POISON_ATTEMPTS * 3
    assert not (tmp_path / DEAD_DIR).exists()

    db.reject = None  # the primary is back
    await _drain_once(processor, spool)
    assert len(spool) == 0
    assert sorted(db.inserts) == ["a", "b"]
    assert sorted(processor.enriched) == ["a", "b"]


@pytest.mark.asyncio
async def test_quarantine_needs_the_findings_own_error(monkeypatch, tmp_path):
    """A data error quarantines only the finding it is about."""
    db = _Db()
    db.refuse["bad"] = _PgError("value too long for type character varying", "22001")
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    spool.append([{"finding_id": "bad"}, {"finding_id": "ok"}], "webhook")
    for _ in range(_SPOOL_POISON_ATTEMPTS):
        await _drain_once(processor, spool)
    assert len(spool) == 0
    assert db.inserts == ["ok"]
    [dead] = list((tmp_path / DEAD_DIR).glob("seg-*.jsonl"))
    assert "22001" not in dead.name
    assert '"bad"' in dead.read_text()
    assert os.stat(dead).st_mode & 0o777 == 0o600


@pytest.mark.asyncio
async def test_a_unique_violation_the_retry_does_not_resolve_is_quarantined(
    monkeypatch, tmp_path
):
    """Round 6: 23505 was always an outage, assuming the retry finds the row.
    One it never finds (a lookup that misses it) held its spool slot forever,
    kept the pending count from draining and paused the feeder."""
    db = _Db()
    db.refuse["dup"] = _PgError(
        'duplicate key value violates unique constraint "uniq_findings_source_extid"',
        "23505",
    )
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    spool.append([{"finding_id": "dup"}, {"finding_id": "ok"}], "webhook")
    for _ in range(_SPOOL_POISON_ATTEMPTS):
        await _drain_once(processor, spool)
    assert len(spool) == 0
    assert db.inserts == ["ok"]
    assert processor.stats["spool_quarantined"] == 1
    assert processor.stats["spool_store_outages"] == 0
    [dead] = list((tmp_path / DEAD_DIR).glob("seg-*.jsonl"))
    assert '"dup"' in dead.read_text()


@pytest.mark.asyncio
async def test_a_unique_violation_from_a_race_stores_nothing_twice(
    monkeypatch, tmp_path
):
    """The race 23505 used to be an outage for: a concurrent insert of the same
    finding. The in-place retry sees the row, so it is not quarantined."""
    db = _Db()
    real_create = db.create_finding

    def racing_create(finding_id: str, **kw):
        if finding_id not in db.rows:  # the other writer wins the race
            db.store(finding_id, triaged=True)
            raise _PgError("duplicate key value", "23505")
        return real_create(finding_id, **kw)

    db.create_finding = racing_create  # type: ignore[method-assign]
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    spool.append([{"finding_id": "r"}], "webhook")
    await _drain_once(processor, spool)
    assert len(spool) == 0
    assert db.inserts == ["r"]
    assert processor.stats["spool_quarantined"] == 0
    assert processor.stats["spool_replay_skipped"] == 1
    assert processor.enriched == []


@pytest.mark.asyncio
async def test_a_triage_that_ends_while_replay_looks_is_not_repeated(
    monkeypatch, tmp_path
):
    """Round 6 (INFO): the backfill's triage of a stored, untriaged finding
    ended between the replay's "not triaged" read and its in-flight check; the
    replay then triaged it a second time."""
    import time as _time

    from services.daemon.processor import BACKFILL_SOURCE

    class _SlowDb(_Db):
        armed = False

        @default_on_error(None)
        def get_finding(self, finding_id: str):
            row = self.rows.get(finding_id)
            snapshot = SimpleNamespace(**row) if row is not None else None
            if self.armed:  # the replay's read: then the backfill triage ends
                self.armed = False
                loop.call_soon_threadsafe(gate.set)
                deadline = _time.monotonic() + 10
                while finding_id not in processor._enrich_ended:
                    assert _time.monotonic() < deadline, "triage never ended"
                    _time.sleep(0.01)
            return snapshot

    loop = asyncio.get_running_loop()
    gate = asyncio.Event()
    db = _SlowDb()
    db.store("x", triaged=False)
    spool = _open(tmp_path)
    processor = _processor(monkeypatch, db, spool)
    # The real spawn (in-flight and ended bookkeeping), a stub triage.
    processor._spawn_enrich = FindingProcessor._spawn_enrich.__get__(processor)
    triaged: List[str] = []

    async def triage(finding, source=None):
        await gate.wait()
        triaged.append(source)
        db.rows[finding["finding_id"]]["ai_enrichment"] = {"ai_triage": {}}

    processor._enrich_in_background = triage  # type: ignore[method-assign]

    await processor._spawn_enrich({"finding_id": "x"}, BACKFILL_SOURCE)
    spool.append([{"finding_id": "x"}], "webhook")  # a replay of the same one
    db.armed = True
    await _drain_once(processor, spool)
    await asyncio.gather(*list(processor._enrich_tasks))

    assert triaged == [BACKFILL_SOURCE]  # once, not again by the replay
    assert len(spool) == 0
    assert processor.stats["spool_replay_skipped"] == 1


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
    # W0.12b: alertable while standby, cleared once the pod leads.
    from core.ingestion.spool import standby_pending

    assert standby_pending() == 1
    daemon._stop_watching_spool()
    assert standby_pending() == 0
    assert "1 ingest spool segment(s) (1 finding(s)) on this pod wait" in caplog.text
