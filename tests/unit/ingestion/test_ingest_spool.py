"""The webhook's durable ingest spool (W0.12, core/ingestion/spool.py)."""

from __future__ import annotations

import json
import os

import pytest

from core.ingestion.spool import (
    CORRUPT_DIR,
    DEAD_DIR,
    IngestSpool,
    SpoolError,
    SpoolFull,
)

pytestmark = pytest.mark.unit


def _spool(path, **kw) -> IngestSpool:
    spool = IngestSpool(path, **kw)
    spool.open()
    return spool


def _segments(path):
    return sorted(p.name for p in path.glob("seg-*.jsonl"))


def test_append_is_on_disk_before_it_returns(tmp_path):
    spool = _spool(tmp_path)
    taken = spool.append([{"finding_id": "a"}, {"finding_id": "b"}], "webhook")
    assert taken == ["a", "b"]
    [segment] = _segments(tmp_path)
    lines = (tmp_path / segment).read_text().splitlines()
    assert json.loads(lines[0])["spool"] == 1
    assert [json.loads(line)["id"] for line in lines[1:]] == ["a", "b"]
    assert not list(tmp_path.glob("*.tmp"))
    assert len(spool) == 2


def test_append_fsyncs_file_and_directory(tmp_path, monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: synced.append(fd) or real(fd))
    spool = _spool(tmp_path)
    spool.append([{"finding_id": "a"}], "webhook")
    assert len(synced) >= 2  # the segment, then its directory


def test_restart_replays_what_was_not_done_and_nothing_else(tmp_path):
    spool = _spool(tmp_path)
    spool.append([{"finding_id": "a"}, {"finding_id": "b"}], "webhook")
    spool.append([{"finding_id": "c"}], "webhook")
    first = spool.claim(10)
    spool.done(first[0])  # a stored
    spool.done(first[2])  # c stored: its segment is gone
    assert len(_segments(tmp_path)) == 1
    spool.close()  # a crash: b was acknowledged, never stored

    again = IngestSpool(tmp_path)
    assert again.open() == 2  # the whole first segment: a (stored) and b
    entries = again.claim(10)
    assert [e.finding_id for e in entries] == ["a", "b"]
    assert all(e.replayed for e in entries)
    assert again.stats["replayed"] == 2


def test_duplicate_ids_are_spooled_once(tmp_path):
    spool = _spool(tmp_path)
    assert spool.append([{"finding_id": "a"}, {"finding_id": "a"}], "webhook") == ["a"]
    assert spool.append([{"finding_id": "a"}], "webhook") == []
    assert spool.contains("a")
    [entry] = spool.claim(5)
    spool.done(entry)
    assert not spool.contains("a")
    assert spool.append([{"finding_id": "a"}], "webhook") == ["a"]


def test_bounded_by_count_all_or_nothing(tmp_path):
    spool = _spool(tmp_path, max_findings=2)
    spool.append([{"finding_id": "a"}], "webhook")
    with pytest.raises(SpoolFull):
        spool.append([{"finding_id": "b"}, {"finding_id": "c"}], "webhook")
    assert len(spool) == 1
    assert len(_segments(tmp_path)) == 1
    assert spool.stats["rejected_full"] == 1
    # Room again once the processor stores one.
    [entry] = spool.claim(1)
    spool.done(entry)
    assert spool.append([{"finding_id": "b"}, {"finding_id": "c"}], "webhook")


def test_bounded_by_bytes(tmp_path):
    spool = _spool(tmp_path, max_bytes=200)
    with pytest.raises(SpoolFull):
        spool.append([{"finding_id": "big", "description": "x" * 500}], "webhook")
    assert len(spool) == 0


def test_a_failed_write_spools_nothing(tmp_path, monkeypatch):
    spool = _spool(tmp_path)

    def broken(fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fsync", broken)
    with pytest.raises(SpoolError):
        spool.append([{"finding_id": "a"}], "webhook")
    assert len(spool) == 0
    assert not _segments(tmp_path)
    assert not list(tmp_path.glob("*.tmp"))


def test_one_process_per_directory(tmp_path):
    _spool(tmp_path)
    with pytest.raises(SpoolError, match="in use"):
        IngestSpool(tmp_path).open()


def test_closed_spool_refuses_writes(tmp_path):
    spool = IngestSpool(tmp_path)
    with pytest.raises(SpoolError):
        spool.append([{"finding_id": "a"}], "webhook")


def test_release_puts_an_entry_back_first(tmp_path):
    spool = _spool(tmp_path)
    spool.append([{"finding_id": "a"}, {"finding_id": "b"}], "webhook")
    a, b = spool.claim(10)
    assert spool.claim(10) == []
    spool.release(b)
    spool.release(a)
    assert [e.finding_id for e in spool.claim(10)] == ["a", "b"]


def test_quarantine_keeps_the_finding_in_a_replayable_file(tmp_path):
    spool = _spool(tmp_path)
    spool.append([{"finding_id": "bad", "x": 1}], "webhook")
    [entry] = spool.claim(1)
    spool.quarantine(entry, "store refused")
    assert len(spool) == 0
    assert not _segments(tmp_path)
    [dead] = list((tmp_path / DEAD_DIR).glob("seg-*.jsonl"))
    spool.close()
    # The documented recovery: move it back, it replays on the next open.
    os.replace(dead, tmp_path / dead.name)
    again = IngestSpool(tmp_path)
    assert again.open() == 1
    assert again.claim(1)[0].finding == {"finding_id": "bad", "x": 1}


def test_a_corrupt_segment_is_set_aside_not_deleted(tmp_path):
    (tmp_path / "seg-00000000000000000001-1-00000001.jsonl").write_text("{not json\n")
    (tmp_path / "seg-00000000000000000002-1-00000002.jsonl.tmp").write_text("partial")
    spool = IngestSpool(tmp_path)
    assert spool.open() == 0
    assert spool.stats["corrupt_segments"] == 1
    assert list((tmp_path / CORRUPT_DIR).iterdir())
    assert not list(tmp_path.glob("*.tmp"))  # never acknowledged


def test_on_ready_is_called_after_append(tmp_path):
    spool = _spool(tmp_path)
    calls = []
    spool.on_ready = lambda: calls.append(1)
    spool.append([{"finding_id": "a"}], "webhook")
    assert calls == [1]


def test_snapshot(tmp_path):
    spool = _spool(tmp_path, max_findings=7)
    spool.append([{"finding_id": "a"}], "webhook")
    snap = spool.snapshot()
    assert snap["pending"] == 1
    assert snap["segments"] == 1
    assert snap["max_findings"] == 7
    assert snap["appended"] == 1
    assert snap["pending_bytes"] > 0


def test_waiting_segments_counts_without_opening(tmp_path):
    from core.ingestion.spool import waiting_segments

    assert waiting_segments(tmp_path / "missing") == 0
    spool = _spool(tmp_path)
    spool.append([{"finding_id": "a"}], "webhook")
    spool.append([{"finding_id": "b"}], "webhook")
    assert waiting_segments(tmp_path) == 2
