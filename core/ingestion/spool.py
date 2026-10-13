"""A durable local spool for findings the daemon webhook acknowledges (W0.12).

The webhook answers 200 only after every finding of the request is on disk
here: one segment file per request, written to a temporary name, fsync'd,
renamed into place and the directory fsync'd. The processor takes entries from
the spool (never from the request), and an entry leaves the spool only once
its row is stored (``done``) or it is set aside as unstorable
(``quarantine``). What a killed or restarted daemon had not stored yet is
loaded again by ``open`` and replayed; the store is idempotent by
``finding_id`` (and ``(data_source, external_id)``), so a replayed finding
that had been stored before the crash makes no second row.

Bounded: when ``max_findings`` or ``max_bytes`` would be exceeded ``append``
raises :class:`SpoolFull` and the webhook answers 503 + ``Retry-After``; the
sender keeps the finding and retries.

One process per directory: ``open`` takes an exclusive ``flock`` on
``.lock``, so a demoted leader that is still alive and a new process on the
same volume never share a spool.

Segment format (JSON lines, UTF-8)::

    {"spool": 1, "source": "webhook", "created": "<iso>"}      # header
    {"id": "<finding_id>", "finding": {...}}                    # one per finding

A quarantined entry is written in the same format under ``dead/``; moving
such a file back into the spool directory replays it on the next start.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional

from core.time import utcnow

logger = logging.getLogger(__name__)

SPOOL_FORMAT = 1
_SEGMENT_PREFIX = "seg-"
_SEGMENT_SUFFIX = ".jsonl"
_TMP_SUFFIX = ".tmp"
DEAD_DIR = "dead"
CORRUPT_DIR = "corrupt"


class SpoolError(Exception):
    """The spool cannot take this write (unavailable, I/O error)."""


class SpoolFull(SpoolError):
    """Accepting the write would exceed the spool's bounds."""


@dataclass(eq=False)
class SpoolEntry:
    """One spooled finding. ``replayed``: loaded from disk at ``open``."""

    segment: str
    index: int
    finding_id: str
    source: str
    finding: Dict[str, Any]
    size: int
    replayed: bool = False
    failures: int = 0
    # Store failures seen while the database answered (poison detection).
    reachable_failures: int = 0
    claimed: bool = field(default=False, repr=False)

    @property
    def key(self) -> str:
        return f"{self.segment}:{self.index}"


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError as e:  # some filesystems refuse a directory fsync
        if e.errno not in (errno.EINVAL, errno.EBADF):
            raise
    finally:
        os.close(fd)


class IngestSpool:
    """Append-only, fsync'd, bounded spool of findings awaiting their store."""

    def __init__(
        self,
        directory: Path | str,
        *,
        max_findings: int = 10_000,
        max_bytes: int = 256 * 1024 * 1024,
        fsync: bool = True,
    ) -> None:
        if max_findings < 1 or max_bytes < 1:
            raise ValueError("spool bounds must be positive")
        self.directory = Path(directory)
        self.max_findings = int(max_findings)
        self.max_bytes = int(max_bytes)
        self._fsync = fsync
        self._lock = threading.Lock()
        self._lock_fd: Optional[int] = None
        self._pending: Dict[str, SpoolEntry] = {}
        self._ready: Deque[SpoolEntry] = deque()
        self._ids: Counter = Counter()
        self._remaining: Dict[str, int] = {}
        self._bytes = 0
        self._seq = 0
        # Called (from any thread) after an append makes entries ready.
        self.on_ready: Optional[Callable[[], None]] = None
        self.stats: Dict[str, int] = {
            "appended": 0,
            "replayed": 0,
            "done": 0,
            "rejected_full": 0,
            "rejected_error": 0,
            "quarantined": 0,
            "corrupt_segments": 0,
        }

    # -- lifecycle -----------------------------------------------------------

    @property
    def is_open(self) -> bool:
        return self._lock_fd is not None

    def open(self) -> int:
        """Lock the directory and load what a previous process left; returns
        the number of findings loaded for replay. Raises :class:`SpoolError`."""
        import fcntl

        try:
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.directory / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as e:
            raise SpoolError(f"spool directory {self.directory}: {e}") from e
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            os.close(fd)
            raise SpoolError(
                f"spool directory {self.directory} is in use by another process"
            ) from e
        self._lock_fd = fd
        try:
            loaded = self._load()
        except Exception:
            self.close()
            raise
        if loaded:
            logger.warning(
                "Ingest spool %s: %d finding(s) acknowledged but not stored before "
                "the last stop; replaying them",
                self.directory,
                loaded,
            )
        return loaded

    def close(self) -> None:
        fd, self._lock_fd = self._lock_fd, None
        if fd is not None:
            try:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _load(self) -> int:
        for stray in self.directory.glob(f"*{_TMP_SUFFIX}"):
            # Never renamed into place: its request was never acknowledged.
            stray.unlink(missing_ok=True)
        loaded = 0
        segments = sorted(
            p
            for p in self.directory.glob(f"{_SEGMENT_PREFIX}*{_SEGMENT_SUFFIX}")
            if p.is_file()
        )
        for path in segments:
            entries = self._read_segment(path)
            if entries is None:
                continue
            if not entries:
                path.unlink(missing_ok=True)
                continue
            self._register(path.name, entries)
            loaded += len(entries)
        self.stats["replayed"] += loaded
        self._seq = len(segments)
        return loaded

    def _read_segment(self, path: Path) -> Optional[List[SpoolEntry]]:
        try:
            raw = path.read_bytes()
            lines = raw.decode("utf-8").splitlines()
            header = json.loads(lines[0]) if lines else {}
            if header.get("spool") != SPOOL_FORMAT:
                raise ValueError(f"unknown spool format {header.get('spool')!r}")
            source = str(header.get("source") or "webhook")
            entries = []
            for index, line in enumerate(lines[1:]):
                record = json.loads(line)
                finding = record["finding"]
                if not isinstance(finding, dict):
                    raise ValueError("finding is not an object")
                entries.append(
                    SpoolEntry(
                        segment=path.name,
                        index=index,
                        finding_id=str(record["id"]),
                        source=source,
                        finding=finding,
                        size=len(line.encode("utf-8")) + 1,
                        replayed=True,
                    )
                )
            return entries
        except Exception as e:  # noqa: BLE001 - keep the bytes, skip the file
            corrupt = self.directory / CORRUPT_DIR
            corrupt.mkdir(exist_ok=True)
            os.replace(path, corrupt / path.name)
            self.stats["corrupt_segments"] += 1
            logger.error(
                "Ingest spool segment %s is unreadable (%s); moved to %s",
                path.name,
                e,
                corrupt,
            )
            return None

    # -- writes --------------------------------------------------------------

    def append(self, findings: Iterable[Dict[str, Any]], source: str) -> List[str]:
        """Durably spool ``findings``; returns the ids taken.

        A finding whose id is already pending here is skipped (not an error).
        All-or-nothing: on :class:`SpoolFull` / :class:`SpoolError` nothing of
        this call is spooled.
        """
        with self._lock:
            if not self.is_open:
                self.stats["rejected_error"] += 1
                raise SpoolError("spool is not open")
            batch: List[tuple] = []
            seen: set = set()
            for finding in findings:
                finding_id = str(finding.get("finding_id") or "")
                if not finding_id or finding_id in seen or self._ids[finding_id]:
                    continue
                seen.add(finding_id)
                line = json.dumps(
                    {"id": finding_id, "finding": finding},
                    ensure_ascii=False,
                    separators=(",", ":"),
                    default=str,
                )
                batch.append((finding_id, finding, line))
            if not batch:
                return []
            size = sum(len(line.encode("utf-8")) + 1 for _, _, line in batch)
            if (
                len(self._pending) + len(batch) > self.max_findings
                or self._bytes + size > self.max_bytes
            ):
                self.stats["rejected_full"] += 1
                raise SpoolFull(
                    f"spool full ({len(self._pending)} finding(s), "
                    f"{self._bytes} bytes pending)"
                )
            self._seq += 1
            name = (
                f"{_SEGMENT_PREFIX}{time.time_ns():020d}-{os.getpid()}-"
                f"{self._seq:08d}{_SEGMENT_SUFFIX}"
            )
            header = json.dumps(
                {
                    "spool": SPOOL_FORMAT,
                    "source": source,
                    "created": utcnow().isoformat(),
                }
            )
            body = header + "\n" + "".join(line + "\n" for _, _, line in batch)
            try:
                self._write_atomic(name, body.encode("utf-8"))
            except OSError as e:
                self.stats["rejected_error"] += 1
                raise SpoolError(f"spool write failed: {e}") from e
            entries = [
                SpoolEntry(
                    segment=name,
                    index=i,
                    finding_id=finding_id,
                    source=source,
                    finding=finding,
                    size=len(line.encode("utf-8")) + 1,
                )
                for i, (finding_id, finding, line) in enumerate(batch)
            ]
            self._register(name, entries)
            self.stats["appended"] += len(entries)
        callback = self.on_ready
        if callback is not None:
            try:
                callback()
            except Exception:  # noqa: BLE001 - a wake-up never fails a write
                logger.debug("spool on_ready callback failed", exc_info=True)
        return [e.finding_id for e in entries]

    def _write_atomic(self, name: str, data: bytes) -> None:
        tmp = self.directory / (name + _TMP_SUFFIX)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            if self._fsync:
                os.fsync(fd)
        except OSError:
            os.close(fd)
            tmp.unlink(missing_ok=True)
            raise
        os.close(fd)
        try:
            os.replace(tmp, self.directory / name)
        except OSError:
            tmp.unlink(missing_ok=True)
            raise
        if self._fsync:
            _fsync_dir(self.directory)

    def _register(self, segment: str, entries: List[SpoolEntry]) -> None:
        self._remaining[segment] = len(entries)
        for entry in entries:
            self._pending[entry.key] = entry
            self._ids[entry.finding_id] += 1
            self._bytes += entry.size
            self._ready.append(entry)

    # -- the consumer side ---------------------------------------------------

    def claim(self, limit: int) -> List[SpoolEntry]:
        """Up to ``limit`` entries no one is working on, oldest first."""
        out: List[SpoolEntry] = []
        with self._lock:
            while self._ready and len(out) < limit:
                entry = self._ready.popleft()
                if entry.key not in self._pending or entry.claimed:
                    continue
                entry.claimed = True
                out.append(entry)
        return out

    def release(self, entry: SpoolEntry) -> None:
        """Give an unstored entry back; it is claimed again before newer ones."""
        with self._lock:
            if entry.key in self._pending and entry.claimed:
                entry.claimed = False
                self._ready.appendleft(entry)

    def done(self, entry: SpoolEntry) -> None:
        """The entry's row is stored: forget it (and its segment when empty)."""
        with self._lock:
            if self._pending.pop(entry.key, None) is None:
                return
            entry.claimed = False
            self._forget(entry)
            self.stats["done"] += 1

    def quarantine(self, entry: SpoolEntry, reason: str) -> None:
        """Set an entry the store keeps refusing aside under ``dead/``.

        Written (fsync'd) before it leaves the spool, so it is never lost;
        moving the file back into the spool directory replays it.
        """
        dead = self.directory / DEAD_DIR
        header = json.dumps(
            {
                "spool": SPOOL_FORMAT,
                "source": entry.source,
                "created": utcnow().isoformat(),
                "quarantined": reason[:500],
            }
        )
        line = json.dumps(
            {"id": entry.finding_id, "finding": entry.finding},
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
        name = f"{_SEGMENT_PREFIX}{time.time_ns():020d}-dead-{entry.index:06d}"
        with self._lock:
            dead.mkdir(exist_ok=True, mode=0o700)
            tmp = dead / (name + _TMP_SUFFIX)
            with open(tmp, "wb") as fh:
                fh.write((header + "\n" + line + "\n").encode("utf-8"))
                fh.flush()
                if self._fsync:
                    os.fsync(fh.fileno())
            os.replace(tmp, dead / (name + _SEGMENT_SUFFIX))
            if self._fsync:
                _fsync_dir(dead)
            if self._pending.pop(entry.key, None) is None:
                return
            entry.claimed = False
            self._forget(entry)
            self.stats["quarantined"] += 1

    def _forget(self, entry: SpoolEntry) -> None:
        self._bytes -= entry.size
        self._ids[entry.finding_id] -= 1
        if self._ids[entry.finding_id] <= 0:
            del self._ids[entry.finding_id]
        left = self._remaining.get(entry.segment, 0) - 1
        if left > 0:
            self._remaining[entry.segment] = left
            return
        self._remaining.pop(entry.segment, None)
        try:
            (self.directory / entry.segment).unlink(missing_ok=True)
        except OSError as e:
            # Harmless: the rows are stored, a replay finds them and skips.
            logger.warning("Ingest spool: could not remove %s: %s", entry.segment, e)

    # -- reads ---------------------------------------------------------------

    def contains(self, finding_id: str) -> bool:
        with self._lock:
            return self._ids[finding_id] > 0

    def ready_count(self) -> int:
        with self._lock:
            return sum(1 for e in self._ready if not e.claimed)

    def __len__(self) -> int:
        return len(self._pending)

    @property
    def pending_bytes(self) -> int:
        return self._bytes

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                **self.stats,
                "pending": len(self._pending),
                "pending_bytes": self._bytes,
                "segments": len(self._remaining),
                "max_findings": self.max_findings,
                "max_bytes": self.max_bytes,
                "directory": str(self.directory),
                "open": self.is_open,
            }


def waiting_segments(directory: Path | str) -> int:
    """Segment files in ``directory`` (read-only: no lock, nothing loaded)."""
    path = Path(directory)
    if not path.is_dir():
        return 0
    return sum(1 for _ in path.glob(f"{_SEGMENT_PREFIX}*{_SEGMENT_SUFFIX}"))


# -- metrics -------------------------------------------------------------------

_gauged: Optional[IngestSpool] = None
_counters: Dict[str, Any] = {}


def register_metrics(spool: IngestSpool) -> None:
    """Expose the spool on the daemon's meter (once per process)."""
    global _gauged
    first = _gauged is None
    _gauged = spool
    if not first:
        return
    try:
        from opentelemetry.metrics import Observation

        from core.telemetry import get_meter

        meter = get_meter("vigil.daemon")

        def _pending(_options: Any):
            s = _gauged
            return [Observation(len(s))] if s is not None else []

        def _bytes(_options: Any):
            s = _gauged
            return [Observation(s.pending_bytes)] if s is not None else []

        meter.create_observable_gauge(
            "soc_daemon_ingest_spool_pending",
            callbacks=[_pending],
            description="Acknowledged webhook findings not yet stored",
            unit="1",
        )
        meter.create_observable_gauge(
            "soc_daemon_ingest_spool_bytes",
            callbacks=[_bytes],
            description="Bytes held by the ingest spool",
            unit="By",
        )
    except Exception as e:  # noqa: BLE001 - metrics never stop ingestion
        logger.debug("ingest spool gauges not registered: %s", e)


def count(name: str, value: int = 1, **attributes: str) -> None:
    """Add to ``soc_daemon_ingest_spool_<name>_total``."""
    try:
        counter = _counters.get(name)
        if counter is None:
            from core.telemetry import get_meter

            counter = get_meter("vigil.daemon").create_counter(
                f"soc_daemon_ingest_spool_{name}_total",
                description=f"Ingest spool: {name.replace('_', ' ')}",
                unit="1",
            )
            _counters[name] = counter
        counter.add(value, attributes)
    except Exception as e:  # noqa: BLE001
        logger.debug("ingest spool counter %s unavailable: %s", name, e)
