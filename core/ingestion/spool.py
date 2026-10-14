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

W0.12b: an entry stored (or quarantined) while others of its segment are still
pending is recorded in ``<segment>.done`` (one ``<index> <crc32>`` mark per line), so a
replay skips it instead of offering a stored finding again. A segment whose
body has unreadable lines keeps its readable entries; the bad lines are copied
to ``corrupt/<segment>-lines-<ns>.jsonl`` (same format: the original header,
then the lines as found) and marked done. Only a segment whose header cannot
be read (unknown format) is set aside whole under ``corrupt/``. The spool
directory and ``dead/``/``corrupt/`` are ``0700``, every file ``0600``.
"""

from __future__ import annotations

import errno
import json
import logging
import os
import stat
import threading
import time
import zlib
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
_DONE_SUFFIX = ".done"
_DIR_MODE = 0o700
_FILE_MODE = 0o600
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


def _done_record(index: int) -> bytes:
    """One done mark: ``<index> <crc32 of index, hex>\\n``."""
    text = str(index).encode("ascii")
    return text + b" " + f"{zlib.crc32(text):08x}".encode("ascii") + b"\n"


def _parse_done(raw: bytes) -> set:
    """Indices of the well-formed marks in a ``.done`` file.

    A mark torn by a crash (or one a later mark was appended onto) fails its
    check and is ignored: that entry replays and the store reports it as
    already stored. A damaged file can lose marks; it never invents one.
    """
    done = set()
    for record in raw.split(b"\n"):
        parts = record.split(b" ")
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        if parts[1] == f"{zlib.crc32(parts[0]):08x}".encode("ascii"):
            done.add(int(parts[0]))
    return done


class IngestSpool:
    """Append-only, fsync'd, bounded spool of findings awaiting their store."""

    def __init__(
        self,
        directory: Path | str,
        *,
        max_findings: int = 10_000,
        max_bytes: int = 128 * 1024 * 1024,
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
            "corrupt_lines": 0,
            "unreadable_segments": 0,
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
            self.directory.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
            fd = os.open(self.directory / ".lock", os.O_RDWR | os.O_CREAT, _FILE_MODE)
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
        self._tighten_permissions()
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

    def _tighten_permissions(self) -> None:
        """The spool holds customer findings: ``0700`` directories, ``0600``
        files, also for a directory an older version (or an operator) made."""
        targets = [(self.directory, _DIR_MODE)]
        for sub in (DEAD_DIR, CORRUPT_DIR):
            path = self.directory / sub
            if _is_real(path, stat.S_ISDIR):
                targets.append((path, _DIR_MODE))
                targets.extend(_real_files(path))
        targets.extend(_real_files(self.directory))
        for path, mode in targets:
            try:
                _chmod_no_follow(path, mode)
            except OSError as e:  # not ours to change (e.g. another owner)
                logger.warning(
                    "Ingest spool: could not set mode %o on %s: %s", mode, path, e
                )

    def _subdir(self, name: str) -> Path:
        path = self.directory / name
        path.mkdir(exist_ok=True, mode=_DIR_MODE)
        if not _is_real(path, stat.S_ISDIR):  # a symlink: never write through it
            raise NotADirectoryError(f"{path} is not a directory of the spool")
        _chmod_no_follow(path, _DIR_MODE)
        return path

    def _done_path(self, segment: str) -> Path:
        return self.directory / (segment + _DONE_SUFFIX)

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
        names = {p.name for p in segments}
        for marks in self.directory.glob(f"{_SEGMENT_PREFIX}*{_DONE_SUFFIX}"):
            # The segment went away after its last entry; only the marks stayed.
            if marks.name[: -len(_DONE_SUFFIX)] not in names:
                marks.unlink(missing_ok=True)
        for path in segments:
            entries = self._read_segment(path)
            if entries is None:
                continue
            if not entries:
                path.unlink(missing_ok=True)
                self._done_path(path.name).unlink(missing_ok=True)
                continue
            self._register(path.name, entries)
            loaded += len(entries)
        self.stats["replayed"] += loaded
        self._seq = len(segments)
        return loaded

    def _read_done(self, segment: str) -> set:
        try:
            return _parse_done(self._done_path(segment).read_bytes())
        except FileNotFoundError:
            return set()

    def _set_aside(self, path: Path, error: Exception) -> None:
        corrupt = self._subdir(CORRUPT_DIR)
        os.replace(path, corrupt / path.name)
        self._done_path(path.name).unlink(missing_ok=True)
        self.stats["corrupt_segments"] += 1
        logger.error(
            "Ingest spool segment %s is unreadable (%s); moved to %s",
            path.name,
            error,
            corrupt,
        )

    def _skip_unreadable(self, path: Path, error: OSError) -> None:
        """Move a segment that cannot be read to ``corrupt/``; if even that
        fails, leave it where it is. Either way it is logged and skipped."""
        self.stats["unreadable_segments"] += 1
        try:
            self._set_aside(path, error)
        except OSError as e:
            logger.error(
                "Ingest spool segment %s is unreadable (%s) and could not be "
                "moved to %s/ (%s); left in place and not replayed",
                path.name,
                error,
                CORRUPT_DIR,
                e,
            )

    def _read_segment(self, path: Path) -> Optional[List[SpoolEntry]]:
        try:
            raw = path.read_bytes()
        except OSError as e:
            # One unreadable file (EACCES, EIO) costs only itself: the rest of
            # the spool keeps working (W0.12b round 6).
            self._skip_unreadable(path, e)
            return None
        lines = raw.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()  # the newline that ends the last line
        try:
            header = json.loads(lines[0].decode("utf-8")) if lines else {}
            if not isinstance(header, dict) or header.get("spool") != SPOOL_FORMAT:
                spool_format = header.get("spool") if isinstance(header, dict) else None
                raise ValueError(f"unknown spool format {spool_format!r}")
        except Exception as e:  # noqa: BLE001 - keep the bytes, skip the file
            # Without a readable header nothing in the file can be trusted.
            self._set_aside(path, e)
            return None
        source = str(header.get("source") or "webhook")
        try:
            done = self._read_done(path.name)
        except OSError as e:
            # Without its done marks a replay would store (and triage) entries
            # again: leave the segment as it is for an operator, skip it.
            self.stats["unreadable_segments"] += 1
            logger.error(
                "Ingest spool segment %s: its done marks are unreadable (%s); "
                "left in place and not replayed",
                path.name,
                e,
            )
            return None
        entries: List[SpoolEntry] = []
        bad: List[tuple] = []
        for index, line in enumerate(lines[1:]):
            if index in done:
                continue
            try:
                record = json.loads(line.decode("utf-8"))
                finding = record["finding"]
                if not isinstance(finding, dict):
                    raise ValueError("finding is not an object")
                finding_id = str(record["id"])
                if not finding_id:
                    raise ValueError("empty id")
            except Exception as e:  # noqa: BLE001 - this line only
                bad.append((index, line, e))
                continue
            entries.append(
                SpoolEntry(
                    segment=path.name,
                    index=index,
                    finding_id=finding_id,
                    source=source,
                    finding=finding,
                    size=len(line) + 1,
                    replayed=True,
                )
            )
        if bad:
            try:
                self._salvage(path, lines[0], bad)
            except OSError as e:
                raise SpoolError(
                    f"spool segment {path.name}: could not set aside "
                    f"{len(bad)} unreadable line(s): {e}"
                ) from e
        return entries

    def _salvage(self, path: Path, header: bytes, bad: List[tuple]) -> None:
        """Copy unreadable body lines to ``corrupt/`` (fsync'd), then mark them
        done so the next open does not copy them again."""
        corrupt = self._subdir(CORRUPT_DIR)
        stem = path.name[: -len(_SEGMENT_SUFFIX)]
        name = f"{stem}-lines-{time.time_ns():020d}{_SEGMENT_SUFFIX}"
        body = header + b"\n" + b"".join(line + b"\n" for _, line, _ in bad)
        self._write_file(corrupt / name, body)
        self._append_done(path.name, [index for index, _, _ in bad], sync=True)
        self.stats["corrupt_lines"] += len(bad)
        logger.error(
            "Ingest spool segment %s: %d unreadable line(s) (first: line %d, %s) "
            "copied to %s; its other entries replay",
            path.name,
            len(bad),
            bad[0][0] + 2,  # 1-based, after the header
            bad[0][2],
            corrupt / name,
        )

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
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
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

    def _write_file(self, path: Path, data: bytes) -> None:
        """Write ``path`` (``0600``) via a temporary name; fsync'd."""
        tmp = path.with_name(path.name + _TMP_SUFFIX)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _FILE_MODE)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            if self._fsync:
                os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(tmp, path)
        except OSError:
            if fd >= 0:
                os.close(fd)
            tmp.unlink(missing_ok=True)
            raise
        if self._fsync:
            _fsync_dir(path.parent)

    def _append_done(self, segment: str, indices: List[int], sync: bool) -> None:
        """Record ``indices`` of ``segment`` as no longer pending.

        Not fsync'd on the hot path: a process kill keeps the write (page
        cache); a power loss may lose it, and then the entry replays and the
        store reports it as already stored.
        """
        fd = os.open(
            self._done_path(segment),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            _FILE_MODE,
        )
        try:
            os.write(fd, b"".join(_done_record(i) for i in indices))
            if sync and self._fsync:
                os.fsync(fd)
        finally:
            os.close(fd)

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
            dead = self._subdir(DEAD_DIR)
            self._write_file(
                dead / (name + _SEGMENT_SUFFIX),
                (header + "\n" + line + "\n").encode("utf-8"),
            )
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
            try:
                self._append_done(entry.segment, [entry.index], sync=False)
            except OSError as e:
                # Harmless: a replay offers it again, the store reports it
                # as already stored and it is not triaged a second time.
                logger.warning("Ingest spool: could not mark %s done: %s", entry.key, e)
            return
        self._remaining.pop(entry.segment, None)
        try:
            (self.directory / entry.segment).unlink(missing_ok=True)
            self._done_path(entry.segment).unlink(missing_ok=True)
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


def _is_real(path: Path, kind) -> bool:
    """``kind`` (``stat.S_ISDIR``/``S_ISREG``) of ``path`` itself: a symlink
    is never one, whatever it points at."""
    try:
        return kind(path.lstat().st_mode)
    except OSError:
        return False


def _real_files(directory: Path) -> List[tuple]:
    """Regular files directly in ``directory`` (not symlinks), as targets."""
    try:
        children = list(directory.iterdir())
    except OSError as e:
        logger.warning("Ingest spool: could not list %s: %s", directory, e)
        return []
    return [(f, _FILE_MODE) for f in children if _is_real(f, stat.S_ISREG)]


def _chmod_no_follow(path: Path, mode: int) -> None:
    """Set ``mode`` on ``path`` itself. Never through a symlink: one planted in
    the spool must not change its target's mode (W0.12b round 6)."""
    st = path.lstat()
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        return  # a symlink, a FIFO, a device: not a spool file
    if (st.st_mode & 0o777) == mode:
        return
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    if stat.S_ISDIR(st.st_mode):
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        # Open without following, then fchmod the descriptor: no window in
        # which the path could be swapped for a symlink before the chmod.
        fd = os.open(path, flags)
    except PermissionError:
        # Ours but not readable (e.g. mode 0200): lstat said it is no symlink.
        os.chmod(path, mode)
        return
    try:
        if stat.S_ISREG(os.fstat(fd).st_mode) or stat.S_ISDIR(os.fstat(fd).st_mode):
            os.fchmod(fd, mode)
    finally:
        os.close(fd)


def waiting_segments(directory: Path | str) -> int:
    """Segment files in ``directory`` (read-only: no lock, nothing loaded)."""
    path = Path(directory)
    if not path.is_dir():
        return 0
    return sum(1 for _ in path.glob(f"{_SEGMENT_PREFIX}*{_SEGMENT_SUFFIX}"))


def waiting_findings(directory: Path | str) -> int:
    """Findings still pending in ``directory``'s segments, read-only (no lock,
    nothing loaded): body lines minus the ones marked done. For a standby,
    which does not open its spool (W0.12b)."""
    path = Path(directory)
    if not path.is_dir():
        return 0
    total = 0
    for segment in path.glob(f"{_SEGMENT_PREFIX}*{_SEGMENT_SUFFIX}"):
        try:
            lines = segment.read_bytes().split(b"\n")
        except OSError:
            continue
        body = [i for i, line in enumerate(lines[1:]) if line.strip()]
        done: set = set()
        try:
            done = _parse_done((path / (segment.name + _DONE_SUFFIX)).read_bytes())
        except OSError:
            pass
        total += sum(1 for i in body if i not in done)
    return total


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


# A standby's own spool waits until that pod leads (W0.12b): exposed as
# soc_daemon_ingest_spool_standby_pending so it can be alerted on.
_STANDBY_REFRESH_SECONDS = 30.0
_standby: Dict[str, Any] = {"directory": None, "value": 0, "at": float("-inf")}
_standby_registered = False


def standby_pending() -> int:
    """Findings waiting in the standby's spool (cached for 30 s); 0 when this
    process is not a standby with a spool."""
    directory = _standby["directory"]
    if directory is None:
        return 0
    now = time.monotonic()
    if now - _standby["at"] >= _STANDBY_REFRESH_SECONDS:
        try:
            _standby["value"] = waiting_findings(directory)
        except Exception:  # noqa: BLE001 - informational only
            pass
        _standby["at"] = now
    return int(_standby["value"])


def watch_standby(directory: Optional[Path | str]) -> None:
    """Report ``directory`` as this standby's waiting spool; ``None`` once the
    pod leads (its spool is then open and counted by the pending gauge)."""
    global _standby_registered
    _standby.update(
        directory=None if directory is None else Path(directory),
        value=0,
        at=float("-inf"),
    )
    if directory is None or _standby_registered:
        return
    try:
        from opentelemetry.metrics import Observation

        from core.telemetry import get_meter

        get_meter("vigil.daemon").create_observable_gauge(
            "soc_daemon_ingest_spool_standby_pending",
            callbacks=[lambda _options: [Observation(standby_pending())]],
            description=(
                "Acknowledged webhook findings in a standby pod's own spool; "
                "replayed only when that pod leads"
            ),
            unit="1",
        )
        _standby_registered = True
    except Exception as e:  # noqa: BLE001 - metrics never stop the daemon
        logger.debug("ingest spool standby gauge not registered: %s", e)


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
