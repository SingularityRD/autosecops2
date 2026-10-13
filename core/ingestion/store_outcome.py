"""What a single finding store did, for callers that must not guess (W0.12b).

``IngestionService.ingest_finding`` answers True for both "inserted" and
"already there", and its lookups turn a database error into "not found". The
daemon's spool replay needs the difference: a finding that was already stored
(and triaged) must not be triaged again, and a write the database rejects as a
whole (read-only after a failover, disk full, no privilege) is an outage to
wait out, not a finding to set aside as poison.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional

CREATED = "created"
EXISTS = "exists"
FAILED = "failed"

# Error kinds of a failed store.
OUTAGE = "outage"  # the database cannot take writes now: back off, keep it
DATA = "data"  # this finding is the problem: may be quarantined
UNKNOWN = "unknown"  # neither is certain: the caller's heuristic decides

# SQLSTATE classes / codes (PostgreSQL appendix A).
_OUTAGE_CLASSES = (
    "08",  # connection exception
    "40",  # transaction rollback (serialization failure, deadlock)
    "53",  # insufficient resources (disk full, out of memory, too many conns)
    "57",  # operator intervention (admin shutdown, cannot connect now, cancel)
    "58",  # system error (I/O error)
    "HV",  # foreign data wrapper (remote unavailable)
)
_OUTAGE_CODES = frozenset(
    {
        "25006",  # read_only_sql_transaction: a standby after failover
        "25P04",  # transaction_timeout
        "42501",  # insufficient_privilege: the role lost INSERT
        "55P03",  # lock_not_available
        "55006",  # object_in_use
        "55000",  # object_not_in_prerequisite_state (e.g. recovery in progress)
        "23505",  # unique_violation: a concurrent insert; the retry sees EXISTS
        "0A000",  # feature_not_supported: e.g. writes on a hot standby
    }
)
_DATA_CLASSES = (
    "22",  # data exception (bad text, too long, out of range, NUL byte, JSON)
    "23",  # integrity constraint (not null, check, foreign key)
    "54",  # program limit exceeded (index row too large)
)

# Message fragments for drivers/wrappers that do not carry a SQLSTATE.
_OUTAGE_TEXT = (
    "read-only transaction",
    "read only transaction",
    "no space left on device",
    "could not extend file",
    "disk full",
    "permission denied",
    "insufficient privilege",
    "the database system is",  # starting up / shutting down / in recovery
    "could not connect",
    "connection refused",
    "server closed the connection",
    "terminating connection",
    "database unavailable",
)


@dataclass(frozen=True)
class StoreOutcome:
    """``status``: CREATED, EXISTS or FAILED.

    ``triaged`` (EXISTS only): whether the stored row already holds a triage;
    None when unknown, or when the match was by ``(data_source, external_id)``
    (a different row id, which this finding's triage would not update).
    ``kind`` / ``error`` (FAILED only): see :func:`classify_store_error`.
    """

    status: str
    triaged: Optional[bool] = None
    kind: Optional[str] = None
    error: Optional[str] = None

    @property
    def stored(self) -> bool:
        return self.status in (CREATED, EXISTS)


def has_triage(ai_enrichment: Any) -> bool:
    """The negation of ``UNRATED_WHERE`` (core/storage/models/finding.py)."""
    if ai_enrichment is None:
        return False
    if isinstance(ai_enrichment, Mapping):
        return not (
            "ai_triage_error" in ai_enrichment and "ai_triage" not in ai_enrichment
        )
    return True


def _sqlstate(exc: BaseException) -> Optional[str]:
    seen = set()
    current: Optional[BaseException] = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        for attr in ("sqlstate", "pgcode"):
            code = getattr(current, attr, None)
            if isinstance(code, str) and len(code) == 5:
                return code.upper()
        orig = getattr(current, "orig", None)  # sqlalchemy DBAPIError
        if isinstance(orig, BaseException) and id(orig) not in seen:
            current = orig
            continue
        current = current.__cause__ or current.__context__
    return None


def classify_store_error(exc: Optional[BaseException]) -> str:
    """OUTAGE, DATA or UNKNOWN for an exception raised while storing."""
    if exc is None:
        return UNKNOWN
    code = _sqlstate(exc)
    if code is not None:
        if code in _OUTAGE_CODES or code.startswith(_OUTAGE_CLASSES):
            return OUTAGE
        if code.startswith(_DATA_CLASSES):
            return DATA
        return UNKNOWN
    text = str(exc).lower()
    if any(fragment in text for fragment in _OUTAGE_TEXT):
        return OUTAGE
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return OUTAGE
    try:
        from sqlalchemy import exc as sa_exc

        if isinstance(exc, (sa_exc.DisconnectionError, sa_exc.TimeoutError)):
            return OUTAGE
        if isinstance(exc, sa_exc.OperationalError):
            return OUTAGE
        if isinstance(exc, sa_exc.StatementError) and not isinstance(
            exc, sa_exc.DBAPIError
        ):
            return DATA  # failed binding this finding's values, before the wire
        if isinstance(exc, (sa_exc.DataError, sa_exc.IntegrityError)):
            return DATA
    except ImportError:  # pragma: no cover - sqlalchemy is a dependency
        pass
    if isinstance(exc, (ValueError, TypeError, KeyError, UnicodeError)):
        return DATA  # raised by this finding's own content
    return UNKNOWN


def failed(kind: str, error: Any) -> StoreOutcome:
    return StoreOutcome(status=FAILED, kind=kind, error=str(error)[:500])
