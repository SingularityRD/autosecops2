"""Store outcomes and error kinds for the daemon spool (W0.12b)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy.exc import DataError, IntegrityError, OperationalError

from core.exceptions import default_on_error
from core.ingestion.ingestion_service import IngestionService
from core.ingestion.store_outcome import (
    CREATED,
    DATA,
    EXISTS,
    FAILED,
    OUTAGE,
    UNKNOWN,
    classify_store_error,
    has_triage,
)

pytestmark = pytest.mark.unit


class _Pg(Exception):
    def __init__(self, message: str, code: str, attr: str = "sqlstate") -> None:
        super().__init__(message)
        setattr(self, attr, code)


@pytest.mark.parametrize(
    "error, kind",
    [
        (_Pg("cannot execute INSERT in a read-only transaction", "25006"), OUTAGE),
        (_Pg("could not extend file: No space left on device", "53100"), OUTAGE),
        (_Pg("permission denied for table findings", "42501"), OUTAGE),
        (_Pg("the database system is in recovery mode", "57P03"), OUTAGE),
        (_Pg("terminating connection", "57P01", attr="pgcode"), OUTAGE),
        (_Pg("deadlock detected", "40P01"), OUTAGE),
        (_Pg("duplicate key value", "23505"), OUTAGE),  # a race: retry sees it
        (_Pg("invalid byte sequence", "22021"), DATA),
        (_Pg("value too long", "22001"), DATA),
        (_Pg("null value in column", "23502"), DATA),
        (_Pg("index row size exceeds maximum", "54000"), DATA),
        (_Pg("syntax error", "42601"), UNKNOWN),
        (OperationalError("x", {}, _Pg("read-only", "25006")), OUTAGE),
        (DataError("x", {}, _Pg("bad", "22P02")), DATA),
        (IntegrityError("x", {}, Exception("no code")), DATA),
        (OperationalError("x", {}, Exception("server closed")), OUTAGE),
        (RuntimeError("ERROR: No space left on device"), OUTAGE),
        (ConnectionError("refused"), OUTAGE),
        (ValueError("not a number"), DATA),
        (RuntimeError("something else"), UNKNOWN),
        (None, UNKNOWN),
    ],
)
def test_classify_store_error(error, kind):
    assert classify_store_error(error) == kind


def test_a_cause_chain_is_followed():
    try:
        try:
            raise _Pg("read-only", "25006")
        except _Pg as inner:
            raise RuntimeError("store failed") from inner
    except RuntimeError as outer:
        assert classify_store_error(outer) == OUTAGE


@pytest.mark.parametrize(
    "enrichment, triaged",
    [
        (None, False),
        ({"ai_triage_error": "timeout"}, False),
        ({"ai_triage_error": "timeout", "ai_triage": {}}, True),
        ({"ai_triage": {}}, True),
        ({"threat_intel": {}}, True),  # as UNRATED_WHERE: not null, no error
    ],
)
def test_has_triage_matches_unrated_where(enrichment, triaged):
    assert has_triage(enrichment) is triaged


class _Db:
    def __init__(self):
        self.rows = {}
        self.fail_lookup = False

    @default_on_error(None)
    def get_finding(self, finding_id):
        if self.fail_lookup:
            raise _Pg("canceling statement due to statement timeout", "57014")
        row = self.rows.get(finding_id)
        return SimpleNamespace(**row) if row else None

    @default_on_error(None)
    def get_finding_by_external_id(self, data_source, external_id):
        for row in self.rows.values():
            if row.get("external_id") == external_id:
                return SimpleNamespace(**row)
        return None

    @default_on_error(None)
    def create_finding(self, finding_id, **kw):
        if finding_id == "poison":
            raise DataError("INSERT", {}, _Pg("invalid byte sequence", "22021"))
        self.rows[finding_id] = {
            "finding_id": finding_id,
            "external_id": kw.get("external_id"),
            "ai_enrichment": None,
        }
        return self.rows[finding_id]


def _service(db):
    service = IngestionService.__new__(IngestionService)
    service.use_database = True
    service.db_service = db
    service.stats = {
        "findings_imported": 0,
        "findings_skipped": 0,
        "findings_errors": 0,
    }
    return service


def test_store_finding_tells_created_from_exists():
    db = _Db()
    service = _service(db)
    assert service.store_finding({"finding_id": "a"}).status == CREATED
    again = service.store_finding({"finding_id": "a"})
    assert (again.status, again.triaged) == (EXISTS, False)
    db.rows["a"]["ai_enrichment"] = {"ai_triage": {}}
    assert service.store_finding({"finding_id": "a"}).triaged is True


def test_a_match_by_external_id_has_unknown_triage():
    db = _Db()
    service = _service(db)
    service.store_finding({"finding_id": "a", "external_id": "e", "data_source": "s"})
    other = service.store_finding(
        {"finding_id": "b", "external_id": "e", "data_source": "s"}
    )
    assert (other.status, other.triaged) == (EXISTS, None)


def test_a_lookup_error_is_a_failure_not_not_found():
    """The wrapped lookups answer None on an error; store_finding unwraps them."""
    db = _Db()
    service = _service(db)
    db.rows["a"] = {"finding_id": "a", "ai_enrichment": {"ai_triage": {}}}
    db.fail_lookup = True
    outcome = service.store_finding({"finding_id": "a"})
    assert (outcome.status, outcome.kind) == (FAILED, OUTAGE)
    assert not outcome.stored


def test_a_data_error_is_reported_as_data():
    outcome = _service(_Db()).store_finding({"finding_id": "poison"})
    assert (outcome.status, outcome.kind) == (FAILED, DATA)


def test_no_database_is_an_outage():
    service = _service(_Db())
    service.use_database = False
    assert service.store_finding({"finding_id": "a"}).kind == OUTAGE


def test_ingest_finding_is_unchanged_for_its_callers():
    db = _Db()
    service = _service(db)
    service._record_error = lambda message: None
    assert service.ingest_finding({"finding_id": "a"}) is True
    assert service.ingest_finding({"finding_id": "a"}) is True  # exists
    assert service.stats["findings_imported"] == 1
    assert service.stats["findings_skipped"] == 1
