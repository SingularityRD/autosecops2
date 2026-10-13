"""eval_runs / eval_results writes, against a recording fake session."""

import json
import re
from pathlib import Path

import pytest

from evalkit.db import INSERT_RESULT, INSERT_RUN, write_all
from tests.unit.evalkit.conftest import make_result

SQL = (
    Path(__file__).resolve().parents[3]
    / "infra"
    / "database"
    / "init"
    / "46_eval_qa_canary.sql"
)

RUN = {
    "backend": {"backend": "stub", "model": "stub-model"},
    "prompt_version": "legacy-triage@abc",
    "git_sha": "deadbeef",
    "started_at": "2026-10-12T00:00:00+00:00",
    "finished_at": "2026-10-12T00:01:00+00:00",
}


class FakeSession:
    def __init__(self, fail=False):
        self.executed = []
        self.committed = self.rolled_back = self.closed = False
        self.fail = fail

    def execute(self, statement, params):
        if self.fail:
            raise RuntimeError("db down")
        self.executed.append((str(statement), params))

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def _columns(table):
    body = SQL.read_text().split(f"CREATE TABLE IF NOT EXISTS {table} (")[1]
    body = body.split("\n);")[0]
    return {
        m.group(1) for m in re.finditer(r"^\s{4}([a-z_]+)\s+[A-Z]", body, re.MULTILINE)
    }


def _insert_columns(sql):
    return {c.strip() for c in sql.split("(", 1)[1].split(")", 1)[0].split(",")}


@pytest.mark.parametrize(
    "sql,table", [(INSERT_RUN, "eval_runs"), (INSERT_RESULT, "eval_results")]
)
def test_inserts_name_real_columns(sql, table):
    assert _insert_columns(sql) <= _columns(table)


def test_writes_one_run_per_suite_with_default_tenant():
    session = FakeSession()
    results = {
        "test": [make_result(), make_result(actual="benign")],
        "injection": [make_result(error="cassette miss")],
    }
    report = {"run": RUN, "suites": {"test": {"m": 1}, "injection": {"m": 2}}}
    ids = write_all(results, report, session_factory=lambda: session)
    assert set(ids) == {"test", "injection"}
    assert session.committed and session.closed

    runs = [p for sql, p in session.executed if "INSERT INTO eval_runs" in sql]
    assert [r["suite"] for r in runs] == ["corpus-v1/test", "injection-v1"]
    assert all(r["tenant_id"] == "default" for r in runs)
    assert json.loads(runs[0]["metrics"]) == {"m": 1}
    assert runs[0]["model"] == "stub-model" and runs[0]["status"] == "completed"

    rows = [p for sql, p in session.executed if "INSERT INTO eval_results" in sql]
    test_rows, inj_rows = rows
    assert [r["passed"] for r in test_rows] == [True, False]
    assert all(
        r["run_id"] == ids["test"] and r["tenant_id"] == "default" for r in test_rows
    )
    [errored] = inj_rows
    assert errored["passed"] is None
    assert errored["actual_verdict"] is None and errored["confidence"] is None
    assert errored["error"] == "cassette miss"


def test_tenant_is_passed_through():
    session = FakeSession()
    write_all(
        {"dev": [make_result()]},
        {"run": RUN, "suites": {"dev": {}}},
        tenant_id="acme",
        session_factory=lambda: session,
    )
    assert all(
        p["tenant_id"] == "acme" for _, p in session.executed if isinstance(p, dict)
    )


def test_failure_rolls_back():
    session = FakeSession(fail=True)
    with pytest.raises(RuntimeError):
        write_all(
            {"dev": [make_result()]},
            {"run": RUN, "suites": {"dev": {}}},
            session_factory=lambda: session,
        )
    assert session.rolled_back and session.closed and not session.committed
