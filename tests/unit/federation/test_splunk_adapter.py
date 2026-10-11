"""A failed Splunk query fails the tick, it is not an empty poll (#1256, #1572).

``SplunkService.search`` returns ``None`` on any error. A query fails if it
raised or returned ``None``, and ``SplunkAdapter.fetch`` then raises so the
cursor keeps the window, even when a later fallback would have run. An empty
list falls through to the next query (non-ES installs have no notable index).
The last query (the ``notable`` macro, undefined without ES) may fail once every
earlier query ran empty.
"""

from __future__ import annotations

import asyncio
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from core.federation.adapters._base import SETTLING_MARGIN, parse_cursor_since
from core.federation.runner import FederationRunner
from core.integrations.splunk.adapter import _QUERIES, SplunkAdapter
from core.time import utcnow
from tests.unit._acking_queue import AckingQueue

pytestmark = pytest.mark.unit

CURSOR = {"last_poll_at": "2026-09-29T02:00:00"}


class _FakeSplunk:
    """Answers each query in order from ``responses``; an exception is raised."""

    def __init__(self, responses: List[Any]):
        self.responses = list(responses)
        self.queries: List[str] = []

    def search(self, **kw) -> Any:
        self.queries.append(kw["query"])
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _fetch(responses: List[Any]):
    adapter = SplunkAdapter()
    svc = _FakeSplunk(responses)
    adapter._service = svc
    return asyncio.run(adapter.fetch(since=None, cursor=CURSOR, max_items=10)), svc


def _event(n: int) -> Dict[str, Any]:
    return {"_cd": f"e{n}", "search_name": f"rule {n}", "urgency": "high"}


def test_all_queries_return_none_raises():
    with pytest.raises(RuntimeError, match="query failed"):
        _fetch([None, None, None])


def test_all_queries_raise_raises_with_last_error():
    with pytest.raises(RuntimeError, match="index=notable.*read"):
        _fetch([TimeoutError("read"), TimeoutError("read"), OSError("handshake")])


def test_empty_first_query_falls_back_to_next():
    res, svc = _fetch([[], [_event(1)], None])
    assert [f["external_id"] for f in res.findings] == ["e1"]
    assert len(svc.queries) == 2


def test_all_empty_is_a_successful_empty_poll():
    res, svc = _fetch([[], [], []])
    assert res.findings == []
    assert res.cursor["last_poll_at"] > CURSOR["last_poll_at"]
    assert len(svc.queries) == len(_QUERIES)


def test_failed_notable_query_raises_even_when_a_fallback_has_events():
    with pytest.raises(RuntimeError, match=r"index=notable.*permission denied"):
        _fetch([PermissionError("permission denied"), [_event(1)], None])


def test_failed_notable_query_raises_when_the_fallback_is_empty():
    with pytest.raises(RuntimeError, match="index=notable.*no result"):
        _fetch([None, [], []])


def test_failed_second_query_raises_after_empty_notable():
    with pytest.raises(RuntimeError, match="index=security"):
        _fetch([[], None, [_event(1)]])


def test_failed_macro_query_after_empty_queries_is_a_successful_empty_tick():
    """Non-ES install: no notable index, no alerts, and the macro is undefined."""
    res, svc = _fetch([[], [], None])
    assert res.findings == []
    assert len(svc.queries) == len(_QUERIES)
    assert res.cursor["last_poll_at"] > CURSOR["last_poll_at"]


@pytest.mark.asyncio
async def test_failed_notable_query_keeps_the_cursor_and_records_the_error(
    monkeypatch,
):
    row = {"cursor": dict(CURSOR), "last_error": None, "consecutive_errors": 0}

    def _failure(source_id, error):
        row["last_error"] = error
        row["consecutive_errors"] += 1

    monkeypatch.setattr("core.federation.runner.store.record_failure", _failure)
    monkeypatch.setattr(
        "core.federation.runner.store.record_success",
        lambda *a, **k: pytest.fail("a failed notable query is not a success"),
    )
    adapter = SplunkAdapter()
    adapter.is_configured = lambda: True  # type: ignore[method-assign]
    adapter._service = _FakeSplunk([None, [_event(1)], None])
    runner = FederationRunner(output_queue=AckingQueue())

    for expected in (1, 2):
        await runner._do_one_tick(adapter, {"max_items": 10, "cursor": row["cursor"]})
        assert row["consecutive_errors"] == expected
        adapter._service = _FakeSplunk([None, [_event(1)], None])

    assert "index=notable" in row["last_error"]
    assert row["cursor"] == CURSOR


def test_service_construction_failure_raises_and_is_retried():
    adapter = SplunkAdapter()
    with (
        patch.object(adapter, "is_configured", return_value=True),
        patch(
            "core.integrations.splunk.client.SplunkService",
            side_effect=ValueError("bad url"),
        ),
    ):
        with pytest.raises(ValueError, match="bad url"):
            asyncio.run(adapter.fetch(since=None, cursor=CURSOR, max_items=10))
    assert adapter._service is None


def test_not_configured_returns_empty():
    adapter = SplunkAdapter()
    with patch.object(adapter, "is_configured", return_value=False):
        res = asyncio.run(adapter.fetch(since=None, cursor=CURSOR, max_items=10))
    assert res.findings == []
    assert "last_poll_at" in res.cursor


# ---------------------------------------------------------------------------
# Full batch (#1571), read by index time (#1262)
# ---------------------------------------------------------------------------

T0 = datetime(2026, 9, 29, 2, 0, 30)  # mid-minute on purpose


def _timed(n: int, when: datetime) -> Dict[str, Any]:
    """An event Splunk indexed at ``when`` (the cursor follows index time)."""
    return {
        "_cd": f"e{n}",
        "_time": when.replace(tzinfo=timezone.utc).isoformat(timespec="milliseconds"),
        "vigil_indextime": str(when.replace(tzinfo=timezone.utc).timestamp()),
        "urgency": "high",
    }


class _WindowSplunk:
    """Honours the index-time search the adapter sends, the way Splunk does:
    ``_index_earliest`` (inclusive), ``sort 0 vigil_indextime``, ``head N``,
    and the appended row carrying Splunk's clock."""

    def __init__(self, events: List[Dict[str, Any]], now: datetime):
        self.events = events
        self.now = now
        self.earliest: List[float] = []

    def search(self, *, query: str, earliest_time: str, max_count: int, **kw):
        assert "| sort 0 vigil_indextime |" in query
        floor = float(re.search(r"_index_earliest=(\d+)", query).group(1))
        self.earliest.append(floor)
        hits = [e for e in self.events if float(e["vigil_indextime"]) >= floor]
        hits = sorted(hits, key=lambda e: float(e["vigil_indextime"]))
        return hits[: max_count - 1] + [{"vigil_now": str(_epoch(self.now))}]


def _epoch(when: datetime) -> float:
    return when.replace(tzinfo=timezone.utc).timestamp()


def _window_adapter(events: List[Dict[str, Any]], now: datetime = T0 + timedelta(hours=1)):
    adapter = SplunkAdapter()
    svc = _WindowSplunk(events, now)
    adapter._service = svc
    return adapter, svc


def test_full_batch_keeps_the_oldest_and_stops_the_cursor_at_the_newest_kept():
    adapter, svc = _window_adapter(
        [_timed(i, T0 + timedelta(minutes=i)) for i in range(1, 6)]
    )

    res = asyncio.run(
        adapter.fetch(since=None, cursor={"last_poll_at": T0.isoformat()}, max_items=3)
    )

    assert [f["external_id"] for f in res.findings] == ["e1", "e2", "e3"]
    assert parse_cursor_since(res.cursor) == T0 + timedelta(minutes=3)
    assert res.truncated is True
    # Absolute epoch of the cursor, not a minute-rounded "-Nm".
    assert svc.earliest[0] == math.floor(_epoch(T0))


def test_events_in_one_minute_still_progress_the_cursor():
    """A full batch inside one minute must not re-read the same page forever."""
    events = [_timed(i, T0 + timedelta(seconds=i)) for i in range(1, 8)]
    adapter, _ = _window_adapter(events)

    cursor = {"last_poll_at": T0.isoformat()}
    seen: List[str] = []
    for _ in range(4):
        res = asyncio.run(adapter.fetch(since=None, cursor=cursor, max_items=3))
        seen += [f["external_id"] for f in res.findings]
        cursor = res.cursor

    assert set(seen) == {f"e{i}" for i in range(1, 8)}
    # Ticks 1-3 filled the batch; the cursor advanced each time (e3, e5, e7...).
    assert parse_cursor_since(cursor) > T0 + timedelta(seconds=7)


def test_events_at_one_instant_step_the_cursor_forward(caplog):
    adapter, _ = _window_adapter([_timed(i, T0) for i in range(1, 6)])

    with caplog.at_level("WARNING"):
        res = asyncio.run(
            adapter.fetch(
                since=None, cursor={"last_poll_at": T0.isoformat()}, max_items=3
            )
        )

    # _indextime is whole seconds, so the step is one second.
    assert parse_cursor_since(res.cursor) == T0 + timedelta(seconds=1)
    assert "not past the tick start" in caplog.text


def test_full_batch_with_unreadable_times_warns_and_moves_to_now(caplog):
    events = [{"_cd": f"e{i}", "vigil_indextime": "garbage"} for i in range(3)]
    adapter = SplunkAdapter()
    adapter._service = _FakeSplunk([events])

    before = utcnow()
    with caplog.at_level("WARNING"):
        res = asyncio.run(adapter.fetch(since=None, cursor=CURSOR, max_items=3))

    # Drained: now less the settling margin, so a late-indexed alert is re-read.
    assert parse_cursor_since(res.cursor) >= before - SETTLING_MARGIN
    assert "no alert carried a readable time" in caplog.text
