"""QRadar offenses: client, transform, federation adapter, MCP tool (W0.41)."""

from __future__ import annotations

import json

import httpx
import pytest

from core.federation.provenance import QRADAR, provenance_for
from core.integrations.qradar import adapter as qradar_adapter
from core.integrations.qradar import ingestion
from core.integrations.qradar.client import QRadarClient, QRadarError, check_filter

pytestmark = pytest.mark.unit

OFFENSE = {
    "id": 4012,
    "description": "Excessive Firewall Denies Between Hosts\n preceded by Port Scan\n",
    "offense_type": 0,
    "offense_source": "10.20.30.40",
    "magnitude": 8,
    "severity": 6,
    "credibility": 3,
    "relevance": 5,
    "status": "OPEN",
    "start_time": 1772438400000,
    "last_updated_time": 1772438500000,
    "event_count": 1532,
    "flow_count": 0,
    "categories": ["Firewall Deny", "Port Scan"],
    "rules": [{"id": 100205, "type": "CRE_RULE"}],
    "domain_id": 0,
}


class _Console:
    """A recorded QRadar: answers offense queries from ``offenses``."""

    def __init__(self, offenses, status=200):
        self.offenses = offenses
        self.status = status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status != 200:
            return httpx.Response(self.status, json={"code": 1002, "message": "x"})
        params = request.url.params
        rng = request.headers["Range"].removeprefix("items=").split("-")
        first, last = int(rng[0]), int(rng[1])
        items = list(self.offenses)
        flt = params.get("filter", "")
        if flt.startswith("id > "):
            after = int(flt.split()[2])
            items = [o for o in items if o["id"] > after]
        if params.get("sort") == "-id":
            items.sort(key=lambda o: -o["id"])
        else:
            items.sort(key=lambda o: o["id"])
        if request.url.path.startswith("/api/siem/offenses/"):
            wanted = int(request.url.path.rsplit("/", 1)[1])
            return httpx.Response(
                200, json=next(o for o in self.offenses if o["id"] == wanted)
            )
        return httpx.Response(200, json=items[first : last + 1])


def _client(console: _Console, **kw) -> QRadarClient:
    client = QRadarClient("https://qradar.test", "tok", **kw)
    client._client = httpx.AsyncClient(
        base_url="https://qradar.test",
        headers=client._headers,
        transport=httpx.MockTransport(console),
    )
    return client


# --- transform -----------------------------------------------------------------


def test_an_offense_becomes_a_finding():
    f = ingestion.transform_offense(OFFENSE)
    assert f["finding_id"] == "qradar-4012"
    assert f["external_id"] == "4012"
    assert f["data_source"] == "qradar"
    assert f["title"] == "Excessive Firewall Denies Between Hosts"
    assert f["severity"] == "high"  # magnitude 8
    assert f["timestamp"] == "2026-03-02T08:00:00+00:00"
    assert f["entity_context"] == {"src_ips": ["10.20.30.40"]}
    assert "Firewall Deny" in f["description"] and "1532" in f["description"]
    assert f["metadata"]["rule_ids"] == [100205]
    assert f["metadata"]["offense_status"] == "OPEN"


@pytest.mark.parametrize(
    "offense_type,source,expected",
    [
        (1, "198.51.100.7", {"dest_ips": ["198.51.100.7"]}),
        (3, "ayse.yilmaz", {"usernames": ["ayse.yilmaz"]}),
        (0, "not-an-ip", {}),
        (6, "FortiGate @ fw01", {}),  # log source: metadata only
    ],
)
def test_offense_source_by_type(offense_type, source, expected):
    f = ingestion.transform_offense(
        {**OFFENSE, "offense_type": offense_type, "offense_source": source}
    )
    assert f["entity_context"] == expected
    assert f["metadata"]["offense_source"] == source


@pytest.mark.parametrize(
    "magnitude,severity", [(1, "low"), (4, "medium"), (7, "high"), (10, "critical")]
)
def test_magnitude_is_the_severity(magnitude, severity):
    assert (
        ingestion.transform_offense({**OFFENSE, "magnitude": magnitude})["severity"]
        == severity
    )


def test_an_offense_without_an_integer_id_is_dropped():
    assert ingestion.transform_offense({**OFFENSE, "id": "4012"}) is None
    assert ingestion.transform_offense({**OFFENSE, "id": True}) is None


def test_qradar_provenance():
    assert provenance_for("qradar") is QRADAR
    assert QRADAR["metadata.magnitude"] == "sensor"
    assert QRADAR["metadata.offense_source"] == "adversary"
    assert QRADAR["title"] == "adversary"
    assert QRADAR["raw_event.*"] == "adversary"


# --- client ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_sends_the_token_version_and_range():
    console = _Console([OFFENSE])
    client = _client(console, api_version="20.0")
    out = await client.offenses_after(4000, 25, "status = 'OPEN'")
    assert [o["id"] for o in out] == [4012]
    req = console.requests[0]
    assert req.headers["SEC"] == "tok"
    assert req.headers["Version"] == "20.0"
    assert req.headers["Range"] == "items=0-24"
    assert req.url.params["filter"] == "id > 4000 and (status = 'OPEN')"
    assert req.url.params["sort"] == "+id"


def test_no_version_header_unless_set():
    assert "Version" not in QRadarClient("https://q.test", "t")._headers


@pytest.mark.parametrize(
    "bad",
    ["id > 1; DROP", 'status = "OPEN"', "a" * 501, "x | y", "magnitude > 5\nor id > 0"],
)
def test_a_bad_offense_filter_is_refused(bad):
    with pytest.raises(QRadarError):
        check_filter(bad)


def test_a_good_offense_filter_passes():
    assert (
        check_filter(" status = 'OPEN' and magnitude >= 5 ")
        == "status = 'OPEN' and magnitude >= 5"
    )
    assert check_filter("") is None


@pytest.mark.asyncio
async def test_an_error_answer_raises_without_the_body():
    client = _client(_Console([], status=401))
    with pytest.raises(QRadarError) as err:
        await client.offenses_after(0, 10)
    assert "401" in str(err.value) and "1002" in str(err.value)
    assert "tok" not in str(err.value)


def test_client_needs_url_and_token():
    with pytest.raises(QRadarError):
        QRadarClient("", "t")
    with pytest.raises(QRadarError):
        QRadarClient("ftp://q", "t")
    with pytest.raises(QRadarError):
        QRadarClient("https://q", "")


# --- adapter ---------------------------------------------------------------------


@pytest.fixture
def configured(monkeypatch):
    console = _Console([{**OFFENSE, "id": i} for i in (4010, 4011, 4012, 4013, 4014)])
    monkeypatch.setattr(
        qradar_adapter.QRadarAdapter, "is_configured", lambda self: True
    )
    monkeypatch.setattr(
        qradar_adapter,
        "qradar_config",
        lambda: {"console_url": "https://qradar.test", "api_token": "tok"},
    )
    monkeypatch.setattr(qradar_adapter, "build_client", lambda cfg: _client(console))
    return console


@pytest.mark.asyncio
async def test_first_run_starts_at_the_newest_offense_without_backfill(configured):
    result = await qradar_adapter.QRadarAdapter().fetch(
        since=None, cursor={}, max_items=100
    )
    assert result.findings == []
    assert result.cursor == {"after_id": 4014}


@pytest.mark.asyncio
async def test_reads_after_the_cursor_and_pages(configured):
    adapter = qradar_adapter.QRadarAdapter()
    first = await adapter.fetch(since=None, cursor={"after_id": 4010}, max_items=2)
    assert [f["external_id"] for f in first.findings] == ["4011", "4012"]
    assert first.cursor == {"after_id": 4012}
    assert first.truncated is True
    second = await adapter.fetch(since=None, cursor=first.cursor, max_items=2)
    assert [f["external_id"] for f in second.findings] == ["4013", "4014"]
    third = await adapter.fetch(since=None, cursor=second.cursor, max_items=2)
    assert third.findings == [] and third.truncated is False
    assert third.cursor == {"after_id": 4014}


@pytest.mark.asyncio
async def test_a_failing_console_raises_so_the_cursor_is_kept(monkeypatch):
    monkeypatch.setattr(
        qradar_adapter.QRadarAdapter, "is_configured", lambda self: True
    )
    monkeypatch.setattr(qradar_adapter, "qradar_config", lambda: {})
    monkeypatch.setattr(
        qradar_adapter, "build_client", lambda cfg: _client(_Console([], status=503))
    )
    with pytest.raises(QRadarError):
        await qradar_adapter.QRadarAdapter().fetch(
            since=None, cursor={"after_id": 1}, max_items=10
        )


@pytest.mark.asyncio
async def test_not_configured_reads_nothing(monkeypatch):
    monkeypatch.setattr(
        qradar_adapter.QRadarAdapter, "is_configured", lambda self: False
    )
    result = await qradar_adapter.QRadarAdapter().fetch(
        since=None, cursor={"after_id": 5}, max_items=10
    )
    assert result.findings == [] and result.cursor == {"after_id": 5}


def test_build_client_needs_url_and_token():
    assert (
        ingestion.build_client({"console_url": "https://q.test", "api_token": None})
        is None
    )
    assert ingestion.build_client({"console_url": None, "api_token": "t"}) is None
    assert (
        ingestion.build_client({"console_url": "https://q.test", "api_token": "t"})
        is not None
    )


def test_the_adapter_is_registered():
    from core.federation.registry import get_adapter

    assert get_adapter("qradar").name == "qradar"


# --- MCP tool -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_tools_are_read_only_and_answer(monkeypatch):
    from core.integrations.qradar import tool
    from core.llm.tool_effects import READ_ONLY, effect_of

    console = _Console([OFFENSE])
    monkeypatch.setattr(tool, "build_client", lambda cfg: _client(console))
    monkeypatch.setattr(tool, "qradar_config", lambda: {})
    names = [t.name for t in await tool.handle_list_tools()]
    assert names == ["qradar_list_offenses", "qradar_get_offense"]
    for name in names:
        assert effect_of(name) == READ_ONLY
    listed = json.loads(
        (await tool.handle_call_tool("qradar_list_offenses", {"max_results": 5}))[
            0
        ].text
    )
    assert listed["count"] == 1 and listed["offenses"][0]["finding_id"] == "qradar-4012"
    one = json.loads(
        (await tool.handle_call_tool("qradar_get_offense", {"offense_id": 4012}))[
            0
        ].text
    )
    assert one["offense"]["title"] == "Excessive Firewall Denies Between Hosts"


@pytest.mark.asyncio
async def test_the_tool_says_when_not_configured(monkeypatch):
    from core.integrations.qradar import tool

    monkeypatch.setattr(tool, "build_client", lambda cfg: None)
    monkeypatch.setattr(tool, "qradar_config", lambda: {})
    out = json.loads((await tool.handle_call_tool("qradar_list_offenses", {}))[0].text)
    assert out == {"error": "QRadar is not configured"}
