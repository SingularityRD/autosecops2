"""The daemon's syslog listener and ``POST /ingest/syslog`` (W0.41)."""

from __future__ import annotations

import asyncio
import ipaddress
import shutil
import socket
import ssl
import subprocess

import pytest
from aiohttp.test_utils import TestClient, TestServer

from core.ingestion.spool import IngestSpool
from services.daemon.config import (
    DaemonConfig,
    PollingConfig,
    SyslogConfig,
    parse_allowed_sources,
)
from services.daemon.poller import DataPoller
from services.daemon.syslog_listener import SyslogListener, is_allowed, read_frame

pytestmark = pytest.mark.unit

TOKEN = "t0ken"
CEF = "<134>Mar  2 08:00:00 fw CEF:0|Acme|NGFW|1|42|Blocked C2|8|src=10.0.0.1 dst=203.0.113.5"
LOCAL = parse_allowed_sources("127.0.0.0/8,::1")


class _Dedup:
    def __init__(self):
        self.processed: set = set()

    async def is_processed(self, key: str) -> bool:
        return key in self.processed

    async def mark_processed(self, key: str) -> None:
        self.processed.add(key)


def _poller(spool=None) -> DataPoller:
    poller = DataPoller(PollingConfig(webhook_token=TOKEN))
    poller._webhook_dedup = _Dedup()  # type: ignore[assignment]
    poller.set_output_queue(asyncio.Queue(maxsize=10))
    poller.set_spool(spool)
    return poller


def _spool(path, **kw) -> IngestSpool:
    spool = IngestSpool(path, **kw)
    spool.open()
    return spool


def _free_port(kind=socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _until(predicate, timeout=5.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.02)


async def _closed(reader):
    """The listener closed the connection: EOF, or a reset if data was unread."""
    try:
        assert await asyncio.wait_for(reader.read(), timeout=5) == b""
    except ConnectionResetError:
        pass


class _Running:
    def __init__(self, listener):
        self.listener = listener
        self.stop = asyncio.Event()

    async def __aenter__(self):
        self.task = asyncio.ensure_future(self.listener.run(self.stop))
        await asyncio.sleep(0.1)
        return self

    async def __aexit__(self, *exc):
        self.stop.set()
        await asyncio.wait_for(self.task, timeout=10)


def _config(**kw) -> SyslogConfig:
    base = dict(
        enabled=True,
        bind_host="127.0.0.1",
        tcp_port=_free_port(),
        allowed_sources=LOCAL,
    )
    base.update(kw)
    return SyslogConfig(**base)


# --- configuration ------------------------------------------------------------


def test_allowed_sources_parse_and_match():
    nets = parse_allowed_sources(" 10.0.0.0/8 , 192.0.2.7,2001:db8::/32 ")
    assert ipaddress.ip_network("192.0.2.7/32") in nets
    assert is_allowed("10.1.2.3", nets)
    assert is_allowed("::ffff:10.1.2.3", nets)  # v4-mapped
    assert is_allowed("2001:db8::1", nets)
    assert not is_allowed("192.0.2.8", nets)
    assert not is_allowed(None, nets)
    assert not is_allowed("10.0.0.1", ())
    with pytest.raises(ValueError, match="DAEMON_SYSLOG_ALLOWED_SOURCES"):
        parse_allowed_sources("10.0.0.0/8,not-a-net")


def test_daemon_config_reads_the_syslog_settings(monkeypatch):
    monkeypatch.setenv("DAEMON_SYSLOG_ENABLED", "true")
    monkeypatch.setenv("DAEMON_SYSLOG_TCP_PORT", "6514")
    monkeypatch.setenv("DAEMON_SYSLOG_ALLOWED_SOURCES", "10.0.0.0/8")
    from core.config import get_settings

    get_settings.cache_clear()
    try:
        cfg = DaemonConfig.from_env().syslog
    finally:
        get_settings.cache_clear()
    assert cfg.enabled and cfg.tcp_port == 6514 and cfg.udp_port == 0
    assert cfg.allowed_sources == (ipaddress.ip_network("10.0.0.0/8"),)


def test_syslog_is_off_by_default():
    assert SyslogConfig().enabled is False
    assert SyslogConfig().udp_port == 0
    assert SyslogConfig().allowed_sources == ()


# --- framing ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_octet_counting_and_newline_frames():
    reader = asyncio.StreamReader()
    reader.feed_data(b"11 <13>hello w<13>line two\r\n123456789 long digits\n")
    reader.feed_eof()
    assert await read_frame(reader) == "<13>hello w"
    assert await read_frame(reader) == "<13>line two"
    # Too many digits for a count: the line is the frame.
    assert await read_frame(reader) == "123456789 long digits"
    assert await read_frame(reader) is None


@pytest.mark.asyncio
async def test_octet_counting_reads_exactly_the_count():
    reader = asyncio.StreamReader()
    body = CEF.encode()
    reader.feed_data(f"{len(body)} ".encode() + body + f"{len(body)} ".encode() + body)
    reader.feed_eof()
    assert await read_frame(reader) == CEF
    assert await read_frame(reader) == CEF
    assert await read_frame(reader) is None


# --- TCP ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tcp_lines_land_in_the_spool(tmp_path):
    spool = _spool(tmp_path)
    poller = _poller(spool)
    cfg = _config()
    async with _Running(SyslogListener(cfg, poller)):
        _, writer = await asyncio.open_connection("127.0.0.1", cfg.tcp_port)
        writer.write((CEF + "\n").encode())
        writer.write(b"<30>Mar  2 08:00:00 host sshd[1]: not an alert\n")
        body = CEF.replace("10.0.0.1", "10.0.0.2").encode()
        writer.write(f"{len(body)} ".encode() + body)
        await writer.drain()
        writer.close()
        await _until(lambda: poller.stats["syslog"]["findings"] == 2)
    claimed = spool.claim(10)
    assert len(claimed) == 2
    assert {e.finding["data_source"] for e in claimed} == {"syslog"}
    assert poller.stats["syslog"]["unparsed"] == 1
    assert poller.stats["syslog"]["lines"] == 3


@pytest.mark.asyncio
async def test_a_sender_outside_the_allowlist_is_refused(tmp_path):
    spool = _spool(tmp_path)
    poller = _poller(spool)
    cfg = _config(allowed_sources=parse_allowed_sources("192.0.2.0/24"))
    async with _Running(SyslogListener(cfg, poller)):
        reader, writer = await asyncio.open_connection("127.0.0.1", cfg.tcp_port)
        writer.write((CEF + "\n").encode())
        await writer.drain()
        await _closed(reader)
        writer.close()
    assert poller.stats["syslog"]["refused"] == 1
    assert spool.claim(10) == []


@pytest.mark.asyncio
async def test_an_empty_allowlist_refuses_everyone(tmp_path):
    poller = _poller(_spool(tmp_path))
    cfg = _config(allowed_sources=())
    async with _Running(SyslogListener(cfg, poller)):
        reader, writer = await asyncio.open_connection("127.0.0.1", cfg.tcp_port)
        await _closed(reader)
        writer.close()
    assert poller.stats["syslog"]["refused"] == 1


@pytest.mark.asyncio
async def test_a_full_spool_holds_the_batch_and_takes_it_once_there_is_room(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("services.daemon.syslog_listener.RETRY_SECONDS", 0.05)
    spool = _spool(tmp_path, max_findings=1)
    spool.append([{"finding_id": "already-there"}], "webhook")
    poller = _poller(spool)
    cfg = _config()
    async with _Running(SyslogListener(cfg, poller)):
        _, writer = await asyncio.open_connection("127.0.0.1", cfg.tcp_port)
        writer.write((CEF + "\n").encode())
        await writer.drain()
        await _until(lambda: poller.stats["webhook_busy"] >= 2)
        assert poller.stats["syslog"]["findings"] == 0
        # The processor drains the spool; the held batch goes in.
        for entry in spool.claim(10):
            spool.done(entry)
        await _until(lambda: poller.stats["syslog"]["findings"] == 1)
        writer.close()
    assert poller.stats["syslog"]["dropped"] == 0


# --- TLS ------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
async def test_tls_listener(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    spool = _spool(tmp_path / "spool")
    poller = _poller(spool)
    cfg = _config(tls_cert=str(cert), tls_key=str(key))
    client = ssl.create_default_context(cafile=str(cert))
    client.check_hostname = False
    async with _Running(SyslogListener(cfg, poller)):
        _, writer = await asyncio.open_connection("127.0.0.1", cfg.tcp_port, ssl=client)
        writer.write((CEF + "\n").encode())
        await writer.drain()
        await _until(lambda: poller.stats["syslog"]["findings"] == 1)
        writer.close()
        # Plain TCP to a TLS port carries nothing in.
        _, plain = await asyncio.open_connection("127.0.0.1", cfg.tcp_port)
        plain.write((CEF.replace("10.0.0.1", "10.0.0.3") + "\n").encode())
        await plain.drain()
        await asyncio.sleep(0.3)
        plain.close()
    assert poller.stats["syslog"]["findings"] == 1


def test_tls_needs_both_cert_and_key():
    from services.daemon.syslog_listener import tls_context

    with pytest.raises(ValueError):
        tls_context(SyslogConfig(tls_cert="/x.pem"))
    assert tls_context(SyslogConfig()) is None


# --- UDP ------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_udp_datagrams(tmp_path):
    spool = _spool(tmp_path)
    poller = _poller(spool)
    cfg = _config(tcp_port=0, udp_port=_free_port(socket.SOCK_DGRAM))
    async with _Running(SyslogListener(cfg, poller)):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(CEF.encode(), ("127.0.0.1", cfg.udp_port))
        await _until(lambda: poller.stats["syslog"]["findings"] == 1)
    assert len(spool.claim(10)) == 1


@pytest.mark.asyncio
async def test_a_port_in_use_does_not_raise(tmp_path, caplog):
    poller = _poller(_spool(tmp_path))
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        cfg = _config(tcp_port=busy.getsockname()[1])
        stop = asyncio.Event()
        await asyncio.wait_for(SyslogListener(cfg, poller).run(stop), timeout=5)
    assert "Syslog listener not started" in caplog.text


# --- HTTP ------------------------------------------------------------------------


async def _post_lines(poller, text, token=TOKEN):
    async with TestClient(TestServer(poller._webhook_app())) as client:
        resp = await client.post(
            "/ingest/syslog",
            data=text.encode(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"},
        )
        return resp.status, await resp.json()


@pytest.mark.asyncio
async def test_http_syslog_lines(tmp_path):
    spool = _spool(tmp_path)
    poller = _poller(spool)
    text = (
        "\n".join([CEF, "plain chatter", CEF, CEF.replace("10.0.0.1", "10.0.0.9")])
        + "\n"
    )
    status, body = await _post_lines(poller, text)
    assert status == 200
    assert body == {"status": "ok", "ingested": 2, "unparsed": 1}
    # A re-send of the same lines is not stored twice.
    status, body = await _post_lines(poller, text)
    assert (status, body["ingested"]) == (200, 0)
    assert len(spool.claim(10)) == 2


@pytest.mark.asyncio
async def test_http_syslog_needs_the_token(tmp_path):
    poller = _poller(_spool(tmp_path))
    status, _ = await _post_lines(poller, CEF, token="wrong")
    assert status == 401
    poller.config.webhook_token = ""
    status, _ = await _post_lines(poller, CEF, token="")
    assert status == 503


@pytest.mark.asyncio
async def test_http_syslog_full_spool_is_503(tmp_path):
    spool = _spool(tmp_path, max_findings=1)
    spool.append([{"finding_id": "x"}], "webhook")
    poller = _poller(spool)
    async with TestClient(TestServer(poller._webhook_app())) as client:
        resp = await client.post(
            "/ingest/syslog",
            data=CEF.encode(),
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        assert resp.status == 503
        assert resp.headers["Retry-After"]


@pytest.mark.asyncio
async def test_http_syslog_body_limit(tmp_path, monkeypatch):
    monkeypatch.setattr("services.daemon.poller._SYSLOG_BODY_MAX", 100)
    poller = _poller(_spool(tmp_path))
    status, _ = await _post_lines(poller, CEF * 5)
    assert status == 413
