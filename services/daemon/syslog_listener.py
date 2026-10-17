"""Syslog listener in the SOC daemon (W0.41): TCP, TLS and UDP.

Off by default (``DAEMON_SYSLOG_ENABLED``). Syslog carries no credential, so
a connection or datagram is read only from an address in
``DAEMON_SYSLOG_ALLOWED_SOURCES`` (comma-separated CIDRs); with the list
empty every sender is refused. With ``DAEMON_SYSLOG_TLS_CERT`` and
``DAEMON_SYSLOG_TLS_KEY`` the TCP port speaks TLS (RFC 5425), and with
``DAEMON_SYSLOG_TLS_CLIENT_CA`` it also asks for a client certificate signed
by that CA.

TCP framing is RFC 6587: octet counting (``LEN SP MSG``) when a frame starts
with a digit, else one message per line. Lines are parsed by
core/ingestion/syslog_formats.py and admitted like webhook findings
(:meth:`services.daemon.poller.DataPoller.ingest_syslog_lines`): into the
spool, or straight to the processor without one.

Back-pressure: on TCP a batch the spool cannot take is retried and the
connection is not read meanwhile, so the sender's own queue holds the lines.
UDP has nothing to push back on; a datagram that cannot be taken is counted
under ``dropped``. UDP is off unless ``DAEMON_SYSLOG_UDP_PORT`` is set.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
from typing import List, Optional, Sequence

from core.ingestion.syslog_formats import MAX_LINE_BYTES
from services.daemon.config import Network, SyslogConfig

logger = logging.getLogger(__name__)

# Lines per hand-off, and how long a partial batch waits for more.
BATCH_LINES = 500
BATCH_SECONDS = 0.5
# A TCP batch the spool refused is retried after this long.
RETRY_SECONDS = 2.0
MAX_CONNECTIONS = 256
IDLE_TIMEOUT = 600.0


def is_allowed(peer: Optional[str], allowed: Sequence[Network]) -> bool:
    if not peer:
        return False
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address in net for net in allowed)


def tls_context(config: SyslogConfig) -> Optional[ssl.SSLContext]:
    if not config.tls_cert and not config.tls_key:
        return None
    if not (config.tls_cert and config.tls_key):
        raise ValueError("DAEMON_SYSLOG_TLS_CERT and DAEMON_SYSLOG_TLS_KEY go together")
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(config.tls_cert, config.tls_key)
    if config.tls_client_ca:
        ctx.load_verify_locations(config.tls_client_ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class FrameError(Exception):
    pass


async def read_frame(reader: asyncio.StreamReader) -> Optional[str]:
    """One RFC 6587 frame, None at end of stream."""
    first = await reader.read(1)
    if not first:
        return None
    if first.isdigit():
        digits = first
        while True:
            ch = await reader.read(1)
            if not ch:
                return None
            if ch == b" ":
                break
            if not ch.isdigit() or len(digits) >= 7:
                # Not octet counting after all: the rest of the line is the frame.
                rest = await _read_line(reader)
                return (digits + ch).decode("utf-8", "replace") + (rest or "")
            digits += ch
        size = int(digits)
        if size > MAX_LINE_BYTES:
            # Read and drop it: the stream stays in step.
            remaining = size
            while remaining:
                chunk = await reader.read(min(remaining, 65536))
                if not chunk:
                    return None
                remaining -= len(chunk)
            raise FrameError(f"frame of {size} bytes over {MAX_LINE_BYTES}")
        data = await reader.readexactly(size)
        return data.decode("utf-8", "replace")
    rest = await _read_line(reader)
    return first.decode("utf-8", "replace") + (rest or "")


async def _read_line(reader: asyncio.StreamReader) -> Optional[str]:
    try:
        data = await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as e:
        data = e.partial
    except asyncio.LimitOverrunError:
        # Over the reader limit: drop up to the next newline.
        while True:
            try:
                await reader.readuntil(b"\n")
                break
            except asyncio.LimitOverrunError as e:
                await reader.readexactly(e.consumed)
            except asyncio.IncompleteReadError:
                break
        raise FrameError("line over the reader limit") from None
    return data.decode("utf-8", "replace").rstrip("\r\n")


class SyslogListener:
    """Hosts the TCP/TLS and UDP syslog ports for a :class:`DataPoller`."""

    def __init__(self, config: SyslogConfig, poller) -> None:
        self.config = config
        self.poller = poller
        self._connections = 0
        self._writers: set = set()

    @property
    def stats(self):
        return self.poller.stats["syslog"]

    async def run(self, shutdown_event: asyncio.Event) -> None:
        cfg = self.config
        if not cfg.allowed_sources:
            logger.warning(
                "Syslog listener enabled with DAEMON_SYSLOG_ALLOWED_SOURCES empty: "
                "every sender is refused"
            )
        servers = []
        transport = None
        try:
            ctx = tls_context(cfg)
            if cfg.tcp_port:
                servers.append(
                    await asyncio.start_server(
                        self._serve_tcp,
                        cfg.bind_host,
                        cfg.tcp_port,
                        ssl=ctx,
                        limit=MAX_LINE_BYTES + 1024,
                    )
                )
                logger.info(
                    "Syslog listener on %s/tcp%s", cfg.tcp_port, " (TLS)" if ctx else ""
                )
            if cfg.udp_port:
                loop = asyncio.get_running_loop()
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _Datagrams(self), local_addr=(cfg.bind_host, cfg.udp_port)
                )
                logger.info("Syslog listener on %s/udp", cfg.udp_port)
        except (OSError, ValueError, ssl.SSLError) as e:
            # The rest of the daemon keeps running, as when the webhook cannot bind.
            logger.error("Syslog listener not started: %s", e)
            for server in servers:
                server.close()
            return
        try:
            await shutdown_event.wait()
        finally:
            for server in servers:
                server.close()
            # wait_closed waits for open connections too: end them first.
            for writer in list(self._writers):
                writer.close()
            for server in servers:
                try:
                    await asyncio.wait_for(server.wait_closed(), timeout=5)
                except asyncio.TimeoutError:
                    logger.warning("Syslog listener: connections still open at stop")
            if transport is not None:
                transport.close()
            logger.info("Syslog listener stopped")

    async def _serve_tcp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peername = writer.get_extra_info("peername")
        peer = peername[0] if peername else None
        if not is_allowed(peer, self.config.allowed_sources) or (
            self._connections >= MAX_CONNECTIONS
        ):
            self.stats["refused"] += 1
            logger.warning("Syslog connection from %s refused", peer)
            writer.close()
            return
        self._connections += 1
        self._writers.add(writer)
        # The reader fills a bounded queue; the batcher drains it. A timeout
        # only ever cancels a queue get, never a half-read frame, and a held
        # batch stops the reader once the queue is full (back-pressure).
        frames: asyncio.Queue = asyncio.Queue(maxsize=BATCH_LINES * 2)
        pump = asyncio.ensure_future(self._pump(reader, frames, peer))
        batch: List[str] = []
        try:
            while True:
                try:
                    frame = await asyncio.wait_for(
                        frames.get(), timeout=BATCH_SECONDS if batch else None
                    )
                except asyncio.TimeoutError:
                    await self._flush(batch, peer)
                    batch = []
                    continue
                if frame is None:
                    break
                batch.append(frame)
                if len(batch) >= BATCH_LINES:
                    await self._flush(batch, peer)
                    batch = []
            if batch:
                await self._flush(batch, peer)
        finally:
            pump.cancel()
            self._connections -= 1
            self._writers.discard(writer)
            writer.close()

    async def _pump(
        self, reader: asyncio.StreamReader, frames: asyncio.Queue, peer: Optional[str]
    ) -> None:
        try:
            while True:
                try:
                    frame = await asyncio.wait_for(read_frame(reader), IDLE_TIMEOUT)
                except FrameError as e:
                    self.stats["dropped"] += 1
                    logger.warning("Syslog frame from %s dropped: %s", peer, e)
                    continue
                if frame is None:
                    break
                if frame.strip():
                    await frames.put(frame)
        except asyncio.TimeoutError:
            logger.info("Syslog connection from %s idle, closed", peer)
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError) as e:
            logger.info("Syslog connection from %s ended: %s", peer, e)
        finally:
            await frames.put(None)

    async def _flush(self, batch: List[str], peer: Optional[str]) -> None:
        """Admit ``batch``; keep retrying (and not reading) until it is taken."""
        while True:
            _, _, why = await self.poller.ingest_syslog_lines(batch, peer, "syslog")
            if why is None:
                return
            logger.warning("Syslog batch from %s held: %s", peer, why)
            await asyncio.sleep(RETRY_SECONDS)
            # Lines already taken are skipped as duplicates on the retry.

    def datagram(self, data: bytes, peer: Optional[str]) -> None:
        if not is_allowed(peer, self.config.allowed_sources):
            self.stats["refused"] += 1
            return
        lines = [
            line
            for line in data[:MAX_LINE_BYTES].decode("utf-8", "replace").split("\n")
            if line.strip()
        ]
        if lines:
            asyncio.ensure_future(self._datagram_lines(lines, peer))

    async def _datagram_lines(self, lines: List[str], peer: Optional[str]) -> None:
        taken, unparsed, why = await self.poller.ingest_syslog_lines(
            lines, peer, "syslog"
        )
        if why is not None:
            self.stats["dropped"] += max(len(lines) - unparsed - taken, 0)


class _Datagrams(asyncio.DatagramProtocol):
    def __init__(self, listener: SyslogListener) -> None:
        self.listener = listener

    def datagram_received(self, data: bytes, addr) -> None:
        self.listener.datagram(data, addr[0] if addr else None)
