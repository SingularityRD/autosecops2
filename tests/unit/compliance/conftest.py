"""Local receivers and a throwaway CA for the audit export tests (WP w3.6)."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import ssl
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass
class Pki:
    ca_pem: str
    cert_path: Path
    key_path: Path

    def server_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(self.cert_path), str(self.key_path))
        return ctx


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_pki(directory: Path, cn: str = "audit-test-ca") -> Pki:
    """A self-signed CA and a server certificate for 127.0.0.1/localhost."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("localhost"))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / "server.crt"
    key_path = directory / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return Pki(
        ca_pem=ca.public_bytes(serialization.Encoding.PEM).decode(),
        cert_path=cert_path,
        key_path=key_path,
    )


@pytest.fixture
def pki(tmp_path) -> Pki:
    return make_pki(tmp_path / "pki")


@pytest.fixture
def other_pki(tmp_path) -> Pki:
    return make_pki(tmp_path / "other-pki", cn="someone-else")


# ---------------------------------------------------------------------------
# Syslog receiver (TLS / TCP with RFC 5425 octet counting, or UDP)
# ---------------------------------------------------------------------------


class SyslogReceiver:
    def __init__(self, ssl_ctx: Optional[ssl.SSLContext] = None) -> None:
        self.ssl_ctx = ssl_ctx
        self.messages: list[bytes] = []
        self.port = 0
        self._server: Optional[asyncio.base_events.Server] = None
        self._writers: set = set()
        self.arrived = asyncio.Event()

    async def _handle(self, reader: asyncio.StreamReader, writer) -> None:
        self._writers.add(writer)
        try:
            while True:
                length = b""
                while True:
                    ch = await reader.read(1)
                    if not ch:
                        return
                    if ch == b" ":
                        break
                    length += ch
                self.messages.append(await reader.readexactly(int(length)))
                self.arrived.set()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            return
        finally:
            self._writers.discard(writer)
            writer.close()

    async def start(self, port: int = 0) -> "SyslogReceiver":
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", port, ssl=self.ssl_ctx
        )
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            # Python 3.12's wait_closed() also waits for open client links.
            for writer in list(self._writers):
                writer.transport.abort()
            await asyncio.wait_for(self._server.wait_closed(), timeout=5)
            self._server = None

    async def wait_for(self, count: int, timeout: float = 10.0) -> None:
        async def _until() -> None:
            while len(self.messages) < count:
                self.arrived.clear()
                await self.arrived.wait()

        await asyncio.wait_for(_until(), timeout)


class UdpReceiver(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.messages: list[bytes] = []
        self.transport = None
        self.port = 0

    def datagram_received(self, data, addr) -> None:
        self.messages.append(data)

    async def start(self) -> "UdpReceiver":
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self, local_addr=("127.0.0.1", 0)
        )
        self.port = self.transport.get_extra_info("sockname")[1]
        return self

    def stop(self) -> None:
        if self.transport is not None:
            self.transport.close()


# ---------------------------------------------------------------------------
# HTTP receiver (threaded, optionally TLS)
# ---------------------------------------------------------------------------


@dataclass
class HttpReceiver:
    ssl_ctx: Optional[ssl.SSLContext] = None
    requests: list[dict] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)  # consumed first; then 200
    port: int = 0
    _server: Optional[ThreadingHTTPServer] = None
    _thread: Optional[threading.Thread] = None

    def start(self) -> "HttpReceiver":
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server API
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                code = receiver.statuses.pop(0) if receiver.statuses else 200
                if code < 300:
                    receiver.requests.append(
                        {"headers": dict(self.headers), "body": body, "path": self.path}
                    )
                self.send_response(code)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):  # silence
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if self.ssl_ctx is not None:
            self._server.socket = self.ssl_ctx.wrap_socket(
                self._server.socket, server_side=True
            )
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
