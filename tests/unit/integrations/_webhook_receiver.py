"""A local HTTP receiver for outbound webhook tests.

A real socket on 127.0.0.1 in a background thread, so a test exercises the
actual HTTP path (connect, headers, body) and works the same from sync code,
async code and a TestClient-driven app.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List


@dataclass
class Received:
    path: str
    headers: Dict[str, str]
    body: bytes


@dataclass
class Receiver:
    server: ThreadingHTTPServer
    requests: List[Received] = field(default_factory=list)
    # Statuses answered in turn; the last one repeats.
    statuses: List[int] = field(default_factory=lambda: [200])
    headers_out: Dict[str, str] = field(default_factory=dict)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def url(self, path: str = "/hook", host: str = "127.0.0.1") -> str:
        return f"http://{host}:{self.port}{path}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def start_receiver() -> Receiver:
    holder: Dict[str, Receiver] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - http.server API
            receiver = holder["r"]
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            receiver.requests.append(
                Received(self.path, {k: v for k, v in self.headers.items()}, body)
            )
            index = min(len(receiver.requests) - 1, len(receiver.statuses) - 1)
            self.send_response(receiver.statuses[index])
            for key, value in receiver.headers_out.items():
                self.send_header(key, value)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):  # keep test output quiet
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    receiver = Receiver(server)
    holder["r"] = receiver
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return receiver
