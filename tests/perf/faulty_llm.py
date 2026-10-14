"""A stub model endpoint whose behaviour can be switched at run time.

Built on the air-gap stub (``tests/airgap/stub_llm.py``): the same
OpenAI/Anthropic-compatible answers, plus a fault mode for the chaos scenarios:

``ok``     answer normally (the air-gap stub's fixed verdict)
``error``  answer every model call with HTTP 503 (provider outage)
``hang``   hold every model call open for ``hang_seconds`` and then drop it
           (provider timeout)
``slow``   wait ``delay_seconds`` and then answer normally (slow vendor)

Only model calls (``/chat/completions``, ``/messages``) are faulted; health and
model-list requests keep answering, as a gateway in front of a dead provider
does.
"""

from __future__ import annotations

import threading
import time
from http.server import ThreadingHTTPServer
from typing import Dict

from tests.airgap.stub_llm import StubLLM, _Handler

MODES = ("ok", "error", "hang", "slow")
_MODEL_PATHS = ("/chat/completions", "/messages")


class _FaultyHandler(_Handler):
    server: "FaultyLLM"  # type: ignore[assignment]

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if not path.endswith(_MODEL_PATHS):
            return super().do_POST()
        mode, delay, hang = self.server.fault()
        self.server.count(mode)
        if mode == "error":
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            self.server.requests.append(("POST", self.path, {"fault": "error"}))
            return self._send(
                503, {"error": {"message": "provider unavailable (chaos stub)"}}
            )
        if mode == "hang":
            time.sleep(hang)
            self.close_connection = True
            return None
        if mode == "slow":
            time.sleep(delay)
        return super().do_POST()


class FaultyLLM(StubLLM):
    """``StubLLM`` with a switchable fault mode; thread-safe."""

    def __init__(self, port: int = 0):
        ThreadingHTTPServer.__init__(self, ("127.0.0.1", port), _FaultyHandler)
        self.requests = []
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._lock = threading.Lock()
        self._mode = "ok"
        self._delay = 0.0
        self._hang = 120.0
        self.counts: Dict[str, int] = {m: 0 for m in MODES}

    def set_mode(
        self, mode: str, *, delay_seconds: float = 0.0, hang_seconds: float = 120.0
    ) -> None:
        if mode not in MODES:
            raise ValueError(f"unknown fault mode {mode!r}; one of {MODES}")
        with self._lock:
            self._mode = mode
            self._delay = float(delay_seconds)
            self._hang = float(hang_seconds)

    @property
    def mode(self) -> str:
        with self._lock:
            return self._mode

    def fault(self):
        with self._lock:
            return self._mode, self._delay, self._hang

    def count(self, mode: str) -> None:
        with self._lock:
            self.counts[mode] = self.counts.get(mode, 0) + 1
