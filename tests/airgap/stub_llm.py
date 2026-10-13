"""A stand-in model endpoint on localhost for the air-gap runtime test.

It plays Bifrost's part: an OpenAI-compatible ``/v1/chat/completions``, an
Anthropic ``/v1/messages`` (``/anthropic/v1/messages`` too), and a ``200 {}``
for anything else (health, admin, model lists). Every request is kept in
``requests`` so the test can show the model was actually asked.

Answers are a fixed triage verdict in JSON, which both free-text and
JSON-expecting callers can use.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List, Tuple

VERDICT = json.dumps(
    {
        "verdict": "suspicious",
        "severity": "medium",
        "confidence": 0.6,
        "summary": "Stub model answer (air-gap test).",
        "reasoning": "Stub model answer (air-gap test).",
        "recommended_actions": ["Review the activity with the asset owner."],
        "mitre_techniques": [],
    }
)


def _openai_body(model: str) -> dict:
    return {
        "id": "chatcmpl-airgap",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model or "stub",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": VERDICT},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
    }


def _anthropic_body(model: str) -> dict:
    return {
        "id": "msg_airgap",
        "type": "message",
        "role": "assistant",
        "model": model or "stub",
        "content": [{"type": "text", "text": VERDICT}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 10},
    }


class _Handler(BaseHTTPRequestHandler):
    server: "StubLLM"  # type: ignore[assignment]

    def log_message(self, *args):  # quiet
        pass

    def _send(self, status: int, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _sse(self, events: List[Tuple[str, dict]]):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for name, payload in events:
            if name:
                self.wfile.write(f"event: {name}\n".encode())
            self.wfile.write(f"data: {json.dumps(payload)}\n\n".encode())
        self.wfile.flush()

    def do_GET(self):
        self.server.requests.append(("GET", self.path, None))
        if self.path.rstrip("/").endswith("/models"):
            self._send(
                200, {"object": "list", "data": [{"id": "stub", "object": "model"}]}
            )
        else:
            self._send(200, {"status": "ok"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        self.server.requests.append(("POST", self.path, body))
        model = body.get("model", "") if isinstance(body, dict) else ""
        path = self.path.split("?", 1)[0]
        stream = isinstance(body, dict) and body.get("stream")
        if path.endswith("/chat/completions"):
            if stream:
                chunk = _openai_body(model)
                delta = {
                    "id": chunk["id"],
                    "object": "chat.completion.chunk",
                    "created": chunk["created"],
                    "model": chunk["model"],
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": VERDICT},
                            "finish_reason": "stop",
                        }
                    ],
                }
                self._sse([("", delta)])
                self.wfile.write(b"data: [DONE]\n\n")
            else:
                self._send(200, _openai_body(model))
        elif path.endswith("/messages"):
            if stream:
                msg = _anthropic_body(model)
                msg_start = dict(
                    msg, content=[], usage={"input_tokens": 10, "output_tokens": 0}
                )
                self._sse(
                    [
                        (
                            "message_start",
                            {"type": "message_start", "message": msg_start},
                        ),
                        (
                            "content_block_start",
                            {
                                "type": "content_block_start",
                                "index": 0,
                                "content_block": {"type": "text", "text": ""},
                            },
                        ),
                        (
                            "content_block_delta",
                            {
                                "type": "content_block_delta",
                                "index": 0,
                                "delta": {"type": "text_delta", "text": VERDICT},
                            },
                        ),
                        (
                            "content_block_stop",
                            {"type": "content_block_stop", "index": 0},
                        ),
                        (
                            "message_delta",
                            {
                                "type": "message_delta",
                                "delta": {
                                    "stop_reason": "end_turn",
                                    "stop_sequence": None,
                                },
                                "usage": {"output_tokens": 10},
                            },
                        ),
                        ("message_stop", {"type": "message_stop"}),
                    ]
                )
            else:
                self._send(200, _anthropic_body(model))
        elif path.endswith("/count_tokens"):
            self._send(200, {"input_tokens": 10})
        else:
            self._send(200, {"status": "ok"})


class StubLLM(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.requests: list = []
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def start(self) -> "StubLLM":
        self._thread.start()
        return self

    def stop(self) -> None:
        self.shutdown()
        self.server_close()

    def model_calls(self) -> list:
        return [
            r
            for r in self.requests
            if r[0] == "POST"
            and r[1].split("?", 1)[0].endswith(("/chat/completions", "/messages"))
        ]
