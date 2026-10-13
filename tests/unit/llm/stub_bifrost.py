"""A stand-in Bifrost on 127.0.0.1 for the local model lane tests.

Serves the OpenAI-format ``POST /v1/chat/completions`` that ``LLMRouter`` uses
and keeps every request body. The answer comes from ``responder(body)``, which
returns the assistant ``content`` string, or ``(status, json_body)`` to fail.
The default responder plays an Ollama model constrained by the request's JSON
schema: it reads the alert's lexical cues (the evalkit stub's scorer) and
answers with a schema-valid object.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Tuple, Union

Answer = Union[str, Tuple[int, Dict[str, Any]]]
Responder = Callable[[Dict[str, Any]], Answer]


def schema_answer(body: Dict[str, Any]) -> str:
    """A schema-valid assessment derived from the prompt (deterministic)."""
    from evalkit.backends import stub_answer

    prompt = "\n".join(
        str(m.get("content") or "") for m in body.get("messages") or []
    )
    fields = {}
    for line in stub_answer(prompt).splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return json.dumps(
        {
            "severity": fields["SEVERITY"],
            "confidence": float(fields["CONFIDENCE"]),
            "category": fields["CATEGORY"],
            "recommended_action": fields["RECOMMENDED_ACTION"],
            "reasoning": fields["REASONING"],
        }
    )


class StubBifrost:
    def __init__(self, responder: Responder = schema_answer):
        self.responder = responder
        self.requests: List[Dict[str, Any]] = []
        self.paths: List[str] = []
        self._lock = threading.Lock()
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # noqa: D401 — keep test output quiet
                pass

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                with stub._lock:
                    stub.requests.append(body)
                    stub.paths.append(self.path)
                if self.path.rstrip("/") != "/v1/chat/completions":
                    self._send(404, {"error": {"message": "not found"}})
                    return
                answer = stub.responder(body)
                if isinstance(answer, tuple):
                    self._send(*answer)
                    return
                self._send(
                    200,
                    {
                        "id": "chatcmpl-stub",
                        "object": "chat.completion",
                        "created": 0,
                        "model": body.get("model"),
                        "choices": [
                            {
                                "index": 0,
                                "finish_reason": "stop",
                                "message": {"role": "assistant", "content": answer},
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 100,
                            "completion_tokens": 20,
                            "total_tokens": 120,
                        },
                    },
                )

            def _send(self, status: int, payload: Dict[str, Any]) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "StubBifrost":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
