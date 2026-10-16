"""A tiny stand-in for the AutoSecOps endpoints the staging scripts call.

Only what smoke.sh / seed-demo.sh / replay.sh touch, with the same paths,
methods, status codes and body shapes as the real routers:

  GET  /api/health, /api/health/ready      services/api/main.py
  GET  /api/auth/bootstrap, POST ...       services/api/routers/auth.py
  POST /api/auth/login                     (username_or_email, password)
  POST /api/ingest/ingest-string           multipart: data, format, data_type
  GET  /api/v1/findings/{id}               core/api/v1/findings_router.py

"Triage" stands in for the daemon + local model: after ``triage_after`` reads
of a finding, ``ai_enrichment.ai_triage`` appears (mode "triage"), never
appears ("never"), or an ``ai_triage_error`` is recorded ("error").
"""

from __future__ import annotations

import email.parser
import email.policy
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional


class FakeState:
    def __init__(self, mode: str = "triage", triage_after: int = 1, healthy: bool = True,
                 auth_bypassed: bool = False):
        self.mode = mode
        self.triage_after = triage_after
        self.healthy = healthy
        self.auth_bypassed = auth_bypassed
        self.users: Dict[str, Dict[str, str]] = {}
        # The first-admin setup token the real route demands (W0.33).
        self.setup_token = "fake-setup-token-for-staging-tests"
        self.setup_tokens_seen: list = []
        self.tokens: set = set()
        self.findings: Dict[str, Dict[str, Any]] = {}
        self.reads: Dict[str, int] = {}
        self.requests: List[str] = []
        self.auth_headers: List[str] = []
        self.lock = threading.Lock()


def _parse_multipart(content_type: str, body: bytes) -> Dict[str, str]:
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
    )
    fields = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        fields[name] = part.get_payload(decode=True).decode("utf-8")
    return fields


def make_handler(state: FakeState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # quiet
            pass

        def _send(self, code: int, doc: Any) -> None:
            body = json.dumps(doc).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def _authed(self) -> bool:
            h = self.headers.get("Authorization") or ""
            state.auth_headers.append(h)
            return h.startswith("Bearer ") and h[7:] in state.tokens

        def do_GET(self):  # noqa: N802
            state.requests.append(f"GET {self.path}")
            if self.path in ("/api/health", "/api/health/ready"):
                return self._send(200, {
                    "status": "healthy" if state.healthy else "degraded",
                    "version": "0.0.0-fake", "demo_mode": False,
                    "auth_bypassed": state.auth_bypassed,
                })
            if self.path == "/api/auth/bootstrap":
                return self._send(200, {"required": not state.users})
            if self.path.startswith("/api/v1/findings/"):
                if not self._authed():
                    return self._send(401, {"detail": "Not authenticated"})
                fid = self.path.rsplit("/", 1)[1]
                with state.lock:
                    f = state.findings.get(fid)
                    if f is None:
                        return self._send(404, {"detail": "Finding not found"})
                    state.reads[fid] = state.reads.get(fid, 0) + 1
                    if state.reads[fid] > state.triage_after:
                        if state.mode == "triage":
                            f["ai_enrichment"] = {"ai_triage": {
                                "timestamp": "2026-10-13T00:00:00",
                                "result": {"recommended_action": "investigate",
                                           "confidence": 0.8, "severity": "high"}}}
                        elif state.mode == "error":
                            f["ai_enrichment"] = {"ai_triage_error": "LLM gateway unavailable"}
                    return self._send(200, f)
            return self._send(404, {"detail": "Not Found"})

        def do_POST(self):  # noqa: N802
            state.requests.append(f"POST {self.path}")
            body = self._body()
            if self.path == "/api/auth/bootstrap":
                if state.users:
                    return self._send(403, {"detail": "An account already exists."})
                state.setup_tokens_seen.append(self.headers.get("X-Setup-Token") or "")
                if self.headers.get("X-Setup-Token") != state.setup_token:
                    return self._send(401, {"detail": "Setup token missing or wrong."})
                doc = json.loads(body)
                if len(doc.get("password", "")) < 12:
                    return self._send(400, {"detail": "weak"})
                state.users[doc["username"]] = doc
                return self._send(201, {"username": doc["username"]})
            if self.path == "/api/auth/login":
                doc = json.loads(body)
                user = state.users.get(doc.get("username_or_email"))
                if not user or user["password"] != doc.get("password"):
                    return self._send(401, {"detail": "Incorrect username or password"})
                tok = secrets.token_hex(16)
                state.tokens.add(tok)
                return self._send(200, {"access_token": tok, "refresh_token": "r",
                                        "token_type": "bearer", "user": {}})
            if self.path == "/api/ingest/ingest-string":
                if not self._authed():
                    return self._send(401, {"detail": "Not authenticated"})
                fields = _parse_multipart(self.headers["Content-Type"], body)
                assert fields.get("format") == "jsonl" and fields.get("data_type") == "finding"
                imported = skipped = 0
                with state.lock:
                    for line in fields["data"].splitlines():
                        if not line.strip():
                            continue
                        f = json.loads(line)
                        if f["finding_id"] in state.findings:
                            skipped += 1
                        else:
                            state.findings[f["finding_id"]] = f
                            imported += 1
                return self._send(200, {
                    "findings_total": imported + skipped, "findings_imported": imported,
                    "findings_skipped": skipped, "findings_errors": 0,
                    "cases_total": 0, "cases_imported": 0, "cases_skipped": 0,
                    "cases_errors": 0, "success": imported + skipped > 0,
                    "message": f"Imported {imported} findings"})
            return self._send(404, {"detail": "Not Found"})

    return Handler


class FakeApi:
    def __init__(self, **kw):
        self.state = FakeState(**kw)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.state))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self) -> "FakeApi":
        self.thread.start()
        return self

    def __exit__(self, *exc: Optional[BaseException]) -> None:
        self.server.shutdown()
        self.server.server_close()
