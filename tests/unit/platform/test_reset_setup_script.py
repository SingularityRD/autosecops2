"""scripts/reset-setup.sh works against a backend that enforces CSRF (W0.33, KS-25).

The fake backend here does what services/api/middleware/csrf.py does with
``VIGIL_CSRF_REPORT_ONLY=false``: a response to a request without the
``csrf_token`` cookie seeds one, and any POST/PUT/PATCH/DELETE whose
``X-CSRF-Token`` header does not match that cookie is a 403 -- Bearer or not,
login included. Before the fix the script's first write (the login) was refused.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

import pytest

pytestmark = pytest.mark.unit

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "reset-setup.sh"
USER, PASSWORD = "admin", "a-password-nobody-should-see-91"


class FakeBackend:
    def __init__(self) -> None:
        self.csrf = secrets.token_urlsafe(16)
        self.bearer = secrets.token_hex(16)
        self.writes: List[str] = []
        self.refused: List[str] = []
        self.argv_bodies: List[str] = []
        self.progress: Dict[str, Any] = {
            "furthest": 4, "passed": [1, 2, 3], "status": "completed", "started": True,
            "updated_by": "admin",
        }
        self.orchestrator: Dict[str, Any] = {"enabled": True, "max_total_hourly_cost": 20}
        self.assignments = {"chat_default": {"provider_id": "p1", "model_id": "m"}}
        self.providers = [{"provider_id": "p1", "is_default": False, "is_active": True}]
        backend = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                pass

            def _send(self, code: int, doc: Any = None) -> None:
                body = json.dumps(doc if doc is not None else {}).encode()
                self.send_response(code)
                if "csrf_token" not in (self.headers.get("Cookie") or ""):
                    self.send_header(
                        "Set-Cookie",
                        f"csrf_token={backend.csrf}; Path=/; SameSite=strict; Secure",
                    )
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _csrf_ok(self) -> bool:
                cookie = self.headers.get("Cookie") or ""
                return (
                    self.headers.get("X-CSRF-Token") == backend.csrf
                    and f"csrf_token={backend.csrf}" in cookie
                )

            def _authed(self) -> bool:
                return self.headers.get("Authorization") == f"Bearer {backend.bearer}"

            def _body(self) -> Any:
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                return json.loads(raw) if raw else None

            def do_GET(self):  # noqa: N802
                p = self.path
                if p == "/api/health":
                    return self._send(200, {"status": "healthy"})
                if not self._authed():
                    return self._send(401, {"detail": "Not authenticated"})
                routes = {
                    "/api/auth/me": {"username": USER},
                    "/api/llm/providers/": backend.providers,
                    "/api/bifrost/routability": {"providers": {}, "keys": {}},
                    "/api/bifrost/providers": {"providers": []},
                    "/api/ai/config": {"assignments": backend.assignments},
                    "/api/analytics/budget": {"default_vk": "vk-1"},
                    "/api/config/orchestrator": backend.orchestrator,
                    "/api/mcp/connections/status": {"connections": []},
                    "/api/config/setup-progress": backend.progress,
                }
                if p in routes:
                    return self._send(200, routes[p])
                return self._send(404, {"detail": "Not Found"})

            def _write(self, method: str):
                p = self.path
                body = self._body()
                if not self._csrf_ok():
                    backend.refused.append(f"{method} {p}")
                    return self._send(403, {"detail": "CSRF token missing or invalid"})
                backend.writes.append(f"{method} {p}")
                if p == "/api/auth/login":
                    if body != {"username_or_email": USER, "password": PASSWORD}:
                        return self._send(401, {"detail": "Incorrect username or password"})
                    return self._send(200, {"access_token": backend.bearer})
                if not self._authed():
                    return self._send(401, {"detail": "Not authenticated"})
                if p == "/api/config/setup-progress" and method == "PUT":
                    backend.progress = {**body, "started": True, "updated_by": USER}
                elif p == "/api/config/orchestrator":
                    backend.orchestrator = body
                elif p.startswith("/api/ai/config/") and method == "DELETE":
                    backend.assignments.pop(p.rsplit("/", 1)[1], None)
                elif p.startswith("/api/llm/providers/") and method == "DELETE":
                    backend.providers = []
                return self._send(200, {"ok": True})

            def do_POST(self):  # noqa: N802
                self._write("POST")

            def do_PUT(self):  # noqa: N802
                self._write("PUT")

            def do_DELETE(self):  # noqa: N802
                self._write("DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/api"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "FakeBackend":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()


def _run(script: Path, backend: FakeBackend, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("VIGIL_")}
    env.update(
        VIGIL_API=backend.url,
        VIGIL_USERNAME=USER,
        VIGIL_PASSWORD=PASSWORD,
        # Nothing listens here: the gateway fallback must not reach a real one.
        BIFROST_URL="http://127.0.0.1:9",
    )
    return subprocess.run(
        ["bash", str(script), *args], env=env, capture_output=True, text=True, timeout=120
    )


@pytest.fixture(autouse=True)
def _needs_curl():
    if not shutil.which("curl"):
        pytest.skip("needs curl")


def test_a_full_reset_passes_csrf_and_starts_the_wizard_over():
    with FakeBackend() as backend:
        r = _run(SCRIPT, backend, "--all", "-y")
        assert r.returncode == 0, r.stdout + r.stderr
        assert backend.refused == []
        assert "POST /api/auth/login" in backend.writes
        assert "PUT /api/config/setup-progress" in backend.writes
        assert "POST /api/config/orchestrator" in backend.writes
        assert "PUT /api/analytics/budget" in backend.writes
        assert backend.progress["status"] == "in_progress"
        assert backend.progress["furthest"] == 1 and backend.progress["passed"] == []
        assert backend.orchestrator["enabled"] is False
        assert backend.orchestrator["max_total_hourly_cost"] == 20  # caps kept
        assert backend.assignments == {}
        assert "reset setup wizard progress" in r.stdout
    assert PASSWORD not in r.stdout + r.stderr


def test_wizard_alone_resets_only_the_progress():
    with FakeBackend() as backend:
        r = _run(SCRIPT, backend, "--wizard", "-y")
        assert r.returncode == 0, r.stdout + r.stderr
        assert backend.refused == []
        assert [w for w in backend.writes if w != "POST /api/auth/login"] == [
            "PUT /api/config/setup-progress"
        ]
        assert backend.orchestrator["enabled"] is True


def test_status_shows_the_wizard_state_and_changes_nothing():
    with FakeBackend() as backend:
        r = _run(SCRIPT, backend, "--status")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "Setup wizard      : completed (step 4, by admin)" in r.stdout
        assert backend.writes == ["POST /api/auth/login"]

