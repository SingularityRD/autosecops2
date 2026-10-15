"""W0.27: secrets in a query string never reach the HTTP access log.

The reset screen's ``?token=`` (older links), an OAuth ``code``/``state`` or an
``api_key`` in a URL would otherwise be written by uvicorn's access log, which
the image's CMD and Helm keep on. The real check starts the backend the way
the image does (``python -m uvicorn services.api.main:app``) on a real socket.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from core.platform.log_redaction import (
    SensitiveQueryFilter,
    install_access_log_redaction,
    redact_query_secrets,
)

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    "raw,expected",
    [
        (
            "/reset-password?token=abc&lang=en",
            "/reset-password?token=[REDACTED]&lang=en",
        ),
        ("/cb?code=c1&state=s1", "/cb?code=[REDACTED]&state=[REDACTED]"),
        ("/x?api_key=k&q=token", "/x?api_key=[REDACTED]&q=token"),
        ("/x?Password=p;secret=s", "/x?Password=[REDACTED];secret=[REDACTED]"),
        ("/x?reset_token=r", "/x?reset_token=[REDACTED]"),
        ("/key=1/plain", "/key=1/plain"),
        ("/no-query", "/no-query"),
    ],
)
def test_redact_query_secrets(raw, expected):
    assert redact_query_secrets(raw) == expected


def test_filter_rewrites_uvicorn_record_args():
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1", "GET", "/reset-password?token=SECRET", "1.1", 200),
        None,
    )
    assert SensitiveQueryFilter().filter(record) is True
    assert "SECRET" not in record.getMessage()
    assert "/reset-password?token=[REDACTED]" in record.getMessage()


def test_install_is_idempotent():
    install_access_log_redaction()
    install_access_log_redaction()
    filters = logging.getLogger("uvicorn.access").filters
    assert sum(isinstance(f, SensitiveQueryFilter) for f in filters) == 1


def test_backend_logging_setup_installs_it():
    from core.telemetry import configure_logging

    root = logging.getLogger()
    saved = (root.handlers[:], root.level)
    logging.getLogger("uvicorn.access").filters[:] = []
    try:
        configure_logging("INFO")
    finally:
        for h in root.handlers[:]:
            if h not in saved[0]:
                root.removeHandler(h)
                h.close()
        for h in saved[0]:
            if h not in root.handlers:
                root.addHandler(h)
        root.setLevel(saved[1])
    assert any(
        isinstance(f, SensitiveQueryFilter)
        for f in logging.getLogger("uvicorn.access").filters
    )


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str) -> None:
    try:
        urllib.request.urlopen(url, timeout=5).read()  # nosec B310 - loopback
    except urllib.error.HTTPError:
        pass  # 404 without a frontend build: still an access-log line


@pytest.mark.parametrize("workers", [None, 2], ids=["single", "workers-2"])
def test_real_uvicorn_access_log_has_no_token(workers, tmp_path):
    port = _free_port()
    log = tmp_path / "uvicorn.log"
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "services.api.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ]
    if workers:
        cmd += ["--workers", str(workers)]
    env = {**os.environ, "BIND_HOST": "127.0.0.1"}
    with log.open("wb") as out:
        proc = subprocess.Popen(  # nosec B603 - fixed argv
            cmd, cwd=REPO, stdout=out, stderr=subprocess.STDOUT, env=env
        )
        try:
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 180
            while True:
                try:
                    urllib.request.urlopen(f"{base}/api/health", timeout=3)
                    break
                except Exception:
                    if proc.poll() is not None or time.monotonic() > deadline:
                        pytest.fail(log.read_text(errors="replace")[-3000:])
                    time.sleep(0.5)
            for _ in range(4):  # reach every worker
                _get(f"{base}/reset-password?token=SECRETTOKENX&lang=en")
                _get(f"{base}/api/health?api_key=SECRETKEYX")
            time.sleep(1.0)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
    text = log.read_text(errors="replace")
    assert "/reset-password?token=[REDACTED]&lang=en" in text, text[-3000:]
    assert "SECRETTOKENX" not in text
    assert "SECRETKEYX" not in text
