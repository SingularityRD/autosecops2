"""``POST /api/findings/export`` writes one file, inside the exports directory.

The route has never returned anything but 500: it called the data service with
``format=`` where the service's parameter is ``fmt``, so every request raised
``TypeError`` before the service ran. Nothing covered the route, so nothing
said so.

The same handler builds the output filename from the query parameter without
validating it. That is less than it looks on POSIX: the caller's string is
always appended to ``findings_export_<timestamp>.``, so the first component of
any injected path is a file that does not exist, and the write fails before it
can leave the directory -- percent-encoded separators included, which the
server really does decode. It is not less than it looks on Windows, where
``\\`` splits and ``..`` cancels lexically.

What the caller does get on any platform is the extension, so the route answers
200 to ``?output_format=csv`` and hands back JSON in a file named ``.csv``.
The closed set is the fix for that, and the Windows case falls out of it.
"""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest.mock import patch

import pytest

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from core.storage.database_data_service import DatabaseDataService  # noqa: E402
from services.api.errors import register_exception_handlers  # noqa: E402
from services.api.routers import findings as findings_api  # noqa: E402

pytestmark = pytest.mark.unit


class _StubDataService:
    """Carries the real signature, so a mismatched call fails here as it does live."""

    def __init__(self):
        self.calls = []

    def export_findings(self, output_path: Path, fmt: str = "json") -> Optional[int]:
        self.calls.append((output_path, fmt))
        output_path.write_text(json.dumps({"findings": [{}, {}, {}]}))
        return 3


@pytest.fixture
def exports_dir(tmp_path, monkeypatch):
    """`vigil_path` resolves under VIGIL_DIR, so the writes land in tmp_path."""
    monkeypatch.setenv("VIGIL_DIR", str(tmp_path))
    return tmp_path / "exports"


@pytest.fixture
def stub(monkeypatch):
    stub = _StubDataService()
    monkeypatch.setattr(findings_api, "data_service", stub)
    return stub


ANALYST = SimpleNamespace(user_id="u-ana", username="ana", role_id="role-analyst")
VIEWER = SimpleNamespace(user_id="u-vic", username="vic", role_id="role-viewer")
GRANTS = {"u-ana": {"findings.read", "findings.write"}, "u-vic": {"findings.read"}}


@pytest.fixture
def recorded(monkeypatch):
    """The export's audit rows, as the route hands them to the database."""
    rows = []
    monkeypatch.setattr(
        findings_api,
        "_record_export",
        lambda user, request, fmt, n, path: rows.append(
            (user.username, fmt, n, path.name, request.client.host)
        ),
    )
    return rows


def _app(user):
    from core.auth.current_user import get_current_user

    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(findings_api.router, prefix="/api/findings")
    app.dependency_overrides[get_current_user] = lambda: user
    return app


@pytest.fixture
def grants(monkeypatch):
    from core.auth.auth_service import AuthService

    monkeypatch.setattr(
        AuthService,
        "check_permission",
        staticmethod(lambda user_id, perm, session=None: perm in GRANTS[user_id]),
    )


@pytest.fixture
def client(grants, recorded):
    return TestClient(_app(ANALYST), raise_server_exceptions=False)


def test_the_stub_matches_the_service_it_stands_in_for():
    """Otherwise this file could go green while the real call still mismatches.

    Parameters only: this module's `from __future__ import annotations` makes
    its own annotations strings, and the service's are objects.
    """

    def shape(fn):
        return [
            (p.name, p.kind, p.default)
            for p in inspect.signature(fn).parameters.values()
        ]

    assert shape(_StubDataService.export_findings) == shape(
        DatabaseDataService.export_findings
    )


@pytest.mark.parametrize("fmt", ["json", "jsonl"])
def test_an_export_writes_its_file_and_answers_with_the_path(
    fmt, client, stub, exports_dir
):
    response = client.post(f"/api/findings/export?output_format={fmt}")

    assert response.status_code == 200, response.text
    written = Path(response.json()["file_path"])
    assert written.exists()
    assert written.parent == exports_dir
    assert stub.calls == [(written, fmt)]
    assert response.json()["rows"] == 3


def test_an_export_is_recorded_with_who_what_and_how_many(
    client, stub, exports_dir, recorded
):
    """U-17 (W0.35): every bulk export leaves an audit row."""
    response = client.post("/api/findings/export?output_format=jsonl")

    assert response.status_code == 200, response.text
    name = Path(response.json()["file_path"]).name
    assert recorded == [("ana", "jsonl", 3, name, "testclient")]


def test_a_viewer_cannot_export(grants, recorded, stub, exports_dir):
    """U-17 (W0.35): bulk export needs findings.write, which Viewer lacks."""
    viewer = TestClient(_app(VIEWER), raise_server_exceptions=False)

    response = viewer.post("/api/findings/export?output_format=json")

    assert response.status_code == 403, response.text
    assert "findings.write" in response.json()["detail"]
    assert stub.calls == [] and recorded == []
    assert not exports_dir.exists() or not any(exports_dir.iterdir())


def test_an_export_that_cannot_be_recorded_is_withdrawn(
    grants, stub, exports_dir, monkeypatch
):
    def fail(*_a):
        raise RuntimeError("database down")

    monkeypatch.setattr(findings_api, "_record_export", fail)
    response = TestClient(_app(ANALYST), raise_server_exceptions=False).post(
        "/api/findings/export?output_format=json"
    )

    assert response.status_code == 500
    assert stub.calls and not stub.calls[0][0].exists()


def test_a_format_the_service_cannot_write_is_refused(client, stub, exports_dir):
    response = client.post("/api/findings/export?output_format=csv")

    assert response.status_code == 400, response.text
    assert stub.calls == []


@pytest.mark.parametrize(
    "escape",
    ["../evil", "../../evil", "json/../../evil", "/etc/evil", "\\..\\..\\evil"],
)
def test_a_format_carrying_a_path_is_refused(
    escape, client, stub, exports_dir, tmp_path
):
    response = client.post(f"/api/findings/export?output_format={escape}")

    assert response.status_code == 400, response.text
    assert stub.calls == []
    assert not (tmp_path.parent / "evil").exists()


def test_every_declared_format_is_one_the_writer_writes_differently():
    """The route's closed set and the writer's branch are one list now, but a
    format could still be added to it that the branch does not know -- which
    would answer 200 and hand back JSON in a file named after it, the exact
    thing the check exists to prevent. So write one for real in each and
    require that they differ."""
    import tempfile

    service = DatabaseDataService()
    written = {}

    with tempfile.TemporaryDirectory() as tmp:
        for fmt in DatabaseDataService.EXPORT_FORMATS:
            path = Path(tmp) / f"findings.{fmt}"
            with patch.object(
                DatabaseDataService,
                "get_findings",
                return_value=[{"finding_id": "f-1"}, {"finding_id": "f-2"}],
            ):
                assert service.export_findings(path, fmt=fmt) == 2
            written[fmt] = path.read_text()

    assert len(set(written.values())) == len(written), (
        "Two declared export formats produced identical bytes, so at least one "
        f"is not a format the writer actually branches on: {sorted(written)}. "
        "Either teach export_findings to write it, or drop it from "
        "DatabaseDataService.EXPORT_FORMATS."
    )
