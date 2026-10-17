"""The case report prints Turkish and can be downloaded (W0.40, P3).

ReportLab's Helvetica is WinAnsi-encoded, so ş, ğ, ı and İ printed as boxes.
The report now embeds DejaVu Sans, shipped next to the code, for every style
and table cell. ``GET /api/cases/{id}/report.pdf`` answers with the PDF itself
(the POST route only wrote a file on the server) and records the download.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.reporting import report_service as rs
from core.reporting.report_service import ReportService

pytestmark = pytest.mark.unit

TURKISH = "ŞşĞğİıÜüÖöÇç"


def test_the_bundled_font_has_every_turkish_letter():
    rs._register_fonts()
    from reportlab.pdfbase import pdfmetrics

    for name in (rs.FONT, rs.FONT_BOLD):
        face = pdfmetrics.getFont(name).face
        missing = [c for c in TURKISH if ord(c) not in face.charToGlyph]
        assert not missing, (name, missing)
    assert (rs._FONT_DIR / "LICENSE-DejaVu.txt").is_file()


def test_no_style_or_table_falls_back_to_helvetica():
    service = ReportService()
    for style in service.styles.byName.values():
        assert style.fontName in (rs.FONT, rs.FONT_BOLD), style.name
    source = Path(rs.__file__).read_text(encoding="utf-8")
    assert '"Helvetica' not in source
    # Every table sets a body font, not only its header row.
    tables = source.count("TableStyle(")
    assert source.count('("FONTNAME", (0, 0), (-1, -1), FONT)') == tables


def test_a_turkish_case_report_embeds_the_font(tmp_path: Path):
    case = {
        "case_id": "case-tr",
        "title": f"Şüpheli giriş {TURKISH}",
        "description": "İstanbul şubesi",
        "assignee": "Ayşe Öztürk",
        "tags": ["kvkk", "şube"],
        "notes": [{"text": "ığüşöç İĞÜŞÖÇ", "timestamp": "t"}],
    }
    out = tmp_path / "tr.pdf"
    assert ReportService().generate_case_report(
        out,
        case,
        [{"finding_id": "F-1", "severity": "yüksek", "data_source": "şube-edr"}],
    )
    pdf = out.read_bytes()
    embedded = set(re.findall(rb"/BaseFont /[A-Z]{6}\+(DejaVuSans(?:-Bold)?)", pdf))
    assert embedded == {b"DejaVuSans", b"DejaVuSans-Bold"}
    # A ToUnicode map, so the text can be searched and copied in Turkish.
    assert b"/ToUnicode" in pdf


# --- GET /api/cases/{id}/report.pdf -------------------------------------------------

ANALYST = SimpleNamespace(user_id="u-ana", username="ana", role_id="role-analyst")
NOBODY = SimpleNamespace(user_id="u-no", username="no", role_id="role-none")
GRANTS = {"u-ana": {"cases.read"}, "u-no": set()}


class _Data:
    def get_case(self, case_id):
        if case_id != "case-1":
            return None
        return {"case_id": "case-1", "title": f"Vaka {TURKISH}", "finding_ids": ["F-1"]}

    def get_findings_by_case(self, case_id):
        return [{"finding_id": "F-1", "severity": "high"}]


@pytest.fixture
def recorded(monkeypatch):
    from services.api.routers import cases as cases_api

    rows = []
    monkeypatch.setattr(
        cases_api,
        "_record_report_download",
        lambda user, request, case_id, size: rows.append(
            (user.username, case_id, size)
        ),
    )
    monkeypatch.setattr(cases_api, "data_service", _Data())
    monkeypatch.setattr(cases_api, "report_service", ReportService())
    return rows


def _client(user, monkeypatch):
    from core.auth import current_user as cu
    from core.auth.auth_service import AuthService
    from services.api.errors import register_exception_handlers
    from services.api.middleware import auth as mw
    from services.api.routers import cases as cases_api

    monkeypatch.setattr(
        AuthService,
        "check_permission",
        staticmethod(lambda user_id, perm, session=None: perm in GRANTS[user_id]),
    )
    app = FastAPI()
    register_exception_handlers(app)
    app.include_router(cases_api.router, prefix="/api/cases")
    app.dependency_overrides[cu.get_current_user] = lambda: user
    app.dependency_overrides[mw.get_current_user] = lambda: user
    return TestClient(app, raise_server_exceptions=False)


def test_the_report_downloads_as_a_pdf_and_is_recorded(recorded, monkeypatch):
    r = _client(ANALYST, monkeypatch).get("/api/cases/case-1/report.pdf")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/pdf"
    assert (
        r.headers["content-disposition"] == 'attachment; filename="case-1-report.pdf"'
    )
    assert r.headers["cache-control"] == "no-store"
    assert r.content.startswith(b"%PDF")
    assert recorded == [("ana", "case-1", len(r.content))]


def test_no_report_without_its_record(recorded, monkeypatch):
    from services.api.routers import cases as cases_api

    def fail(*a):
        raise RuntimeError("db down")

    monkeypatch.setattr(cases_api, "_record_report_download", fail)
    r = _client(ANALYST, monkeypatch).get("/api/cases/case-1/report.pdf")
    assert r.status_code == 500
    assert not r.content.startswith(b"%PDF")


def test_unknown_case_and_missing_permission(recorded, monkeypatch):
    assert (
        _client(ANALYST, monkeypatch).get("/api/cases/nope/report.pdf").status_code
        == 404
    )
    assert (
        _client(NOBODY, monkeypatch).get("/api/cases/case-1/report.pdf").status_code
        == 403
    )
    assert recorded == []
