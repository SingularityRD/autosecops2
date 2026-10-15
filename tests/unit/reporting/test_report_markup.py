# W0.30 round 7: ReportLab's Paragraph parses its text as markup. A case
# description (a hunt's handoff and its subject block), a note or a finding id is
# escaped, so a subject's value can neither add a link or an image nor stop the
# report from building.

from __future__ import annotations

import base64
import re
import zlib
from pathlib import Path

import pytest

from core.reporting.report_service import ReportService

pytestmark = pytest.mark.unit

PROBES = {
    "rawa": '<a href="http://evil.example">INJECT</a>',
    "html": "<b>bold</b><img src=x onerror=alert(1)><a href='http://evil'>c</a> INJECT",
    "rawimg": "<img src=x onerror=alert(1)>INJECT",
}


def _page_text(pdf: bytes) -> bytes:
    """Every content stream, decoded (ReportLab writes ASCII85 then Flate)."""
    out = []
    for raw in re.findall(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        data = raw.strip()
        try:
            if data.endswith(b"~>"):
                data = base64.a85decode(data[:-2])
            out.append(zlib.decompress(data))
        except Exception:  # noqa: BLE001 — not every stream is page text
            out.append(raw)
    return b"\n".join(out)


@pytest.mark.parametrize("probe", sorted(PROBES))
def test_the_report_builds_with_the_text_shown_literally(tmp_path: Path, probe: str):
    value = PROBES[probe]
    block = f'Written by the subject (untrusted):\n[1] host = "{value}"'
    case = {
        "case_id": "case-1",
        "title": f"Hunt {value}",
        "description": f"Handed off: [subject value 1]\n\n{block}",
        "tags": [value],
        "notes": [{"text": value, "timestamp": "2026-10-15T00:00:00Z"}],
        "resolution_steps": [{"description": value, "timestamp": "t"}],
    }
    out = tmp_path / f"{probe}.pdf"

    assert ReportService().generate_case_report(out, case, [{"finding_id": value}])

    pdf = out.read_bytes()
    assert b"/Annot" not in pdf and b"/URI" not in pdf and b"/Link" not in pdf
    assert b"/XObject" not in pdf  # no image was drawn
    text = _page_text(pdf)
    assert b"INJECT" in text
    assert b"href" in text or b"img src" in text  # the markup is text on the page
