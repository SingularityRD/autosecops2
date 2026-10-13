"""Evidence pack download: RBAC, 404, the zip, the export audit row (W3.7).

The reader is swapped for an in-memory record and the session for a recorder;
the SQL reader is covered by tests/unit/storage/test_evidence_pack_db.py.
"""

from __future__ import annotations

import io
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.compliance import evidence_router, verify_bundle
from core.compliance.evidence_bundle import SigningKeyError
from core.routing import request_unit_of_work
from tests.unit.compliance.test_verify_bundle import CASE, SEED, make_record

pytestmark = pytest.mark.unit

PREFIX = evidence_router.ROUTER_META.prefix
URL = f"{PREFIX}/{CASE}/evidence-pack"


class RecordingSession:
    def __init__(self):
        self.added = []

    def add(self, row):
        self.added.append(row)

    def flush(self):
        pass


@pytest.fixture()
def session(monkeypatch):
    session = RecordingSession()
    monkeypatch.setattr(
        evidence_router,
        "_collect",
        lambda s, case_id: make_record() if case_id == CASE else None,
    )
    monkeypatch.setattr(
        evidence_router,
        "_signing_key",
        lambda: (Ed25519PrivateKey.from_private_bytes(SEED), "configured"),
    )
    return session


@pytest.fixture()
def client(authenticate_app, session):
    app = FastAPI()
    authenticate_app(app)
    app.include_router(evidence_router.router, prefix=PREFIX)
    app.dependency_overrides[request_unit_of_work] = lambda: session
    return TestClient(app, raise_server_exceptions=False)


def test_needs_cases_read(client, session, monkeypatch):
    monkeypatch.setattr(
        "core.auth.auth_service.AuthService.check_permission",
        lambda user_id, perm, session=None: perm != "cases.read",
    )
    response = client.get(URL)
    assert response.status_code == 403
    assert "cases.read" in response.json()["detail"]
    assert session.added == []


def test_download_is_a_verifying_zip_and_is_audited(client, session):
    response = client.get(URL)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/zip"
    assert f'filename="evidence-pack-{CASE}-' in response.headers["content-disposition"]
    assert response.headers["x-evidence-pack-key-source"] == "configured"
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        files = {i.filename: z.read(i) for i in z.infolist()}
    assert all(c.ok for c in verify_bundle.verify_files(files))
    manifest_sha = verify_bundle.sha256_hex(files["manifest.json"])
    assert response.headers["x-evidence-pack-manifest-sha256"] == manifest_sha
    [row] = session.added
    assert (row.entity_type, row.entity_id, row.action, row.field_name) == (
        "case",
        CASE,
        "export",
        "evidence_pack",
    )
    assert row.new_value == manifest_sha
    assert row.changed_by == "test-admin"  # from the login, not the request


def test_unknown_case_is_404(client, session):
    response = client.get(f"{PREFIX}/nope/evidence-pack")
    assert response.status_code == 404
    assert session.added == []


def test_unusable_key_is_500_without_a_pack(client, session, monkeypatch):
    def _bad():
        raise SigningKeyError("bad")

    monkeypatch.setattr(evidence_router, "_signing_key", _bad)
    response = client.get(URL)
    assert response.status_code == 500
    assert "EVIDENCE_PACK_SIGNING_KEY" in response.json()["detail"]
    assert session.added == []
