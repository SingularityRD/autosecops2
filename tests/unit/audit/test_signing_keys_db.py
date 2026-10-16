"""A fresh install signs from day one (W0.36, U-13), against Postgres.

The install step (``python -m core.audit.signing_keys provision``) runs on an
empty secrets store; then the daemon's checkpoint key and the backend's
evidence-pack key are the provisioned ones, a checkpoint is signed and verifies
with the *exported* public key, and an evidence pack verifies offline with the
exported key pinned.

The checkpoint is written inside a transaction that is rolled back, as in
test_checkpoint_db.py, so no committed checkpoint signed by this key confronts
another test's trusted key.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import text

from core import secrets_manager
from core.audit import signing_keys
from core.audit.checkpoint import (
    load_public_key,
    signing_key_from_secrets,
    verify_checkpoints,
    write_checkpoint,
)
from core.compliance import verify_bundle
from core.compliance.evidence_bundle import build_bundle, load_signing_key
from tests.unit.audit.conftest import insert_action
from tests.unit.compliance.test_verify_bundle import NOW, make_record

pytestmark = [pytest.mark.unit, pytest.mark.external_service, pytest.mark.database]

SECRETS = ("AUDIT_CHECKPOINT_SIGNING_KEY", "EVIDENCE_PACK_SIGNING_KEY")


@pytest.fixture
def fresh_install(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VIGIL_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("VIGIL_DISABLE_DOTENV", "1")
    for name in SECRETS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        secrets_manager,
        "_secrets_manager",
        secrets_manager.SecretsManager(write_backend="encrypted"),
    )
    assert signing_keys.main(["provision"]) == 0
    capsys.readouterr()
    assert signing_keys.main(["export"]) == 0
    exported = dict(
        line.split("=", 1) for line in capsys.readouterr().out.strip().splitlines()
    )
    yield exported
    for name in SECRETS:
        os.environ.pop(name, None)


@pytest.fixture
def conn(audit_db):
    connection = audit_db.engine.connect()
    tx = connection.begin()
    connection.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
    try:
        yield connection
    finally:
        tx.rollback()
        connection.close()


def test_checkpoints_are_signed_and_verify_with_the_exported_key(fresh_install, conn):
    key = signing_key_from_secrets()
    assert key is not None, "the daemon would skip the checkpoint"
    insert_action(conn, "action-w036-fresh")
    checkpoint = write_checkpoint(conn, key)
    trusted = load_public_key(fresh_install["AUDIT_CHECKPOINT_PUBLIC_KEY"])
    assert checkpoint.public_key == fresh_install["AUDIT_CHECKPOINT_PUBLIC_KEY"]
    report = verify_checkpoints(conn, trusted)
    assert report.ok and report.trusted and report.count >= 1


def test_evidence_pack_verifies_offline_with_the_exported_key(fresh_install, tmp_path):
    key, source = load_signing_key()
    assert source == "configured"
    bundle = build_bundle(make_record(), "auditor", NOW, key, source)
    assert bundle.manifest["signer"]["key_source"] == "configured"
    pack = tmp_path / "pack.zip"
    pack.write_bytes(bundle.data)
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(verify_bundle.__file__)),
            str(pack),
            "--public-key",
            fresh_install["EVIDENCE_PACK_PUBLIC_KEY"],
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: VERIFIED" in result.stdout


def test_recent_checkpoint_counts_for_the_health(fresh_install, audit_db, monkeypatch):
    """Without the key in the backend (Helm), a fresh signed checkpoint is the signal."""
    monkeypatch.delenv("AUDIT_CHECKPOINT_SIGNING_KEY", raising=False)
    with audit_db.engine.begin() as c:
        has_recent = c.execute(
            text(
                "SELECT count(*) FROM audit_checkpoints "
                "WHERE created_at >= now() - interval '2 hours'"
            )
        ).scalar()
    assert signing_keys._recent_checkpoint(3600) is bool(has_recent)
