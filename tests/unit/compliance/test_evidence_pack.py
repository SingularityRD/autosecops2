"""The evidence pack's contents, manifest and signature (W3.7).

Also pins that W3.8's drafts read the same citable index: the names stay
importable from ``regulatory_drafts`` and the digest is the one the pack's
manifest carries.
"""

from __future__ import annotations

import base64
import io
import json
import sys
import types
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.compliance import evidence, evidence_bundle, regulatory_drafts, verify_bundle
from core.compliance.evidence import build_evidence_pack, drop_canary_findings
from core.compliance.evidence_bundle import (
    SigningKeyError,
    load_signing_key,
    parse_private_key,
    public_bytes,
)
from tests.unit.compliance.test_verify_bundle import CASE, SEED, make_bundle, make_record

pytestmark = pytest.mark.unit


def _files(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {i.filename: z.read(i) for i in z.infolist()}


def _json(files, name):
    return json.loads(files[name])


def test_drafts_use_the_evidence_module_builder():
    assert regulatory_drafts.build_evidence_pack is evidence.build_evidence_pack
    assert regulatory_drafts.EvidencePack is evidence.EvidencePack
    assert regulatory_drafts.EvidenceItem is evidence.EvidenceItem


def test_citable_digest_is_unchanged_from_w38():
    """The digest formula W3.8 shipped: sha256 of the sorted-key compact JSON."""
    import hashlib

    pack = build_evidence_pack(
        {"case_id": "c-1", "title": "Outage"},
        findings=[{"finding_id": "f-1", "title": "Beacon"}],
    )
    body = json.dumps(
        [i.to_dict() for i in pack.items], sort_keys=True, separators=(",", ":")
    )
    assert pack.digest == hashlib.sha256(body.encode()).hexdigest()


def test_pack_lists_every_file_and_signs_the_manifest():
    bundle = make_bundle()
    files = _files(bundle.data)
    manifest = _json(files, "manifest.json")
    assert manifest["format"] == "autosecops.evidence-pack" and manifest["version"] == 1
    assert manifest["case_id"] == CASE and manifest["created_by"] == "ayse"
    listed = {e["path"] for e in manifest["files"]}
    assert listed == set(files) - {"manifest.json", "manifest.sig"}
    assert {
        "data/case.json",
        "data/findings.json",
        "data/case_evidence.json",
        "data/case_audit.json",
        "data/actions.json",
        "data/ledger.json",
        "data/ai_provenance.json",
        "data/regulatory_clock_events.json",
        "data/citable_index.json",
        "data/verification.json",
        "verify_bundle.py",
        "README.txt",
    } <= listed
    assert "data/audit_chain.json" not in listed
    assert manifest["sources"]["audit_chain"] == "absent"
    pub = public_bytes(Ed25519PrivateKey.from_private_bytes(SEED))
    assert base64.b64decode(manifest["signer"]["public_key"]) == pub
    assert manifest["signer"]["key_source"] == "configured"
    assert verify_bundle.ed25519_verify(
        pub, files["manifest.json"], base64.b64decode(files["manifest.sig"])
    )
    assert bundle.key_id == verify_bundle.key_id(pub)
    assert bundle.filename.startswith(f"evidence-pack-{CASE}-") and bundle.filename.endswith(".zip")
    assert all(c.ok for c in verify_bundle.verify_files(files, pub))


def test_pack_carries_the_case_findings_actions_and_provenance():
    files = _files(make_bundle().data)
    assert _json(files, "data/case.json")["title"] == "Beaconing from build host"
    finding = _json(files, "data/findings.json")["findings"][0]
    assert finding["finding_id"] == "f-1"
    assert finding["ai_enrichment"]["ai_triage"]["result"]["confidence"] == 0.9
    action = _json(files, "data/actions.json")["actions"][0]
    assert action["before_state"] == {"isolated": False}
    assert action["after_state"] == {"isolated": True}
    assert action["second_approver"] == "mehmet"
    verification = _json(files, "data/verification.json")
    assert verification["actions"][0]["verify_status"] == "verified"
    assert verification["ledger"][0]["ok"] is True
    assert verification["clock_chain"]["ok"] is True
    run = _json(files, "data/ledger.json")["runs"][0]
    assert [e["seq"] for e in run["events"]] == [0, 1, 2]
    clocks = _json(files, "data/regulatory_clock_events.json")["events"]
    assert [c["instant"] for c in clocks] == ["aware_at", "notified_at"]
    assert _json(files, "data/case_evidence.json")["evidence"][0]["file_hash_sha256"] == "ab" * 32
    assert _json(files, "data/case_audit.json")["audit"][0]["audit_id"] == 11


def test_manifest_digest_is_what_a_draft_cites():
    record = make_record()
    files = _files(make_bundle(record).data)
    manifest = _json(files, "manifest.json")
    index = _json(files, "data/citable_index.json")
    assert manifest["citable_digest"] == index["digest"] == record.citable().digest
    draft = regulatory_drafts.generate_draft(
        record.citable(), "nis2", "early_warning", [], record.clock_events, "ayse",
        verify_bundle_now(),
    )
    assert draft["pack_digest"] == manifest["citable_digest"]
    assert set(draft["cited_ids"]) <= {i["id"] for i in index["items"]}


def verify_bundle_now():
    from datetime import datetime, timezone

    return datetime(2026, 3, 2, 12, tzinfo=timezone.utc)


def test_a_broken_ledger_at_export_is_recorded_and_rejected():
    record = make_record()
    record.ledger[0]["events"][1]["payload_text"] = '{"kind": "finding", "answer": "benign"}'
    files = _files(make_bundle(record).data)
    verification = _json(files, "data/verification.json")
    assert verification["ledger"][0]["ok"] is False
    assert "seq 1" in verification["ledger"][0]["break"]
    checks = {c.name: c for c in verify_bundle.verify_files(files)}
    assert checks["ledger"].ok is False


def test_audit_chain_included_when_present():
    row = {
        "seq": 1,
        "source_table": "approval_actions",
        "source_id": "act-1",
        "event": "insert",
        "prev_hash": "",
        "event_hash": verify_bundle.chain_hash("", "{}"),
        "canonical": "{}",
    }
    files = _files(make_bundle(make_record(audit_chain=[row])).data)
    manifest = _json(files, "manifest.json")
    assert manifest["sources"]["audit_chain"] == "included"
    assert manifest["counts"]["audit_chain_rows"] == 1
    assert _json(files, "data/verification.json")["audit_chain"]["ok"] is True


def test_canary_exclusion_is_optional(monkeypatch):
    monkeypatch.setattr(evidence, "_optional", lambda module, name: None)
    kept, dropped, status = drop_canary_findings(None, [{"finding_id": "a"}])
    assert (kept, dropped, status) == ([{"finding_id": "a"}], 0, "unavailable")


def test_canary_findings_are_dropped_when_w15_is_installed(monkeypatch):
    fake = types.ModuleType("core.storage.canary_exclusion")
    fake.drop_canaries = lambda items, session=None, key="finding_id": [
        i for i in items if i["finding_id"] != "canary"
    ]
    monkeypatch.setitem(sys.modules, "core.storage.canary_exclusion", fake)
    kept, dropped, status = drop_canary_findings(
        None, [{"finding_id": "a"}, {"finding_id": "canary"}]
    )
    assert kept == [{"finding_id": "a"}] and dropped == 1 and status == "applied"


def test_signing_key_from_secret(monkeypatch):
    monkeypatch.setattr(evidence_bundle, "get_secret", lambda name: SEED.hex())
    key, source = load_signing_key()
    assert source == "configured"
    assert public_bytes(key) == public_bytes(Ed25519PrivateKey.from_private_bytes(SEED))
    monkeypatch.setattr(
        evidence_bundle, "get_secret", lambda name: base64.b64encode(SEED).decode()
    )
    assert public_bytes(load_signing_key()[0]) == public_bytes(key)


def test_missing_key_is_ephemeral_and_bad_key_is_refused(monkeypatch):
    monkeypatch.setattr(evidence_bundle, "get_secret", lambda name: None)
    _, source = load_signing_key()
    assert source == "ephemeral"
    with pytest.raises(SigningKeyError):
        parse_private_key("not a key")
    with pytest.raises(SigningKeyError):
        parse_private_key("00" * 16)


def test_pem_private_key_parses():
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.from_private_bytes(SEED)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    assert public_bytes(parse_private_key(pem)) == public_bytes(key)


def test_keygen_prints_a_usable_seed(capsys):
    assert evidence_bundle.main(["keygen"]) == 0
    out = capsys.readouterr().out
    seed = out.splitlines()[0].split("=", 1)[1]
    assert len(parse_private_key(seed).sign(b"x")) == 64


def test_jsonable_handles_db_types():
    import uuid
    from datetime import date, datetime
    from decimal import Decimal

    out = evidence.jsonable(
        {
            "d": Decimal("0.950"),
            "t": datetime(2026, 1, 1, 8, 0),
            "day": date(2026, 1, 2),
            "u": uuid.UUID(int=1),
            "b": b"\x00\x01",
            "s": {1},
        }
    )
    assert out == {
        "d": 0.95,
        "t": "2026-01-01T08:00:00+00:00",
        "day": "2026-01-02",
        "u": "00000000-0000-0000-0000-000000000001",
        "b": "AAE=",
        "s": [1],
    }
