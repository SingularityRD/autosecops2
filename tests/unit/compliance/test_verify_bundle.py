"""The offline verifier rejects every kind of tampering (W3.7).

Packs are built by ``evidence_bundle.build_bundle`` from an in-memory
``CaseRecord``; the verifier runs as the CLI does, on a file, and on the copy
of itself the pack carries, in a subprocess with ``-I`` (no AutoSecOps on the
path).
"""

from __future__ import annotations

import base64
import io
import json
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.compliance import verify_bundle
from core.compliance.evidence import CaseRecord
from core.compliance.evidence_bundle import build_bundle, public_bytes
from core.compliance.regulatory_service import ClockEvent, event_hash
from core.storage.models import Case, CaseAuditLog, CaseEvidence, Finding

pytestmark = pytest.mark.unit

NOW = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)
CASE = "CASE-W37"
SEED = bytes(range(32))


def _ledger_run(run_id: str, payloads):
    events, prev = [], ""
    for seq, payload in enumerate(payloads):
        text = json.dumps(payload)
        h = verify_bundle.chain_hash(prev, text)
        events.append(
            {
                "seq": seq,
                "ts": "2026-03-02T08:00:00+00:00",
                "run_kind": "investigation",
                "kind": payload["kind"],
                "prev_hash": prev,
                "event_hash": h,
                "payload_text": text,
            }
        )
        prev = h
    return {"run_id": run_id, "status": "read", "events": events}


def _clock_events():
    out, prev = [], ""
    for seq, (instant, hour) in enumerate([("aware_at", 8), ("notified_at", 10)], 1):
        ev = ClockEvent(
            case_id=CASE,
            seq=seq,
            regime="nis2",
            instant=instant,
            value=datetime(2026, 3, 2, hour, tzinfo=timezone.utc),
            previous_value=None,
            actor="ayse",
            reason=None,
            recorded_at=datetime(2026, 3, 2, hour, 5, tzinfo=timezone.utc),
        )
        h = event_hash(ev, prev)
        ev = ClockEvent(**{**ev.__dict__, "prev_hash": prev, "row_hash": h})
        out.append(ev)
        prev = h
    return out


def make_record(audit_chain=None, canary_exclusion="unavailable") -> CaseRecord:
    case = Case(
        case_id=CASE,
        title="Beaconing from build host",
        description="C2 beacon",
        status="open",
        priority="high",
        created_at=datetime(2026, 3, 1, 9, 0),
    )
    findings = [
        Finding(
            finding_id="f-1",
            title="Beacon",
            data_source="edr",
            severity="high",
            timestamp=datetime(2026, 3, 1, 8, 0),
            ai_enrichment={
                "ai_triage": {
                    "timestamp": "2026-03-01T08:01:00",
                    "result": {"severity": "high", "confidence": 0.9},
                }
            },
        )
    ]
    evidence = [
        CaseEvidence(
            evidence_id=7,
            case_id=CASE,
            evidence_type="file",
            name="pcap",
            collected_by="ayse",
            collected_at=datetime(2026, 3, 1, 10, 0),
            file_hash_sha256="ab" * 32,
        )
    ]
    audits = [
        CaseAuditLog(
            audit_id=11,
            entity_type="case",
            entity_id=CASE,
            action="update",
            field_name="status",
            old_value="new",
            new_value="open",
            changed_by="ayse",
            timestamp=datetime(2026, 3, 1, 9, 30),
        )
    ]
    actions = [
        {
            "action_id": "act-1",
            "action_type": "isolate_host",
            "status": "executed",
            "approved_by": "ayse",
            "second_approver": "mehmet",
            "verify_status": "verified",
            "verified_at": "2026-03-01T11:00:00Z",
            "before_state": {"isolated": False},
            "after_state": {"isolated": True},
        }
    ]
    return CaseRecord(
        case=case,
        findings=findings,
        evidence=evidence,
        audits=audits,
        actions=actions,
        ledger=[
            _ledger_run(
                "6ba7b813-0000-5000-8000-000000000001",
                [
                    {"kind": "dispatch", "agent_id": "triage"},
                    {"kind": "finding", "answer": "malicious"},
                    {"kind": "terminal", "outcome": "done"},
                ],
            )
        ],
        ai={
            "finding_verdicts": [],
            "decisions": [],
            "investigations": [],
            "workflow_runs": [],
        },
        clock_events=_clock_events(),
        clock_status="read",
        audit_chain=audit_chain,
        canary_exclusion=canary_exclusion,
    )


def make_bundle(record=None, key=None, source="configured"):
    key = key or Ed25519PrivateKey.from_private_bytes(SEED)
    return build_bundle(record or make_record(), "ayse", NOW, key, source)


def _files(data: bytes):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return {i.filename: z.read(i) for i in z.infolist()}


def _zip(files) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
    return buf.getvalue()


def _resign(files, key):
    """Recompute the manifest for altered files and sign it: an insider with the key."""
    manifest = json.loads(files["manifest.json"])
    for entry in manifest["files"]:
        body = files[entry["path"]]
        entry["sha256"] = verify_bundle.sha256_hex(body)
        entry["bytes"] = len(body)
    pub = public_bytes(key)
    manifest["signer"]["public_key"] = base64.b64encode(pub).decode()
    manifest["signer"]["key_id"] = verify_bundle.key_id(pub)
    raw = json.dumps(manifest, sort_keys=True, indent=2).encode()
    files["manifest.json"] = raw
    files["manifest.sig"] = base64.b64encode(key.sign(raw))
    return files


def _run(tmp_path, data: bytes, *args, verifier=None):
    pack = tmp_path / "pack.zip"
    pack.write_bytes(data)
    script = verifier or Path(verify_bundle.__file__)
    return subprocess.run(
        [sys.executable, "-I", str(script), str(pack), *args],
        capture_output=True,
        text=True,
        timeout=120,
    )


PUB_HEX = public_bytes(Ed25519PrivateKey.from_private_bytes(SEED)).hex()


def test_a_fresh_pack_verifies_with_the_pinned_key(tmp_path):
    result = _run(tmp_path, make_bundle().data, "--public-key", PUB_HEX)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "RESULT: VERIFIED" in result.stdout
    for name in ("signature", "files", "ledger", "clock_chain", "citable_index"):
        assert f"ok    {name}" in result.stdout


def test_the_copy_inside_the_pack_verifies_it_too(tmp_path):
    bundle = make_bundle()
    inner = tmp_path / "inner_verify.py"
    inner.write_bytes(_files(bundle.data)["verify_bundle.py"])
    result = _run(tmp_path, bundle.data, "--public-key", PUB_HEX, verifier=inner)
    assert result.returncode == 0, result.stdout + result.stderr


def test_an_unpinned_key_verifies_with_a_warning(tmp_path):
    result = _run(tmp_path, make_bundle(source="ephemeral").data)
    assert result.returncode == 0
    assert "warn  signature" in result.stdout and "ephemeral" in result.stdout


def test_an_extracted_directory_verifies(tmp_path):
    root = tmp_path / "x"
    for name, body in _files(make_bundle().data).items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(body)
    assert verify_bundle.main([str(root), "--public-key", PUB_HEX]) == 0


def _tampered(edit):
    files = _files(make_bundle().data)
    edit(files)
    return _zip(files)


def _edit_json(files, name, change):
    body = json.loads(files[name])
    change(body)
    files[name] = json.dumps(body).encode()


TAMPERS = {
    "data file edited": lambda f: _edit_json(
        f,
        "data/actions.json",
        lambda b: b["actions"][0].update(after_state={"isolated": False}),
    ),
    "file added": lambda f: f.__setitem__("data/extra.json", b"{}"),
    "file removed": lambda f: f.pop("data/case_audit.json"),
    "manifest edited": lambda f: f.__setitem__(
        "manifest.json", f["manifest.json"].replace(b'"ayse"', b'"mallory"')
    ),
    "signature swapped": lambda f: f.__setitem__(
        "manifest.sig", base64.b64encode(b"\0" * 64)
    ),
    "verifier replaced": lambda f: f.__setitem__("verify_bundle.py", b"print('ok')\n"),
}


@pytest.mark.parametrize("name", sorted(TAMPERS))
def test_tampering_is_rejected(tmp_path, name):
    result = _run(tmp_path, _tampered(TAMPERS[name]), "--public-key", PUB_HEX)
    assert result.returncode == 1, (name, result.stdout, result.stderr)
    assert "RESULT: REJECTED" in result.stdout


def test_resigned_by_another_key_fails_only_when_pinned(tmp_path):
    other = Ed25519PrivateKey.generate()
    files = _files(make_bundle().data)
    _edit_json(files, "data/case.json", lambda b: b.update(title="nothing happened"))
    data = _zip(_resign(files, other))
    assert _run(tmp_path, data).returncode == 0  # self-consistent, unpinned
    pinned = _run(tmp_path, data, "--public-key", PUB_HEX)
    assert pinned.returncode == 1
    assert "not the pinned key" in pinned.stdout


@pytest.mark.parametrize(
    "path,change,check",
    [
        (
            "data/ledger.json",
            lambda b: b["runs"][0]["events"][1].update(
                payload_text=json.dumps({"kind": "finding", "answer": "benign"})
            ),
            "ledger",
        ),
        (
            "data/ledger.json",
            lambda b: b["runs"][0]["events"].pop(1),
            "ledger",
        ),
        (
            "data/regulatory_clock_events.json",
            lambda b: b["events"][0].update(value="2026-03-02T09:00:00+00:00"),
            "clock_chain",
        ),
        (
            "data/citable_index.json",
            lambda b: b["items"].pop(),
            "citable_index",
        ),
    ],
)
def test_a_key_holder_cannot_rewrite_a_chain(tmp_path, path, change, check):
    """Even re-signed with the real key, a doctored chain does not recompute."""
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    files = _files(make_bundle().data)
    _edit_json(files, path, change)
    result = _run(tmp_path, _zip(_resign(files, key)), "--public-key", PUB_HEX)
    assert result.returncode == 1, result.stdout
    assert f"FAIL  {check}" in result.stdout


def test_audit_chain_rows_are_checked_when_present(tmp_path):
    canonical = '{"seq": 4, "event": "insert"}'
    row = {
        "seq": 4,
        "source_table": "case_audit_logs",
        "source_id": "11",
        "event": "insert",
        "prev_hash": "aa",
        "event_hash": verify_bundle.chain_hash("aa", canonical),
        "canonical": canonical,
    }
    good = make_bundle(make_record(audit_chain=[row]))
    assert _run(tmp_path, good.data, "--public-key", PUB_HEX).returncode == 0
    files = _files(good.data)
    _edit_json(
        files, "data/audit_chain.json", lambda b: b["rows"][0].update(canonical="{}")
    )
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    result = _run(tmp_path, _zip(_resign(files, key)), "--public-key", PUB_HEX)
    assert result.returncode == 1 and "FAIL  audit_chain" in result.stdout


def test_duplicate_zip_entries_and_garbage_are_unreadable(tmp_path):
    bundle = make_bundle()
    files = _files(bundle.data)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
        with pytest.warns(UserWarning):
            z.writestr("data/case.json", b"{}")
    assert _run(tmp_path, buf.getvalue()).returncode == 2
    assert _run(tmp_path, b"not a zip").returncode == 2


def test_bad_public_key_is_usage_error(tmp_path):
    assert _run(tmp_path, make_bundle().data, "--public-key", "zz").returncode == 2


def test_json_output(tmp_path):
    result = _run(tmp_path, make_bundle().data, "--json", "--public-key", PUB_HEX)
    body = json.loads(result.stdout)
    assert body["ok"] is True and {c["name"] for c in body["checks"]} >= {
        "signature",
        "ledger",
    }


def test_pure_python_ed25519_agrees_with_cryptography():
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    pub = public_bytes(key)
    for message in (b"", b"manifest", bytes(range(200))):
        sig = key.sign(message)
        assert verify_bundle.ed25519_verify_pure(pub, message, sig)
        assert not verify_bundle.ed25519_verify_pure(pub, message + b"x", sig)
        bad = bytes([sig[0] ^ 1]) + sig[1:]
        assert not verify_bundle.ed25519_verify_pure(pub, message, bad)
    assert not verify_bundle.ed25519_verify_pure(pub[:31], b"m", key.sign(b"m"))


def test_pem_and_base64_public_keys_parse():
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.from_private_bytes(SEED).public_key()
    pem = key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    raw = bytes.fromhex(PUB_HEX)
    assert verify_bundle.parse_public_key(pem) == raw
    assert verify_bundle.parse_public_key(base64.b64encode(raw).decode()) == raw


def test_cli_wrapper_runs_the_verifier(tmp_path):
    pack = tmp_path / "p.zip"
    pack.write_bytes(make_bundle().data)
    script = Path(__file__).resolve().parents[3] / "scripts" / "autosecops"
    result = subprocess.run(
        ["bash", str(script), "verify-bundle", str(pack), "--public-key", PUB_HEX],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
