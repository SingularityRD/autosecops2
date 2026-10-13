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


# -- the ZIP container itself (W3.7 round 3) -----------------------------------
# In-process through main(): the -I subprocess runs above already prove the
# verifier is stdlib-only.


def _main(tmp_path, data: bytes, *args):
    pack = tmp_path / "pack.zip"
    pack.write_bytes(data)
    return verify_bundle.main([str(pack), "--public-key", PUB_HEX, *args])


def _offsets(data: bytes, name: str):
    """(local header offset, central header offset) of ``name``."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        local = z.getinfo(name).header_offset
    central = data.index(b"PK\x01\x02", data.rindex(b"PK\x05\x06") - 4096)
    while data[central + 46 : central + 46 + len(name)] != name.encode():
        central = data.index(b"PK\x01\x02", central + 4)
    return local, central


def _patch(data: bytes, name: str, *, local=None, central=None) -> bytes:
    """Overwrite little-endian fields: {byte offset in the header: (fmt, value)}."""
    import struct

    out = bytearray(data)
    lo, co = _offsets(data, name)
    for base, fields in ((lo, local or {}), (co, central or {})):
        for at, (fmt, value) in fields.items():
            struct.pack_into(fmt, out, base + at, value)
    return bytes(out)


def _other_zip() -> bytes:
    files = _files(make_bundle().data)
    files["data/case.json"] = b'{"case_id": "SOMETHING-ELSE"}'
    return _zip(files)


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda d: b"MZ" + b"\0" * 62 + d, id="prepended bytes"),
        pytest.param(lambda d: d + b"trailing", id="appended bytes"),
        pytest.param(lambda d: d + _other_zip(), id="second zip appended"),
        pytest.param(lambda d: _other_zip() + d, id="second zip prepended"),
    ],
)
def test_bytes_around_the_archive_are_refused(tmp_path, capsys, build):
    good = make_bundle().data
    assert _main(tmp_path, good) == 0
    assert _main(tmp_path, build(good)) == 2
    assert "error:" in capsys.readouterr().err


def test_a_zip_comment_is_refused(tmp_path):
    files = _files(make_bundle().data)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
        z.comment = b"hello"
    assert _main(tmp_path, buf.getvalue()) == 2


def test_a_local_header_that_disagrees_with_the_directory_is_refused(tmp_path):
    data = make_bundle().data
    lo, _ = _offsets(data, "data/case.json")
    renamed = bytearray(data)
    renamed[lo + 30 : lo + 30 + len("data/case.json")] = b"data/cas3.json"
    assert _main(tmp_path, bytes(renamed)) == 2
    # local compressed size differs from the central one
    assert _main(tmp_path, _patch(data, "data/case.json", local={18: ("<I", 1)})) == 2
    # local method differs
    assert _main(tmp_path, _patch(data, "data/case.json", local={8: ("<H", 0)})) == 2


def test_a_directory_entry_is_rejected(tmp_path, capsys):
    files = _files(make_bundle().data)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("data/"), b"")
        for name, body in files.items():
            z.writestr(name, body)
    assert _main(tmp_path, buf.getvalue()) == 1
    out = capsys.readouterr().out
    assert "FAIL  archive" in out and "data/ is a directory entry" in out


def test_an_unlisted_entry_is_rejected_without_being_read(
    tmp_path, capsys, monkeypatch
):
    files = _files(make_bundle().data)
    files["data/zz-extra.json"] = b"{}"
    inflated = []
    real = verify_bundle._inflate
    monkeypatch.setattr(
        verify_bundle,
        "_inflate",
        lambda h, e: inflated.append(e.name) or real(h, e),
    )
    assert _main(tmp_path, _zip(files)) == 1
    assert "data/zz-extra.json is not in the manifest" in capsys.readouterr().out
    assert set(inflated) == {"manifest.json", "manifest.sig"}


def test_a_declared_size_unlike_the_manifest_is_not_inflated(tmp_path, capsys):
    files = _files(make_bundle().data)
    files["data/case.json"] = b"0" * (
        50 * 1024 * 1024
    )  # 50 MiB of zeros, ~50 KiB zipped
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in files.items():
            z.writestr(name, body)
    assert _main(tmp_path, buf.getvalue()) == 1
    assert "data/case.json declares 52428800 bytes" in capsys.readouterr().out


def test_an_entry_that_inflates_past_its_declared_size_is_refused(tmp_path, capsys):
    data = make_bundle().data
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        size = z.getinfo("data/case.json").file_size
    # Under-declare by one byte in both headers: the stream yields more.
    lie = _patch(
        data,
        "data/case.json",
        local={22: ("<I", size - 1)},
        central={24: ("<I", size - 1)},
    )
    assert _main(tmp_path, lie) == 1  # the manifest size check fires first
    # With the manifest consulted out of the way, the inflater itself stops.
    pack = tmp_path / "lie.zip"
    pack.write_bytes(lie)
    with open(pack, "rb") as handle:
        entries = verify_bundle._zip_entries(handle, len(lie))
        [entry] = [e for e in entries if e.name == "data/case.json"]
        with pytest.raises(verify_bundle.PackUnreadable, match="past its declared"):
            verify_bundle._inflate(handle, entry)


def test_the_total_size_cap_applies_before_reading(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(verify_bundle, "MAX_PACK_BYTES", 1024)
    assert _main(tmp_path, make_bundle().data, "--json") == 2
    body = json.loads(capsys.readouterr().out)
    assert body["ok"] is False and "uncompressed" in body["error"]


@pytest.mark.parametrize(
    "fields,message",
    [
        ({6: ("<H", 0x0001)}, "encrypted"),
        ({8: ("<H", 99)}, "unsupported compression method 99"),
        ({8: ("<H", 12)}, "unsupported compression method 12"),
    ],
)
def test_encrypted_or_unknown_compression_is_a_clean_exit_2(
    tmp_path, capsys, fields, message
):
    data = make_bundle().data
    central = {at + 2: spec for at, spec in fields.items()}  # same field, +2 in CD
    bad = _patch(data, "data/case.json", local=fields, central=central)
    assert _main(tmp_path, bad, "--json") == 2
    captured = capsys.readouterr()
    body = json.loads(captured.out)
    assert body == {"ok": False, "error": body["error"]} and message in body["error"]
    assert "Traceback" not in captured.err
    assert _main(tmp_path, bad) == 2
    captured = capsys.readouterr()
    assert message in captured.err and "Traceback" not in captured.err


def test_an_unexpected_failure_is_still_exit_2_without_a_traceback(
    tmp_path, capsys, monkeypatch
):
    def boom(path, *_args):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(verify_bundle, "read_pack", boom)
    assert _main(tmp_path, make_bundle().data, "--json") == 2
    body = json.loads(capsys.readouterr().out)
    assert body["ok"] is False and "disk on fire" in body["error"]


def test_a_truncated_or_corrupt_stream_is_exit_2(tmp_path):
    data = make_bundle().data
    lo, _ = _offsets(data, "data/case.json")
    corrupt = bytearray(data)
    start = lo + 30 + len("data/case.json")
    corrupt[start : start + 4] = b"\xff\xff\xff\xff"
    assert _main(tmp_path, bytes(corrupt)) == 2
    assert _main(tmp_path, data[: len(data) // 2]) == 2


# -- round 5: one directory for every reader -----------------------------------
import hashlib  # noqa: E402
import shutil  # noqa: E402
import struct  # noqa: E402
import zlib  # noqa: E402


def _raw_entries(data: bytes):
    """[(central header bytes, name, local header bytes, payload)] of a plain ZIP."""
    _, _, _, _, n, cd_size, cd_off, _ = struct.unpack("<4sHHHHIIH", data[-22:])
    out, pos = [], cd_off
    for _ in range(n):
        nl, xl, cl = struct.unpack_from("<HHH", data, pos + 28)
        central = data[pos : pos + 46]
        name = data[pos + 46 : pos + 46 + nl]
        (lo,) = struct.unpack_from("<I", data, pos + 42)
        (csize,) = struct.unpack_from("<I", data, pos + 20)
        lnl, lxl = struct.unpack_from("<HH", data, lo + 26)
        start = lo + 30 + lnl + lxl
        out.append((central, name, data[lo : lo + 30], data[start : start + csize]))
        pos += 46 + nl + xl + cl
    return out


def _rebuild(data: bytes, *, local_extra=None, central_extra=None, comment=None):
    """``data`` again, with an extra field or comment added to chosen entries.

    Each keyword maps an entry name to the bytes to add for it.
    """
    local_extra, central_extra = local_extra or {}, central_extra or {}
    comment = comment or {}
    body, directory = b"", b""
    for central, name, local, payload in _raw_entries(data):
        key = name.decode()
        lx = local_extra.get(key, b"")
        cx, cc = central_extra.get(key, b""), comment.get(key, b"")
        offset = len(body)
        body += local[:28] + struct.pack("<H", len(lx)) + name + lx + payload
        directory += (
            central[:30]
            + struct.pack("<HH", len(cx), len(cc))
            + central[34:42]
            + struct.pack("<I", offset)
            + name
            + cx
            + cc
        )
    n = len(_raw_entries(data))
    eocd = struct.pack(
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, n, n, len(directory), len(body), 0
    )
    return body + directory + eocd


def _unicode_path_extra(real_name: str) -> bytes:
    """Info-ZIP Unicode Path extra (0x7075): some readers use this name instead."""
    payload = b"\x01" + struct.pack("<I", zlib.crc32(real_name.encode()))
    payload += b"data/evil.json"
    return struct.pack("<HH", 0x7075, len(payload)) + payload


def _zip64_swap(good: bytes) -> bytes:
    """A pack whose last central entry's comment hides a second directory.

    The comment holds a local header with a doctored ledger.json, a central
    directory pointing at it, a ZIP64 EOCD record and a ZIP64 locator ending
    exactly where the classic EOCD begins; CPython's zipfile follows the
    locator and reads that ledger (the round-4 finding).
    """
    _, _, _, _, nt, cds, cdo, _ = struct.unpack("<4sHHHHIIH", good[-22:])
    cd, recs, p = good[cdo : cdo + cds], [], 0
    while p < len(cd):
        nl, xl, cml = struct.unpack_from("<HHH", cd, p + 28)
        recs.append(cd[p : p + 46 + nl + xl + cml])
        p += 46 + nl + xl + cml

    def name(r):
        return r[46 : 46 + struct.unpack_from("<H", r, 28)[0]]

    pre, last = b"".join(recs[:-1]), recs[-1]
    head = last[: 46 + struct.unpack_from("<H", last, 28)[0]]
    lfh_off = cdo + len(pre) + len(head)
    with zipfile.ZipFile(io.BytesIO(good)) as z:
        evil = z.read("data/ledger.json").replace(b"malicious", b"BENIGN!!!")
    crc = zlib.crc32(evil)
    lfh = (
        struct.pack(
            "<4sHHHHHIIIHH",
            b"PK\x03\x04",
            20,
            0,
            0,
            0,
            0x5C62,
            crc,
            len(evil),
            len(evil),
            16,
            0,
        )
        + b"data/ledger.json"
        + evil
    )
    alt = b""
    for r in recs:
        if name(r) == b"data/ledger.json":
            r = (
                r[:10]
                + struct.pack("<H", 0)
                + r[12:16]
                + struct.pack("<III", crc, len(evil), len(evil))
                + r[28:42]
                + struct.pack("<I", lfh_off)
                + r[46:]
            )
        alt += r
    alt_off = lfh_off + len(lfh)
    z64_off = alt_off + len(alt)
    z64 = struct.pack(
        "<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, nt, nt, len(alt), alt_off
    )
    loc = struct.pack("<4sIQI", b"PK\x06\x07", 0, z64_off, 1)
    hidden = lfh + alt + z64 + loc
    head = head[:32] + struct.pack("<H", len(hidden)) + head[34:]
    newcd = pre + head + hidden
    return (
        good[:cdo]
        + newcd
        + struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, nt, nt, len(newcd), cdo, 0)
    )


def test_a_hidden_zip64_directory_is_refused(tmp_path, capsys):
    good = make_bundle().data
    swapped = _zip64_swap(good)
    # The attack is real: CPython's zipfile reads the doctored ledger ...
    with zipfile.ZipFile(io.BytesIO(swapped)) as z:
        assert b"BENIGN!!!" in z.read("data/ledger.json")
    # ... so the verifier must not call the pack verified.
    assert _main(tmp_path, swapped) == 2
    assert "extra field or comment" in capsys.readouterr().err


@pytest.mark.parametrize("sig", [b"PK\x06\x06", b"PK\x06\x07"])
def test_a_zip64_signature_outside_entry_data_is_refused(tmp_path, capsys, sig):
    files = _files(make_bundle().data)
    files["data/x" + sig.decode("latin-1") + ".json"] = b"{}"
    assert _main(tmp_path, _zip(files)) == 2
    assert "ZIP64 record or locator signature" in capsys.readouterr().err


@pytest.mark.parametrize(
    "where",
    [
        pytest.param({"central_extra": True}, id="central extra"),
        pytest.param({"local_extra": True}, id="local extra"),
        pytest.param({"central_extra": True, "local_extra": True}, id="both"),
    ],
)
def test_an_info_zip_unicode_path_extra_is_refused(tmp_path, capsys, where):
    good = make_bundle().data
    name = "data/case.json"
    extra = {name: _unicode_path_extra(name)}
    bad = _rebuild(
        good,
        local_extra=extra if where.get("local_extra") else None,
        central_extra=extra if where.get("central_extra") else None,
    )
    assert _main(tmp_path, bad) == 2
    assert "extra field" in capsys.readouterr().err


def test_an_entry_comment_is_refused(tmp_path, capsys):
    good = make_bundle().data
    assert _main(tmp_path, _rebuild(good)) == 0  # the rebuild alone is harmless
    bad = _rebuild(good, comment={"manifest.sig": b"note"})
    assert _main(tmp_path, bad) == 2
    assert "extra field or comment" in capsys.readouterr().err


def test_the_builder_writes_no_extra_field_and_no_comment():
    data = make_bundle().data
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert z.comment == b""
        for info in z.infolist():
            assert info.extra == b"" and info.comment == b"", info.filename
            assert not info.flag_bits & 0x08  # no data descriptor either
    for central, _name, local, _payload in _raw_entries(data):
        assert struct.unpack_from("<HH", central, 30) == (0, 0)
        assert struct.unpack_from("<H", local, 28) == (0,)


def _streamed(monkeypatch):
    seen = []
    real = verify_bundle._stream

    def spy(handle, entry):
        seen.append(entry.name)
        return real(handle, entry)

    monkeypatch.setattr(verify_bundle, "_stream", spy)
    return seen


def test_no_entry_is_inflated_before_the_signature_holds(tmp_path, capsys, monkeypatch):
    # A forged manifest (not re-signed) that lists a 50 MiB entry.
    files = _files(make_bundle().data)
    files["data/case.json"] = b"0" * (50 * 1024 * 1024)
    manifest = json.loads(files["manifest.json"])
    for entry in manifest["files"]:
        if entry["path"] == "data/case.json":
            entry["bytes"] = len(files["data/case.json"])
            entry["sha256"] = verify_bundle.sha256_hex(files["data/case.json"])
    files["manifest.json"] = json.dumps(manifest, sort_keys=True, indent=2).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in files.items():
            z.writestr(name, body)
    seen = _streamed(monkeypatch)
    assert _main(tmp_path, buf.getvalue()) == 1
    assert "FAIL  signature" in capsys.readouterr().out
    assert set(seen) == {"manifest.json", "manifest.sig"}


def test_a_pack_signed_by_another_key_is_not_inflated_when_pinned(
    tmp_path, capsys, monkeypatch
):
    files = _resign(_files(make_bundle().data), Ed25519PrivateKey.generate())
    seen = _streamed(monkeypatch)
    assert _main(tmp_path, _zip(files)) == 1
    assert "not the pinned key" in capsys.readouterr().out
    assert set(seen) == {"manifest.json", "manifest.sig"}


def test_entries_are_hashed_while_streaming_not_buffered(tmp_path, monkeypatch):
    import tracemalloc

    key = Ed25519PrivateKey.from_private_bytes(SEED)
    files = _files(make_bundle().data)
    big = b"\0" * (32 * 1024 * 1024)
    files["data/big.bin"] = big
    manifest = json.loads(files["manifest.json"])
    manifest["files"].append({"path": "data/big.bin", "sha256": "", "bytes": 0})
    files["manifest.json"] = json.dumps(manifest).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in _resign(files, key).items():
            z.writestr(name, body)
    del big, files
    pack = tmp_path / "big.zip"
    pack.write_bytes(buf.getvalue())
    del buf
    inflated = []
    real = verify_bundle._inflate
    monkeypatch.setattr(
        verify_bundle, "_inflate", lambda h, e: inflated.append(e.name) or real(h, e)
    )
    tracemalloc.start()
    try:
        read = verify_bundle.read_pack(str(pack))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * 1024 * 1024, peak
    assert read["data/big.bin"] == verify_bundle.Digest(
        hashlib.sha256(b"\0" * (32 * 1024 * 1024)).hexdigest(), 32 * 1024 * 1024
    )
    assert "data/big.bin" not in inflated and "verify_bundle.py" not in inflated
    assert set(inflated) <= verify_bundle.CONTENT_FILES
    assert all(c.ok for c in verify_bundle.verify_files(read, bytes.fromhex(PUB_HEX)))
    assert verify_bundle.main([str(pack), "--public-key", PUB_HEX]) == 0


def test_every_zip_reader_lists_the_same_pack(tmp_path):
    """CPython zipfile, ``python -m zipfile -l``, unzip and the verifier agree."""
    data = make_bundle().data
    pack = tmp_path / "pack.zip"
    pack.write_bytes(data)
    read = verify_bundle.read_pack(str(pack))

    def digest(body):
        return hashlib.sha256(body).hexdigest()

    ours = {
        name: (v.sha256 if isinstance(v, verify_bundle.Digest) else digest(v))
        for name, v in read.items()
    }
    with zipfile.ZipFile(pack) as z:
        cpython = {i.filename: digest(z.read(i)) for i in z.infolist()}
    assert cpython == ours

    listing = subprocess.run(
        [sys.executable, "-I", "-m", "zipfile", "-l", str(pack)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout.splitlines()
    assert listing[0].startswith("File Name")
    assert sorted(line.split()[0] for line in listing[1:] if line.strip()) == sorted(
        ours
    )

    if shutil.which("unzip") is None:
        pytest.skip("unzip is not installed")
    names = subprocess.run(
        ["unzip", "-Z1", str(pack)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout.split()
    assert sorted(names) == sorted(ours)
    for name in names:
        body = subprocess.run(
            ["unzip", "-p", str(pack), name],
            capture_output=True,
            timeout=120,
            check=True,
        ).stdout
        assert digest(body) == ours[name], name
    test = subprocess.run(
        ["unzip", "-tq", str(pack)], capture_output=True, text=True, timeout=120
    )
    assert test.returncode == 0, test.stdout + test.stderr
