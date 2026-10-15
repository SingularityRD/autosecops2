"""scripts/release/verify-release.sh against a fake release and a stub cosign.

Keyless signatures cannot be made offline in a unit test, so cosign is a stub
that records its arguments and fails on demand. The tests pin what the script
asks cosign to check (identity, issuer, trusted root, digests, predicate types)
and that every checksum, path and bundle problem stops it before "VERIFIED".
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
VERIFY = REPO / "scripts" / "release" / "verify-release.sh"
V = "2.0.0"
IDENTITY = (
    "https://github.com/SingularityRD/autosecops2/.github/workflows/release.yml"
    f"@refs/tags/v{V}"
)
ISSUER = "https://token.actions.githubusercontent.com"

STUB = """#!/bin/sh
printf '%s\\n' "$*" >> "$CALLS"
if [ -n "${FAIL_ON:-}" ]; then
  case " $* " in *"$FAIL_ON"*) echo "stub: refusing" >&2; exit 1 ;; esac
fi
exit 0
"""


def _d(c: str) -> str:
    return "sha256:" + hashlib.sha256(c.encode()).hexdigest()


@pytest.fixture()
def release(tmp_path: Path) -> Path:
    d = tmp_path / "rel"
    d.mkdir()
    files = {
        f"autosecops-{V}-python.cdx.json": "{}",
        f"autosecops-{V}-node-web.cdx.json": "{}",
        f"autosecops-{V}-image-backend-amd64.cdx.json": "{}",
        f"autosecops-{V}-image-backend.provenance.json": "{}",
        f"autosecops-{V}-images.json": "{}",
        f"autosecops-{V}-web.tar.gz": "tgz",
        "verify-release.sh": VERIFY.read_text(),
    }
    rows = [
        ("backend", "index", f"ghcr.io/x/autosecops-backend@{_d('bi')}"),
        ("backend", "amd64", f"ghcr.io/x/autosecops-backend@{_d('ba')}"),
    ]
    files[f"autosecops-{V}-images.tsv"] = "".join("\t".join(r) + "\n" for r in rows)
    for name, body in files.items():
        (d / name).write_text(body)
        (d / f"{name}.sigstore.json").write_text("{}")
    lines = [
        f"{hashlib.sha256((d / n).read_bytes()).hexdigest()}  {n}"
        for n in sorted(files)
    ]
    (d / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    (d / "SHA256SUMS.sigstore.json").write_text("{}")
    for suffix in (
        "image-backend.provenance.att.sigstore.json",
        "image-backend-amd64.sbom.att.sigstore.json",
    ):
        (d / f"autosecops-{V}-{suffix}").write_text("{}")
    (d / "trusted_root.json").write_text("{}")
    return d


def _run(tmp_path: Path, rel: Path, *args: str, fail_on: str = ""):
    stub = tmp_path / "cosign"
    stub.write_text(STUB)
    stub.chmod(0o755)
    calls = tmp_path / "calls.log"
    calls.write_text("")
    env = {**os.environ, "COSIGN": str(stub), "CALLS": str(calls), "FAIL_ON": fail_on}
    proc = subprocess.run(
        ["sh", str(VERIFY), "--dir", str(rel), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return proc, [line for line in calls.read_text().splitlines() if line]


def test_verifies_files_and_image_attestations(tmp_path: Path, release: Path) -> None:
    root = release / "trusted_root.json"
    proc, calls = _run(tmp_path, release, "--trusted-root", str(root))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.rstrip().endswith("RESULT: VERIFIED")

    for call in calls:
        assert f"--certificate-identity {IDENTITY} " in call + " "
        assert f"--certificate-oidc-issuer {ISSUER} " in call + " "
        assert f"--trusted-root {root} " in call + " "

    blobs = [c for c in calls if c.startswith("verify-blob ")]
    assert blobs[0].endswith(" SHA256SUMS")
    assert "--bundle SHA256SUMS.sigstore.json" in blobs[0]
    signed = {c.rsplit(" ", 1)[1] for c in blobs}
    assert signed == {
        "SHA256SUMS",
        f"autosecops-{V}-python.cdx.json",
        f"autosecops-{V}-node-web.cdx.json",
        f"autosecops-{V}-image-backend-amd64.cdx.json",
        f"autosecops-{V}-image-backend.provenance.json",
        f"autosecops-{V}-images.json",
        f"autosecops-{V}-images.tsv",
        f"autosecops-{V}-web.tar.gz",
    }

    atts = [c for c in calls if c.startswith("verify-blob-attestation ")]
    assert len(atts) == 2
    prov, sbom = atts
    assert "--type slsaprovenance1" in prov
    assert f"--digest {_d('bi')[7:]} --digestAlg sha256" in prov
    assert f"--bundle autosecops-{V}-image-backend.provenance.att.sigstore.json" in prov
    assert "--type cyclonedx" in sbom
    assert f"--digest {_d('ba')[7:]} --digestAlg sha256" in sbom
    assert f"--bundle autosecops-{V}-image-backend-amd64.sbom.att.sigstore.json" in sbom


def test_version_is_read_from_the_image_list(tmp_path: Path, release: Path) -> None:
    proc, _ = _run(tmp_path, release, "--skip-images")
    assert proc.returncode == 0, proc.stderr
    assert f"release {V}, expected signer {IDENTITY}" in proc.stdout


def test_custom_repo_changes_the_expected_identity(
    tmp_path: Path, release: Path
) -> None:
    proc, calls = _run(tmp_path, release, "--repo", "acme/fork", "--skip-images")
    assert proc.returncode == 0
    assert all(
        "--certificate-identity https://github.com/acme/fork/.github/workflows/release.yml"
        f"@refs/tags/v{V} " in c
        for c in calls
    )


def test_modified_file_is_rejected_before_any_signature_check(
    tmp_path: Path, release: Path
) -> None:
    (release / f"autosecops-{V}-python.cdx.json").write_text('{"evil": 1}')
    proc, calls = _run(tmp_path, release)
    assert proc.returncode != 0
    assert "checksum mismatch" in proc.stderr
    assert "VERIFIED" not in proc.stdout
    assert calls == []


def test_path_outside_the_release_is_rejected(tmp_path: Path, release: Path) -> None:
    sums = release / "SHA256SUMS"
    sums.write_text(sums.read_text() + f"{'0' * 64}  ../etc/passwd\n")
    proc, calls = _run(tmp_path, release)
    assert proc.returncode != 0
    assert "outside the release directory" in proc.stderr
    assert calls == []


def test_bad_signature_fails(tmp_path: Path, release: Path) -> None:
    proc, _ = _run(tmp_path, release, fail_on=f"autosecops-{V}-web.tar.gz")
    assert proc.returncode != 0
    assert "web.tar.gz: signature does not verify" in proc.stderr
    assert "VERIFIED" not in proc.stdout


def test_bad_image_attestation_fails(tmp_path: Path, release: Path) -> None:
    proc, _ = _run(tmp_path, release, fail_on="--type cyclonedx")
    assert proc.returncode != 0
    assert "backend/amd64: cyclonedx attestation does not verify" in proc.stderr


def test_missing_bundle_fails(tmp_path: Path, release: Path) -> None:
    (release / f"autosecops-{V}-images.json.sigstore.json").unlink()
    proc, _ = _run(tmp_path, release)
    assert proc.returncode != 0
    assert "signature bundle" in proc.stderr and "missing" in proc.stderr


def test_unlisted_file_fails(tmp_path: Path, release: Path) -> None:
    sums = release / "SHA256SUMS"
    kept = [
        line
        for line in sums.read_text().splitlines()
        if not line.endswith(f"autosecops-{V}-node-web.cdx.json")
    ]
    sums.write_text("\n".join(kept) + "\n")
    proc, _ = _run(tmp_path, release)
    assert proc.returncode != 0
    assert "is not listed in SHA256SUMS" in proc.stderr


def test_missing_attestation_bundle_fails(tmp_path: Path, release: Path) -> None:
    (release / f"autosecops-{V}-image-backend.provenance.att.sigstore.json").unlink()
    proc, _ = _run(tmp_path, release)
    assert proc.returncode != 0
    assert "attestation bundle" in proc.stderr


def test_rejects_v_prefixed_version(tmp_path: Path, release: Path) -> None:
    proc, _ = _run(tmp_path, release, "--version", "v2.0.0")
    assert proc.returncode != 0
    assert "without the leading v" in proc.stderr


def _add(rel: Path, name: str, body: str, listed: bool = True) -> None:
    (rel / name).write_text(body)
    (rel / f"{name}.sigstore.json").write_text("{}")
    if listed:
        digest = hashlib.sha256(body.encode()).hexdigest()
        with (rel / "SHA256SUMS").open("a") as fh:
            fh.write(f"{digest}  {name}\n")


def test_desktop_installers_are_verified_when_present(
    tmp_path: Path, release: Path
) -> None:
    """W0.24: the dmg / AppImage / exe of a release carry their own signature."""
    names = (
        f"autosecops-{V}-desktop-mac-arm64-unsigned.dmg",
        f"autosecops-{V}-desktop-linux-x86_64.AppImage",
        f"autosecops-{V}-desktop-win-x64-unsigned.exe",
    )
    for n in names:
        _add(release, n, n)
    proc, calls = _run(tmp_path, release, "--skip-images")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    signed = {c.rsplit(" ", 1)[1] for c in calls if c.startswith("verify-blob ")}
    assert set(names) <= signed

    proc, _ = _run(tmp_path, release, "--skip-images", fail_on=names[1])
    assert proc.returncode != 0
    assert "RESULT: VERIFIED" not in proc.stdout


def test_desktop_installer_missing_from_sha256sums_fails(
    tmp_path: Path, release: Path
) -> None:
    _add(release, f"autosecops-{V}-desktop-mac-x64.dmg", "dmg", listed=False)
    proc, _ = _run(tmp_path, release, "--skip-images")
    assert proc.returncode != 0
    assert "not listed in SHA256SUMS" in proc.stderr
