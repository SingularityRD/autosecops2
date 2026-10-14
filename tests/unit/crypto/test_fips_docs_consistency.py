"""Operator docs must not claim FIPS_MODE switches checkpoint signing to ECDSA (W3.10).

core/crypto/signing.py offers ECDSA P-256, but the audit checkpoint and
evidence-pack code still sign with Ed25519 directly. Until they are wired to
core.crypto.signing, the docs have to say plainly that those signatures stay
Ed25519 under FIPS_MODE. When they are wired, this test fails on purpose:
update docs/fips.md, env.example, core/config.py and this test together.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

SIGNING_MODULES = (
    "core/audit/checkpoint.py",
    "core/audit/verify.py",
    "core/compliance/evidence_bundle.py",
    "core/compliance/verify_bundle.py",
)

# Operator-facing text that describes FIPS_MODE. None of it may mention ECDSA
# while the checkpoint code is Ed25519-only (the only correct thing to say about
# ECDSA there would be a negation, and docs/fips.md is the place for that).
NO_ECDSA_FILES = (
    "env.example",
    "infra/helm/vigil/values.yaml",
    "infra/helm/vigil/README.md",
    "infra/docker/Dockerfile.backend",
)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _wired() -> list:
    return [
        m
        for m in SIGNING_MODULES
        if "core.crypto.signing" in _read(m) or "core.crypto import signing" in _read(m)
    ]


def test_checkpoint_code_is_still_ed25519_only():
    for rel in SIGNING_MODULES:
        assert "ed25519" in _read(rel).lower(), rel
    assert _wired() == [], (
        f"{_wired()} now use core.crypto.signing: update docs/fips.md, env.example, "
        "core/config.py (FIPS_MODE) and this test to describe the new behaviour"
    )


def test_operator_docs_do_not_claim_ecdsa_checkpoints():
    if _wired():
        return  # test_checkpoint_code_is_still_ed25519_only already fails
    for rel in NO_ECDSA_FILES:
        text = _read(rel)
        assert not re.search(r"ecdsa|p-?256", text, re.I), f"{rel} mentions ECDSA/P-256"

    config = _read("core/config.py")
    block = config[config.index("# FIPS 140-3 mode") : config.index("fips_mode: bool")]
    assert not re.search(r"ecdsa|p-?256", block, re.I), block
    assert "Ed25519" in block

    fips = _read("docs/fips.md")
    rows = [
        line
        for line in fips.splitlines()
        if line.startswith("|") and "kontrol noktası" in line
    ]
    assert rows, "docs/fips.md 'Mod ne yapar' table lost its checkpoint row"
    for row in rows:
        fips_column = row.strip("|").split("|")[-1]
        assert "Ed25519" in fips_column and "ECDSA" not in fips_column, row
    gaps = fips[fips.index("## Bilinen boşluklar") :]
    assert "yalnızca Ed25519" in gaps and "FIPS_MODE=true" in gaps

    for line in _read("CHANGELOG.md").splitlines():
        if re.search(r"ecdsa", line, re.I):
            assert "does not switch" in line, line
