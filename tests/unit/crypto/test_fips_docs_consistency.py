"""Operator docs must not claim FIPS_MODE switches checkpoint signing to ECDSA (W3.10).

core/crypto/signing.py offers ECDSA P-256, but the audit checkpoint and
evidence-pack code still sign with Ed25519 directly. Until they are wired to
core.crypto.signing, the docs have to say plainly that those signatures stay
Ed25519 under FIPS_MODE. When they are wired, this test fails on purpose:
update docs/fips.md, env.example, core/config.py and this test together.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

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


def _imports_signing(rel: str) -> bool:
    """``rel`` imports core.crypto.signing, absolutely or relatively (W0.18:
    ``from ..crypto import signing`` / ``from ..crypto.signing import x``)."""
    import ast

    package = rel[: -len(".py")].replace("/", ".").rpartition(".")[0].split(".")
    for node in ast.walk(ast.parse(_read(rel))):
        if isinstance(node, ast.Import):
            if any(a.name == "core.crypto.signing" or a.name.startswith("core.crypto.signing.") for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parent = package[: len(package) - node.level + 1]
                base = ".".join(parent + ([base] if base else []))
            if base == "core.crypto.signing" or base.startswith("core.crypto.signing."):
                return True
            if base == "core.crypto" and any(a.name == "signing" for a in node.names):
                return True
    return "core.crypto.signing" in _read(rel)


def _wired() -> list:
    return [m for m in SIGNING_MODULES if _imports_signing(m)]


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


# W0.18: operator text that describes FIPS_MODE, read as prose.
PROSE_FILES = (
    "docs/fips.md",
    "CHANGELOG.md",
    *NO_ECDSA_FILES,
)

_SIG_SUBJECT = re.compile(
    r"kontrol noktas|kanıt paket|checkpoint|evidence[- ]?(pack|bundle)"
    r"|\b(tüm|bütün|her|all|every)\b[^.;]{0,40}\b(imza|signature)",
    re.I,
)
_APPROVED = re.compile(r"onayl|approved|uyumlu|compliant|validated|doğrulanmış", re.I)
_NEGATION = re.compile(
    r"sayılmaz|değil|desteklenmez|kullanılmaz|kullanılmaması|olmaz|hiçbir"
    r"|\bnot\b|n't\b|\bno\b|\bnever\b",
    re.I,
)
_BLANKET = re.compile(
    r"\b(yalnızca|sadece|only|exclusively)\b[^.;]{0,80}(onayl|approved)"
    r"|\b(tüm|bütün|all|every)\b[^.;]{0,40}(algoritma|algorithm|ilkel|primitive)[^.;]{0,40}(onayl|approved)",
    re.I,
)


def _paragraphs(text: str) -> list:
    """Paragraphs of ``text`` (table rows count as one each), comment markers
    stripped and lines joined."""
    out, cur = [], []
    for raw in text.splitlines():
        line = re.sub(r"^\s*#+\s?", "", raw).strip()
        if line.startswith("|"):
            if cur:
                out.append(" ".join(cur))
                cur = []
            out.append(line)
        elif line:
            cur.append(line)
        elif cur:
            out.append(" ".join(cur))
            cur = []
    if cur:
        out.append(" ".join(cur))
    return out


def unqualified_fips_claims(text: str) -> list:
    """Sentences that call checkpoint / evidence-pack / all signatures
    FIPS-approved, or say FIPS_MODE uses only approved algorithms without
    naming the exceptions (Ed25519 signatures, ssh_tunnel)."""
    bad = []
    for para in _paragraphs(text):
        units = [para] if para.startswith("|") else re.split(r"(?<=[.;!?])\s+", para)
        for unit in units:
            if _SIG_SUBJECT.search(unit) and _APPROVED.search(unit) and not _NEGATION.search(unit):
                bad.append(unit)
            elif _BLANKET.search(unit) and not ("Ed25519" in para and "ssh_tunnel" in para):
                bad.append(unit)
    return bad


@pytest.mark.parametrize(
    "text",
    [
        "AutoSecOps, `FIPS_MODE=true` ile yalnızca FIPS 140-3 onaylı algoritmaları kullanan bir modda çalışır.",
        "In FIPS mode AutoSecOps uses only FIPS 140-3 approved algorithms.",
        "FIPS modunda kontrol noktası imzaları FIPS onaylıdır.",
        "Kanıt paketi manifest imzası FIPS 140-3 uyumlu bir algoritmayla atılır.",
        "Audit checkpoints are FIPS-approved signatures.",
        "Evidence-pack signatures are FIPS 140-3 validated.",
        "FIPS_MODE=true ile tüm imzalar FIPS onaylı hale gelir.",
        "With FIPS_MODE on, all signatures are FIPS-approved.",
        "| Denetim kontrol noktası imzası | Ed25519 | FIPS onaylı imza |",
        "# FIPS_MODE: every signature AutoSecOps writes is approved.",
    ],
)
def test_claim_detector_catches_broad_or_signature_claims(text):
    assert unqualified_fips_claims(text), text


@pytest.mark.parametrize(
    "text",
    [
        "Denetim kontrol noktası imzaları Ed25519 kalır; FIPS onaylı sayılmaz.",
        "do not count them as FIPS-approved signatures",
        "Yeni parola hash'leri FIPS 140-3 onaylı PBKDF2-HMAC-SHA256 ile üretilir.",
        "Yalnızca FIPS onaylı algoritmalar kullanılır; istisnalar: Ed25519 imzaları ve ssh_tunnel.",
    ],
)
def test_claim_detector_accepts_qualified_text(text):
    assert not unqualified_fips_claims(text), text


def test_operator_docs_make_no_unqualified_fips_claims():
    for rel in PROSE_FILES:
        assert unqualified_fips_claims(_read(rel)) == [], rel
    config = _read("core/config.py")
    block = config[config.index("# FIPS 140-3 mode") : config.index("fips_mode: bool")]
    assert unqualified_fips_claims(block) == [], block


def test_fips_intro_names_the_exceptions():
    fips = _read("docs/fips.md")
    intro = fips[: fips.index("## Mod ne yapar")]
    assert "Ed25519" in intro and "ssh_tunnel" in intro, intro


@pytest.mark.parametrize(
    "source",
    [
        "from ..crypto import signing\n",
        "from ..crypto.signing import sign\n",
        "from ..crypto import fips, signing as s\n",
        "import core.crypto.signing as s\n",
        "from core.crypto import signing\n",
    ],
)
def test_wiring_detector_sees_relative_imports(monkeypatch, source):
    monkeypatch.setattr(sys.modules[__name__], "_read", lambda rel: source)
    assert _imports_signing("core/audit/checkpoint.py")


def test_wiring_detector_ignores_other_crypto_imports(monkeypatch):
    monkeypatch.setattr(sys.modules[__name__], "_read", lambda rel: "from ..crypto import fips\n")
    assert not _imports_signing("core/audit/checkpoint.py")
