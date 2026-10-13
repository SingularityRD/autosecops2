"""Inventory of non-FIPS-approved cryptographic primitives (W3.10). A ratchet.

FIPS_MODE only holds if nothing in the shipped code quietly reaches for an
algorithm the OpenSSL 3 FIPS provider does not offer. Every such use is listed
in BASELINE with its reason. A new one fails this test; removing one also fails
it until BASELINE shrinks to match, so the list only ever gets shorter.

What counts (shipped Python and the TypeScript agent, tests excluded):
  - md5 / sha1 / md4 through hashlib without ``usedforsecurity=False``. With the
    flag the call is a non-security identifier and is allowed under FIPS too;
    without it, a FIPS OpenSSL raises at runtime. No baseline: always zero.
  - bcrypt, BLAKE2, Ed25519/Ed448/X25519/X448, ChaCha20, DES/3DES, RC4,
    Blowfish, CAST5, IDEA, SEED, Camellia, HMAC-MD5, and crypto libraries that
    bypass OpenSSL (PyCryptodome, PyNaCl).

Approved and therefore not listed: SHA-2/SHA-3, HMAC-SHA*, PBKDF2-HMAC-SHA256,
AES (Fernet = AES-128-CBC + HMAC-SHA256), ECDSA P-256, RSA >= 2048, HS256 JWT.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
PY_DIRS = ("core", "services", "tools", "scripts", "evalkit", "eval")
TS_DIRS = ("services/agent",)

# path -> {primitive: count}. Shrink it; never grow it without a FIPS story.
BASELINE: dict[str, dict[str, int]] = {
    # Verifies and rewrites legacy bcrypt hashes; never produces one under
    # FIPS_MODE (core/auth/passwords.py, FIPS_LEGACY_BCRYPT_VERIFY).
    "core/auth/passwords.py": {"bcrypt": 1},
    # Non-FIPS default for audit checkpoints; FIPS_MODE selects ECDSA P-256.
    "core/crypto/signing.py": {"ed25519": 1},
    # Medic's own signed-pack trust root (separate image and contract, F2).
    "services/medic/contracts/trust_check.py": {"ed25519": 1},
    "services/medic/contracts/tools/gen_f2_fixtures.py": {"ed25519": 1},
}

_WEAK_HASHES = {"md5", "sha1", "md4", "md5-sha1", "ripemd160"}
_NON_FIPS_HASHES = {"blake2b": "blake2", "blake2s": "blake2"}
_ASYM_MODULES = {"ed25519", "ed448", "x25519", "x448"}
_CIPHERS = {
    "ChaCha20": "chacha20",
    "ChaCha20Poly1305": "chacha20",
    "TripleDES": "3des",
    "ARC4": "rc4",
    "Blowfish": "blowfish",
    "CAST5": "cast5",
    "IDEA": "idea",
    "SEED": "seed",
    "Camellia": "camellia",
}
_FOREIGN_LIBS = {
    "bcrypt": "bcrypt",
    "Crypto": "pycryptodome",
    "Cryptodome": "pycryptodome",
    "nacl": "pynacl",
}


def _is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    return (
        any(p in ("tests", "test", "__tests__", "node_modules", ".venv") for p in parts)
        or name.startswith("test_")
        or name.endswith(("_test.py", ".test.ts", ".spec.ts"))
    )


def _security_flag_off(call: ast.Call) -> bool:
    return any(
        kw.arg == "usedforsecurity"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is False
        for kw in call.keywords
    )


def _str_arg(call: ast.Call, index: int = 0) -> str | None:
    if len(call.args) > index and isinstance(call.args[index], ast.Constant):
        value = call.args[index].value
        return value.lower() if isinstance(value, str) else None
    return None


def scan_python(source: str) -> Counter:
    found: Counter = Counter()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _FOREIGN_LIBS:
                    found[_FOREIGN_LIBS[root]] += 1
                leaf = alias.name.split(".")[-1]
                if leaf in _ASYM_MODULES and "asymmetric" in alias.name:
                    found[leaf] += 1
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in _FOREIGN_LIBS:
                found[_FOREIGN_LIBS[root]] += 1
            leaf = node.module.split(".")[-1]
            if leaf in _ASYM_MODULES:
                found[leaf] += 1
            for alias in node.names:
                if node.module.endswith("asymmetric") and alias.name in _ASYM_MODULES:
                    found[alias.name] += 1
                if alias.name in _CIPHERS:
                    found[_CIPHERS[alias.name]] += 1
                if node.module == "hashlib" and alias.name in _WEAK_HASHES | set(
                    _NON_FIPS_HASHES
                ):
                    found[_NON_FIPS_HASHES.get(alias.name, alias.name)] += 1
        elif isinstance(node, ast.Attribute) and node.attr in _CIPHERS:
            if isinstance(node.value, ast.Name) and node.value.id in (
                "algorithms",
                "aead",
            ):
                found[_CIPHERS[node.attr]] += 1
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            owner = node.func.value
            if not (isinstance(owner, ast.Name) and owner.id in ("hashlib", "hmac")):
                continue
            fn = node.func.attr
            if owner.id == "hashlib":
                if fn in _NON_FIPS_HASHES:
                    found[_NON_FIPS_HASHES[fn]] += 1
                name = (
                    fn
                    if fn in _WEAK_HASHES
                    else _str_arg(node) if fn == "new" else None
                )
                if name in _NON_FIPS_HASHES:
                    found[_NON_FIPS_HASHES[name]] += 1
                elif name in _WEAK_HASHES and not _security_flag_off(node):
                    found[f"{name} (security use)"] += 1
            elif fn == "new" and len(node.args) >= 3:
                digest = node.args[2]
                text = (
                    digest.value.lower()
                    if isinstance(digest, ast.Constant)
                    and isinstance(digest.value, str)
                    else ast.unparse(digest).lower()
                )
                if "md5" in text:
                    found["hmac-md5"] += 1
    return found


_TS_PATTERNS = {
    "md5 (security use)": re.compile(r"create(?:Hash|Hmac)\(\s*['\"]md5['\"]", re.I),
    "sha1 (security use)": re.compile(r"createHash\(\s*['\"]sha-?1['\"]", re.I),
    "ed25519": re.compile(r"['\"](?:ed25519|ed448|x25519|x448)['\"]", re.I),
    "legacy cipher": re.compile(
        r"createCipheriv\(\s*['\"](?:des|bf|rc4|cast|idea|seed|chacha20)", re.I
    ),
}


def scan_typescript(source: str) -> Counter:
    return Counter(
        {k: len(p.findall(source)) for k, p in _TS_PATTERNS.items() if p.search(source)}
    )


def _inventory() -> dict[str, Counter]:
    inventory: dict[str, Counter] = {}
    for d in PY_DIRS:
        for path in (REPO_ROOT / d).rglob("*.py"):
            rel = path.relative_to(REPO_ROOT).as_posix()
            if _is_test_path(rel):
                continue
            found = scan_python(path.read_text(encoding="utf-8"))
            if found:
                inventory[rel] = found
    for d in TS_DIRS:
        for path in (REPO_ROOT / d).rglob("*.ts"):
            rel = path.relative_to(REPO_ROOT).as_posix()
            if _is_test_path(rel) or rel.endswith(".d.ts"):
                continue
            found = scan_typescript(path.read_text(encoding="utf-8"))
            if found:
                inventory[rel] = found
    return inventory


def test_no_new_non_fips_primitives():
    inventory = _inventory()
    grown = [
        f"{path}: {name} x{count} (baseline {BASELINE.get(path, {}).get(name, 0)})"
        for path, found in sorted(inventory.items())
        for name, count in sorted(found.items())
        if count > BASELINE.get(path, {}).get(name, 0)
    ]
    assert not grown, (
        "New non-FIPS-approved primitive(s). Use an approved one (SHA-256, "
        "PBKDF2-HMAC-SHA256, AES, ECDSA P-256), mark a non-security digest "
        "usedforsecurity=False, or route it through core/auth/passwords.py / "
        "core/crypto/signing.py so FIPS_MODE can switch it:\n  " + "\n  ".join(grown)
    )


def test_baseline_has_no_stale_entries():
    inventory = _inventory()
    stale = [
        f"{path}: {name} baseline {count}, found {inventory.get(path, Counter())[name]}"
        for path, names in sorted(BASELINE.items())
        for name, count in sorted(names.items())
        if inventory.get(path, Counter())[name] < count
    ]
    assert not stale, (
        "Ratchet: these uses are gone or fewer; lower BASELINE to match:\n  "
        + "\n  ".join(stale)
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import hashlib\nhashlib.md5(b'x')", "md5 (security use)"),
        ("import hashlib\nhashlib.sha1(\n    b'x',\n)", "sha1 (security use)"),
        ("import hashlib\nhashlib.new('MD5')", "md5 (security use)"),
        ("import hashlib\nhashlib.blake2b(b'x')", "blake2"),
        ("import bcrypt", "bcrypt"),
        (
            "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey",
            "ed25519",
        ),
        ("from cryptography.hazmat.primitives.asymmetric import x25519", "x25519"),
        (
            "from cryptography.hazmat.primitives.ciphers import algorithms\nalgorithms.TripleDES(k)",
            "3des",
        ),
        (
            "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305",
            "chacha20",
        ),
        ("import hmac\nhmac.new(k, m, 'md5')", "hmac-md5"),
        ("from Crypto.Cipher import AES", "pycryptodome"),
    ],
)
def test_scanner_catches_synthetic_violations(source, expected):
    assert scan_python(source)[expected] >= 1


@pytest.mark.parametrize(
    "source",
    [
        "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)",
        "import hashlib\nhashlib.new('sha1', usedforsecurity=False)",
        "import hashlib\nhashlib.sha256(b'x'); hashlib.pbkdf2_hmac('sha256', b'p', b's', 1000)",
        "import hmac, hashlib\nhmac.new(k, m, hashlib.sha256)",
        "from cryptography.hazmat.primitives.asymmetric import ec",
        "from cryptography.fernet import Fernet",
    ],
)
def test_scanner_passes_approved_uses(source):
    assert not scan_python(source)


def test_typescript_scanner():
    assert scan_typescript("crypto.createHash('md5')")["md5 (security use)"] == 1
    assert scan_typescript("generateKeyPairSync('ed25519')")["ed25519"] == 1
    assert not scan_typescript("crypto.createHash('sha256')")


def test_the_scan_reaches_real_code():
    """Guard against a vacuous pass after a directory move."""
    scanned = [p for d in PY_DIRS for p in (REPO_ROOT / d).rglob("*.py")]
    assert len(scanned) > 300
    assert (REPO_ROOT / "core/auth/auth_service.py") in scanned
    assert any(
        (REPO_ROOT / d).exists() and any((REPO_ROOT / d).rglob("*.ts")) for d in TS_DIRS
    )
