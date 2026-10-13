"""Inventory of non-FIPS-approved cryptographic primitives (W3.10). A ratchet.

FIPS_MODE only holds if nothing in the shipped code quietly reaches for an
algorithm the OpenSSL 3 FIPS provider does not offer. Every such use is listed
in BASELINE with its reason. A new one fails this test; removing one also fails
it until BASELINE shrinks to match, so the list only ever gets shorter.

What counts (shipped Python and the TypeScript agent, tests excluded):
  - md5 / sha1 / md4 through hashlib without ``usedforsecurity=False``. With the
    flag the call is a non-security identifier and is allowed under FIPS too;
    without it, a FIPS OpenSSL raises at runtime. No baseline: always zero.
  - bcrypt, BLAKE2, scrypt, Ed25519/Ed448/X25519/X448, ChaCha20, DES/3DES,
    RC4, Blowfish, CAST5, IDEA, SEED, Camellia, SM3/SM4, HMAC-MD5, and crypto
    libraries that bypass OpenSSL (PyCryptodome, PyNaCl, passlib, argon2).

Python is scanned on the AST with import aliases resolved to dotted names
(``import hashlib as h; h.md5``, ``from ...hashes import MD5``, lazy imports
inside functions), string digest names (``hashlib.new('SHA-1')``,
``hmac.new(k, m, digestmod='md5')``, ``hashlib.pbkdf2_hmac('sha1', ...)``),
``cryptography``'s ``hashes.MD5/SHA1/BLAKE2*`` and dynamic imports
(``importlib.import_module('bcrypt')``, ``__import__``). Imports of a foreign
library or an Ed/X curve module count once per statement; hashes and ciphers
count per use. TypeScript is scanned with regexes (``createHash``,
``crypto.hash``, ``subtle.digest``, WebCrypto ``hash:`` params, pbkdf2 digest
args, ``createCipheriv`` and imports of JS crypto libraries).

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

_WEAK_HASHES = {"md5", "sha1", "md4", "md5-sha1", "ripemd160", "sha", "md5_sha1"}
_NON_FIPS_HASHES = {
    "blake2b": "blake2",
    "blake2s": "blake2",
    "blake2b512": "blake2",
    "blake2s256": "blake2",
    "sm3": "sm3",
}
# hashlib / OpenSSL spelling of a digest name -> canonical weak name.
_HASH_ALIASES = {"sha-1": "sha1", "sha_1": "sha1", "md-5": "md5"}
# HMAC over these is not approved (HMAC-SHA1 is, SP 800-131A; TOTP uses it).
_HMAC_FORBIDDEN = {"md5", "md4", "md5-sha1", "md5_sha1", "ripemd160"}
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
    "SM4": "sm4",
}
_CIPHER_OWNERS = ("ciphers.algorithms", "ciphers.aead")
# cryptography.hazmat.primitives.hashes.<Name> -> primitive.
_CRYPTOGRAPHY_HASHES = {
    "MD5": "md5 (security use)",
    "SHA1": "sha1 (security use)",
    "BLAKE2b": "blake2",
    "BLAKE2s": "blake2",
    "SM3": "sm3",
}
_FOREIGN_LIBS = {
    "bcrypt": "bcrypt",
    "Crypto": "pycryptodome",
    "Cryptodome": "pycryptodome",
    "nacl": "pynacl",
    "pysodium": "pynacl",
    "passlib": "passlib",
    "argon2": "argon2",
    "scrypt": "scrypt",
    "pyscrypt": "scrypt",
    "blake3": "blake3",
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


def _arg(call: ast.Call, index: int, keyword: str) -> ast.expr | None:
    if len(call.args) > index:
        return call.args[index]
    return next((kw.value for kw in call.keywords if kw.arg == keyword), None)


def _digest_name(text: str) -> str:
    name = text.lower()
    return _HASH_ALIASES.get(name, name)


class _Scanner(ast.NodeVisitor):
    """Resolves import aliases to dotted names, then classifies every import,
    call and attribute reference by what it resolves to."""

    def __init__(self) -> None:
        self.found: Counter = Counter()
        self.aliases: dict[str, str] = {}
        self.handled: set[int] = set()

    # --- name resolution ---------------------------------------------------

    def resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            owner = self.resolve(node.value)
            return f"{owner}.{node.attr}" if owner else None
        return None

    def _imported(self, module: str) -> None:
        """One import statement (or dynamic import) of ``module``."""
        root = module.split(".")[0]
        if root in _FOREIGN_LIBS:
            self.found[_FOREIGN_LIBS[root]] += 1
        leaf = module.split(".")[-1]
        if leaf in _ASYM_MODULES and ".asymmetric." in f".{module}":
            self.found[leaf] += 1

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._imported(alias.name)
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                root = alias.name.split(".")[0]
                self.aliases.setdefault(root, root)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.module or node.level:
            return
        module = node.module
        counted = False
        root = module.split(".")[0]
        if root in _FOREIGN_LIBS or module.split(".")[-1] in _ASYM_MODULES:
            self._imported(module)
            counted = True
        for alias in node.names:
            full = f"{module}.{alias.name}"
            self.aliases[alias.asname or alias.name] = full
            if not counted and alias.name in _ASYM_MODULES:
                self._imported(full)

    # --- classification ----------------------------------------------------

    def _hash_ref(self, name: str) -> str | None:
        """Primitive named by a reference to ``name`` (no call semantics)."""
        owner, _, attr = name.rpartition(".")
        if owner == "hashlib":
            low = attr.lower()
            if low in _NON_FIPS_HASHES:
                return _NON_FIPS_HASHES[low]
            if low in _WEAK_HASHES:
                return f"{low} (security use)"
            if low == "scrypt":
                return "scrypt"
        if owner.endswith("primitives.hashes") and attr in _CRYPTOGRAPHY_HASHES:
            return _CRYPTOGRAPHY_HASHES[attr]
        if attr in _CIPHERS and owner.endswith(_CIPHER_OWNERS):
            return _CIPHERS[attr]
        return None

    def _string_digest(self, node: ast.expr | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _digest_name(node.value)
        return None

    def _digest_of(self, node: ast.expr | None) -> str | None:
        """Digest named by an hmac ``digestmod``: a string, a hashlib function
        or a lambda / call around one."""
        if node is None:
            return None
        text = self._string_digest(node)
        if text:
            return text
        target = node.func if isinstance(node, ast.Call) else node
        name = self.resolve(target)
        if name:
            return _digest_name(name.rpartition(".")[2])
        return None

    def visit_Call(self, node: ast.Call) -> None:
        name = self.resolve(node.func)
        if name:
            self.handled.add(id(node.func))
            self._call(node, name)
        self.generic_visit(node)

    def _call(self, node: ast.Call, name: str) -> None:
        if name in ("importlib.import_module", "__import__"):
            module = _arg(node, 0, "name")
            if isinstance(module, ast.Constant) and isinstance(module.value, str):
                self._imported(module.value)
            return
        if name in ("hashlib.new", "hashlib.pbkdf2_hmac"):
            digest = self._string_digest(_arg(node, 0, "name"))
            if digest in _NON_FIPS_HASHES:
                self.found[_NON_FIPS_HASHES[digest]] += 1
            elif digest in _WEAK_HASHES and (
                name == "hashlib.pbkdf2_hmac" or not _security_flag_off(node)
            ):
                self.found[f"{digest} (security use)"] += 1
            return
        if name in ("hmac.new", "hmac.digest", "hmac.HMAC"):
            arg = _arg(node, 2, "digestmod" if name != "hmac.digest" else "digest")
            if arg is not None:
                self.handled.update(id(n) for n in ast.walk(arg))
            digest = self._digest_of(arg)
            if digest in _HMAC_FORBIDDEN:
                self.found["hmac-md5"] += 1
            return
        primitive = self._hash_ref(name)
        if primitive:
            if primitive.endswith("(security use)") and name.startswith("hashlib."):
                if _security_flag_off(node):
                    return
            self.found[primitive] += 1

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if id(node) not in self.handled:
            name = self.resolve(node)
            primitive = self._hash_ref(name) if name else None
            if primitive:
                self.handled.add(id(node))
                self.found[primitive] += 1
                return  # the owner chain is part of this reference
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if id(node) in self.handled or node.id not in self.aliases:
            return
        primitive = self._hash_ref(self.aliases[node.id])
        if primitive:
            self.found[primitive] += 1


def scan_python(source: str) -> Counter:
    tree = ast.parse(source)
    scanner = _Scanner()
    # Imports first, so a name is resolved wherever it is used (incl. lazily
    # imported inside a function).
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            scanner.visit(node)
    scanner.visit(_without_imports(tree))
    return +scanner.found


def _without_imports(tree: ast.Module) -> ast.Module:
    class _Strip(ast.NodeTransformer):
        def visit_Import(self, node):
            return None

        def visit_ImportFrom(self, node):
            return None

    return _Strip().visit(tree)


_Q = r"['\"`]"
_TS_PATTERNS = {
    "md5 (security use)": re.compile(
        rf"(?:create(?:Hash|Hmac)|\bhash|pbkdf2(?:Sync)?)\(\s*{_Q}md5{_Q}"
        rf"|pbkdf2(?:Sync)?\([^;]*?,\s*{_Q}md5{_Q}\s*[,)]",
        re.I,
    ),
    "sha1 (security use)": re.compile(
        rf"(?:createHash|\bhash)\(\s*{_Q}sha-?1{_Q}"
        rf"|subtle\s*\.\s*digest\(\s*(?:\{{\s*name\s*:\s*)?{_Q}sha-?1{_Q}"
        rf"|pbkdf2(?:Sync)?\([^;]*?,\s*{_Q}sha-?1{_Q}\s*[,)]"
        rf"|hash\s*:\s*{_Q}sha-?1{_Q}",
        re.I,
    ),
    "weak hash": re.compile(
        rf"(?:createHash|createHmac|\bhash)\(\s*{_Q}(?:md4|ripemd160|blake2[bs]\d*){_Q}",
        re.I,
    ),
    "ed25519": re.compile(rf"{_Q}(?:ed25519|ed448|x25519|x448){_Q}", re.I),
    "legacy cipher": re.compile(
        rf"createCipheriv\(\s*{_Q}(?:des|bf|rc4|rc2|cast|idea|seed|chacha20|camellia|sm4)",
        re.I,
    ),
    "foreign crypto lib": re.compile(
        r"(?:from\s+|require\(\s*|import\(\s*)['\"](?:bcrypt|bcryptjs|tweetnacl|"
        r"libsodium[\w-]*|crypto-js|node-forge|js-sha1|md5|argon2|scrypt-js|"
        r"@noble/(?:hashes|curves|ed25519))(?:/[^'\"]*)?['\"]",
        re.I,
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
            "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\n"
            "ChaCha20Poly1305(k)",
            "chacha20",
        ),
        ("import hmac\nhmac.new(k, m, 'md5')", "hmac-md5"),
        ("from Crypto.Cipher import AES", "pycryptodome"),
        # Round 3: alias resolution, cryptography hashes, string digest names,
        # dynamic imports and password-hashing libraries outside OpenSSL.
        (
            "from cryptography.hazmat.primitives import hashes\nhashes.MD5()",
            "md5 (security use)",
        ),
        (
            "from cryptography.hazmat.primitives import hashes\nhashes.SHA1()",
            "sha1 (security use)",
        ),
        (
            "from cryptography.hazmat.primitives import hashes as H\nH.BLAKE2b(64)",
            "blake2",
        ),
        (
            "from cryptography.hazmat.primitives.hashes import MD5\nMD5()",
            "md5 (security use)",
        ),
        (
            "import cryptography.hazmat.primitives.hashes\n"
            "cryptography.hazmat.primitives.hashes.SHA1()",
            "sha1 (security use)",
        ),
        ("import hashlib as h\nh.md5(b'x')", "md5 (security use)"),
        ("from hashlib import md5 as m\nm(b'x')", "md5 (security use)"),
        ("import hashlib\nf = hashlib.md5", "md5 (security use)"),
        ("import hashlib\nhashlib.new('SHA-1')", "sha1 (security use)"),
        (
            "import hashlib\nhashlib.pbkdf2_hmac('sha1', p, s, 1000)",
            "sha1 (security use)",
        ),
        ("import hmac\nhmac.new(k, m, digestmod='md5')", "hmac-md5"),
        ("import hmac\nhmac.digest(k, m, 'md5')", "hmac-md5"),
        ("import hmac\nhmac.digest(k, m, digest='MD5')", "hmac-md5"),
        ("import hmac, hashlib\nhmac.new(k, m, hashlib.md5)", "hmac-md5"),
        ("import hmac as H\nfrom hashlib import md5\nH.new(k, m, md5)", "hmac-md5"),
        (
            "from cryptography.hazmat.primitives.ciphers import algorithms as A\n"
            "A.TripleDES(k)",
            "3des",
        ),
        (
            "import cryptography.hazmat.primitives.ciphers.algorithms as alg\n"
            "alg.Blowfish(k)",
            "blowfish",
        ),
        ("import hashlib\nhashlib.scrypt(p, salt=s, n=2, r=8, p=1)", "scrypt"),
        ("from hashlib import scrypt\nscrypt(p, salt=s, n=2, r=8, p=1)", "scrypt"),
        ("from passlib.hash import bcrypt", "passlib"),
        ("import passlib.context", "passlib"),
        ("from argon2 import PasswordHasher", "argon2"),
        ("import argon2", "argon2"),
        ("import importlib\nimportlib.import_module('bcrypt')", "bcrypt"),
        (
            "from importlib import import_module\nimport_module('nacl.signing')",
            "pynacl",
        ),
        ("__import__('Crypto.Cipher')", "pycryptodome"),
        (
            "import importlib\nimportlib.import_module("
            "'cryptography.hazmat.primitives.asymmetric.ed25519')",
            "ed25519",
        ),
        (
            "def f():\n    import hashlib as hl\n    return hl.new('md5').hexdigest()",
            "md5 (security use)",
        ),
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
        "from cryptography.hazmat.primitives import hashes\nhashes.SHA256()",
        "import hashlib as h\nh.md5(b'x', usedforsecurity=False)",
        "from hashlib import sha1\nsha1(b'x', usedforsecurity=False)",
        "import hmac\nhmac.new(k, m, 'sha1')",  # HMAC-SHA1 is approved (TOTP)
        "import hmac\nhmac.digest(k, m, 'sha256')",
        "import hashlib\nhashlib.new(name)",  # dynamic; not resolvable
        "from cryptography.hazmat.primitives.ciphers import algorithms\n"
        "algorithms.AES(k)",
        "import importlib\nimportlib.import_module('json')",
        "md5 = 1\nmd5",  # a local name is not hashlib.md5
    ],
)
def test_scanner_passes_approved_uses(source):
    assert not scan_python(source)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("crypto.createHash('md5')", "md5 (security use)"),
        ("generateKeyPairSync('ed25519')", "ed25519"),
        ("await crypto.subtle.digest('SHA-1', data)", "sha1 (security use)"),
        ("await crypto.subtle.digest({ name: 'SHA-1' }, data)", "sha1 (security use)"),
        (
            "crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-1' })",
            "sha1 (security use)",
        ),
        ("crypto.hash('sha1', data)", "sha1 (security use)"),
        ("crypto.pbkdf2Sync(p, s, 1000, 32, 'md5')", "md5 (security use)"),
        ("crypto.createHash('ripemd160')", "weak hash"),
        ("crypto.createCipheriv('des-ede3-cbc', k, iv)", "legacy cipher"),
        ("import bcrypt from 'bcryptjs';", "foreign crypto lib"),
        ("const nacl = require('tweetnacl');", "foreign crypto lib"),
        ("import { sha1 } from '@noble/hashes/sha1';", "foreign crypto lib"),
    ],
)
def test_typescript_scanner_catches(source, expected):
    assert scan_typescript(source)[expected] >= 1


@pytest.mark.parametrize(
    "source",
    [
        "crypto.createHash('sha256')",
        "await crypto.subtle.digest('SHA-256', data)",
        "crypto.createHmac('sha1', k)",  # HMAC-SHA1 is approved
        "crypto.pbkdf2Sync(p, s, 600000, 32, 'sha256')",
        "import { createHash } from 'node:crypto';",
    ],
)
def test_typescript_scanner_passes(source):
    assert not scan_typescript(source)


def test_the_scan_reaches_real_code():
    """Guard against a vacuous pass after a directory move."""
    scanned = [p for d in PY_DIRS for p in (REPO_ROOT / d).rglob("*.py")]
    assert len(scanned) > 300
    assert (REPO_ROOT / "core/auth/auth_service.py") in scanned
    assert any(
        (REPO_ROOT / d).exists() and any((REPO_ROOT / d).rglob("*.ts")) for d in TS_DIRS
    )
