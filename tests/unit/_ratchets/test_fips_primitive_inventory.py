"""Inventory of non-FIPS-approved cryptographic primitives (W3.10). A ratchet.

FIPS_MODE only holds if nothing in the shipped code quietly reaches for an
algorithm the OpenSSL 3 FIPS provider does not offer. Every such use is listed
in BASELINE with its reason. A new one fails this test; removing one also fails
it until BASELINE shrinks to match, so the list only ever gets shorter.

What counts (every Python and TS/JS source file in the repo except tests,
third-party and generated trees; see the scope comment below REPO_ROOT):
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
(``importlib.import_module('bcrypt')``, ``__import__``).
Round 5: string expressions are constant-folded (concatenation, f-strings,
``''.join``, module-level constants); ``getattr``, ``sys.modules[...]``,
``import_module(...)`` results, ``x = hashlib`` reassignments, star imports,
``functools.partial`` and constant ``eval``/``exec`` strings are resolved too.
A non-literal ``getattr`` on a crypto module, or a dynamic import whose pieces
look crypto-ish, is flagged conservatively. Imports of a foreign
library or an Ed/X curve module count once per statement; hashes and ciphers
count per use. TypeScript/JavaScript is scanned with regexes (``createHash``,
``crypto.hash``, ``subtle.digest``, WebCrypto ``hash:`` params, pbkdf2 digest
args, ``createCipheriv`` and imports of JS crypto libraries).

Round 6: more non-OpenSSL libraries (ecdsa, rsa, pyDes, pyaes, python-jose,
paramiko/sshtunnel, crypt, ...) are denied on ``import x`` and ``from x import
y``; any other import whose top-level name looks crypto-capable must be on the
_VETTED_CRYPTO_LIBS allow-list (with its reason) or it is reported as
"unvetted crypto lib (<name>)". A digest name that is not a constant
(``hashlib.new(name)``, ``pbkdf2_hmac``, ``file_digest``, hmac ``digestmod``)
is "dynamic digest name" unless it is provably approved: every binding of the
name is a constant approved digest, ``a if c else b`` over such, or the call
goes through ``core.crypto.fips.approved_digest``. itsdangerous serializers
and signers must choose their digest (the library defaults to SHA-1). TS/JS
also covers crypto-js (``CryptoJS.MD5/SHA1/RIPEMD160/DES/TripleDES/RC4``) and
``createHash(<variable>)``.

Approved and therefore not listed: SHA-2/SHA-3, HMAC-SHA*, PBKDF2-HMAC-SHA256,
AES (Fernet = AES-128-CBC + HMAC-SHA256), ECDSA P-256, RSA >= 2048, HS256 JWT.
"""

from __future__ import annotations

import ast
import os
import re
from collections import Counter
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]

# --- scope (Round 6) ----------------------------------------------------------
# Every *.py and TS/JS file under REPO_ROOT is scanned: there is no list of
# directories to keep up to date, so a new top-level package, a new client
# under clients/ or a script under infra/ is covered the day it lands
# (test_new_top_level_code_is_scanned). The only things left out:
#   1. directories pruned wherever they appear (_PRUNE): third-party code
#      (node_modules, venv, site-packages), build output (dist, build), caches
#      and generated reports (__pycache__, coverage, htmlcov). None of it is
#      our source; dependencies are covered by the import rules below.
#   2. dot-directories (.git, .github, .cursor, ...): VCS, CI and editor state.
#   3. test code (_is_test_path: any tests/test/__tests__ directory, test_*.py,
#      *_test.py, *.test.* / *.spec.*): not shipped; fixtures use weak
#      primitives on purpose.
#   4. TypeScript declaration files (*.d.ts): types only, no executable code.
_PRUNE = frozenset(
    {
        "node_modules",
        "venv",
        ".venv",
        "site-packages",
        "dist",
        "build",
        "__pycache__",
        "coverage",
        "htmlcov",
    }
)
_PY_EXTS = (".py",)
_TS_EXTS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")

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
    # Round 6 (arrived with the integration merge, W1.10 / W3.7): audit
    # checkpoints and evidence-pack manifests are signed with Ed25519 only.
    # Known FIPS gap, docs/fips.md "Bilinen boşluklar": move them onto
    # core/crypto/signing.py (ECDSA P-256 under FIPS_MODE) in a follow-up
    # owned by those WPs; until then do not rely on them in FIPS_MODE.
    "core/audit/checkpoint.py": {"ed25519": 1},
    "core/audit/verify.py": {"ed25519": 1},
    "core/compliance/evidence_bundle.py": {"ed25519": 1},
    "core/compliance/verify_bundle.py": {"ed25519": 1},
    # Optional SSH-tunnel DB proxy (lazy `from sshtunnel import ...`):
    # paramiko negotiates Ed25519/ChaCha20 and is not FIPS-restricted.
    # Unsupported in FIPS_MODE (docs/fips.md); use a TLS proxy instead.
    "core/storage/db_proxy.py": {"paramiko": 1},
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
# cryptography.hazmat.primitives.asymmetric.<module>: never FIPS here (DSA
# signature generation is withdrawn in FIPS 186-5).
_ASYM_MODULES = {"ed25519", "ed448", "x25519", "x448", "dsa"}
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
# (owner suffix, attribute) -> primitive, for the rest of cryptography.
_CRYPTOGRAPHY_OTHER = {
    ("kdf.scrypt", "Scrypt"): "scrypt",
    ("kdf.argon2", "Argon2id"): "argon2",
    ("kdf.argon2", "Argon2i"): "argon2",
    ("kdf.argon2", "Argon2d"): "argon2",
    ("primitives.poly1305", "Poly1305"): "poly1305",
    ("asymmetric.ec", "SECP256K1"): "secp256k1",
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
    # Round 6: pure-Python / non-OpenSSL implementations, and wrappers whose
    # algorithm choice is not under FIPS_MODE's control.
    "ecdsa": "ecdsa (pure python)",
    "fastecdsa": "ecdsa (non-openssl)",
    "coincurve": "secp256k1",
    "tinyec": "ecc (pure python)",
    "pyelliptic": "ecc (non-validated)",
    "rsa": "rsa (pure python)",
    "pyDes": "des",
    "des": "des",
    "pyaes": "aes (pure python)",
    "twofish": "twofish",
    "tlslite": "tlslite",
    "M2Crypto": "m2crypto",
    "jose": "python-jose",
    "pgpy": "pgp",
    "gnupg": "pgp",
    "sha3": "keccak (pysha3)",
    "pyblake2": "blake2",
    "Cryptodome": "pycryptodome",
    "simplecrypt": "simplecrypt",
    "ed25519": "ed25519",
    "pure25519": "ed25519",
    "curve25519": "x25519",
    "paramiko": "paramiko",
    "sshtunnel": "paramiko",
    "crypt": "crypt(3)",
    "_crypt": "crypt(3)",
}
# Round 6 allow-list: an import whose top-level name looks crypto-capable
# (_CRYPTO_CAPABLE) must be in _FOREIGN_LIBS (counted) or here (vetted, with
# the reason it is FIPS-safe); anything else is "unvetted crypto lib (<name>)".
_VETTED_CRYPTO_LIBS = {
    "hashlib": "OpenSSL-backed; individual algorithms are checked per use",
    "_hashlib": "CPython's OpenSSL binding; openssl_* names are checked per use",
    "hmac": "OpenSSL-backed; digestmod is checked per use",
    "secrets": "os.urandom; no algorithm choice",
    "ssl": "system OpenSSL; the FIPS provider governs TLS ciphers",
    "cryptography": "OpenSSL-backed; hazmat algorithms are checked per use",
    "jwt": "PyJWT on cryptography; decode pins algorithms=[HS256]",
    "pyotp": "TOTP = HMAC-SHA1, approved (SP 800-131A); see Non-goals",
    "itsdangerous": "HMAC signer; core/auth/password_reset.py pins SHA-256 + "
    "HMAC key derivation (test_password_reset_serializer_is_sha256_hmac)",
    "keyring": "delegates to the OS keychain; no in-process crypto",
}
_CRYPTO_CAPABLE = re.compile(
    r"crypt|cipher|hash|nacl|sodium|ecdsa|ecc|25519|448|curve|secp|rsa|des|aes|"
    r"blake|sha\d|^sha|md5|argon|jose|jw[tske]|pgp|gpg|ssh|paramiko|otp|ssl|tls|"
    r"keyring|dangerous|fernet|tink|pkcs|x509|asn1|kdf|hmac|secret",
    re.I,
)
# CPython's private builtin hash modules bypass the OpenSSL FIPS provider.
_PRIVATE_HASH_MODULES = {
    "_md5": "md5 (security use)",
    "_sha1": "sha1 (security use)",
    "_blake2": "blake2",
}
# Roots whose dynamic (non-literal) getattr is flagged as "dynamic crypto access".
_CRYPTO_ROOTS = {"hashlib", "_hashlib", "hmac", "cryptography", *_FOREIGN_LIBS}
_CRYPTO_ROOTS |= set(_PRIVATE_HASH_MODULES)
# A dynamic import whose string pieces look like this is flagged.
_CRYPTOISH = re.compile(
    r"hash|crypt|md5|sha1|blake|nacl|sodium|argon|ed25519|ed448|x25519|x448|"
    r"chacha|scrypt|passlib|primitives|asymmetric",
    re.I,
)
# Approved digests (mirrors core/crypto/fips.py APPROVED_DIGESTS; asserted
# equal in test_approved_digest_sets_agree) and the helper that enforces them
# at runtime for names only known then.
_APPROVED_DIGESTS = frozenset(
    {"sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256"}
    | {f"sha3_{n}" for n in (224, 256, 384, 512)}
    | {"shake_128", "shake_256"}
)
_APPROVED_HELPER = "core.crypto.fips.approved_digest"
_ITSDANGEROUS_SERIALIZERS = {
    "Serializer",
    "URLSafeSerializer",
    "TimedSerializer",
    "URLSafeTimedSerializer",
}
_ITSDANGEROUS_SIGNERS = {"Signer", "TimestampSigner"}
_DIGEST_CALLS = {"hashlib.new", "hashlib.pbkdf2_hmac", "hashlib.file_digest"}
_HMAC_CALLS = {"hmac.new", "hmac.digest", "hmac.HMAC"}
_IMPORT_CALLS = {"importlib.import_module", "__import__"}
_KNOWN_CALLS = _DIGEST_CALLS | _HMAC_CALLS | _IMPORT_CALLS


def _is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    return (
        any(
            p in ("tests", "test", "__tests__", "node_modules", ".venv", "dist")
            for p in parts
        )
        or name.startswith("test_")
        or name.endswith(_TEST_SUFFIXES)
    )


_TEST_SUFFIXES = ("_test.py",) + tuple(
    f".{kind}.{ext}"
    for kind in ("test", "spec")
    for ext in ("ts", "tsx", "mts", "cts", "js", "mjs", "cjs")
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
    name = text.strip().lower()
    name = _HASH_ALIASES.get(name, name)
    if name.startswith("sha-"):  # SHA-256, SHA-512/256
        name = "sha" + name[4:]
    return name.replace("-", "_").replace("/", "_")  # SHA3-256 -> sha3_256


def _canon(name: str) -> str:
    """``_hashlib.openssl_md5`` -> ``hashlib.md5``."""
    if name == "_hashlib" or name.startswith("_hashlib."):
        name = name[1:]
    owner, _, attr = name.rpartition(".")
    if owner == "hashlib" and attr.startswith("openssl_"):
        return f"hashlib.{attr[len('openssl_'):]}"
    return name


def _asym_of(name: str) -> str | None:
    parts = name.split(".")
    for i, part in enumerate(parts[1:], 1):
        if part in _ASYM_MODULES and parts[i - 1] == "asymmetric":
            return part
    return None


def _classify(name: str) -> str | None:
    """Primitive named by a reference to ``name`` (no call semantics, no
    asymmetric modules: those are counted per import, see ``_Scanner._ref``)."""
    name = _canon(name)
    owner, _, attr = name.rpartition(".")
    if owner == "hashlib":
        low = attr.lower()
        if low in _NON_FIPS_HASHES:
            return _NON_FIPS_HASHES[low]
        if low in _WEAK_HASHES:
            return f"{low} (security use)"
        if low == "scrypt":
            return "scrypt"
    if owner in _PRIVATE_HASH_MODULES:
        return _PRIVATE_HASH_MODULES[owner]
    if owner.endswith("primitives.hashes") and attr in _CRYPTOGRAPHY_HASHES:
        return _CRYPTOGRAPHY_HASHES[attr]
    if attr in _CIPHERS and owner.endswith(_CIPHER_OWNERS):
        return _CIPHERS[attr]
    for (suffix, name_), primitive in _CRYPTOGRAPHY_OTHER.items():
        if attr == name_ and owner.endswith(suffix):
            return primitive
    return None


def _resolve_relative(name: str, package: str | None) -> str | None:
    if not name.startswith("."):
        return name
    if not package:
        return None
    level = len(name) - len(name.lstrip("."))
    base = package.split(".")
    if level - 1 >= len(base):
        return None
    base = base[: len(base) - (level - 1)]
    rest = name[level:]
    return ".".join(base + ([rest] if rest else []))


class _Scanner(ast.NodeVisitor):
    """Resolves import aliases (and ``x = hashlib`` style reassignments,
    ``sys.modules[...]``, ``getattr``, ``import_module``) to dotted names,
    constant-folds string expressions, then classifies every import, call and
    attribute reference by what it resolves to."""

    def __init__(
        self, parent: _Scanner | None = None, local_roots: frozenset = frozenset()
    ) -> None:
        self.found: Counter = Counter()
        # First-party top-level names (core, services, ...): never third party.
        self.local_roots = parent.local_roots if parent else local_roots
        self.aliases: dict[str, str] = dict(parent.aliases) if parent else {}
        self.consts: dict[str, object] = dict(parent.consts) if parent else {}
        self.const_sets: dict[str, set] = dict(parent.const_sets) if parent else {}
        self.star_modules: list[str] = list(parent.star_modules) if parent else []
        # (bound name, curve) pairs whose import statement already counted.
        self.asym_counted: set[tuple[str, str]] = (
            set(parent.asym_counted) if parent else set()
        )
        self.handled: set[int] = set()

    # --- entry ---------------------------------------------------------------

    def scan(self, tree: ast.AST) -> Counter:
        # Imports, constants and module aliases first, so a name is resolved
        # wherever it is used (incl. lazily imported inside a function).
        nodes = list(ast.walk(tree))
        for node in nodes:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.visit(node)
        assigns = [
            node
            for node in nodes
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ]
        self._collect_consts(nodes, assigns)
        for _ in range(3):  # chains: a = hashlib; b = a
            self._collect_module_aliases(assigns)
        self.visit(_without_imports(tree))
        return +self.found

    def _collect_consts(self, nodes: list, assigns: list) -> None:
        seen: dict[str, list] = {}
        for node in assigns:
            seen.setdefault(node.targets[0].id, []).append(node.value)
        # Round 6: names bound only by plain ``name = <constant str>``
        # assignments (any number) and never any other way: parameter, loop /
        # with / walrus / augmented / unpacking target, except-as.
        simple = {id(node.targets[0]) for node in assigns}
        rebound = set()
        for n in nodes:
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                if id(n) not in simple:
                    rebound.add(n.id)
            elif isinstance(n, ast.arg):
                rebound.add(n.arg)
            elif isinstance(n, ast.ExceptHandler) and n.name:
                rebound.add(n.name)
        for _ in range(2):  # a = "md"; b = a + "5"
            for name, values in seen.items():
                folded = {self.fold(v) for v in values}
                if len(values) == 1 and None not in folded and name not in rebound:
                    self.consts[name] = folded.pop()
        for name, values in seen.items():
            folded = [self.fold(v) for v in values]
            if name not in rebound and all(isinstance(v, str) for v in folded):
                self.const_sets[name] = set(folded)

    def _collect_module_aliases(self, assigns: list) -> None:
        for node in assigns:
            if not isinstance(
                node.value, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)
            ):
                continue
            target = node.targets[0].id
            if target in self.aliases:
                continue
            resolved = self.resolve(node.value)
            if (
                resolved
                and _canon(resolved).split(".")[0]
                in _CRYPTO_ROOTS | {"sys", "importlib"}
                and not _classify(resolved)
                and not _asym_of(resolved)
            ):
                self.aliases[target] = resolved

    # --- constant folding ----------------------------------------------------

    def fold(self, node: ast.AST | None):
        """A str/int value for a constant expression, else None."""
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
            if isinstance(node.value, bool):
                return None
            return node.value
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
            left, right = self.fold(node.left), self.fold(node.right)
            if left is None or right is None:
                return None
            try:
                return left + right if isinstance(node.op, ast.Add) else left * right
            except TypeError:
                return None
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if value.conversion != -1 or value.format_spec is not None:
                        return None
                    value = value.value
                part = self.fold(value)
                if part is None:
                    return None
                parts.append(str(part))
            return "".join(parts)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            base = self.fold(node.func.value)
            if not isinstance(base, str):
                return None
            method = node.func.attr
            if method == "join" and len(node.args) == 1:
                seq = node.args[0]
                if isinstance(seq, (ast.List, ast.Tuple)):
                    items = [self.fold(e) for e in seq.elts]
                    if all(isinstance(i, str) for i in items):
                        return base.join(items)
            if method in ("lower", "upper", "strip") and not node.args:
                return getattr(base, method)()
        return None

    def _fold_str(self, node: ast.AST | None) -> str | None:
        value = self.fold(node)
        return value if isinstance(value, str) else None

    # --- name resolution -----------------------------------------------------

    def resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.aliases:
                return self.aliases[node.id]
            for module in self.star_modules:
                candidate = f"{module}.{node.id}"
                if (
                    _classify(candidate)
                    or _asym_of(candidate)
                    or _canon(candidate) in _KNOWN_CALLS
                ):
                    return candidate
            return node.id
        if isinstance(node, ast.Attribute):
            owner = self.resolve(node.value)
            return f"{owner}.{node.attr}" if owner else None
        if isinstance(node, ast.Subscript):
            if self.resolve(node.value) == "sys.modules":
                return self._fold_str(node.slice)
            return None
        if isinstance(node, ast.Call):
            func = self.resolve(node.func)
            if func in _IMPORT_CALLS or func == "sys.modules.get":
                return (
                    self._module_arg(node)
                    if func != "sys.modules.get"
                    else (self._fold_str(_arg(node, 0, "key")))
                )
            if func == "getattr" and len(node.args) >= 2:
                owner = self.resolve(node.args[0])
                attr = self._fold_str(node.args[1])
                return f"{owner}.{attr}" if owner and attr else None
        return None

    def _module_arg(self, call: ast.Call) -> str | None:
        name = self._fold_str(_arg(call, 0, "name"))
        if name is None:
            return None
        package = self._fold_str(_arg(call, 1, "package"))
        return _resolve_relative(name, package)

    @staticmethod
    def _base(node: ast.AST) -> str | None:
        while isinstance(node, ast.Attribute):
            node = node.value
        return node.id if isinstance(node, ast.Name) else None

    def _mark_chain(self, node: ast.AST) -> None:
        while isinstance(node, (ast.Attribute, ast.Name)):
            self.handled.add(id(node))
            if isinstance(node, ast.Name):
                break
            node = node.value

    def _ref(self, node: ast.AST, name: str) -> bool:
        """Count one reference to ``name`` if it is a non-FIPS primitive."""
        primitive = _classify(name)
        if primitive is None:
            curve = _asym_of(name)
            base = self._base(node)
            key = base if base in self.aliases else "*"
            if curve and (key, curve) not in self.asym_counted:
                primitive = curve
        if primitive is None:
            return False
        self.found[primitive] += 1
        self._mark_chain(node)
        return True

    # --- imports -------------------------------------------------------------

    def _imported(self, module: str, bound: str | None = None) -> None:
        """One import statement (or dynamic import) of ``module``."""
        root = module.split(".")[0]
        if root in _FOREIGN_LIBS:
            self.found[_FOREIGN_LIBS[root]] += 1
        elif (
            root not in _VETTED_CRYPTO_LIBS
            and root not in _PRIVATE_HASH_MODULES
            and root not in self.local_roots
            and _CRYPTO_CAPABLE.search(root)
        ):
            self.found[f"unvetted crypto lib ({root})"] += 1
        if root in _PRIVATE_HASH_MODULES:
            self.found[_PRIVATE_HASH_MODULES[root]] += 1
        leaf = module.split(".")[-1]
        if leaf in _ASYM_MODULES and ".asymmetric." in f".{module}":
            self.found[leaf] += 1
            if bound:
                self.asym_counted.add((bound, leaf))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".")[0]
            self._imported(alias.name, bound)
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                self.aliases.setdefault(bound, bound)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if not node.module or node.level:
            return
        module = node.module
        leaf = module.split(".")[-1]
        counted = False
        if module.split(".")[0] in {*_FOREIGN_LIBS, *_PRIVATE_HASH_MODULES} or (
            leaf in _ASYM_MODULES
        ):
            self._imported(module)
            counted = True
        else:
            self._imported(module)  # Round 6: allow-list check for `from x import y`
        for alias in node.names:
            if alias.name == "*":
                self.star_modules.append(module)
                if counted and _asym_of(module):
                    self.asym_counted.add(("*", _asym_of(module)))
                continue
            bound = alias.asname or alias.name
            full = f"{module}.{alias.name}"
            self.aliases[bound] = full
            if counted and _asym_of(full):
                self.asym_counted.add((bound, _asym_of(full)))
            elif not counted and alias.name in _ASYM_MODULES:
                self._imported(full, bound)

    # --- calls ---------------------------------------------------------------

    def _string_digest(self, node: ast.expr | None) -> str | None:
        text = self._fold_str(node)
        return _digest_name(text) if text else None

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
            return _digest_name(_canon(name).rpartition(".")[2])
        return None

    def _digest_provable(self, node: ast.expr | None, approved: frozenset) -> bool:
        """True if ``node`` provably names a digest in ``approved``: a constant,
        ``a if c else b`` over provable branches, a module name every
        assignment of which is provable, or the result of
        ``core.crypto.fips.approved_digest(...)`` (raises otherwise)."""
        if node is None:
            return False
        text = self._fold_str(node)
        if text is not None:
            return _digest_name(text) in approved
        if isinstance(node, ast.IfExp):
            return self._digest_provable(node.body, approved) and self._digest_provable(
                node.orelse, approved
            )
        if isinstance(node, ast.Name) and node.id in self.const_sets:
            return all(_digest_name(v) in approved for v in self.const_sets[node.id])
        if isinstance(node, ast.Call):
            return _canon(self.resolve(node.func) or "") == _APPROVED_HELPER
        if isinstance(node, ast.Attribute):
            # file_digest(f, hashlib.sha256): a hashlib constructor
            name = _canon(self.resolve(node) or "")
            owner, _, attr = name.rpartition(".")
            return owner == "hashlib" and _digest_name(attr) in approved
        return False

    def _digest_known(self, node: ast.expr) -> bool:
        """An hmac ``digestmod`` / ``file_digest`` digest the scanner can judge:
        a provable string, a hashlib/cryptography name (classified where it is
        referenced), or a lambda/call around one."""
        if self._digest_provable(node, _APPROVED_DIGESTS | {"sha1"}):
            return True
        if isinstance(node, ast.Lambda):
            return self._digest_known(node.body)
        target = node.func if isinstance(node, ast.Call) else node
        name = _canon(self.resolve(target) or "")
        return name.split(".")[0] in ("hashlib", "cryptography") and "." in name

    def visit_Call(self, node: ast.Call) -> None:
        if id(node) not in self.handled:
            name = self.resolve(node.func)
            if name:
                self.handled.add(id(node.func))
                self._call(node, _canon(name))
        self.generic_visit(node)

    def _dynamic(self, node: ast.AST | None) -> bool:
        """Non-literal expression whose string pieces look crypto-ish."""
        if node is None:
            return False
        return any(
            isinstance(n, ast.Constant)
            and isinstance(n.value, str)
            and _CRYPTOISH.search(n.value)
            for n in ast.walk(node)
        ) or any(
            isinstance(n, ast.Name)
            and isinstance(self.consts.get(n.id), str)
            and _CRYPTOISH.search(self.consts[n.id])
            for n in ast.walk(node)
        )

    def _call(self, node: ast.Call, name: str) -> None:
        if name in _IMPORT_CALLS:
            module = self._module_arg(node)
            if module:
                self._imported(module)
            elif self._dynamic(_arg(node, 0, "name")) or self._dynamic(
                _arg(node, 1, "package")
            ):
                self.found["dynamic crypto import"] += 1
            return
        if name == "getattr" and len(node.args) >= 2:
            owner = self.resolve(node.args[0])
            if not owner:
                return
            attr = self._fold_str(node.args[1])
            if attr is None:
                if _canon(owner).split(".")[0] in _CRYPTO_ROOTS:
                    self.found["dynamic crypto access"] += 1
                return
            self._ref(node, f"{owner}.{attr}")
            return
        if name in ("eval", "exec", "compile", "builtins.eval", "builtins.exec"):
            source = self._fold_str(_arg(node, 0, "source"))
            if source:
                self._scan_string(source)
            return
        if name == "functools.partial" and node.args:
            inner_name = self.resolve(node.args[0])
            if inner_name:
                inner = ast.Call(
                    func=node.args[0], args=node.args[1:], keywords=node.keywords
                )
                self._call(inner, _canon(inner_name))
                self.handled.add(id(node.args[0]))
            return
        if name in _DIGEST_CALLS:
            if name == "hashlib.file_digest":
                arg = _arg(node, 1, "digest")
            else:
                arg = _arg(node, 0, "name" if name == "hashlib.new" else "hash_name")
            digest = self._string_digest(arg)
            known = (
                self._digest_known(arg)
                if name == "hashlib.file_digest"
                else self._digest_provable(arg, _APPROVED_DIGESTS)
            )
            if digest is None and not known:
                # Round 6: a digest name the scanner cannot prove approved.
                self.found["dynamic digest name"] += 1
            elif digest in _NON_FIPS_HASHES:
                self.found[_NON_FIPS_HASHES[digest]] += 1
            elif digest in _WEAK_HASHES and (
                name != "hashlib.new" or not _security_flag_off(node)
            ):
                self.found[f"{digest} (security use)"] += 1
            return
        if name in _HMAC_CALLS:
            arg = _arg(node, 2, "digestmod" if name != "hmac.digest" else "digest")
            if arg is not None:
                self.handled.update(id(n) for n in ast.walk(arg))
            digest = self._digest_of(arg)
            if digest in _HMAC_FORBIDDEN:
                self.found["hmac-md5"] += 1
            elif arg is not None and not self._digest_known(arg):
                self.found["dynamic digest name"] += 1
            return
        if name.startswith("itsdangerous.") and name.rpartition(".")[2] in (
            _ITSDANGEROUS_SERIALIZERS | _ITSDANGEROUS_SIGNERS
        ):
            # Round 6: itsdangerous defaults to SHA-1 ("django-concat" key
            # derivation + HMAC-SHA1); a FIPS caller must pick the digest.
            attr = name.rpartition(".")[2]
            keyword = (
                "signer_kwargs"
                if attr in _ITSDANGEROUS_SERIALIZERS
                else "digest_method"
            )
            if not any(kw.arg in (keyword, None) for kw in node.keywords):
                self.found["sha1 (itsdangerous default)"] += 1
            return
        if name.endswith("asymmetric.rsa.generate_private_key"):
            size = self.fold(_arg(node, 1, "key_size"))
            if isinstance(size, int) and size < 2048:
                self.found["rsa < 2048"] += 1
            return
        primitive = _classify(name)
        if (
            primitive
            and primitive.endswith("(security use)")
            and name.startswith("hashlib.")
            and _security_flag_off(node)
        ):
            return
        self._ref(node.func, name)

    def _scan_string(self, source: str) -> None:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return
        self.found.update(_Scanner(self).scan(tree))

    # --- references ----------------------------------------------------------

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if id(node) not in self.handled:
            name = self.resolve(node)
            if name and self._ref(node, name):
                return  # the owner chain is part of this reference
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if id(node) in self.handled or not isinstance(node.ctx, ast.Load):
            return
        name = self.resolve(node)
        if name and name != node.id:
            self._ref(node, name)


def scan_python(source: str, local_roots: frozenset = frozenset()) -> Counter:
    return _Scanner(local_roots=local_roots).scan(ast.parse(source))


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
        rf"(?:create(?:Hash|Hmac)|\bhash|pbkdf2(?:Sync)?|hkdf(?:Sync)?)\(\s*{_Q}md5{_Q}"
        rf"|pbkdf2(?:Sync)?\([^;]*?,\s*{_Q}md5{_Q}\s*[,)]"
        rf"|(?:create(?:Sign|Verify)|\bsign|\bverify)\(\s*{_Q}(?:rsa-)?md5"
        rf"(?:WithRSAEncryption)?{_Q}"
        rf"|hash\s*:\s*(?:\{{\s*name\s*:\s*)?{_Q}md5{_Q}"
        r"|\bCryptoJS\s*\.\s*(?:Hmac)?MD5\b",  # Round 6: crypto-js
        re.I,
    ),
    "sha1 (security use)": re.compile(
        rf"(?:createHash|\bhash)\(\s*{_Q}sha-?1{_Q}"
        rf"|subtle\s*\.\s*digest\(\s*(?:\{{\s*name\s*:\s*)?{_Q}sha-?1{_Q}"
        rf"|pbkdf2(?:Sync)?\([^;]*?,\s*{_Q}sha-?1{_Q}\s*[,)]"
        rf"|hash\s*:\s*(?:\{{\s*name\s*:\s*)?{_Q}sha-?1{_Q}"
        rf"|(?:create(?:Sign|Verify)|\bsign|\bverify)\(\s*{_Q}(?:rsa-)?sha-?1"
        rf"(?:WithRSAEncryption)?{_Q}"
        r"|\bCryptoJS\s*\.\s*SHA1\b",  # Round 6 (HmacSHA1 is approved)
        re.I,
    ),
    "weak hash": re.compile(
        rf"(?:createHash|createHmac|\bhash)\(\s*{_Q}(?:md4|ripemd160|blake2[bs]\d*){_Q}"
        r"|\bCryptoJS\s*\.\s*(?:Hmac)?RIPEMD160\b",
        re.I,
    ),
    "scrypt": re.compile(r"\bscrypt(?:Sync)?\s*\("),
    "ed25519": re.compile(rf"{_Q}(?:ed25519|ed448|x25519|x448){_Q}", re.I),
    "legacy cipher": re.compile(
        rf"create(?:Cipheriv|Decipheriv)\(\s*{_Q}(?:des|bf|rc4|rc2|cast|idea|seed|"
        r"chacha20|camellia|sm4)"
        r"|\bCryptoJS\s*\.\s*(?:DES|TripleDES|RC4|RC4Drop|Rabbit|RabbitLegacy|"
        r"Blowfish)\b",
        re.I,
    ),
    # Round 6: a digest picked at runtime (createHash(algo)) cannot be judged.
    "dynamic digest name": re.compile(
        r"(?:create(?:Hash|Hmac)|subtle\s*\.\s*digest)\(\s*(?![\'\"`{])"
        r"[A-Za-z_$][\w$.]*\s*[,)]"
    ),
    "foreign crypto lib": re.compile(
        r"(?:from\s+|require\(\s*|import\(\s*|import\s+)['\"](?:bcrypt|bcryptjs|"
        r"tweetnacl|libsodium[\w-]*|crypto-js|node-forge|js-sha1|js-md5|sha1|md5|"
        r"blakejs|argon2|scrypt-js|"
        # Round 6: more userland JS crypto that bypasses the platform provider.
        r"jsrsasign|elliptic|hash\.js|create-hash|sha\.js|md5\.js|ripemd160|"
        r"spark-md5|object-hash|browserify-cipher|crypto-browserify|pbkdf2|"
        r"bcrypt-ts|node-rsa|jsencrypt|openpgp|"
        r"@noble/(?:hashes|curves|ed25519|ciphers|secp256k1))(?:/[^'\"]*)?['\"]",
        re.I,
    ),
}
# 'bcr' + 'ypt' -> 'bcrypt' (repeat until stable) before matching.
_TS_CONCAT = re.compile(r"(['\"`])([^'\"`\\\n$]*)\1\s*\+\s*(['\"`])([^'\"`\\\n$]*)\3")


def _fold_ts_strings(source: str) -> str:
    while True:
        folded = _TS_CONCAT.sub(lambda m: f"'{m.group(2)}{m.group(4)}'", source)
        if folded == source:
            return folded
        source = folded


def scan_typescript(source: str) -> Counter:
    source = _fold_ts_strings(source)
    return Counter(
        {k: len(p.findall(source)) for k, p in _TS_PATTERNS.items() if p.search(source)}
    )


def _scanned_files():
    """(relative path, absolute path) of every file in scope (see the scope
    comment at the top). Symlinked directories are not followed."""
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = sorted(
            d for d in dirnames if d not in _PRUNE and not d.startswith(".")
        )
        for name in sorted(filenames):
            if not name.endswith(_PY_EXTS + _TS_EXTS) or name.endswith(".d.ts"):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(REPO_ROOT).as_posix()
            if not _is_test_path(rel):
                yield rel, path


def _entries(directory: Path, cache: dict) -> frozenset:
    if directory not in cache:
        cache[directory] = frozenset(
            entry.name[:-3] if entry.name.endswith(".py") else entry.name
            for entry in directory.iterdir()
        )
    return cache[directory]


def _local_roots(path: Path, cache: dict) -> frozenset:
    """First-party import roots for ``path``: top-level entries of the repo and
    sibling modules (``import trust_check`` next to trust_check.py)."""
    return _entries(REPO_ROOT, cache) | _entries(path.parent, cache)


def _inventory() -> dict[str, Counter]:
    inventory: dict[str, Counter] = {}
    cache: dict = {}
    for rel, path in _scanned_files():
        source = path.read_text(encoding="utf-8", errors="replace")
        if rel.endswith(_PY_EXTS):
            found = scan_python(source, _local_roots(path, cache))
        else:
            found = scan_typescript(source)
        if found:
            inventory[rel] = found
    return inventory


_INVENTORY_CACHE: dict = {}


def _cached_inventory() -> dict[str, Counter]:
    """The full-repo scan takes seconds; the two ratchet tests share it."""
    if REPO_ROOT not in _INVENTORY_CACHE:
        _INVENTORY_CACHE[REPO_ROOT] = _inventory()
    return _INVENTORY_CACHE[REPO_ROOT]


def test_no_new_non_fips_primitives():
    inventory = _cached_inventory()
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
    inventory = _cached_inventory()
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
    scanned = {rel for rel, _ in _scanned_files()}
    assert len([r for r in scanned if r.endswith(".py")]) > 300
    for rel in (
        "core/auth/auth_service.py",
        "services/agent/arch/registry.ts",
        "infra/airgap/airgap_images.py",
    ):
        assert rel in scanned, rel
    assert any(r.startswith("clients/web/src/") for r in scanned)
    assert any(r.startswith("clients/desktop/src/") for r in scanned)


# --- Round 5: evasions the round-3 scanner missed ---------------------------

_ASYM = "cryptography.hazmat.primitives.asymmetric"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # getattr with literal / folded names
        ("import hashlib\ngetattr(hashlib, 'md5')(b'x')", "md5 (security use)"),
        ("import hashlib\ngetattr(hashlib, 'm' + 'd5')(b'x')", "md5 (security use)"),
        ("import hashlib\nf = getattr(hashlib, 'sha1')", "sha1 (security use)"),
        ("import hashlib\nN = 'md5'\ngetattr(hashlib, N)(b'x')", "md5 (security use)"),
        # conservative rule: non-literal getattr on a crypto module
        ("import hashlib\ngetattr(hashlib, name)(b'x')", "dynamic crypto access"),
        (
            "from cryptography.hazmat.primitives import hashes\ngetattr(hashes, n)()",
            "dynamic crypto access",
        ),
        # star imports
        ("from hashlib import *\nmd5(b'x')", "md5 (security use)"),
        (
            "from cryptography.hazmat.primitives.hashes import *\nSHA1()",
            "sha1 (security use)",
        ),
        (f"from {_ASYM} import *\ned25519.Ed25519PrivateKey.generate()", "ed25519"),
        # functools.partial
        (
            "import functools, hashlib\nfunctools.partial(hashlib.new, 'md5')",
            "md5 (security use)",
        ),
        (
            "from functools import partial\nimport hashlib\n"
            "partial(hashlib.pbkdf2_hmac, 'sha1')",
            "sha1 (security use)",
        ),
        # eval / exec of a constant string
        ("import hashlib\neval('hashlib.md5(b\"x\")')", "md5 (security use)"),
        ("exec('import hashlib; hashlib.sha1(b\"x\")')", "sha1 (security use)"),
        ("exec('import ' + 'bcrypt')", "bcrypt"),
        # asymmetric module aliases and fully-qualified paths
        (
            "from cryptography.hazmat.primitives import asymmetric as A\n"
            "A.ed25519.Ed25519PrivateKey.generate()",
            "ed25519",
        ),
        (
            "import cryptography.hazmat.primitives.asymmetric\n"
            f"{_ASYM}.x25519.X25519PrivateKey.generate()",
            "x25519",
        ),
        (
            "import cryptography\n"
            "cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey",
            "ed448",
        ),
        # keyword digest names
        (
            "import hashlib\nhashlib.pbkdf2_hmac(hash_name='md5', password=p, salt=s,"
            " iterations=1)",
            "md5 (security use)",
        ),
        ("import hashlib\nhashlib.file_digest(f, 'md5')", "md5 (security use)"),
        (
            "import hashlib\nhashlib.file_digest(f, digest='sha1')",
            "sha1 (security use)",
        ),
        ("import hashlib\nhashlib.file_digest(f, hashlib.md5)", "md5 (security use)"),
        # private CPython hash modules / _hashlib
        ("import _md5\n_md5.md5(b'x')", "md5 (security use)"),
        ("from _sha1 import sha1", "sha1 (security use)"),
        ("import _blake2", "blake2"),
        ("import _hashlib\n_hashlib.openssl_md5(b'x')", "md5 (security use)"),
        ("import _hashlib\n_hashlib.new('sha1')", "sha1 (security use)"),
        # alias reassignment and sys.modules
        ("import hashlib\nhl = hashlib\nhl.md5(b'x')", "md5 (security use)"),
        ("import hashlib\na = hashlib\nb = a\nb.sha1(b'x')", "sha1 (security use)"),
        ("import sys\nsys.modules['hashlib'].md5(b'x')", "md5 (security use)"),
        (
            "import sys\nh = sys.modules['hash' + 'lib']\nh.sha1(b'x')",
            "sha1 (security use)",
        ),
        ("import sys\nsys.modules.get('hashlib').md5(b'x')", "md5 (security use)"),
        # importlib: concatenated, relative, attribute access on the result
        ("import importlib\nimportlib.import_module('bcr' + 'ypt')", "bcrypt"),
        ("import importlib\nimportlib.import_module(f'{\"na\"}cl')", "pynacl"),
        (
            "import importlib\n"
            f"importlib.import_module('.ed25519', package='{_ASYM}')",
            "ed25519",
        ),
        (
            "import importlib\n"
            f"importlib.import_module('..asymmetric.x448', '{_ASYM}.ec')",
            "x448",
        ),
        (
            "import importlib\nimportlib.import_module('hashlib').md5(b'x')",
            "md5 (security use)",
        ),
        (
            f"import importlib\nimportlib.import_module('.' + algo, package='{_ASYM}')",
            "dynamic crypto import",
        ),
        (
            "import importlib\nimportlib.import_module('cryptography.' + suffix)",
            "dynamic crypto import",
        ),
        ("__import__(prefix + 'crypt')", "dynamic crypto import"),
        # more of cryptography
        (
            "from cryptography.hazmat.primitives.kdf.scrypt import Scrypt\n"
            "Scrypt(salt=s, length=32, n=2**14, r=8, p=1)",
            "scrypt",
        ),
        (
            "from cryptography.hazmat.primitives.kdf.argon2 import Argon2id\n"
            "Argon2id(salt=s, length=32, iterations=1, lanes=4, memory_cost=64)",
            "argon2",
        ),
        (
            "from cryptography.hazmat.primitives import poly1305\n"
            "poly1305.Poly1305(k)",
            "poly1305",
        ),
        (
            f"from {_ASYM} import rsa\n"
            "rsa.generate_private_key(public_exponent=65537, key_size=1024)",
            "rsa < 2048",
        ),
        (
            f"from {_ASYM} import rsa\nBITS = 512 * 2\n"
            "rsa.generate_private_key(65537, BITS)",
            "rsa < 2048",
        ),
        (f"from {_ASYM} import dsa\ndsa.generate_private_key(2048)", "dsa"),
        (f"from {_ASYM}.dsa import DSAPrivateKey", "dsa"),
        (
            f"from {_ASYM} import ec\nec.generate_private_key(ec.SECP256K1())",
            "secp256k1",
        ),
    ],
)
def test_scanner_catches_round5_evasions(source, expected):
    assert scan_python(source)[expected] >= 1, scan_python(source)


@pytest.mark.parametrize(
    "source",
    [
        "import hashlib\ngetattr(hashlib, 'sha256')(b'x')",
        "import hashlib\ngetattr(hashlib, 'md5')(b'x', usedforsecurity=False)",
        "import functools, hashlib\nfunctools.partial(hashlib.new, 'sha256')",
        "import hashlib\nhashlib.file_digest(f, 'sha256')",
        "import hashlib\nhl = hashlib\nhl.sha256(b'x')",
        "import sys\nsys.modules['json'].dumps({})",
        "eval('1 + 1')",
        "import importlib\nimportlib.import_module(f'core.integrations.{pkg}.descriptor')",
        f"from {_ASYM} import rsa\nrsa.generate_private_key(65537, 3072)",
        f"from {_ASYM} import ec\nec.generate_private_key(ec.SECP256R1())",
        "getattr(obj, name)",  # not a crypto module
        "x = 'md5'\nprint(x)",
    ],
)
def test_scanner_round5_approved_uses(source):
    assert not scan_python(source), scan_python(source)


def test_asymmetric_import_counts_once_per_statement():
    """Baseline compatibility: a counted import is not double-counted by the
    references made through the name it bound."""
    source = (
        f"from {_ASYM} import ed25519\n"
        "k = ed25519.Ed25519PrivateKey.generate()\n"
        "isinstance(k, ed25519.Ed25519PrivateKey)\n"
    )
    assert scan_python(source) == Counter({"ed25519": 1})
    source = (
        f"from {_ASYM}.ed25519 import Ed25519PrivateKey\nEd25519PrivateKey.generate()"
    )
    assert scan_python(source) == Counter({"ed25519": 1})


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("crypto.createSign('sha1')", "sha1 (security use)"),
        ("crypto.createSign('RSA-SHA1')", "sha1 (security use)"),
        ("crypto.createVerify('md5')", "md5 (security use)"),
        ("crypto.sign('sha1', data, key)", "sha1 (security use)"),
        ("crypto.hkdfSync('md5', ikm, salt, info, 32)", "md5 (security use)"),
        ("crypto.scryptSync(p, s, 64)", "scrypt"),
        ("crypto.scrypt(p, s, 64, cb)", "scrypt"),
        (
            "crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: { name: 'SHA-1' } })",
            "sha1 (security use)",
        ),
        (
            "import { chacha20poly1305 } from '@noble/ciphers/chacha';",
            "foreign crypto lib",
        ),
        ("import sha1 from 'sha1';", "foreign crypto lib"),
        ("const b = require('bcr' + 'ypt');", "foreign crypto lib"),
        ("const b = await import(\"bc\" + 'ry' + `pt`);", "foreign crypto lib"),
        ("import 'tweetnacl';", "foreign crypto lib"),
    ],
)
def test_typescript_scanner_catches_round5(source, expected):
    assert scan_typescript(source)[expected] >= 1


@pytest.mark.parametrize(
    "source",
    [
        "crypto.createSign('sha256')",
        "crypto.createVerify('RSA-SHA256')",
        "crypto.hkdfSync('sha256', ikm, salt, info, 32)",
        "const label = 'a' + 'b';",
        "bcryptVerify(x)",
    ],
)
def test_typescript_scanner_round5_passes(source):
    assert not scan_typescript(source)


def test_javascript_files_are_scanned(tmp_path, monkeypatch):
    agent = tmp_path / "services/agent"
    (agent / "lib").mkdir(parents=True)
    (agent / "node_modules/x").mkdir(parents=True)
    (agent / "lib/a.mjs").write_text("require('crypto').createHash('md5')")
    (agent / "lib/b.cjs").write_text("require('bcryptjs')")
    (agent / "lib/c.js").write_text("crypto.scryptSync(p, s, 64)")
    (agent / "lib/d.test.js").write_text("crypto.createHash('md5')")
    (agent / "node_modules/x/e.js").write_text("crypto.createHash('md5')")
    monkeypatch.setitem(globals(), "REPO_ROOT", tmp_path)
    assert sorted(_inventory()) == [
        "services/agent/lib/a.mjs",
        "services/agent/lib/b.cjs",
        "services/agent/lib/c.js",
    ]


# --- Round 6 ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # 1. non-OpenSSL / pure-Python crypto libraries, both import forms
        ("import ecdsa", "ecdsa (pure python)"),
        ("from ecdsa import SigningKey, NIST256p", "ecdsa (pure python)"),
        ("from ecdsa.keys import SigningKey", "ecdsa (pure python)"),
        ("import rsa", "rsa (pure python)"),
        ("from rsa import newkeys", "rsa (pure python)"),
        ("import pyDes", "des"),
        ("from pyDes import triple_des", "des"),
        ("from pyaes import AESModeOfOperationCTR", "aes (pure python)"),
        ("from jose import jwt", "python-jose"),
        ("import paramiko", "paramiko"),
        ("def f():\n    from sshtunnel import SSHTunnelForwarder", "paramiko"),
        ("import crypt", "crypt(3)"),
        ("from Cryptodome.Cipher import AES", "pycryptodome"),
        ("import sha3", "keccak (pysha3)"),
        ("from coincurve import PrivateKey", "secp256k1"),
        ("import importlib\nimportlib.import_module('ecdsa')", "ecdsa (pure python)"),
        ("__import__('rsa')", "rsa (pure python)"),
        # allow-list: a crypto-looking library nobody vetted
        ("import cryptopp", "unvetted crypto lib (cryptopp)"),
        ("from hashids import Hashids", "unvetted crypto lib (hashids)"),
        ("from pgpkit.sign import sign", "unvetted crypto lib (pgpkit)"),
        ("import _sha256", "unvetted crypto lib (_sha256)"),
        # itsdangerous defaults to SHA-1
        (
            "from itsdangerous import URLSafeTimedSerializer\n"
            "URLSafeTimedSerializer(k, salt='x')",
            "sha1 (itsdangerous default)",
        ),
        ("import itsdangerous\nitsdangerous.Signer(k)", "sha1 (itsdangerous default)"),
        # 2. digest names the scanner cannot prove approved
        ("import hashlib\nhashlib.new(name)", "dynamic digest name"),
        (
            "import hashlib\nhashlib.new(algo, usedforsecurity=False)",
            "dynamic digest name",
        ),
        ("import hashlib\nhashlib.new(cfg['digest'])", "dynamic digest name"),
        ("import hashlib\nhashlib.new(name=self.algo)", "dynamic digest name"),
        (
            "import hashlib\ndef f(n='sha256'):\n    return hashlib.new(n)",
            "dynamic digest name",
        ),
        (
            "import hashlib\nN = 'sha256'\nN += suffix\nhashlib.new(N)",
            "dynamic digest name",
        ),
        (
            "import hashlib\nN = 'sha256'\nN = 'md5'\nhashlib.new(N)",
            "dynamic digest name",
        ),
        (
            "import hashlib\nfor n in ('sha256', 'md5'):\n    hashlib.new(n)",
            "dynamic digest name",
        ),
        (
            "import hashlib\nhashlib.new('sha256' if a else algo)",
            "dynamic digest name",
        ),
        ("import hashlib\nhashlib.pbkdf2_hmac(alg, p, s, 1)", "dynamic digest name"),
        ("import hashlib\nhashlib.file_digest(f, algo)", "dynamic digest name"),
        ("import _hashlib\n_hashlib.new(name)", "dynamic digest name"),
        ("import hmac\nhmac.new(k, m, digestmod=self.digest)", "dynamic digest name"),
        ("import hmac\nhmac.digest(k, m, algo)", "dynamic digest name"),
        (
            "import hashlib\nfrom somewhere import approved_digest\n"
            "hashlib.new(approved_digest(n))",
            "dynamic digest name",
        ),
    ],
)
def test_scanner_catches_round6(source, expected):
    assert scan_python(source)[expected] >= 1, scan_python(source)


@pytest.mark.parametrize(
    "source",
    [
        # vetted libraries (see _VETTED_CRYPTO_LIBS for why)
        "import ssl, secrets, hmac, hashlib",
        "import jwt\njwt.decode(t, k, algorithms=['HS256'])",
        "import pyotp",
        "import keyring",
        "from cryptography.fernet import Fernet",
        "from itsdangerous import URLSafeTimedSerializer\n"
        "URLSafeTimedSerializer(k, signer_kwargs={'digest_method': h})",
        "from itsdangerous import TimestampSigner\nTimestampSigner(k, digest_method=h)",
        "from itsdangerous import BadSignature",
        # not crypto at all
        "import signal, dataclasses, unicodedata, shutil, json",
        "from core.crypto import signing",
        # provable digest names
        "import hashlib\nA = 'sha256'\nhashlib.new(A)",
        "import hashlib\nA = 'sha256'\nif big:\n    A = 'sha384'\nhashlib.new(A)",
        "import hashlib\nhashlib.new('sha512' if big else 'sha256')",
        "import hashlib\nhashlib.new('SHA3-256')",
        "import hashlib\nhashlib.new('SHA-512/256')",
        "import hashlib\nfrom core.crypto.fips import approved_digest\n"
        "hashlib.new(approved_digest(name))",
        "import hashlib\nimport core.crypto.fips as F\n"
        "hashlib.pbkdf2_hmac(F.approved_digest(n), p, s, 600000)",
        "import hashlib\nhashlib.file_digest(f, hashlib.sha256)",
        "import hashlib\nhashlib.file_digest(f, lambda: hashlib.sha256())",
        "import hmac, hashlib\nhmac.new(k, m, hashlib.sha256)",
        "import hmac, hashlib\nhmac.new(k, m, lambda d=b'': hashlib.sha512(d))",
        "import hmac\nhmac.new(k, m, 'sha1')",
        "import hmac\nfrom hashlib import sha256\nhmac.new(k, m, sha256)",
        "import hmac\nhmac.new(k)",  # digestmod omitted: TypeError at runtime
    ],
)
def test_scanner_round6_approved_uses(source):
    assert not scan_python(source), scan_python(source)


def test_local_modules_are_not_third_party_crypto():
    source = "import hashing_utils\nfrom hashing_utils import fingerprint"
    assert scan_python(source)["unvetted crypto lib (hashing_utils)"] == 2
    assert not scan_python(source, frozenset({"hashing_utils"}))


def test_approved_digest_sets_agree():
    from core.crypto.fips import APPROVED_DIGESTS

    assert APPROVED_DIGESTS == _APPROVED_DIGESTS


def test_password_reset_serializer_is_sha256_hmac():
    """The itsdangerous allow-list entry relies on this (see _VETTED_CRYPTO_LIBS)."""
    import hashlib

    from core.auth import password_reset

    signer = password_reset._get_serializer().make_signer()
    assert signer.digest_method is hashlib.sha256
    assert signer.key_derivation == "hmac"


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("CryptoJS.MD5(message).toString()", "md5 (security use)"),
        ("CryptoJS.HmacMD5(message, key)", "md5 (security use)"),
        ("const d = CryptoJS.SHA1(message);", "sha1 (security use)"),
        ("CryptoJS.RIPEMD160(message)", "weak hash"),
        ("CryptoJS.TripleDES.encrypt(m, k)", "legacy cipher"),
        ("CryptoJS.RC4.encrypt(m, k)", "legacy cipher"),
        ("CryptoJS.Rabbit.decrypt(c, k)", "legacy cipher"),
        ("crypto.createDecipheriv('des-ede3-cbc', k, iv)", "legacy cipher"),
        ("import md5 from 'crypto-js/md5';", "foreign crypto lib"),
        ("import CryptoJS from 'crypto-js';", "foreign crypto lib"),
        ("import { KJUR } from 'jsrsasign';", "foreign crypto lib"),
        ("import SparkMD5 from 'spark-md5';", "foreign crypto lib"),
        ("const EC = require('elliptic').ec;", "foreign crypto lib"),
        ("const hash = require('object-hash');", "foreign crypto lib"),
        ("crypto.createHash(algorithm).update(x)", "dynamic digest name"),
        ("crypto.createHmac(cfg.alg, key)", "dynamic digest name"),
        ("await crypto.subtle.digest(alg, data)", "dynamic digest name"),
        ("crypto.createHash('md5')", "md5 (security use)"),
        ("await window.crypto.subtle.digest('SHA-1', buf)", "sha1 (security use)"),
    ],
)
def test_typescript_scanner_catches_round6(source, expected):
    assert scan_typescript(source)[expected] >= 1, scan_typescript(source)


@pytest.mark.parametrize(
    "source",
    [
        "CryptoJS.SHA256(message)",
        "CryptoJS.HmacSHA1(message, key)",  # HMAC-SHA1 is approved
        "CryptoJS.AES.encrypt(m, k)",
        "crypto.createHash('sha256')",
        "await crypto.subtle.digest({ name: 'SHA-256' }, data)",
        "const hash = e.file_hash_sha256 || e.file_hash_md5",  # field names
        "const md5Label = 'MD5';",
    ],
)
def test_typescript_scanner_round6_passes(source):
    assert not scan_typescript(source), scan_typescript(source)


def test_new_top_level_code_is_scanned(tmp_path, monkeypatch):
    """No directory list to forget: a package or client added anywhere is in
    scope; only the documented prunes, dot-dirs, tests and .d.ts are not."""
    files = {
        # in scope
        "newpkg/__init__.py": "import ecdsa",
        "newpkg/sub/mod.py": "import hashlib\nhashlib.md5(b'')",
        "standalone_script.py": "import rsa",
        "infra/tools/x.py": "import pyDes",
        "clients/mobile/src/a.ts": "crypto.createHash('md5')",
        "clients/web/src/b.tsx": "CryptoJS.SHA1(m)",
        "docs/examples/c.js": "require('crypto-js')",
        # out of scope
        "newpkg/tests/test_a.py": "import ecdsa",
        "newpkg/test_b.py": "import ecdsa",
        "node_modules/x/e.js": "createHash('md5')",
        "clients/web/dist/f.js": "createHash('md5')",
        "build/g.py": "import ecdsa",
        "htmlcov/h.js": "createHash('md5')",
        ".github/scripts/i.py": "import ecdsa",
        ".venv/lib/j.py": "import ecdsa",
        "clients/web/src/k.d.ts": "createHash('md5')",
        "clients/web/src/l.test.ts": "createHash('md5')",
    }
    for rel, text in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text)
    monkeypatch.setitem(globals(), "REPO_ROOT", tmp_path)
    assert sorted(_inventory()) == [
        "clients/mobile/src/a.ts",
        "clients/web/src/b.tsx",
        "docs/examples/c.js",
        "infra/tools/x.py",
        "newpkg/__init__.py",
        "newpkg/sub/mod.py",
        "standalone_script.py",
    ]


def test_every_top_level_source_dir_is_reached():
    """Each real top-level directory holding non-test source is reached by
    the walk unless it is a documented prune (guards a reintroduced dir list)."""
    scanned_tops = {rel.split("/")[0] for rel, _ in _scanned_files()}
    for top in sorted(REPO_ROOT.iterdir()):
        if not top.is_dir() or top.name.startswith(".") or top.name in _PRUNE:
            continue
        has_source = any(
            not _is_test_path(p.relative_to(REPO_ROOT).as_posix())
            and not p.name.endswith(".d.ts")
            and not any(part in _PRUNE for part in p.relative_to(REPO_ROOT).parts)
            for ext in ("*.py", "*.ts", "*.tsx", "*.js")
            for p in top.rglob(ext)
            if "node_modules" not in p.parts
        )
        if has_source:
            assert top.name in scanned_tops, top.name
