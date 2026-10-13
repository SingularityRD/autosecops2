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
(``importlib.import_module('bcrypt')``, ``__import__``).
Round 5: string expressions are constant-folded (concatenation, f-strings,
``''.join``, module-level constants); ``getattr``, ``sys.modules[...]``,
``import_module(...)`` results, ``x = hashlib`` reassignments, star imports,
``functools.partial`` and constant ``eval``/``exec`` strings are resolved too.
A non-literal ``getattr`` on a crypto module, or a dynamic import whose pieces
look crypto-ish, is flagged conservatively. Imports of a foreign
library or an Ed/X curve module count once per statement; hashes and ciphers
count per use. TypeScript/JavaScript (.ts/.js/.mjs/.cjs...) is scanned with regexes (``createHash``,
``crypto.hash``, ``subtle.digest``, WebCrypto ``hash:`` params, pbkdf2 digest
args, ``createCipheriv`` and imports of JS crypto libraries).

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
}
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
    name = text.lower()
    return _HASH_ALIASES.get(name, name)


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

    def __init__(self, parent: _Scanner | None = None) -> None:
        self.found: Counter = Counter()
        self.aliases: dict[str, str] = dict(parent.aliases) if parent else {}
        self.consts: dict[str, object] = dict(parent.consts) if parent else {}
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
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.visit(node)
        self._collect_consts(tree)
        for _ in range(3):  # chains: a = hashlib; b = a
            self._collect_module_aliases(tree)
        self.visit(_without_imports(tree))
        return +self.found

    def _collect_consts(self, tree: ast.AST) -> None:
        seen: dict[str, list] = {}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                seen.setdefault(node.targets[0].id, []).append(node.value)
        for _ in range(2):  # a = "md"; b = a + "5"
            for name, values in seen.items():
                folded = {self.fold(v) for v in values}
                if len(values) == 1 and None not in folded:
                    self.consts[name] = folded.pop()

    def _collect_module_aliases(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(
                    node.value, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)
                )
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
            if digest in _NON_FIPS_HASHES:
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


def scan_python(source: str) -> Counter:
    return _Scanner().scan(ast.parse(source))


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
        rf"|hash\s*:\s*(?:\{{\s*name\s*:\s*)?{_Q}md5{_Q}",
        re.I,
    ),
    "sha1 (security use)": re.compile(
        rf"(?:createHash|\bhash)\(\s*{_Q}sha-?1{_Q}"
        rf"|subtle\s*\.\s*digest\(\s*(?:\{{\s*name\s*:\s*)?{_Q}sha-?1{_Q}"
        rf"|pbkdf2(?:Sync)?\([^;]*?,\s*{_Q}sha-?1{_Q}\s*[,)]"
        rf"|hash\s*:\s*(?:\{{\s*name\s*:\s*)?{_Q}sha-?1{_Q}"
        rf"|(?:create(?:Sign|Verify)|\bsign|\bverify)\(\s*{_Q}(?:rsa-)?sha-?1"
        rf"(?:WithRSAEncryption)?{_Q}",
        re.I,
    ),
    "weak hash": re.compile(
        rf"(?:createHash|createHmac|\bhash)\(\s*{_Q}(?:md4|ripemd160|blake2[bs]\d*){_Q}",
        re.I,
    ),
    "scrypt": re.compile(r"\bscrypt(?:Sync)?\s*\("),
    "ed25519": re.compile(rf"{_Q}(?:ed25519|ed448|x25519|x448){_Q}", re.I),
    "legacy cipher": re.compile(
        rf"createCipheriv\(\s*{_Q}(?:des|bf|rc4|rc2|cast|idea|seed|chacha20|camellia|sm4)",
        re.I,
    ),
    "foreign crypto lib": re.compile(
        r"(?:from\s+|require\(\s*|import\(\s*|import\s+)['\"](?:bcrypt|bcryptjs|"
        r"tweetnacl|libsodium[\w-]*|crypto-js|node-forge|js-sha1|js-md5|sha1|md5|"
        r"blakejs|argon2|scrypt-js|"
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


_TS_EXTS = (".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs")
_PRUNE = {"node_modules", "dist", "build", "coverage", ".venv", ".git"}


def _walk(root: Path, suffixes: tuple[str, ...]):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _PRUNE]
        for name in filenames:
            if name.endswith(suffixes):
                yield Path(dirpath) / name


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
        for path in _walk(REPO_ROOT / d, _TS_EXTS):
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
    monkeypatch.setitem(globals(), "PY_DIRS", ())
    assert sorted(_inventory()) == [
        "services/agent/lib/a.mjs",
        "services/agent/lib/b.cjs",
        "services/agent/lib/c.js",
    ]
