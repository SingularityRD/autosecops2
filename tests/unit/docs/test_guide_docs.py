"""The customer documentation set in docs/guide (W4.6) stays true to the code.

Two checks, both over every ``docs/guide/*.md``:

* Links: every relative Markdown link resolves to a file in the repository, and
  a ``#fragment`` on a Markdown target names a heading in it (GitHub's slug).
* Reconciliation (plan W4.6: "every setting and command in the docs exists in
  the code"): in inline code and fenced blocks, every environment variable,
  repository path, ``/api/...`` route, ``python -m`` module, ``npm run`` script
  and flag of ``install.sh`` / ``build-bundle.sh`` / ``start.sh`` /
  ``python -m core.backup`` must exist in the tree at this commit. A line that
  carrying the marker ``Planlı —`` documents an unmerged work package (and must
  name its branch, ``wp/...``, or say ``dal yok``); it is skipped.

The ``detects_*`` tests feed a deliberately wrong document through the same
checks so a checker that silently passes everything fails here.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
from functools import lru_cache
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
GUIDE = REPO / "docs" / "guide"
PLANNED = re.compile(r"Planlı\s+—")

# Where a documented name must be found. Docs and tests are excluded so a page
# cannot vouch for itself; tests/airgap is the egress-proof tooling the install
# guide tells operators to run, so it counts as product.
CORPUS_PREFIXES = (
    "core/",
    "services/",
    "infra/",
    "scripts/",
    "evalkit/",
    "eval/suites/",
    "clients/web/src/",
    ".github/workflows/",
    "tests/airgap/",
)
CORPUS_FILES = ("start.sh", "env.example", "INTENT.md", "setup_dev.sh")
TEXT_SUFFIXES = {
    ".py",
    ".ts",
    ".tsx",
    ".sql",
    ".yaml",
    ".yml",
    ".json",
    ".sh",
    ".env",
    ".md",
    ".tpl",
    ".txt",
    ".toml",
    "",
}

# Script name -> source files its flags must appear in.
SCRIPTS = {
    "install.sh": ("infra/airgap/install.sh",),
    "build-bundle.sh": ("infra/airgap/build-bundle.sh",),
    "start.sh": ("start.sh",),
    "python -m core.backup": (
        "core/backup/__main__.py",
        "core/backup/create.py",
        "core/backup/restore.py",
    ),
}
PACKAGE_JSONS = ("services/agent/package.json", "clients/web/package.json")
HELM_VALUES = (
    "infra/helm/vigil/values.yaml",
    "infra/airgap/values-airgap.yaml",
)
REPO_TOP = (
    "core",
    "services",
    "infra",
    "scripts",
    "tests",
    "clients",
    "docs",
    "eval",
    "evalkit",
    "tools",
    ".github",
)
TOP_FILES = (
    "start.sh",
    "env.example",
    "INTENT.md",
    "README.md",
    "SECURITY.md",
    "FORK.md",
    "VERSION",
    "setup_dev.sh",
    "mcp-config.json",
)
FILE_SUFFIXES = (
    ".md",
    ".py",
    ".sh",
    ".yaml",
    ".yml",
    ".json",
    ".env",
    ".sql",
    ".ts",
    ".tsx",
    ".tgz",
    ".tar",
    ".gz",
    ".key",
    ".pub",
    ".enc",
    ".sig",
    ".minisig",
    ".tsv",
    ".db",
    ".txt",
)

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
INLINE_CODE = re.compile(r"`([^`\n]+)`")
ENV = re.compile(r"^\$?([A-Z][A-Z0-9]*_[A-Z0-9_]*[A-Z0-9])(=.*)?$")
ENV_ASSIGN = re.compile(r"(?:^|\s|export\s+)([A-Z][A-Z0-9]*_[A-Z0-9_]*[A-Z0-9])=")
API = re.compile(r"(/api/[A-Za-z0-9_\-/{}.]*)")
PY_MODULE = re.compile(r"python3?\s+-m\s+([A-Za-z_][\w.]*)")
NPM_RUN = re.compile(r"npm run ([\w:.-]+)")
FLAG = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)")
SNAKE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
DOTTED = re.compile(r"^[a-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")
PATHLIKE = re.compile(r"^(?:\./)?([A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]*)*)$")
WORD = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*[A-Za-z0-9]$")
COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
EMBEDDED_PATH = re.compile(
    r"(?<![\w/.~-])((?:core|services|infra|scripts|tests|clients|docs|eval|evalkit|tools)"
    r"/[A-Za-z0-9_./-]*[A-Za-z0-9_/])"
)


# --------------------------------------------------------------------- corpus


@lru_cache(maxsize=1)
def _tracked() -> tuple[str, ...]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout
    return tuple(out.splitlines())


@lru_cache(maxsize=1)
def _corpus() -> tuple[frozenset[str], str]:
    """(identifier set, whole text) of the product files."""
    parts: list[str] = []
    for rel in _tracked():
        if not (rel.startswith(CORPUS_PREFIXES) or rel in CORPUS_FILES):
            continue
        if "node_modules/" in rel or Path(rel).suffix not in TEXT_SUFFIXES:
            continue
        try:
            parts.append((REPO / rel).read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
    text = "\n".join(parts)
    ids = frozenset(re.findall(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*", text))
    words = frozenset(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text))
    return ids | words, text


@lru_cache(maxsize=1)
def _settings_fields() -> frozenset[str]:
    from core.config import Settings

    return frozenset(name.upper() for name in Settings.model_fields)


@lru_cache(maxsize=1)
def _api_paths() -> frozenset[str]:
    schema = (REPO / "clients/web/src/services/generated/schema.d.ts").read_text(
        encoding="utf-8"
    )
    found = re.findall(r'^\s{4}"(/api/[^"]+)"\s*:', schema, flags=re.M)
    return frozenset(_norm_api(p) for p in found)


def _norm_api(path: str) -> str:
    path = path.split("?", 1)[0].rstrip(".,;:)")
    return re.sub(r"\{[^}]*\}", "{}", path).rstrip("/") or "/"


@lru_cache(maxsize=1)
def _helm_values() -> tuple[dict, ...]:
    return tuple(
        yaml.safe_load((REPO / p).read_text(encoding="utf-8")) or {}
        for p in HELM_VALUES
    )


@lru_cache(maxsize=1)
def _npm_scripts() -> frozenset[str]:
    names: set[str] = set()
    for p in PACKAGE_JSONS:
        data = json.loads((REPO / p).read_text(encoding="utf-8"))
        names.update((data.get("scripts") or {}).keys())
    return frozenset(names)


def _script_source(name: str) -> str:
    return "\n".join((REPO / p).read_text(encoding="utf-8") for p in SCRIPTS[name])


# --------------------------------------------------------------------- checks


def _strip_code(text: str) -> str:
    """Text with fenced blocks and inline code blanked (links there are not links)."""
    out, fenced = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            out.append("")
            continue
        out.append("" if fenced else INLINE_CODE.sub("", line))
    return "\n".join(out)


def slug(heading: str) -> str:
    """GitHub's anchor for a heading."""
    text = re.sub(r"`", "", heading.strip()).lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(md: Path) -> set[str]:
    seen: dict[str, int] = {}
    result: set[str] = set()
    fenced = False
    for line in md.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        m = None if fenced else re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not m:
            continue
        base = slug(m.group(1))
        n = seen.get(base, 0)
        seen[base] = n + 1
        result.add(base if n == 0 else f"{base}-{n}")
    return result


def link_problems(docs: list[Path]) -> list[str]:
    problems: list[str] = []
    for doc in docs:
        text = _strip_code(doc.read_text(encoding="utf-8"))
        for target in LINK.findall(text):
            if re.match(r"^[a-z][a-z0-9+.-]*:", target):  # http:, https:, mailto:
                continue
            path_part, _, frag = target.partition("#")
            dest = (doc.parent / path_part).resolve() if path_part else doc
            if not dest.exists():
                problems.append(f"{doc.name}: broken link {target}")
                continue
            if frag and dest.suffix == ".md" and frag not in anchors(dest):
                problems.append(f"{doc.name}: no heading #{frag} in {dest.name}")
    return problems


def _code_tokens(line: str, fenced: bool) -> list[str]:
    return [line.strip()] if fenced else INLINE_CODE.findall(line)


def _check_token(tok: str, where: str, problems: list[str]) -> None:
    ids, _ = _corpus()
    tok = tok.strip()
    m = ENV.match(tok)
    if m:
        name = m.group(1)
        if name not in ids and name not in _settings_fields():
            problems.append(f"{where}: env {name} not in code")
        return
    for api in API.findall(tok):
        if "..." in api:  # a placeholder ("/api/..."), not a route
            continue
        if _norm_api(api) not in _api_paths():
            problems.append(f"{where}: API {api} not in the OpenAPI schema")
    if API.search(tok):
        return
    if SNAKE.match(tok):
        if tok not in ids:
            problems.append(f"{where}: identifier {tok} not in code")
        return
    if DOTTED.match(tok) and not tok.endswith(FILE_SUFFIXES):
        if tok not in ids and not _in_helm(tok):
            problems.append(f"{where}: key {tok} not in code or Helm values")
        return
    pm = PATHLIKE.match(tok)
    if pm and "/" in tok and tok.split("/", 1)[0].lstrip("./") in REPO_TOP:
        rel = pm.group(1).rstrip("/")
        if not (REPO / rel).exists():
            problems.append(f"{where}: path {rel} does not exist")
        return
    if tok in TOP_FILES:
        if not (REPO / tok).exists():
            problems.append(f"{where}: file {tok} does not exist")
        return
    if WORD.match(tok) and not COMMIT.match(tok):
        _, text = _corpus()
        if tok not in ids and tok not in text:
            problems.append(f"{where}: name {tok} not in code")


def _in_helm(key: str) -> bool:
    for values in _helm_values():
        node = values
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                break
            node = node[part]
        else:
            return True
    return False


def _check_command(line: str, where: str, problems: list[str]) -> None:
    for rel in EMBEDDED_PATH.findall(line):
        if "<" in rel or "*" in rel:
            continue
        if not (REPO / rel.rstrip("/")).exists():
            problems.append(f"{where}: path {rel} does not exist")
    for module in PY_MODULE.findall(line):
        base = REPO / Path(*module.split("."))
        if (REPO / module.split(".")[0]).is_dir():
            found = base.with_suffix(".py").exists() or (base / "__main__.py").exists()
        else:  # a third-party tool the docs tell operators to run (pytest)
            found = importlib.util.find_spec(module) is not None
        if not found:
            problems.append(f"{where}: python -m {module} has no module")
    for script in NPM_RUN.findall(line):
        if script not in _npm_scripts():
            problems.append(f"{where}: npm run {script} is not a script")
    for name in SCRIPTS:
        idx = line.find(name)
        if idx < 0:
            continue
        tail = line[idx + len(name) :].split(" -- ", 1)[0]
        source = _script_source(name)
        for flag in FLAG.findall(tail):
            if flag not in source:
                problems.append(f"{where}: {name} has no flag {flag}")
    for name in ENV_ASSIGN.findall(line):
        ids, _ = _corpus()
        if name not in ids and name not in _settings_fields():
            problems.append(f"{where}: env {name} not in code")


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Lines numbered from 1, a shell continuation (``\\``) joined to the next."""
    out: list[tuple[int, str]] = []
    pending: tuple[int, str] | None = None
    for no, line in enumerate(text.splitlines(), 1):
        if pending is not None:
            line = pending[1] + " " + line.strip()
            no = pending[0]
            pending = None
        if line.rstrip().endswith("\\") and not line.lstrip().startswith("```"):
            pending = (no, line.rstrip()[:-1].rstrip())
            continue
        out.append((no, line))
    if pending is not None:
        out.append(pending)
    return out


def reconciliation_problems(docs: list[Path]) -> list[str]:
    problems: list[str] = []
    for doc in docs:
        fenced = False
        for no, line in _logical_lines(doc.read_text(encoding="utf-8")):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if PLANNED.search(line):
                continue
            where = f"{doc.name}:{no}"
            for tok in _code_tokens(line, fenced):
                if fenced:
                    _check_command(tok, where, problems)
                    for word in re.findall(r"(?<![\w$/.-])(/api/[^\s'\"]+)", tok):
                        _check_token(word, where, problems)
                else:
                    _check_token(tok, where, problems)
                    _check_command(tok, where, problems)
    return problems


# ---------------------------------------------------------------------- tests

EXPECTED = {
    "README.md",
    "kapsam.md",
    "kurulum-internetsiz.md",
    "yonetici-kilavuzu.md",
    "guvenlik-teknik-belgesi.md",
    "tehdit-modeli.md",
    "mevzuat-eslemesi.md",
}


def _guide_docs() -> list[Path]:
    return sorted(GUIDE.glob("*.md"))


def test_guide_set_is_complete():
    assert EXPECTED <= {p.name for p in _guide_docs()}


def test_index_links_every_page():
    index = (GUIDE / "README.md").read_text(encoding="utf-8")
    missing = [n for n in sorted(EXPECTED - {"README.md"}) if f"({n}" not in index]
    assert not missing, missing


def test_relative_links_resolve():
    assert link_problems(_guide_docs()) == []


def test_documented_settings_and_commands_exist():
    assert reconciliation_problems(_guide_docs()) == []


def test_regulatory_mapping_says_not_legal_advice():
    text = (GUIDE / "mevzuat-eslemesi.md").read_text(encoding="utf-8")
    assert "hukuki görüş değildir" in text


def test_planned_lines_name_their_branch():
    bad = []
    for doc in _guide_docs():
        for no, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            if PLANNED.search(line) and "wp/" not in line and "dal yok" not in line:
                bad.append(f"{doc.name}:{no}")
    assert not bad, bad


BAD_DOC = """# Başlık

[kırık](yok-boyle-bir-dosya.md) ve [çapa](#olmayan-baslik) ve [iyi](#başlık)

`AUTOSECOPS_UYDURMA_AYAR=true` ve `core/uydurma/modul.py` ve
`GET /api/uydurma/{id}/yol` ve `uydurma_tablo_adi`.

```bash
./install.sh install --uydurma-bayrak x
python -m core.uydurma_modul
npm run uydurma:script
UYDURMA_ORTAM_DEGISKENI=1 ./start.sh
pytest tests/uydurma/test_yok.py
./install.sh install --registry r \\
  --uydurma-ikinci-satir
```

`UydurmaSinifAdi` ve `uydurma-servis-adi`.

Planlı — `wp/w9.9-ornek`: `PLANLI_AYAR_YOK` burada atlanır.
"""


def test_link_check_detects_broken_links(tmp_path):
    doc = tmp_path / "bad.md"
    doc.write_text(BAD_DOC, encoding="utf-8")
    problems = link_problems([doc])
    assert any("yok-boyle-bir-dosya.md" in p for p in problems), problems
    assert any("olmayan-baslik" in p for p in problems), problems
    assert not any("başlık" in p for p in problems), problems


def test_reconciliation_detects_invented_settings_and_commands(tmp_path):
    doc = tmp_path / "bad.md"
    doc.write_text(BAD_DOC, encoding="utf-8")
    problems = "\n".join(reconciliation_problems([doc]))
    for needle in (
        "AUTOSECOPS_UYDURMA_AYAR",
        "core/uydurma/modul.py",
        "/api/uydurma/{id}/yol",
        "uydurma_tablo_adi",
        "--uydurma-bayrak",
        "core.uydurma_modul",
        "uydurma:script",
        "UYDURMA_ORTAM_DEGISKENI",
        "tests/uydurma/test_yok.py",
        "--uydurma-ikinci-satir",
        "UydurmaSinifAdi",
        "uydurma-servis-adi",
    ):
        assert needle in problems, (needle, problems)
    assert "PLANLI_AYAR_YOK" not in problems


def test_reconciliation_detects_nothing_wrong_in_real_names(tmp_path):
    doc = tmp_path / "good.md"
    doc.write_text(
        "`DAEMON_FORCE_APPROVAL=true` `infra/airgap/airgap.env` "
        "`POST /api/v1/approvals/{id}/approve` `approval_actions` "
        "`networkPolicies.egress.extraCIDRs` `settings.write`\n\n"
        "```bash\n./install.sh verify --pubkey k.pub\n"
        "python -m core.backup restore --repo r --passphrase-file p --test\n"
        "cd services/agent && npm run ledger:verify\n```\n",
        encoding="utf-8",
    )
    assert reconciliation_problems([doc]) == []
