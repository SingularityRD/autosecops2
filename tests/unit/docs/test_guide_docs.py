"""The customer documentation set in docs/guide (W4.6) stays true to the code.

Two checks, both over every ``docs/guide/*.md``:

* Links: every relative Markdown link resolves to a file in the repository, and
  a ``#fragment`` on a Markdown target names a heading in it (GitHub's slug).
* Reconciliation (plan W4.6: "every setting and command in the docs exists in
  the code"): in inline code and fenced blocks, every environment variable,
  repository path, ``/api/...`` route, ``python -m`` module, ``npm run`` script
  and flag of ``install.sh`` / ``build-bundle.sh`` / ``start.sh`` /
  ``python -m core.backup`` must exist in the tree at this commit, and so must
  every environment variable written in plain prose (``JWT_SECRET_KEY`` without
  backticks). The marker ``Planlı —`` documents an unmerged work package (and
  marker phrase must name the branch, ``wp/...``, or say ``dal yok``). Only
  what the marker governs is skipped: its *segment* (the parenthesis it sits
  in, else its table cell, else its sentence) from the segment's start up to
  the end of the marker phrase (``Planlı — `wp/...`, bu sürümde yok``). Text
  after the phrase -- later in the same sentence, cell or parenthesis -- and
  the rest of the line are checked, so a present-tense claim cannot hide
  behind a marker, and a prose line carrying the marker stays short
  (``PLANNED_LINE_MAX``).
* Planned means unmerged: a marker phrase may not name a work-package branch
  that is already merged. The merged branches are listed in the checked-in
  ``merged_wps.txt`` (deterministic, no git needed); when ``wp/*`` refs and
  history are available the list is checked against git in both directions,
  and every page must state one base commit (``main`` @ ``<sha>``) that
  contains every listed branch.

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
# The marker phrase: the marker, then the branch(es) it names and the usual
# "bu sürümde yok" tail. What follows the phrase is ordinary, checked text.
PLANNED_PHRASE = re.compile(
    r"Planlı\s+—(?:[\s,]*(?:`wp/[^`\s]+`|wp/[\w.\-]+|dal yok|W\d+(?:\.\d+)*[a-z]?"
    r"|\(acil düzeltme\)|bu sürümde yok))*"
)
BRANCH = re.compile(r"wp/[A-Za-z0-9][\w.\-]*[A-Za-z0-9]")
MERGED_FILE = Path(__file__).resolve().parent / "merged_wps.txt"
# The branch that carries this documentation set: merged into itself by
# definition, never into the base the pages describe.
SELF_BRANCH = "wp/w4.6-docs"
# The pages name the branch they were checked against: `main` once released,
# `integration` while the release candidate is still being assembled.
BASE = re.compile(
    r"`(?:main|integration)` @ `([0-9a-f]{7,40})`"
    r"|(?:main|integration) @ ([0-9a-f]{7,40})"
)
# The user-visible product name is AutoSecOps. The old name survives only in
# internal identifiers, which the pages write as code (`VIGIL_*`, `vigil_app`,
# `infra/helm/vigil`); in prose it is a branding regression.
OLD_PRODUCT_NAME = re.compile(r"\bvigil\b", re.IGNORECASE)
PLANNED_LINE_MAX = 200
# Where a sentence a marker governs ends.
SENTENCE_BREAK = re.compile(r"[.;:!?]\s")
SENTENCE_END = re.compile(r"[.;:!?](?:\s|$)")

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
PROSE_ENV = re.compile(r"(?<![\w/.\-$])([A-Z][A-Z0-9]*_[A-Z0-9_]*[A-Z0-9])(?![\w/.\-])")
ENV_ASSIGN = re.compile(r"(?:^|\s|export\s+)([A-Z][A-Z0-9]*_[A-Z0-9_]*[A-Z0-9])=")
API = re.compile(r"(?<![\w.])(/api/[A-Za-z0-9_\-/{}.]*)")
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


def _planned_span(line: str, at: int) -> tuple[int, int]:
    """The segment a ``Planlı —`` marker at ``at`` governs: [start, end).

    Inside parentheses: up to the matching ``)``. An unclosed ``(`` does not
    count, so it cannot hide the rest of the line. In a table row: its cell.
    Otherwise: its sentence, which ends at ``.``, ``;``, ``:``, ``!`` or ``?``.
    """
    depth = 0
    for i in range(at - 1, -1, -1):  # the parenthesis the marker sits in
        if line[i] == ")":
            depth += 1
        elif line[i] == "(":
            if depth == 0:
                inner = 0
                for j in range(i + 1, len(line)):
                    if line[j] == "(":
                        inner += 1
                    elif line[j] == ")":
                        if inner == 0:
                            return i, j + 1
                        inner -= 1
                break  # unclosed: fall back to the cell or the sentence
            depth -= 1
    if line.lstrip().startswith("|"):  # its table cell
        start = line.rfind("|", 0, at) + 1
        end = line.find("|", at)
        return start, len(line) if end < 0 else end
    starts = [m.end() for m in SENTENCE_BREAK.finditer(line[:at])]
    end = SENTENCE_END.search(line, at)
    return (starts[-1] if starts else 0), (end.end() if end else len(line))


def unplanned(line: str) -> str:
    """The line with what each ``Planlı —`` marker governs blanked: its segment
    from the start up to the end of the marker phrase. Text after the phrase in
    the same sentence, cell or parenthesis is kept (and so checked)."""
    while True:
        m = PLANNED.search(line)
        if not m:
            return line
        start, end = _planned_span(line, m.start())
        phrase = PLANNED_PHRASE.match(line, m.start())
        stop = max(phrase.end() if phrase else m.end(), m.end())
        end = min(max(end, m.end()), stop)
        line = line[:start] + " " * (end - start) + line[end:]


def planned_branches(line: str) -> list[list[str]]:
    """For each marker on the line, the branches its phrase names."""
    return [BRANCH.findall(m.group(0)) for m in PLANNED_PHRASE.finditer(line)]


def planned_merged_problems(docs: list[Path], merged: frozenset[str]) -> list[str]:
    """Markers that call a merged branch planned."""
    problems: list[str] = []
    for doc in docs:
        for no, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            for names in planned_branches(line):
                for name in names:
                    if name in merged:
                        problems.append(f"{doc.name}:{no}: {name} is merged, not planned")
    return problems


def merged_list() -> frozenset[str]:
    names = set()
    for raw in MERGED_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            names.add(line)
    return frozenset(names)


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=False
    )


@lru_cache(maxsize=None)
def _merge_subjects(rev: str) -> str:
    out = _git("log", "--merges", "--format=%s", rev)
    return out.stdout if out.returncode == 0 else ""


def _named_in(subjects: str, branch: str) -> bool:
    return re.search(re.escape(branch) + r"(?![\w.\-])", subjects) is not None


def _is_ancestor(ref: str, rev: str) -> bool:
    return _git("merge-base", "--is-ancestor", ref, rev).returncode == 0


def _wp_refs() -> dict[str, list[str]]:
    """Branch name (``wp/...``) -> the local/remote refs that carry it."""
    out = _git("for-each-ref", "--format=%(refname)", "refs/heads", "refs/remotes")
    refs: dict[str, list[str]] = {}
    for ref in out.stdout.splitlines():
        at = ref.find("/wp/")
        if at < 0 or ref.endswith("/HEAD"):
            continue
        refs.setdefault(ref[at + 1 :], []).append(ref)
    return refs


def _history_available() -> bool:
    shallow = _git("rev-parse", "--is-shallow-repository")
    return shallow.returncode == 0 and shallow.stdout.strip() == "false"


def merged_list_problems(
    listed: frozenset[str], refs: dict[str, list[str]], rev: str = "HEAD"
) -> list[str]:
    """The checked-in list against git. A branch counts as merged when one of
    its refs is an ancestor of ``rev`` and a merge commit in ``rev``'s history
    names it (a fresh branch cut from integration is an ancestor too, but no
    merge names it). A listed branch is accepted when a merge names it, even if
    its tip moved on after the merge."""
    subjects = _merge_subjects(rev)
    problems: list[str] = []
    for name, carriers in sorted(refs.items()):
        if name == SELF_BRANCH:
            continue
        merged = _named_in(subjects, name) and any(
            _is_ancestor(ref, rev) for ref in carriers
        )
        if merged and name not in listed:
            problems.append(f"{name} is merged into {rev} but not in merged_wps.txt")
    for name in sorted(listed):
        if name in refs and not _named_in(subjects, name):
            if not any(_is_ancestor(ref, rev) for ref in refs[name]):
                problems.append(f"{name} is in merged_wps.txt but not merged into {rev}")
    return problems


def old_name_problems(docs: list[Path]) -> list[str]:
    """Lines whose prose (outside inline code and link targets) says Vigil."""
    problems: list[str] = []
    for doc in docs:
        fenced = False
        for no, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            if fenced:
                continue
            prose = re.sub(r"\]\([^)]*\)", "]", INLINE_CODE.sub(" ", line))
            if OLD_PRODUCT_NAME.search(prose):
                problems.append(f"{doc.name}:{no}: {line.strip()[:80]}")
    return problems


def doc_bases(docs: list[Path]) -> dict[str, set[str]]:
    """Base commit each page says it describes -> pages."""
    found: dict[str, set[str]] = {}
    for doc in docs:
        for m in BASE.finditer(doc.read_text(encoding="utf-8")):
            found.setdefault(m.group(1) or m.group(2), set()).add(doc.name)
    return found


def _check_prose_env(line: str, where: str, problems: list[str]) -> None:
    prose = LINK.sub(" ", INLINE_CODE.sub(" ", line))
    ids, _ = _corpus()
    for name in PROSE_ENV.findall(prose):
        if name not in ids and name not in _settings_fields():
            problems.append(f"{where}: env {name} (prose) not in code")


def reconciliation_problems(docs: list[Path]) -> list[str]:
    problems: list[str] = []
    for doc in docs:
        fenced = False
        for no, line in _logical_lines(doc.read_text(encoding="utf-8")):
            if line.lstrip().startswith("```"):
                fenced = not fenced
                continue
            line = unplanned(line)
            where = f"{doc.name}:{no}"
            if not fenced:
                _check_prose_env(line, where, problems)
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
            for m in PLANNED_PHRASE.finditer(line):
                if not BRANCH.search(m.group(0)) and "dal yok" not in m.group(0):
                    bad.append(f"{doc.name}:{no}")
    assert not bad, bad


def test_pages_use_the_product_name_not_vigil():
    assert old_name_problems(_guide_docs()) == []


def test_old_name_check_detects_vigil_in_prose(tmp_path):
    doc = tmp_path / "x.md"
    doc.write_text(
        "Vigil 0.7.x'ten yükseltme.\n"
        "Rol `vigil_app`, grafik `infra/helm/vigil`, `VIGIL_DIR`.\n"
        "[upgrade](../vigil/x.md) bağlantısı.\n"
        "```\nvigil komutu\n```\n",
        encoding="utf-8",
    )
    problems = old_name_problems([doc])
    assert len(problems) == 1 and problems[0].startswith("x.md:1:"), problems


# W1.9: an unmatched SSO user gets the provider's configurable default role
# (Viewer by default, never Admin; core/auth/oidc_accounts.py), not always Viewer.
SSO_ALWAYS_VIEWER = re.compile(r"eşleşme yoksa\s+Viewer", re.IGNORECASE)


def sso_default_role_problems(docs: list[Path]) -> list[str]:
    problems: list[str] = []
    for doc in docs:
        text = re.sub(r"\n>?\s*", " ", doc.read_text(encoding="utf-8"))
        for m in SSO_ALWAYS_VIEWER.finditer(text):
            problems.append(f"{doc.name}: '{m.group(0)}' (the default role is configurable)")
    return problems


def test_sso_unmatched_role_is_the_configurable_default():
    assert sso_default_role_problems(_guide_docs()) == []
    admin = (GUIDE / "yonetici-kilavuzu.md").read_text(encoding="utf-8")
    assert "varsayılan rolü" in admin and "Admin olamaz" in admin


def test_sso_default_role_check_detects_always_viewer(tmp_path):
    doc = tmp_path / "x.md"
    doc.write_text("Rol eşlemeden gelir; eşleşme\nyoksa Viewer olur.\n", encoding="utf-8")
    assert len(sso_default_role_problems([doc])) == 1


def test_planned_markers_do_not_name_merged_branches():
    assert planned_merged_problems(_guide_docs(), merged_list()) == []


def test_merged_list_matches_git():
    """merged_wps.txt is what git says, when git can say it (a full clone with
    the wp/* refs); CI's shallow checkout has neither and skips."""
    refs = _wp_refs()
    if not refs or not _history_available():
        pytest.skip("no wp/* refs or no full history: merged_wps.txt is trusted")
    assert merged_list_problems(merged_list(), refs) == []


def test_pages_describe_one_base_that_contains_every_merged_branch():
    bases = doc_bases(_guide_docs())
    assert len(bases) == 1, bases
    pages = next(iter(bases.values()))
    assert {"README.md", "kapsam.md"} <= pages, pages
    if not _history_available():
        pytest.skip("no full history: the base commit cannot be inspected")
    base = next(iter(bases))
    if _git("cat-file", "-e", f"{base}^{{commit}}").returncode != 0:
        pytest.skip(f"base {base} is not in this clone")
    assert _is_ancestor(base, "HEAD"), f"base {base} is not in HEAD"
    subjects = _merge_subjects(base)
    refs = _wp_refs()
    missing = [
        name
        for name in sorted(merged_list())
        if not _named_in(subjects, name)
        and not any(_is_ancestor(ref, base) for ref in refs.get(name, []))
    ]
    assert not missing, f"merged after the documented base {base}: {missing}"


def test_planned_prose_lines_are_short():
    bad = []
    for doc in _guide_docs():
        for no, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            if (
                PLANNED.search(line)
                and not line.lstrip().startswith("|")
                and len(line) > PLANNED_LINE_MAX
            ):
                bad.append(f"{doc.name}:{no} ({len(line)})")
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

`PLANLI_AYAR_YOK` burada atlanır, Planlı — `wp/w9.9-ornek`, bu sürümde yok.
`PLANLI_IKI_NOKTA` Planlı — `wp/w9.9-ornek`: `UYDURMA_IKI_NOKTA_SONRASI` açıktır.
`PLANLI_UNLEM` Planlı — `wp/w9.9-ornek` yok! `UYDURMA_UNLEM_SONRASI` vardır.
`PLANLI_SORU` Planlı — `wp/w9.9-ornek` yok? `UYDURMA_SORU_SONRASI` vardır.
(`PLANLI_KAPANMAMIS` Planlı — `wp/w9.9-ornek` yok; `UYDURMA_KAPANMAMIS_PARANTEZ` vardır

`UYDURMA_PARANTEZ_DISI=1` bugün vardır (`PLANLI_PARANTEZ` Planlı — `wp/w9.9-ornek`).
`PLANLI_CUMLE` Planlı — `wp/w9.9-ornek`, bu sürümde yok; ama `UYDURMA_CUMLE_SONRASI` var.
`PLANLI_ONCE` gelecek Planlı — `wp/w9.9-ornek`, bu sürümde yok ve `UYDURMA_AYNI_CUMLE` var.
(`PLANLI_P2` Planlı — dal yok, W9.9, bu sürümde yok, ama `UYDURMA_PARANTEZ_SONU` var)

| `UYDURMA_TABLO_HUCRESI` | `PLANLI_HUCRE` Planlı — `wp/w9.9-ornek` |
| `PLANLI_HUCRE2` Planlı — `wp/w9.9-ornek`, bu sürümde yok; `UYDURMA_HUCRE_SONRASI` var |

Düz metinde UYDURMA_DUZ_METIN_AYARI açık gelir; JWT_SECRET_KEY gerçektir.
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
        "UYDURMA_PARANTEZ_DISI",
        "UYDURMA_CUMLE_SONRASI",
        "UYDURMA_TABLO_HUCRESI",
        "UYDURMA_DUZ_METIN_AYARI",
        "UYDURMA_IKI_NOKTA_SONRASI",
        "UYDURMA_UNLEM_SONRASI",
        "UYDURMA_SORU_SONRASI",
        "UYDURMA_KAPANMAMIS_PARANTEZ",
        "UYDURMA_AYNI_CUMLE",
        "UYDURMA_PARANTEZ_SONU",
        "UYDURMA_HUCRE_SONRASI",
    ):
        assert needle in problems, (needle, problems)
    for skipped in (
        "PLANLI_AYAR_YOK",
        "PLANLI_PARANTEZ",
        "PLANLI_CUMLE",
        "PLANLI_HUCRE",
        "PLANLI_IKI_NOKTA",
        "PLANLI_KAPANMAMIS",
        "PLANLI_UNLEM",
        "PLANLI_SORU",
        "PLANLI_ONCE",
        "PLANLI_P2",
        "PLANLI_HUCRE2",
    ):
        assert skipped not in problems, (skipped, problems)
    assert "JWT_SECRET_KEY" not in problems


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


def test_planned_check_detects_a_merged_branch_called_planned(tmp_path):
    doc = tmp_path / "stale.md"
    doc.write_text(
        "Zincir (Planlı — `wp/w9.1-birlesti`, bu sürümde yok).\n"
        "| Özellik | Planlı — `wp/w9.2-acik`, `wp/w9.1-birlesti` |\n"
        "Henüz yok (Planlı — `wp/w9.2-acik`, bu sürümde yok); "
        "`wp/w9.1-birlesti` birleşti.\n",
        encoding="utf-8",
    )
    problems = planned_merged_problems([doc], frozenset({"wp/w9.1-birlesti"}))
    assert [p.split(":")[1] for p in problems] == ["1", "2"], problems


def test_merged_list_check_detects_drift():
    """Against this clone's own history: a merged branch left off the list, and
    a listed branch git has never merged, are both reported."""
    refs = _wp_refs()
    if not refs or not _history_available():
        pytest.skip("no wp/* refs or no full history")
    listed = merged_list()
    if not listed:
        pytest.skip("empty list")
    dropped = sorted(listed & set(refs))[0]
    problems = merged_list_problems(listed - {dropped}, refs)
    assert any(dropped in p and "not in merged_wps.txt" in p for p in problems)
    unmerged = [
        ref for carriers in refs.values() for ref in carriers if not _is_ancestor(ref, "HEAD")
    ]
    if not unmerged:
        pytest.skip("every wp/* ref is merged: nothing to list wrongly")
    fake = {"wp/w9.9-hic-birlesmedi": [unmerged[0]]}
    problems = merged_list_problems(listed | {"wp/w9.9-hic-birlesmedi"}, {**refs, **fake})
    assert any("w9.9-hic-birlesmedi" in p for p in problems), problems
