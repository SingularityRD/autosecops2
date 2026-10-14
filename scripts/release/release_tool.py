#!/usr/bin/env python3
"""AutoSecOps release helper: version checks, offline SBOMs, provenance, checksums.

Standard library only, and no network access: every subcommand reads files in
the repository (or a directory it is pointed at) and writes files. The release
workflow (.github/workflows/release.yml) and the local dry run
(scripts/release/dry-run.sh) call the same code, so what the dry run proves is
what the tag pipeline produces.

Subcommands
  check-tag       validate a vX.Y.Z[-rc.N] tag against VERSION
  check-versions  every file that carries the release version agrees with VERSION
  check-notes     release notes: every "Dahil" WP really was merged (--strict:
                  every merged wp/<id>-* branch has a "Dahil" row; --data: the
                  notes are exactly what render-notes produces)
  render-notes    release notes + CHANGELOG block from git log --merges and
                  the WP data file (docs/release/<V>.json)
  check-on-main   the tagged commit is an ancestor of main
  sbom-python     CycloneDX SBOM from a pip/uv lock (name==version lines)
  sbom-npm        CycloneDX SBOM from an npm package-lock.json (v2/v3)
  sboms           all lockfile SBOMs of the repository into one directory
  validate-sbom   structural CycloneDX check (format, refs, purls)
  provenance      SLSA v1 provenance predicate for one subject (GitHub env)
  images-manifest images.json (+ .tsv) from the build job's digests and indexes
  image-refs      repository@digest rows of an images.json (index or platforms)
  checksums       SHA256SUMS over every file of a directory
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import quote

REPO = Path(__file__).resolve().parents[2]
TOOL_NAME = "autosecops-release-tool"
CDX_SPEC = "1.6"
# uuid5 namespace for deterministic serial numbers (same inputs → same SBOM).
SERIAL_NS = uuid.UUID("5d0b3a8e-7c1f-4f57-9a43-2c0e6f1b9a10")

TAG_RE = re.compile(r"^v(?P<base>\d+\.\d+\.\d+)(?:-rc\.(?P<rc>[1-9]\d*))?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
WP_ID_RE = re.compile(r"^W\d+\.\d+[a-z]?$")

# Lockfiles the release covers, as (sbom-suffix, kind, path, component name).
LOCKFILES = (
    ("python", "python", "requirements.lock", "autosecops-backend"),
    ("node-web", "npm", "clients/web/package-lock.json", "autosecops-web"),
    ("node-agent", "npm", "services/agent/package-lock.json", "autosecops-agent"),
    (
        "node-mcp-packages",
        "npm",
        "infra/docker/mcp-packages/package-lock.json",
        "autosecops-mcp-packages",
    ),
    ("node-desktop", "npm", "clients/desktop/package-lock.json", "autosecops-desktop"),
)


class ReleaseError(Exception):
    """A check failed; the message says what to fix."""


# --------------------------------------------------------------------------- versions


def read_version(repo: Path = REPO) -> str:
    v = (repo / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER_RE.match(v):
        raise ReleaseError(f"VERSION is not X.Y.Z: {v!r}")
    return v


def parse_tag(tag: str, version: str) -> tuple[str, bool]:
    """Return (image/release version without the v, prerelease?) for a tag."""
    m = TAG_RE.match(tag)
    if not m:
        raise ReleaseError(
            f"tag {tag!r} is not vX.Y.Z or vX.Y.Z-rc.N; refusing to release"
        )
    if m.group("base") != version:
        raise ReleaseError(
            f"tag {tag!r} does not match VERSION {version!r}; bump VERSION first"
        )
    return tag[1:], m.group("rc") is not None


def _json_path(doc: dict, path: tuple) -> object:
    cur: object = doc
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur


def version_fields(repo: Path = REPO) -> list[tuple[str, Optional[str]]]:
    """Every (location, value) that release-please bumps alongside VERSION."""
    out: list[tuple[str, Optional[str]]] = []
    for rel, path in (
        ("clients/web/package.json", ("version",)),
        ("clients/web/package-lock.json", ("version",)),
        ("clients/web/package-lock.json", ("packages", "", "version")),
        ("clients/desktop/package.json", ("version",)),
        ("clients/desktop/package-lock.json", ("version",)),
        ("clients/desktop/package-lock.json", ("packages", "", "version")),
        (".github/.release-please-manifest.json", (".",)),
    ):
        doc = json.loads((repo / rel).read_text(encoding="utf-8"))
        val = _json_path(doc, path)
        dotted = ".".join(p or "''" for p in path)
        out.append((f"{rel}:{dotted}", val))
    chart = (repo / "infra/helm/vigil/Chart.yaml").read_text(encoding="utf-8")
    for key in ("version", "appVersion"):
        m = re.search(rf"^{key}:\s*['\"]?([^'\"\s]+)", chart, re.M)
        out.append((f"infra/helm/vigil/Chart.yaml:{key}", m.group(1) if m else None))
    support = (repo / "scripts/vigil-support/VERSION").read_text(encoding="utf-8")
    out.append(
        (
            "scripts/vigil-support/VERSION",
            support.split()[0] if support.split() else None,
        )
    )
    return out


def check_versions(repo: Path = REPO) -> str:
    version = read_version(repo)
    bad = [f"{loc} = {val!r}" for loc, val in version_fields(repo) if val != version]
    if bad:
        raise ReleaseError(
            f"version drift against VERSION {version}:\n  " + "\n  ".join(bad)
        )
    return version


# --------------------------------------------------------------------------- notes

# Subjects of the merge commits that bring a branch in, most specific first:
#   Merge pull request #12 from owner/wp/w1.2-x          (GitHub merge button)
#   Merge remote-tracking branch 'origin/wp/w1.2-x' [into y]
#   Merge branch 'wp/w1.2-x' [into y]                    (git merge default)
#   Merge wp/w1.2-x into integration (verified PASS)     (this repo's merges)
#   Merge brand/x: summary
# GitHub's owner/ (fork) and the remote name are not part of the branch.
MERGE_RE = (
    re.compile(r"^Merge pull request #(?P<pr>\d+) from [^/\s]+/(?P<branch>[^\s']+)"),
    re.compile(r"^Merge remote-tracking branch '[^/']+/(?P<branch>[^']+)'"),
    re.compile(r"^Merge branch '(?P<branch>[^']+)'"),
    re.compile(r"^Merge (?:branch )?(?P<branch>\w[\w./-]*)(?=[\s:,]|$)"),
)
# A squash merge is an ordinary commit; GitHub appends " (#N)" to the PR title.
# Only a title that names its WP ("W1.2: ..." / "W1.2 ...") counts, and the
# merged "branch" is the label "PR #N (W1.2)" (the branch name is gone).
SQUASH_RE = re.compile(r"^(?P<wp>W\d+\.\d+[a-z]?)\b[^\n]*\(#(?P<pr>\d+)\)$")
SQUASH_LABEL_RE = re.compile(r"^PR #\d+ \((?P<wp>W\d+\.\d+[a-z]?)\)$")
# wp/<id>-<slug>: w0.4b, w0.10, w0.11, w12.3 ... (the id is upper-cased: W0.10)
WP_BRANCH_RE = re.compile(r"^wp/(?P<id>w\d+\.\d+[a-z]?)-")

SHALLOW_HINT = (
    "run `git fetch --unshallow --tags` (CI: actions/checkout with fetch-depth: 0)"
)


def is_shallow(repo: Path) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--is-shallow-repository"],
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def require_full_history(repo: Path, why: str) -> None:
    """A shallow clone lacks merges: refuse instead of answering wrongly."""
    if is_shallow(repo):
        raise ReleaseError(f"{repo} is a shallow clone; {why} needs the full history: {SHALLOW_HINT}")


def branch_of_subject(subject: str, parents: int = 2) -> Optional[str]:
    """Branch (or squash label) brought in by a commit with this subject."""
    subject = subject.strip()
    if parents > 1:
        for rx in MERGE_RE:
            m = rx.match(subject)
            if m:
                return m.group("branch")
        return None
    m = SQUASH_RE.match(subject)
    return f"PR #{m.group('pr')} ({m.group('wp')})" if m else None


def merged_branches(repo: Path, ref: str = "HEAD") -> set[str]:
    """Branches merged into ref (merge commits and squash-merged WP PRs)."""
    require_full_history(repo, "reading the merged branches")
    proc = subprocess.run(
        ["git", "-C", str(repo), "log", "--format=%P%x09%s", ref],
        capture_output=True,
        text=True,
        check=True,
    )
    out = set()
    for line in proc.stdout.splitlines():
        parents, _, subject = line.partition("\t")
        b = branch_of_subject(subject, len(parents.split()))
        if b:
            out.add(b)
    return out


def wp_id_of_branch(branch: str) -> Optional[str]:
    """W<major>.<minor>[x] for a wp/<id>-<slug> branch, else None."""
    m = WP_BRANCH_RE.match(branch)
    if m:
        return "W" + m.group("id")[1:]
    m = SQUASH_LABEL_RE.match(branch)
    return m.group("wp") if m else None


def merged_wps(merged: Iterable[str]) -> dict[str, str]:
    """WP id -> merged wp/<id>-* branch (sorted, first wins on duplicates)."""
    out: dict[str, str] = {}
    for b in sorted(merged):
        wp = wp_id_of_branch(b)
        if wp and wp not in out:
            out[wp] = b
    return out


def merged_wp_branches(merged: Iterable[str]) -> dict[str, list[str]]:
    """WP id -> every merged branch of it (W0.13 has several review branches)."""
    out: dict[str, list[str]] = {}
    for b in sorted(merged):
        wp = wp_id_of_branch(b)
        if wp:
            out.setdefault(wp, []).append(b)
    return out


def parse_notes(text: str) -> list[dict]:
    """Rows of the WP table: | WP | Konu | Durum | Birleştirme |."""
    rows = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or not WP_ID_RE.match(cells[0]):
            continue
        status = cells[2].strip("* ")
        if status not in ("Dahil", "Dahil değil"):
            raise ReleaseError(
                f"{cells[0]}: status must be Dahil or 'Dahil değil', got {status!r}"
            )
        branches = [
            b.strip("` ") for b in cells[3].split(",") if b.strip("` ") not in ("", "—", "-")
        ]
        rows.append(
            {
                "wp": cells[0],
                "included": status == "Dahil",
                "branch": branches[0] if branches else None,
                "branches": branches,
            }
        )
    if not rows:
        raise ReleaseError("no WP table rows found in release notes")
    return rows


def check_notes(
    notes: Path,
    repo: Path,
    ref: str = "HEAD",
    strict: bool = False,
    data: Optional[Path] = None,
) -> list[dict]:
    """Release notes against the merge history of ref.

    Always: every "Dahil" row has a merge commit, no WP is listed twice.
    strict (the tag pipeline): no merged wp/<id>-* branch is "Dahil değil" or
    missing from the table (the release's own WP, ``self`` in the data file,
    excepted). With data: the notes (and the CHANGELOG block) are exactly what
    ``render-notes`` produces for ref, so stale notes fail the tag.
    """
    rows = parse_notes(notes.read_text(encoding="utf-8"))
    merged = merged_branches(repo, ref)
    by_wp = merged_wps(merged)
    errors = []
    seen = set()
    for row in rows:
        wp = row["wp"]
        if wp in seen:
            errors.append(f"{wp}: listed twice")
        seen.add(wp)
        if row["included"]:
            if not row["branch"]:
                errors.append(f"{wp}: marked Dahil without a merged branch")
            else:
                for b in row["branches"]:
                    if b not in merged:
                        errors.append(
                            f"{wp}: marked Dahil but branch {b} has no merge commit on {ref}"
                        )
        elif strict and wp in by_wp:
            errors.append(
                f"{wp}: marked 'Dahil değil' but {by_wp[wp]} is merged on {ref};"
                " update the release notes"
            )
    if strict:
        self_wps = set()
        if data is not None:
            self_wps = set(_load_notes_data(data).get("self", []))
        for wp, branch in sorted(by_wp.items(), key=lambda kv: _wp_key(kv[0])):
            if wp not in seen and wp not in self_wps:
                errors.append(
                    f"{wp}: {branch} is merged on {ref} but has no row in the"
                    " release notes; add it to the data file and re-render"
                )
    if data is not None:
        for path, want in render_notes(_load_notes_data(data), repo, ref).items():
            have = path.read_text(encoding="utf-8") if path.is_file() else ""
            if have != want:
                root = repo.resolve()
                rel = path.relative_to(root) if path.is_relative_to(root) else path
                errors.append(
                    f"{rel} is stale against {ref}; run: release_tool.py"
                    f" render-notes --data {data} --ref {ref} --write"
                )
    if errors:
        raise ReleaseError(
            "release notes disagree with git history:\n  " + "\n  ".join(errors)
        )
    return rows


# --- rendering the notes from the merge history + a WP table -----------------
#
# docs/release/<V>.json holds what git cannot know: every WP of the plan with
# its topic, highlights, upgrade notes and known issues, each guarded by
# ``when`` (all of these WPs merged) / ``unless`` (none of them merged). Which
# WPs are merged, with which branch, and which init SQL files exist come from
# ``git log --merges <ref>`` and ``git ls-tree <ref>``, so the notes are
# regenerated, not edited, at tag time.


def _wp_key(wp: str) -> tuple:
    m = re.match(r"^W(\d+)\.(\d+)([a-z]?)$", wp)
    if not m:
        return (1 << 30, wp)
    return (int(m.group(1)), int(m.group(2)), m.group(3))


def _load_notes_data(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ReleaseError(f"{path}: {exc}") from exc
    for key in ("notes", "template", "wps"):
        if key not in doc:
            raise ReleaseError(f"{path}: missing key {key!r}")
    ids = [w["id"] for w in doc["wps"]]
    bad = [i for i in ids if not WP_ID_RE.match(i)]
    if bad:
        raise ReleaseError(f"{path}: bad WP ids {bad}")
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise ReleaseError(f"{path}: WPs listed twice: {dup}")
    doc["_base"] = path.resolve().parent
    return doc


def _repo_path(repo: Path, rel: str) -> Path:
    return (repo / rel).resolve()


def init_sql_numbers(repo: Path, ref: str, start: int) -> list[int]:
    proc = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "--name-only", ref, "infra/database/init/"],
        capture_output=True,
        text=True,
        check=True,
    )
    nums = set()
    for line in proc.stdout.splitlines():
        m = re.match(r"^(\d+)_.*\.sql$", line.rsplit("/", 1)[-1])
        if m and int(m.group(1)) >= start:
            nums.add(int(m.group(1)))
    return sorted(nums)


def _ranges(nums: list[int]) -> str:
    if not nums:
        return "—"
    parts, lo, prev = [], nums[0], nums[0]
    for n in nums[1:] + [None]:
        if n is not None and n == prev + 1:
            prev = n
            continue
        parts.append(str(lo) if lo == prev else f"{lo}–{prev}")
        if n is not None:
            lo = prev = n
    return ", ".join(parts)


def _applies(item: dict, included: set[str]) -> bool:
    return all(w in included for w in item.get("when", [])) and not any(
        w in included for w in item.get("unless", [])
    )


def _bullets(items: list[dict], included: set[str], key: str = "text") -> str:
    lines = [f"- {i[key]}" for i in items if _applies(i, included)]
    return "\n".join(lines) if lines else "- —"


def _join_ids(ids: list[str]) -> str:
    return ", ".join(ids) if ids else "—"


def render_notes(data: dict, repo: Path, ref: str = "HEAD") -> dict[Path, str]:
    """{path: content} for the notes (and the CHANGELOG block when configured)."""
    merged = merged_branches(repo, ref)
    by_wp = merged_wps(merged)
    all_by_wp = merged_wp_branches(merged)
    rows, included = [], set()
    for wp in data["wps"]:
        if wp.get("branch"):
            branches = [wp["branch"]] if wp["branch"] in merged else []
        else:
            branches = all_by_wp.get(wp["id"], [])
        inc = bool(branches)
        if inc:
            included.add(wp["id"])
        cell = ", ".join(f"`{b}`" for b in branches) if inc else "—"
        rows.append(
            f"| {wp['id']} | {wp['topic']} | {'Dahil' if inc else 'Dahil değil'} | {cell} |"
        )
    self_ids = set(data.get("self", []))
    known = {w["id"] for w in data["wps"]} | self_ids
    missing = sorted((set(by_wp) - known), key=_wp_key)
    if missing:
        raise ReleaseError(
            "merged WPs missing from the data file: "
            + ", ".join(f"{w} ({by_wp[w]})" for w in missing)
        )
    open_issues, fixed_issues = [], []
    for issue in data.get("known_issues", []):
        if issue["wp"] not in included:
            continue
        fixer = issue.get("fixed_by")
        if fixer and fixer in included:
            fixed_issues.append(f"- {issue['wp']}: {issue['text']} ({fixer} ile giderildi)")
        else:
            note = f" {issue['open_note']}" if issue.get("open_note") else ""
            open_issues.append(f"- {issue['wp']}: {issue['text']}{note}")
    inc_sorted = sorted(included, key=_wp_key)
    not_inc = [w["id"] for w in data["wps"] if w["id"] not in included]
    en = {w["id"]: w.get("topic_en", w["topic"]) for w in data["wps"]}
    values = {
        "wp_table": "\n".join(
            ["| WP | Konu | Durum | Birleştirme |", "|---|---|---|---|", *rows]
        ),
        "highlights": _bullets(data.get("highlights", []), included),
        "upgrade_notes": _bullets(data.get("upgrade_notes", []), included),
        "known_issues": "\n".join(open_issues) if open_issues else "- —",
        "fixed_issues": "\n".join(fixed_issues) if fixed_issues else "- —",
        **{
            name: "\n".join(i["text"] for i in items if _applies(i, included))
            for name, items in data.get("sections", {}).items()
        },
        "init_sql": _ranges(
            init_sql_numbers(repo, ref, int(data.get("init_sql_from", 0)))
        ),
        "included_count": str(len(included)),
        "not_included_count": str(len(not_inc)),
        "included_ids": _join_ids(inc_sorted),
        "not_included_ids": _join_ids(not_inc),
        "included_en": "; ".join(f"{w} {en[w]}" for w in inc_sorted) or "—",
        "not_included_en": "; ".join(f"{w} {en[w]}" for w in not_inc) or "—",
    }

    def fill(template: str) -> str:
        def sub(m: re.Match) -> str:
            key = m.group(1)
            if key not in values:
                raise ReleaseError(f"unknown template field {{{{{key}}}}}")
            return values[key]

        return re.sub(r"\{\{(\w+)\}\}", sub, template)

    out: dict[Path, str] = {}
    tpl = (data["_base"] / data["template"]).read_text(encoding="utf-8")
    out[_repo_path(repo, data["notes"])] = fill(tpl)
    cl = data.get("changelog")
    if cl:
        path = _repo_path(repo, cl["file"])
        text = path.read_text(encoding="utf-8")
        begin, end = cl["begin"], cl["end"]
        if text.count(begin) != 1 or text.count(end) != 1 or text.index(begin) > text.index(end):
            raise ReleaseError(f"{cl['file']}: needs exactly one {begin} ... {end} block")
        block = fill((data["_base"] / cl["template"]).read_text(encoding="utf-8"))
        head, rest = text.split(begin, 1)
        _, tail = rest.split(end, 1)
        out[path] = f"{head}{begin}\n{block.rstrip()}\n{end}{tail}"
    return out


# --- tag safety --------------------------------------------------------------


def check_on_main(repo: Path, commit: str, main_ref: str) -> str:
    """The tagged commit must already be on main (an ancestor of main_ref)."""

    def rev(r: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", r + "^{commit}"],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise ReleaseError(f"cannot resolve {r!r}; fetch it first")
        return proc.stdout.strip()

    sha, main_sha = rev(commit), rev(main_ref)
    proc = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", sha, main_sha],
        capture_output=True,
        text=True,
    )
    if proc.returncode == 1:
        # In a shallow clone "not an ancestor" may just be missing history.
        require_full_history(repo, "check-on-main")
        raise ReleaseError(
            f"{commit} ({sha[:12]}) is not on {main_ref} ({main_sha[:12]}); release"
            " tags must point at a commit already merged to main"
        )
    if proc.returncode != 0:
        raise ReleaseError(f"git merge-base failed: {proc.stderr.strip()}")
    return sha


# --------------------------------------------------------------------------- SBOM


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


LOCK_LINE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(?P<version>[^\s;\\]+)"
    r"\s*(?:;\s*(?P<marker>[^\\#]+?))?\s*(?:\\)?\s*(?:#.*)?$"
)


def python_components(lock: Path) -> list[dict]:
    comps: dict[str, dict] = {}
    for raw in lock.read_text(encoding="utf-8").splitlines():
        if not raw or raw[0] in " \t#-":
            continue  # comments, "# via" lines, hash continuations, -r/-e options
        m = LOCK_LINE_RE.match(raw.strip())
        if not m:
            raise ReleaseError(f"{lock}: cannot parse lock line {raw!r}")
        name = _pep503(m.group("name"))
        version = m.group("version")
        purl = f"pkg:pypi/{name}@{quote(version, safe='.+!')}"
        comp = comps.setdefault(
            purl,
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
            },
        )
        marker = (m.group("marker") or "").strip()
        if marker:
            props = comp.setdefault("properties", [])
            props.append({"name": "autosecops:python-marker", "value": marker})
    return [comps[k] for k in sorted(comps)]


def npm_purl(name: str, version: str) -> str:
    """pkg:npm purl; the @ of a scope is percent-encoded (%40scope/name)."""
    return f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='.+-')}"


def _npm_name(key: str, entry: dict) -> Optional[str]:
    if entry.get("name"):
        return str(entry["name"])
    idx = key.rfind("node_modules/")
    if idx < 0:
        return None
    return key[idx + len("node_modules/") :]


def _integrity_hashes(integrity: str) -> list[dict]:
    algs = {
        "sha512": "SHA-512",
        "sha384": "SHA-384",
        "sha256": "SHA-256",
        "sha1": "SHA-1",
    }
    out = []
    for part in integrity.split():
        alg, _, b64 = part.partition("-")
        if alg in algs and b64:
            try:
                out.append({"alg": algs[alg], "content": base64.b64decode(b64).hex()})
            except ValueError:
                continue
    return out


def npm_components(lock: Path, omit_dev: bool = False) -> list[dict]:
    doc = json.loads(lock.read_text(encoding="utf-8"))
    if doc.get("lockfileVersion", 1) < 2 or "packages" not in doc:
        raise ReleaseError(f"{lock}: need lockfileVersion 2 or 3 (a 'packages' map)")
    comps: dict[str, dict] = {}
    for key, entry in sorted(doc["packages"].items()):
        if key == "" or entry.get("link") or not entry.get("version"):
            continue
        dev = bool(entry.get("dev") or entry.get("devOptional"))
        if omit_dev and dev:
            continue
        name = _npm_name(key, entry)
        if not name:
            continue
        version = str(entry["version"])
        purl = npm_purl(name, version)
        if purl in comps:
            if not dev:
                comps[purl].pop("scope", None)  # required somewhere → required
            continue
        comp: dict = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
        }
        if dev:
            comp["scope"] = "excluded"
        hashes = _integrity_hashes(str(entry.get("integrity", "")))
        if hashes:
            comp["hashes"] = hashes
        lic = entry.get("license")
        if isinstance(lic, str) and lic:
            comp["licenses"] = [{"license": {"name": lic}}]
        if entry.get("resolved"):
            comp["externalReferences"] = [
                {"type": "distribution", "url": str(entry["resolved"])}
            ]
        comps[purl] = comp
    return [comps[k] for k in sorted(comps)]


def build_bom(
    components: list[dict], name: str, version: str, source: Path, repo: Path = REPO
) -> dict:
    try:
        rel = str(source.resolve().relative_to(repo.resolve()))
    except ValueError:
        rel = source.name
    digest = _sha256_file(source)
    root_ref = f"pkg:generic/{name}@{version}"
    metadata: dict = {
        "tools": {
            "components": [
                {"type": "application", "name": TOOL_NAME, "version": version}
            ]
        },
        "component": {
            "type": "application",
            "bom-ref": root_ref,
            "name": name,
            "version": version,
            "purl": root_ref,
            "supplier": {"name": "AutoSecOps"},
        },
        "properties": [
            {"name": "autosecops:lockfile", "value": rel},
            {"name": "autosecops:lockfile-sha256", "value": digest},
        ],
    }
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        import datetime as _dt

        metadata["timestamp"] = _dt.datetime.fromtimestamp(
            int(epoch), _dt.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = uuid.uuid5(SERIAL_NS, f"{name}@{version}:{rel}:{digest}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": [c["bom-ref"] for c in components]}
        ],
    }


def write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_bom(doc: dict) -> int:
    """Structural CycloneDX check; returns the component count."""
    errs = []
    if doc.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat != CycloneDX")
    if doc.get("specVersion") not in ("1.4", "1.5", "1.6"):
        errs.append(f"unsupported specVersion {doc.get('specVersion')!r}")
    if not re.match(r"^urn:uuid:[0-9a-f-]{36}$", str(doc.get("serialNumber", ""))):
        errs.append("serialNumber is not urn:uuid")
    meta = doc.get("metadata") or {}
    if not (meta.get("component") or {}).get("name"):
        errs.append("metadata.component.name missing")
    comps = doc.get("components")
    if not isinstance(comps, list) or not comps:
        errs.append("no components")
        comps = []
    refs = set()
    for i, c in enumerate(comps):
        for key in ("type", "name"):
            if not c.get(key):
                errs.append(f"components[{i}].{key} missing")
        ref = c.get("bom-ref")
        if ref:
            if ref in refs:
                errs.append(f"duplicate bom-ref {ref}")
            refs.add(ref)
        purl = c.get("purl")
        if purl is not None and not str(purl).startswith("pkg:"):
            errs.append(f"components[{i}].purl not a purl: {purl!r}")
    root = (meta.get("component") or {}).get("bom-ref")
    for dep in doc.get("dependencies") or []:
        for r in dep.get("dependsOn", []):
            if r not in refs and r != root:
                errs.append(f"dependency on unknown ref {r}")
    if errs:
        raise ReleaseError("invalid CycloneDX: " + "; ".join(errs[:10]))
    return len(comps)


def build_lockfile_sboms(out: Path, version: str, repo: Path = REPO) -> list[Path]:
    written = []
    for suffix, kind, rel, name in LOCKFILES:
        lock = repo / rel
        if not lock.is_file():
            raise ReleaseError(f"missing lockfile {rel}")
        comps = python_components(lock) if kind == "python" else npm_components(lock)
        bom = build_bom(comps, name, version, lock, repo)
        validate_bom(bom)
        path = out / f"autosecops-{version}-{suffix}.cdx.json"
        write_json(path, bom)
        written.append(path)
    return written


# --------------------------------------------------------------------------- provenance


def provenance_predicate(subject_name: str, subject_digest: str, env: dict) -> dict:
    """SLSA v1 provenance predicate for a GitHub Actions build of one subject."""
    if not re.match(r"^sha256:[0-9a-f]{64}$", subject_digest):
        raise ReleaseError(
            f"subject digest must be sha256:<64 hex>, got {subject_digest!r}"
        )
    need = (
        "GITHUB_SERVER_URL",
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    )
    missing = [k for k in need if not env.get(k)]
    if missing:
        raise ReleaseError("provenance needs GitHub env: " + ", ".join(missing))
    server, repo = env["GITHUB_SERVER_URL"], env["GITHUB_REPOSITORY"]
    wf_ref = env[
        "GITHUB_WORKFLOW_REF"
    ]  # owner/repo/.github/workflows/x.yml@refs/tags/v…
    wf_path = (
        wf_ref.split("@", 1)[0][len(repo) + 1 :]
        if wf_ref.startswith(repo + "/")
        else wf_ref
    )
    return {
        "buildDefinition": {
            "buildType": "https://actions.github.io/buildtypes/workflow/v1",
            "externalParameters": {
                "workflow": {
                    "ref": env["GITHUB_REF"],
                    "repository": f"{server}/{repo}",
                    "path": wf_path,
                }
            },
            "internalParameters": {
                "github": {
                    "event_name": env.get("GITHUB_EVENT_NAME", ""),
                    "repository_id": env.get("GITHUB_REPOSITORY_ID", ""),
                    "repository_owner_id": env.get("GITHUB_REPOSITORY_OWNER_ID", ""),
                    "runner_environment": env.get("RUNNER_ENVIRONMENT", ""),
                }
            },
            "resolvedDependencies": [
                {
                    "uri": f"git+{server}/{repo}@{env['GITHUB_REF']}",
                    "digest": {"gitCommit": env["GITHUB_SHA"]},
                }
            ],
        },
        "runDetails": {
            "builder": {"id": f"{server}/{wf_ref}"},
            "metadata": {
                "invocationId": (
                    f"{server}/{repo}/actions/runs/{env['GITHUB_RUN_ID']}"
                    f"/attempts/{env['GITHUB_RUN_ATTEMPT']}"
                )
            },
            "byproducts": [
                {
                    "name": subject_name,
                    "digest": {"sha256": subject_digest.split(":", 1)[1]},
                }
            ],
        },
    }


# --------------------------------------------------------------------------- images

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMPONENTS = ("backend", "daemon", "agent")


def _platform_entries(index: dict) -> list[dict]:
    out = []
    for m in index.get("manifests") or []:
        plat = m.get("platform") or {}
        os_, arch = plat.get("os"), plat.get("architecture")
        if not os_ or not arch or os_ == "unknown" or arch == "unknown":
            continue  # attestation manifests and the like
        digest = m.get("digest", "")
        if not DIGEST_RE.match(digest):
            raise ReleaseError(f"bad platform digest {digest!r}")
        variant = plat.get("variant")
        out.append(
            {
                "platform": f"{os_}/{arch}" + (f"/{variant}" if variant else ""),
                "arch": arch,
                "variant": variant,
                "digest": digest,
            }
        )
    archs = [e["arch"] for e in out]
    for e in out:
        if archs.count(e["arch"]) > 1 and e["variant"]:
            e["arch"] = f"{e['arch']}-{e['variant']}"
    for e in out:
        e.pop("variant")
    if not out:
        raise ReleaseError("image index lists no platform manifests")
    return sorted(out, key=lambda e: e["platform"])


def _hashes_to(raw: bytes, digest: str) -> bool:
    return any(
        "sha256:" + hashlib.sha256(c).hexdigest() == digest
        for c in (raw, raw.rstrip(b"\n"))
    )


def _config_digest(digests: Path, comp: str, manifest_digest: str) -> str:
    """Config digest (= `docker image inspect` Id) of one platform manifest.

    It survives `docker save` / `docker load`, unlike the manifest digest, so an
    air-gapped site can tie a loaded image back to the signed images.json.
    """
    path = digests / f"{comp}.{manifest_digest.split(':', 1)[1]}.json"
    if not path.is_file():
        raise ReleaseError(f"{comp}: platform manifest {path.name} missing")
    raw = path.read_bytes()
    if not _hashes_to(raw, manifest_digest):
        raise ReleaseError(f"{comp}: {path.name} does not hash to {manifest_digest}")
    cfg = (json.loads(raw).get("config") or {}).get("digest", "")
    if not DIGEST_RE.match(cfg):
        raise ReleaseError(f"{comp}: platform manifest has no sha256 config digest")
    return cfg


def images_manifest(version: str, prefix: str, digests: Path) -> dict:
    """images.json from the build job's digests/<c> and digests/<c>.index.json."""
    images = []
    for comp in COMPONENTS:
        digest = (digests / comp).read_text(encoding="utf-8").strip()
        if not DIGEST_RE.match(digest):
            raise ReleaseError(f"{comp}: bad index digest {digest!r}")
        raw = (digests / f"{comp}.index.json").read_bytes()
        if not _hashes_to(raw, digest):
            raise ReleaseError(f"{comp}: index JSON does not hash to {digest}")
        platforms = _platform_entries(json.loads(raw))
        for plat in platforms:
            plat["config_digest"] = _config_digest(digests, comp, plat["digest"])
        images.append(
            {
                "component": comp,
                "repository": f"{prefix}-{comp}",
                "tag": version,
                "index_digest": digest,
                "platforms": platforms,
            }
        )
    return {
        "schema": "autosecops.release-images/v1",
        "version": version,
        "images": images,
    }


def image_rows(doc: dict, index: bool) -> list[tuple[str, str, str]]:
    rows = []
    for img in doc["images"]:
        repo = img["repository"]
        if index:
            rows.append((img["component"], "index", f"{repo}@{img['index_digest']}"))
        else:
            for p in img["platforms"]:
                rows.append((img["component"], p["arch"], f"{repo}@{p['digest']}"))
    return rows


# --------------------------------------------------------------------------- checksums


def write_checksums(directory: Path, out_name: str = "SHA256SUMS") -> Path:
    lines = []
    for path in sorted(p for p in directory.iterdir() if p.is_file()):
        if path.name == out_name or path.name.startswith(out_name + "."):
            continue
        lines.append(f"{_sha256_file(path)}  {path.name}")
    if not lines:
        raise ReleaseError(f"{directory}: nothing to checksum")
    out = directory / out_name
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


# --------------------------------------------------------------------------- CLI


def _emit(pairs: Iterable[tuple[str, str]], github_output: Optional[str]) -> None:
    text = "".join(f"{k}={v}\n" for k, v in pairs)
    sys.stdout.write(text)
    if github_output:
        with open(github_output, "a", encoding="utf-8") as fh:
            fh.write(text)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument(
        "--repo", default=str(REPO), help="repository root (default: this checkout)"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("check-tag")
    s.add_argument("--tag", required=True)
    s.add_argument("--github-output")

    sub.add_parser("check-versions")

    s = sub.add_parser("check-notes")
    s.add_argument("--notes", required=True)
    s.add_argument("--ref", default="HEAD")
    s.add_argument("--strict", action="store_true")
    s.add_argument(
        "--data", help="WP data file; the notes must equal render-notes output"
    )

    s = sub.add_parser("render-notes")
    s.add_argument("--data", required=True)
    s.add_argument("--ref", default="HEAD")
    s.add_argument("--write", action="store_true", help="write instead of print")

    s = sub.add_parser("check-on-main")
    s.add_argument("--commit", required=True)
    s.add_argument("--main", default="origin/main")

    for name in ("sbom-python", "sbom-npm"):
        s = sub.add_parser(name)
        s.add_argument("--lock", required=True)
        s.add_argument("--name", required=True)
        s.add_argument("--version")
        s.add_argument("--out", required=True)
        if name == "sbom-npm":
            s.add_argument("--omit-dev", action="store_true")

    s = sub.add_parser("sboms")
    s.add_argument("--out", required=True)
    s.add_argument("--version")

    s = sub.add_parser("validate-sbom")
    s.add_argument("files", nargs="+")

    s = sub.add_parser("provenance")
    s.add_argument("--subject-name", required=True)
    s.add_argument("--subject-digest", required=True)
    s.add_argument("--out", required=True)

    s = sub.add_parser("images-manifest")
    s.add_argument("--version", required=True)
    s.add_argument("--prefix", required=True)
    s.add_argument("--digests", required=True)
    s.add_argument("--out", required=True)

    s = sub.add_parser("image-refs")
    s.add_argument("--images", required=True)
    s.add_argument("--index", action="store_true")

    s = sub.add_parser("checksums")
    s.add_argument("--dir", required=True)
    s.add_argument("--name", default="SHA256SUMS")

    a = p.parse_args(argv)
    repo = Path(a.repo)
    try:
        if a.cmd == "check-tag":
            version, pre = parse_tag(a.tag, read_version(repo))
            _emit(
                [("version", version), ("prerelease", str(pre).lower())],
                a.github_output,
            )
        elif a.cmd == "check-versions":
            print(f"versions ok: {check_versions(repo)}")
        elif a.cmd == "check-notes":
            rows = check_notes(
                Path(a.notes),
                repo,
                a.ref,
                a.strict,
                Path(a.data) if a.data else None,
            )
            inc = sum(r["included"] for r in rows)
            print(f"notes ok: {inc} included, {len(rows) - inc} not included")
        elif a.cmd == "render-notes":
            rendered = render_notes(_load_notes_data(Path(a.data)), repo, a.ref)
            for path, text in rendered.items():
                if a.write:
                    path.write_text(text, encoding="utf-8")
                    print(f"wrote {path}")
                else:
                    sys.stdout.write(text)
        elif a.cmd == "check-on-main":
            sha = check_on_main(repo, a.commit, a.main)
            print(f"on main: {sha}")
        elif a.cmd in ("sbom-python", "sbom-npm"):
            lock = Path(a.lock)
            version = a.version or read_version(repo)
            comps = (
                python_components(lock)
                if a.cmd == "sbom-python"
                else npm_components(lock, a.omit_dev)
            )
            bom = build_bom(comps, a.name, version, lock, repo)
            validate_bom(bom)
            write_json(Path(a.out), bom)
            print(f"{a.out}: {len(comps)} components")
        elif a.cmd == "sboms":
            version = a.version or read_version(repo)
            for path in build_lockfile_sboms(Path(a.out), version, repo):
                n = len(json.loads(path.read_text(encoding="utf-8"))["components"])
                print(f"{path.name}: {n} components")
        elif a.cmd == "validate-sbom":
            for f in a.files:
                n = validate_bom(json.loads(Path(f).read_text(encoding="utf-8")))
                print(f"{f}: valid CycloneDX, {n} components")
        elif a.cmd == "provenance":
            pred = provenance_predicate(
                a.subject_name, a.subject_digest, dict(os.environ)
            )
            write_json(Path(a.out), pred)
            print(a.out)
        elif a.cmd == "images-manifest":
            doc = images_manifest(a.version, a.prefix, Path(a.digests))
            out = Path(a.out)
            write_json(out, doc)
            # Same rows as TSV, so verify-release.sh needs no JSON parser.
            rows = image_rows(doc, True) + image_rows(doc, False)
            out.with_suffix(".tsv").write_text(
                "".join("\t".join(r) + "\n" for r in rows), encoding="utf-8"
            )
            print(out)
        elif a.cmd == "image-refs":
            doc = json.loads(Path(a.images).read_text(encoding="utf-8"))
            for row in image_rows(doc, a.index):
                print("\t".join(row))
        elif a.cmd == "checksums":
            print(write_checksums(Path(a.dir), a.name))
    except ReleaseError as exc:
        print(f"release_tool: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
