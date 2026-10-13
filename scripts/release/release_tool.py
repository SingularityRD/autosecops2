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
  check-notes     release notes: every "Dahil" WP really was merged
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

MERGE_RE = re.compile(r"^Merge (?:branch )?'?(?P<branch>[\w./-]+)'?")


def merged_branches(repo: Path, ref: str = "HEAD") -> set[str]:
    """Branch names of every merge commit reachable from ref."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "log", "--merges", "--format=%s", ref],
        capture_output=True,
        text=True,
        check=True,
    )
    out = set()
    for line in proc.stdout.splitlines():
        m = MERGE_RE.match(line.strip())
        if m:
            out.add(m.group("branch"))
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
        branch = cells[3].strip("` ")
        rows.append(
            {
                "wp": cells[0],
                "included": status == "Dahil",
                "branch": None if branch in ("", "—", "-") else branch,
            }
        )
    if not rows:
        raise ReleaseError("no WP table rows found in release notes")
    return rows


def check_notes(
    notes: Path, repo: Path, ref: str = "HEAD", strict: bool = False
) -> list[dict]:
    rows = parse_notes(notes.read_text(encoding="utf-8"))
    merged = merged_branches(repo, ref)
    errors = []
    seen = set()
    for row in rows:
        wp = row["wp"]
        if wp in seen:
            errors.append(f"{wp}: listed twice")
        seen.add(wp)
        wp_prefix = f"wp/{wp.lower()}-"
        wp_merged = any(b.startswith(wp_prefix) for b in merged)
        if row["included"]:
            if not row["branch"]:
                errors.append(f"{wp}: marked Dahil without a merged branch")
            elif row["branch"] not in merged:
                errors.append(
                    f"{wp}: marked Dahil but branch {row['branch']} has no merge commit on {ref}"
                )
        elif strict and wp_merged:
            errors.append(
                f"{wp}: marked 'Dahil değil' but a wp/{wp.lower()}-* branch is merged on {ref};"
                " update the release notes"
            )
    if errors:
        raise ReleaseError(
            "release notes disagree with git history:\n  " + "\n  ".join(errors)
        )
    return rows


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
            rows = check_notes(Path(a.notes), repo, a.ref, a.strict)
            inc = sum(r["included"] for r in rows)
            print(f"notes ok: {inc} included, {len(rows) - inc} not included")
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
