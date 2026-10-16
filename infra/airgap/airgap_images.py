#!/usr/bin/env python3
"""Enumerate the container images an air-gapped AutoSecOps install needs.

Reads the Helm chart's values (infra/helm/vigil/values.yaml, with
infra/airgap/values-airgap.yaml merged on top to decide what is *enabled*), the
Compose file (services in the default profile plus the selected ones) and the
in-cluster LLM stack manifest (Bifrost + Ollama). Nothing is pulled: this is a
static parse, so it runs offline and is what ``build-bundle.sh --dry-run`` prints.

Image references are taken from the chart's *upstream* values, not from the
air-gap overlay, because those are what a build machine pulls. The overlay
points the chart at a local registry; ``localize`` is the mapping between the
two, and the tests check the overlay renders exactly ``localize(upstream)``.

Usage:
  airgap_images.py list --version V [--repo DIR] [--format tsv|json]
                        [--image-registry R] [--image-namespace N]
                        [--compose-profiles daemon,...] [--ollama-image REF]
  airgap_images.py rules [--repo DIR]
  airgap_images.py localize --registry R REF [REF...]

Needs PyYAML (the build machine has the repo's venv). The installer does not
use this file: it only needs bash, sha256sum and openssl.
"""

from __future__ import annotations

import argparse
import ast
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml

HERE = Path(__file__).resolve().parent
DEFAULT_REPO = HERE.parent.parent

CHART_REL = Path("infra/helm/vigil")
COMPOSE_REL = Path("infra/docker/docker-compose.yml")
OVERLAY_REL = Path("infra/airgap/values-airgap.yaml")
LLM_STACK_REL = Path("infra/airgap/k8s/llm-stack.yaml")
RULES_SERVICE_REL = Path("core/detections/detection_rules_service.py")

# The placeholder registry values-airgap.yaml and llm-stack.yaml are written
# against; install.sh replaces it with the operator's --registry.
PLACEHOLDER_REGISTRY = "registry.airgap.local:5000"

DEFAULT_COMPOSE_PROFILES = ("daemon",)

# Chart components rendered through "vigil.image" / "vigil.medic.image": the
# repository is <registry>/<namespace>-<suffix> when values leave it empty.
# (values path, image suffix, enabled path or None when always rendered)
APP_COMPONENTS = (
    (("backend",), "backend", None),
    (("daemon",), "daemon", ("daemon", "enabled")),
    (("llmWorker",), "backend", ("llmWorker", "enabled")),
    (("agentWorker",), "agent", ("agentWorker", "enabled")),
    (("agentServe",), "agent", ("agentServe", "enabled")),
    (("medic",), "medic", ("medic", "enabled")),
    (("medic", "gateway"), "medic-gateway", ("medic", "enabled")),
)

# Third-party images the chart renders as "<repository>:<tag>".
# (values path, enabled predicate)
THIRD_PARTY = (
    (("postgresql",), "postgres"),
    (("redis",), "redis"),
    (("dbInit",), ("dbInit", "enabled")),
    (("tests",), None),
    (("splunk",), ("splunk", "enabled")),
    (("pgadmin",), ("pgadmin", "enabled")),
)

# Compose builds these locally (image: vigil-*:local or no image at all); a
# release publishes the same Dockerfile as <registry>/<namespace>-<suffix>.
DOCKERFILE_SUFFIX = {
    "Dockerfile.backend": "backend",
    "Dockerfile.daemon": "daemon",
    "Dockerfile.agent": "agent",
    "Dockerfile.medic": "medic",
    "Dockerfile.medic-gateway": "medic-gateway",
    "Dockerfile.medic-dockerproxy": "medic-dockerproxy",
}

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}")


def deep_merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    """Helm's values merge: maps merge recursively, anything else replaces."""
    out = copy.deepcopy(base)
    for key, value in (over or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def dig(data: Any, path: Iterable[str], default: Any = None) -> Any:
    for key in path:
        if not isinstance(data, dict) or key not in data:
            return default
        data = data[key]
    return data


def split_digest(ref: str) -> tuple:
    """``name:tag@sha256:…`` -> (``name:tag``, ``sha256:…``); no digest -> (ref, None).

    The bundle pulls the pinned digest and stores the image under its tag: the
    local registry gets the tag (a pushed single-platform image has a different
    digest than the multi-platform index that was pinned).
    """
    name, sep, digest = ref.partition("@")
    return (name, digest) if sep else (ref, None)


def localize(ref: str, registry: str) -> str:
    """Map an upstream reference to its place in the local registry.

    The first path component is dropped when it names a registry host (contains
    "." or ":" or is "localhost"); a single-component Docker Hub name gets
    "library/". ``ghcr.io/a/b:t`` -> ``R/a/b:t``; ``postgres:16`` -> ``R/library/postgres:16``.
    install.sh carries the same rule in bash.
    """
    first, sep, rest = ref.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        path = rest
    else:
        path = ref
    if "/" not in path:
        path = "library/" + path
    return f"{registry.rstrip('/')}/{path}"


def expand_compose_vars(value: str) -> str:
    """${VAR:-default} / ${VAR-default} -> default; a bare ${VAR} -> ''."""
    return _VAR.sub(lambda m: m.group(2) or "", value)


def _image(registry: str, namespace: str, suffix: str, tag: str) -> str:
    return f"{registry}/{namespace}-{suffix}:{tag}"


class Enumerator:
    def __init__(
        self,
        repo: Path,
        version: str,
        image_registry: Optional[str] = None,
        image_namespace: Optional[str] = None,
        compose_profiles: Iterable[str] = DEFAULT_COMPOSE_PROFILES,
        ollama_image: Optional[str] = None,
    ) -> None:
        self.repo = Path(repo)
        self.version = version
        chart = self.repo / CHART_REL
        self.upstream = yaml.safe_load((chart / "values.yaml").read_text()) or {}
        overlay_path = self.repo / OVERLAY_REL
        overlay = (
            yaml.safe_load(overlay_path.read_text()) if overlay_path.exists() else {}
        )
        # What is enabled is decided by the merged values; what is pulled comes
        # from the upstream ones.
        self.merged = deep_merge(self.upstream, overlay or {})
        g = self.upstream.get("global") or {}
        self.registry = image_registry or g.get("imageRegistry") or "ghcr.io"
        self.namespace = image_namespace or g.get("imageNamespace") or "singularityrd/autosecops"
        self.compose_profiles = {p for p in compose_profiles if p}
        self.ollama_image = ollama_image
        self.images: Dict[str, Dict[str, Any]] = {}

    # -- collection --------------------------------------------------------
    def _add(self, ref: str, source: str) -> None:
        ref, digest = split_digest(ref)
        entry = self.images.setdefault(ref, {"ref": ref, "sources": []})
        if digest:
            if entry.setdefault("digest", digest) != digest:
                raise SystemExit(
                    f"{ref}: {source} pins {digest}, another source {entry['digest']}"
                )
        if source not in entry["sources"]:
            entry["sources"].append(source)

    def _enabled(self, path: Optional[tuple]) -> bool:
        if path is None:
            return True
        value = dig(self.merged, path, False)
        return str(value).lower() == "true"

    def chart(self) -> None:
        for path, suffix, enabled in APP_COMPONENTS:
            if not self._enabled(enabled):
                continue
            img = dig(self.upstream, path + ("image",), {}) or {}
            repo = img.get("repository") or ""
            tag = str(img.get("tag") or "") or self.version
            if not repo and path == ("llmWorker",):
                backend = dig(self.upstream, ("backend", "image"), {}) or {}
                repo = backend.get("repository") or ""
                tag = str(img.get("tag") or backend.get("tag") or "") or self.version
            ref = (
                f"{repo}:{tag}"
                if repo
                else _image(self.registry, self.namespace, suffix, tag)
            )
            self._add(ref, "helm:" + ".".join(path))
        for path, enabled in THIRD_PARTY:
            if enabled == "postgres":
                on = self._enabled(("postgresql", "enabled")) and not self._enabled(
                    ("postgresql", "bitnami", "enabled")
                )
            elif enabled == "redis":
                on = self._enabled(("redis", "enabled")) and not self._enabled(
                    ("redis", "bitnami", "enabled")
                )
            else:
                on = self._enabled(enabled)
            if not on:
                continue
            img = dig(self.upstream, path + ("image",), {}) or {}
            if not img.get("repository") or not img.get("tag"):
                raise SystemExit(
                    f"values.yaml: {'.'.join(path)}.image has no repository/tag"
                )
            self._add(f"{img['repository']}:{img['tag']}", "helm:" + ".".join(path))
        for flag in (
            ("otelCollector", "enabled"),
            ("postgresql", "bitnami", "enabled"),
            ("redis", "bitnami", "enabled"),
        ):
            if self._enabled(flag):
                raise SystemExit(
                    f"{'.'.join(flag)} is on: its subchart images are not enumerated "
                    "and the air-gap chart is packaged without subcharts"
                )

    def compose(self) -> None:
        data = yaml.safe_load((self.repo / COMPOSE_REL).read_text()) or {}
        for name, svc in (data.get("services") or {}).items():
            profiles = set(svc.get("profiles") or [])
            if profiles and not profiles & self.compose_profiles:
                continue
            build = svc.get("build")
            image = svc.get("image")
            if build is not None:
                dockerfile = (
                    build.get("dockerfile", "Dockerfile")
                    if isinstance(build, dict)
                    else "Dockerfile"
                )
                suffix = DOCKERFILE_SUFFIX.get(Path(dockerfile).name)
                if suffix is None:
                    raise SystemExit(
                        f"compose service {name}: unknown Dockerfile {dockerfile}"
                    )
                self._add(
                    _image(self.registry, self.namespace, suffix, self.version),
                    f"compose:{name}",
                )
            elif image:
                self._add(expand_compose_vars(str(image)), f"compose:{name}")

    def llm_stack(self) -> None:
        path = self.repo / LLM_STACK_REL
        for doc in yaml.safe_load_all(path.read_text()):
            for ref in _images_in(doc):
                if self.ollama_image and ref.split(":")[0].endswith("ollama/ollama"):
                    ref = self.ollama_image
                self._add(ref, "llm-stack:" + ref.split("/")[-1].split(":")[0])

    def run(self) -> List[Dict[str, Any]]:
        self.chart()
        self.compose()
        self.llm_stack()
        out = []
        for ref in sorted(self.images):
            entry = self.images[ref]
            entry["local_path"] = localize(ref, "").lstrip("/")
            entry["file"] = "images/" + archive_name(ref)
            out.append(entry)
        return out


def _images_in(node: Any) -> List[str]:
    found: List[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "image" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_images_in(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_images_in(item))
    return found


def rule_clone_names(repo: Path) -> List[str]:
    """clone_name of every DEFAULT_SOURCES entry DetectionRulesService seeds.

    Parsed (not imported) so the build machine needs no app dependencies, and so
    the bundle snapshots exactly the directories the service looks for under
    ~/security-detections.
    """
    tree = ast.parse((Path(repo) / RULES_SERVICE_REL).read_text())
    for node in tree.body:
        targets = [
            t.id for t in getattr(node, "targets", []) if isinstance(t, ast.Name)
        ]
        if "DEFAULT_SOURCES" in targets:
            sources = ast.literal_eval(node.value)
            return [s["clone_name"] for s in sources if s.get("type") == "git"]
    raise SystemExit(f"{RULES_SERVICE_REL}: DEFAULT_SOURCES not found")


def archive_name(ref: str) -> str:
    """A stable, filesystem-safe archive name for a reference."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", ref) + ".tar"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list", help="enumerate images (no network)")
    ls.add_argument("--version", required=True)
    ls.add_argument("--repo", default=str(DEFAULT_REPO))
    ls.add_argument("--format", choices=("tsv", "json"), default="tsv")
    ls.add_argument("--image-registry")
    ls.add_argument("--image-namespace")
    ls.add_argument("--compose-profiles", default=",".join(DEFAULT_COMPOSE_PROFILES))
    ls.add_argument("--ollama-image")
    rules = sub.add_parser("rules", help="rule-corpus clone names (one per line)")
    rules.add_argument("--repo", default=str(DEFAULT_REPO))
    loc = sub.add_parser("localize", help="map references to a local registry")
    loc.add_argument("--registry", required=True)
    loc.add_argument("refs", nargs="+")
    args = parser.parse_args(argv)

    if args.cmd == "rules":
        print("\n".join(rule_clone_names(Path(args.repo))))
        return 0
    if args.cmd == "localize":
        for ref in args.refs:
            print(localize(ref, args.registry))
        return 0

    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]*", args.version):
        parser.error(f"bad --version {args.version!r}")
    images = Enumerator(
        Path(args.repo),
        args.version,
        image_registry=args.image_registry,
        image_namespace=args.image_namespace,
        compose_profiles=args.compose_profiles.split(","),
        ollama_image=args.ollama_image,
    ).run()
    if args.format == "json":
        json.dump(images, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for entry in images:
            print(
                f"{entry['ref']}\t{entry['file']}\t{','.join(entry['sources'])}"
                f"\t{entry.get('digest') or ''}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
