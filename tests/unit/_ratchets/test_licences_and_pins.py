"""Licence files travel with every distribution; third-party pins stay pinned (W0.38).

Apache-2.0 section 4: LICENSE and NOTICE go with every copy we distribute (the
images, the air-gap bundle, the support tool and the desktop app are tested
where they are built). Redis stays on the BSD 7.2 line, pinned by digest;
Node is the LTS line, pinned by digest; CI runners are pinned images.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
DOCKER = REPO / "infra" / "docker"
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))

REDIS = "redis:7.2.16-alpine@sha256:29e8589c3f9ba699b5f7aa4b3c7733c58852a3626439e619aa0ee78de08c6ca0"
NODE = re.compile(r"^node:22\.\d+\.\d+-bookworm-slim@sha256:[0-9a-f]{64}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")


def test_licence_names_both_copyright_holders_and_no_template() -> None:
    text = (REPO / "LICENSE").read_text(encoding="utf-8")
    assert "[yyyy]" not in text and "[name of copyright owner]" not in text
    assert "Copyright 2026 SingularityRD" in text
    assert "The Vigil-SOC authors" in text
    assert text.lstrip().startswith("Apache License")


def test_notice_attributes_upstream_and_third_parties() -> None:
    text = (REPO / "NOTICE").read_text(encoding="utf-8")
    for needle in (
        "Copyright 2026 SingularityRD",
        "based on Vigil (Apache-2.0)",
        "https://github.com/Vigil-SOC/vigil",
        "modified version of Vigil",  # section 4(b)
        "has modified files",
        "THIRD_PARTY_LICENSES",
        "Built with Llama.",
        "Llama 3.1 Community License",
        "llama.meta.com/llama3_1/use-policy",
        "Detection Rule License (DRL) 1.1",
        "Elastic License 2.0",
        "BSD-3-Clause",
    ):
        assert needle in text, needle


def _final_stage(dockerfile: Path) -> str:
    text = dockerfile.read_text(encoding="utf-8")
    return re.split(r"^FROM ", text, flags=re.M)[-1]


@pytest.mark.parametrize(
    "dockerfile", sorted(DOCKER.glob("Dockerfile.*")), ids=lambda p: p.name
)
def test_every_image_ships_the_licence_files(dockerfile: Path) -> None:
    assert "COPY LICENSE NOTICE THIRD_PARTY_LICENSES /licenses/" in _final_stage(
        dockerfile
    )


def test_build_context_keeps_the_licence_files() -> None:
    lines = (REPO / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES"):
        assert f"!{name}" in lines, name
        assert name not in lines, f"{name} excluded from the build context"


def _redis_refs() -> dict[str, str]:
    refs = {}
    for rel in (
        "infra/docker/docker-compose.yml",
        "clients/desktop/standalone/docker-compose.yml",
    ):
        services = yaml.safe_load((REPO / rel).read_text(encoding="utf-8"))["services"]
        refs[rel] = services["redis"]["image"]
    img = yaml.safe_load(
        (REPO / "infra/helm/vigil/values.yaml").read_text(encoding="utf-8")
    )["redis"]["image"]
    refs["helm values.yaml"] = f"{img['repository']}:{img['tag']}"
    for wf in WORKFLOWS:
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = re.match(r"^\s*image:\s*(redis\S*)", line)
            if m:
                refs[f"{wf.name}:{n}"] = m.group(1)
    return refs


def test_redis_is_the_bsd_line_pinned_by_digest_everywhere() -> None:
    refs = _redis_refs()
    assert len(refs) >= 6, refs
    wrong = {k: v for k, v in refs.items() if v != REDIS}
    assert not wrong, f"every Redis must be {REDIS}: {wrong}"
    # 7.4 and later are RSALv2/SSPL; 7.2 is the last BSD-3-Clause line.
    assert re.match(r"^redis:7\.2\.\d+-alpine@", REDIS)


@pytest.mark.parametrize(
    "dockerfile", sorted(DOCKER.glob("Dockerfile.*")), ids=lambda p: p.name
)
def test_node_base_images_are_the_lts_line_pinned_by_digest(dockerfile: Path) -> None:
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^FROM (?:--platform=\S+ )?(node\S*)", line)
        if m:
            assert NODE.match(m.group(1)), line


def test_ci_tests_on_the_node_major_the_images_ship() -> None:
    for wf in WORKFLOWS:
        text = wf.read_text(encoding="utf-8")
        for m in re.finditer(r"node-version:\s*['\"]?(\d+)", text):
            assert m.group(1) == "22", f"{wf.name}: node-version {m.group(1)}"
    ci = (REPO / ".github/workflows/ci-cd.yml").read_text(encoding="utf-8")
    assert "  NODE_VERSION: '22'" in ci


def test_runners_are_pinned_images() -> None:
    hits = []
    for wf in WORKFLOWS:
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\b(ubuntu|macos|windows)-latest\b", line):
                hits.append(f"{wf.name}:{n}: {line.strip()}")
    assert not hits, "\n".join(hits)


JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}


def test_openvex_document_is_well_formed_and_matches_the_doc() -> None:
    import json

    doc = json.loads(
        (REPO / "docs/security/autosecops.openvex.json").read_text("utf-8")
    )
    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    for key in ("@id", "author", "timestamp", "version", "statements"):
        assert doc.get(key), key
    vex_md = (REPO / "docs/security/vex.md").read_text(encoding="utf-8")
    assert doc["statements"]
    for st in doc["statements"]:
        cve = st["vulnerability"]["name"]
        assert st["products"] and all(
            p["@id"].startswith("pkg:") for p in st["products"]
        )
        assert st["status"] in {
            "not_affected",
            "affected",
            "fixed",
            "under_investigation",
        }
        if st["status"] == "not_affected":
            assert st["justification"] in JUSTIFICATIONS and st["impact_statement"]
        assert cve in vex_md, f"{cve} is in the OpenVEX file but not in vex.md"


REDIS_START = REPO / "infra/helm/vigil/files/redis-start.sh"


@pytest.mark.parametrize(
    "rel",
    [
        "infra/docker/docker-compose.yml",
        "clients/desktop/standalone/docker-compose.yml",
    ],
)
def test_compose_redis_starts_through_the_same_wrapper(rel: str) -> None:
    """Redis 7.4 data must not stop the 7.2 pin from starting (W0.38)."""
    command = yaml.safe_load((REPO / rel).read_text(encoding="utf-8"))["services"][
        "redis"
    ]["command"]
    assert command[:2] == ["sh", "-c"]
    # Compose writes $ as $$; the script is otherwise the chart's file.
    assert command[2].replace("$$", "$") == REDIS_START.read_text(encoding="utf-8")
    # $0: through the image's entrypoint, which drops to the redis user.
    assert command[3] == "docker-entrypoint.sh"
    assert command[4:] == [
        "--appendonly",
        "yes",
        "--maxmemory",
        "512mb",
        "--maxmemory-policy",
        "noeviction",
    ]


def test_helm_redis_starts_through_the_wrapper() -> None:
    tpl = (REPO / "infra/helm/vigil/templates/redis-statefulset.yaml").read_text(
        "utf-8"
    )
    assert (
        '- {{ .Files.Get "files/redis-start.sh" | quote }}\n            - redis-server'
        in tpl
    )


def test_the_wrapper_only_moves_data_newer_than_7_2_reads() -> None:
    script = REDIS_START.read_text(encoding="utf-8")
    assert '[ "$v" -gt 11 ]' in script  # 7.2 reads RDB <= 11; 7.4 writes 12
    assert "rm " not in script  # moved aside, never deleted
    assert script.rstrip().endswith('exec redis-server "$@"')
