"""Lint for .github/workflows/release.yml (WP W4.7).

actionlint runs when it is installed (PATH or $ACTIONLINT); the structural
checks below always run: trigger, canonical-repo guard, least-privilege
permissions, OIDC only in the signing job, SHA-pinned actions, and that every
release_tool.py subcommand the workflow calls exists.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
WF_PATH = REPO / ".github" / "workflows" / "release.yml"
CANONICAL = "github.repository == 'SingularityRD/autosecops2'"
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")

sys.path.insert(0, str(REPO / "scripts" / "release"))
import release_tool  # noqa: E402


@pytest.fixture(scope="module")
def raw() -> str:
    return WF_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def wf(raw: str) -> dict:
    doc = yaml.safe_load(raw)
    # YAML 1.1 reads the bare key `on` as boolean True.
    if True in doc:
        doc["on"] = doc.pop(True)
    return doc


def _steps(wf: dict):
    for name, job in wf["jobs"].items():
        for step in job.get("steps", []):
            yield name, step


def test_actionlint_clean_when_available() -> None:
    exe = os.environ.get("ACTIONLINT") or shutil.which("actionlint")
    if not exe:
        pytest.skip("actionlint not installed; structural checks below still run")
    proc = subprocess.run(
        [exe, "-no-color", str(WF_PATH)], capture_output=True, text=True, cwd=REPO
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip() == ""


def test_triggers_only_on_v_tags(wf: dict) -> None:
    assert wf["on"] == {"push": {"tags": ["v*"]}}


OPT_IN = "vars.RELEASE_GITHUB_ATTESTATIONS == 'true'"


def test_every_job_is_guarded_to_the_canonical_repo(wf: dict) -> None:
    for name, job in wf["jobs"].items():
        if name == "github-attestations":
            assert job.get("if") == f"{CANONICAL} && {OPT_IN}", name
        else:
            assert job.get("if") == CANONICAL, name


def test_least_privilege_permissions(wf: dict) -> None:
    assert wf["permissions"] == {}, "top-level permissions must be empty"
    for name, job in wf["jobs"].items():
        perms = job.get("permissions")
        assert isinstance(perms, dict), f"{name}: explicit permissions required"
        for scope, level in perms.items():
            assert level in ("read", "write"), f"{name}: {scope}={level}"
    id_token = {n for n, j in wf["jobs"].items() if "id-token" in j["permissions"]}
    # The opt-in attestation job is skipped unless the variable is set.
    assert id_token == {"sign", "github-attestations"}, id_token
    assert wf["jobs"]["sign"]["permissions"]["id-token"] == "write"
    attest = {n for n, j in wf["jobs"].items() if "attestations" in j["permissions"]}
    assert attest == {"github-attestations"}, "attestations: write only when opted in"
    contents_write = [
        n for n, j in wf["jobs"].items() if j["permissions"].get("contents") == "write"
    ]
    assert contents_write == ["update-release"]
    packages_write = {
        n for n, j in wf["jobs"].items() if j["permissions"].get("packages") == "write"
    }
    assert packages_write == {"build-images", "sign", "github-attestations"}


def test_actions_pinned_by_full_sha_with_tag_comment(raw: str, wf: dict) -> None:
    uses = [s["uses"] for _, s in _steps(wf) if "uses" in s]
    assert uses, "no actions found"
    for ref in uses:
        if ref.startswith("./"):
            continue
        assert SHA_PIN.match(ref), f"not pinned by commit SHA: {ref}"
    for line in raw.splitlines():
        if re.match(r"^\s*(-\s+)?uses:", line):
            assert re.search(r"@[0-9a-f]{40} # v\d+(\.\d+)*$", line), line


def test_tool_versions_pinned(wf: dict) -> None:
    for key in ("COSIGN_VERSION", "SYFT_VERSION"):
        assert re.match(r"^v\d+\.\d+\.\d+$", wf["env"][key]), key
    installer = [
        s
        for _, s in _steps(wf)
        if s.get("uses", "").startswith("sigstore/cosign-installer@")
    ]
    assert installer and all(
        s["with"]["cosign-release"] == "${{ env.COSIGN_VERSION }}" for s in installer
    )


def test_no_untrusted_context_in_run_scripts(wf: dict) -> None:
    for name, step in _steps(wf):
        run = step.get("run", "")
        for bad in ("github.event.", "github.head_ref", "inputs."):
            assert bad not in run, f"{name}: {bad} interpolated into a shell script"
        assert "secrets." not in run, f"{name}: secret in a shell script"
    secrets = set(re.findall(r"secrets\.(\w+)", WF_PATH.read_text(encoding="utf-8")))
    assert secrets <= {"GITHUB_TOKEN"}, secrets


def test_checkouts_do_not_persist_credentials(wf: dict) -> None:
    for name, step in _steps(wf):
        if step.get("uses", "").startswith("actions/checkout@"):
            assert step.get("with", {}).get("persist-credentials") is False, name


def test_builds_backend_daemon_agent_and_web(wf: dict) -> None:
    matrix = wf["jobs"]["build-images"]["strategy"]["matrix"]["include"]
    assert {m["component"] for m in matrix} == {"backend", "daemon", "agent"}
    for m in matrix:
        assert (REPO / m["dockerfile"]).is_file(), m["dockerfile"]
    push = [
        s
        for _, s in _steps(wf)
        if s.get("uses", "").startswith("docker/build-push-action@")
    ]
    assert push and push[0]["with"]["push"] is True
    assert push[0]["with"]["platforms"] == "linux/amd64,linux/arm64"
    assert push[0]["with"]["no-cache"] is True
    web = " ".join(s.get("run", "") for s in wf["jobs"]["build-web"]["steps"])
    assert "npm ci" in web and "npm run build" in web and "-web.tar.gz" in web


def test_sboms_signatures_attestations_and_provenance(wf: dict) -> None:
    sbom = " ".join(s.get("run", "") for s in wf["jobs"]["sbom"]["steps"])
    assert "release_tool.py sboms" in sbom
    assert "cyclonedx-json" in sbom and "syft" in sbom.lower()
    sign = " ".join(s.get("run", "") for s in wf["jobs"]["sign"]["steps"])
    assert "cosign sign --yes" in sign
    assert "cosign attest --yes --type cyclonedx" in sign
    assert "cosign attest --yes --type slsaprovenance1" in sign
    assert "release_tool.py provenance" in sign
    assert "cosign sign-blob --yes --bundle" in sign
    assert "release_tool.py checksums" in sign
    assert "SHA256SUMS.sigstore.json" in sign
    assert "verify-release.sh" in sign  # self-check with the customer script
    needs = set(wf["jobs"]["sign"]["needs"])
    assert {"build-images", "build-web", "sbom", "smoke-test"} <= needs


def test_version_job_checks_before_building(wf: dict) -> None:
    run = " ".join(s.get("run", "") for s in wf["jobs"]["version"]["steps"])
    assert "check-tag" in run and "check-versions" in run
    assert "check-notes" in run and "--strict" in run
    assert '--data "docs/release/${base}.json"' in run  # notes must be fresh
    for name, job in wf["jobs"].items():
        if name != "version":
            assert "version" in job["needs"], name


def test_release_is_a_draft(wf: dict) -> None:
    rel = [
        s
        for s in wf["jobs"]["update-release"]["steps"]
        if s.get("uses", "").startswith("softprops/action-gh-release@")
    ]
    assert rel and rel[0]["with"]["draft"] is True
    assert "dist/*" in rel[0]["with"]["files"]


def test_release_tool_subcommands_exist(raw: str) -> None:
    used = set(re.findall(r"release_tool\.py\s+(?:--repo\s+\S+\s+)?([a-z-]+)", raw))
    assert used
    for cmd in used:
        with pytest.raises(SystemExit) as exc:
            release_tool.main([cmd, "--help"])
        assert exc.value.code == 0, cmd


def test_version_job_requires_the_tagged_commit_on_main(wf: dict) -> None:
    steps = wf["jobs"]["version"]["steps"]
    co = steps[0]
    assert co["uses"].startswith("actions/checkout@")
    assert co["with"]["fetch-depth"] == 0
    names = [s.get("name", "") for s in steps]
    on_main = steps[names.index("Tagged commit is on main")]
    # Before the version/notes checks, so nothing runs for an off-main tag.
    assert names.index("Tagged commit is on main") < names.index(
        "Tag, version files and release notes agree"
    )
    run = on_main["run"]
    assert "fetch --no-tags" in run
    assert "+refs/heads/main:refs/remotes/origin/main" in run
    assert "check-on-main" in run and '--commit "$GITHUB_SHA"' in run
    assert "--main refs/remotes/origin/main" in run
    assert on_main["env"]["GH_TOKEN"] == "${{ github.token }}"


def test_github_attestations_are_a_separate_opt_in_job(wf: dict) -> None:
    sign = wf["jobs"]["sign"]
    assert not any(
        s.get("uses", "").startswith("actions/attest-build-provenance@")
        for s in sign["steps"]
    ), "sign job must not write GitHub attestations"
    job = wf["jobs"]["github-attestations"]
    assert set(job["needs"]) == {"version", "sign"}
    attest = [
        s
        for s in job["steps"]
        if s.get("uses", "").startswith("actions/attest-build-provenance@")
    ]
    assert len(attest) == 4
    for s in attest:
        assert "if" not in s  # the job condition covers every step
    # The release does not wait for (or skip because of) the optional job.
    assert "github-attestations" not in wf["jobs"]["update-release"]["needs"]


RULESETS = REPO / "scripts" / "release" / "rulesets"


def test_tag_rulesets_restrict_create_and_forbid_update_delete() -> None:
    import json

    create = json.loads((RULESETS / "release-tags-create.json").read_text())
    immutable = json.loads((RULESETS / "release-tags-immutable.json").read_text())
    for rs in (create, immutable):
        assert rs["target"] == "tag"
        assert rs["enforcement"] == "active"
        assert rs["conditions"]["ref_name"]["include"] == ["refs/tags/v*"]
    assert [r["type"] for r in create["rules"]] == ["creation"]
    assert [b["actor_type"] for b in create["bypass_actors"]] == ["Team"]
    assert {r["type"] for r in immutable["rules"]} == {"update", "deletion"}
    assert immutable["bypass_actors"] == [], "nobody may move or delete v* tags"
    doc = (REPO / "VERSIONING.md").read_text(encoding="utf-8")
    assert "## Tag protection (required)" in doc
    for f in ("release-tags-create.json", "release-tags-immutable.json"):
        assert f"scripts/release/rulesets/{f}" in doc
    assert "gh api --method POST repos/SingularityRD/autosecops2/rulesets" in doc
