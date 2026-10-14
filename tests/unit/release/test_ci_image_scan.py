"""Backend and daemon images are scanned in ci-cd.yml before any tag (WP W0.22).

W0.23: every Trivy step in ci-cd.yml (Agent Image included) runs the same
SHA-pinned action and Trivy version, and the gates fail on secrets too, with no
allow-list or skip that could hide one.

release.yml builds and signs backend, daemon and agent on a tag. Until W0.22
only the agent image was built and scanned on PRs; this pins the job that does
the same for backend and daemon, and the rule that ci-cd.yml never pushes an
image anywhere (publishing is release.yml's job).
"""

from __future__ import annotations

import copy
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[3]
CI_PATH = REPO / ".github" / "workflows" / "ci-cd.yml"
RELEASE_PATH = REPO / ".github" / "workflows" / "release.yml"
CANONICAL = "github.repository == 'SingularityRD/autosecops2'"
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
JOB = "build-service-images"


def _load(path: Path) -> dict:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if True in doc:  # YAML 1.1 reads the bare key `on` as boolean True
        doc["on"] = doc.pop(True)
    return doc


@pytest.fixture(scope="module")
def raw() -> str:
    return CI_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ci() -> dict:
    return _load(CI_PATH)


@pytest.fixture(scope="module")
def job(ci: dict) -> dict:
    assert JOB in ci["jobs"], f"ci-cd.yml has no {JOB} job"
    return ci["jobs"][JOB]


def _step(job: dict, prefix: str) -> list[dict]:
    return [s for s in job["steps"] if s.get("name", "").startswith(prefix)]


def _job_text(raw: str, name: str) -> str:
    """The job's block of ci-cd.yml, comments included."""
    m = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)", raw, re.M | re.S)
    assert m, name
    return m.group(1)


def test_actionlint_clean_when_available() -> None:
    exe = os.environ.get("ACTIONLINT") or shutil.which("actionlint")
    if not exe:
        pytest.skip("actionlint not installed; the Lint Backend job runs it in CI")
    proc = subprocess.run(
        [exe, "-no-color", str(CI_PATH)], capture_output=True, text=True, cwd=REPO
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_runs_on_push_to_main_and_on_prs(ci: dict) -> None:
    on = ci["on"]
    assert "main" in on["push"]["branches"]
    assert "main" in on["pull_request"]["branches"]
    assert "workflow_dispatch" in on


def test_builds_backend_and_daemon_from_the_release_dockerfiles(job: dict) -> None:
    matrix = {
        e["component"]: e["dockerfile"] for e in job["strategy"]["matrix"]["include"]
    }
    assert matrix == {
        "backend": "infra/docker/Dockerfile.backend",
        "daemon": "infra/docker/Dockerfile.daemon",
    }
    release = _load(RELEASE_PATH)["jobs"]["build-images"]["strategy"]["matrix"][
        "include"
    ]
    released = {e["component"]: e["dockerfile"] for e in release}
    for component, dockerfile in matrix.items():
        assert released[component] == dockerfile, component
    assert job["strategy"].get("fail-fast") is False


def test_guarded_least_privilege_no_secrets(raw: str, job: dict) -> None:
    assert job["if"] == CANONICAL
    assert job["permissions"] == {"contents": "read"}
    assert "secrets." not in _job_text(raw, JOB)


def test_actions_pinned_by_sha_and_match_release(raw: str, job: dict) -> None:
    release_refs = set(
        re.findall(r"uses: (\S+@[0-9a-f]{40})", RELEASE_PATH.read_text())
    )
    uses = [s["uses"] for s in job["steps"] if "uses" in s]
    assert uses
    for ref in uses:
        assert SHA_PIN.match(ref), f"not pinned by commit SHA: {ref}"
    for prefix in (
        "actions/checkout@",
        "docker/setup-buildx-action@",
        "docker/build-push-action@",
    ):
        mine = {r for r in uses if r.startswith(prefix)}
        assert (
            mine and mine <= release_refs
        ), f"{prefix} differs from release.yml: {mine}"
    for line in _job_text(raw, JOB).splitlines():
        if re.match(r"^\s*(-\s+)?uses:", line):
            assert re.search(r"@[0-9a-f]{40} # v\d+(\.\d+)*$", line), line
    checkout = [
        s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@")
    ]
    assert all(s["with"]["persist-credentials"] is False for s in checkout)


def test_builds_locally_never_pushes(job: dict) -> None:
    (build,) = [
        s
        for s in job["steps"]
        if s.get("uses", "").startswith("docker/build-push-action@")
    ]
    w = build["with"]
    assert w["push"] is False and w["load"] is True
    assert w["file"] == "${{ matrix.dockerfile }}"
    assert "PYTHON_VERSION=" in w["build-args"]


def test_trivy_reports_high_critical_and_fails_on_fixable_critical(job: dict) -> None:
    (report,) = _step(job, "Trivy — report")
    (gate,) = _step(job, "Trivy — fail on fixable CRITICAL")
    (secret_gate,) = _step(job, "Trivy — fail on any secret")
    for s in (report, gate, secret_gate):
        assert s["uses"].startswith("aquasecurity/trivy-action@")
        assert re.match(
            r"^v\d+\.\d+\.\d+$", s["with"]["version"]
        ), "pin the Trivy version"
        assert s["with"]["image-ref"] == "${{ env.IMAGE }}"
        assert "continue-on-error" not in s
    assert report["uses"] == gate["uses"] == secret_gate["uses"]
    assert report["with"]["version"] == gate["with"]["version"]
    assert report["with"]["severity"] == "HIGH,CRITICAL"
    assert "scanners" not in report["with"]
    names = [s.get("name", "") for s in job["steps"]]
    assert names.index(report["name"]) < names.index(gate["name"])
    assert names.index(report["name"]) < names.index(secret_gate["name"])


def test_smoke_test_runs_the_image(job: dict) -> None:
    (smoke,) = _step(job, "Smoke test")
    assert '"$IMAGE"' in smoke["run"] and "docker run --rm" in smoke["run"]
    # matrix values reach the shell through env, not ${{ }} in the script
    assert "${{" not in smoke["run"]
    smokes = {e["component"]: e["smoke"] for e in job["strategy"]["matrix"]["include"]}
    assert "services.api.main" in smokes["backend"]
    assert "services.daemon.main" in smokes["daemon"]


def test_ci_cd_never_pushes_or_logs_in_to_a_registry(raw: str, ci: dict) -> None:
    for name, j in ci["jobs"].items():
        perms = j.get("permissions") or {}
        assert perms != "write-all", name
        assert "packages" not in perms, f"{name}: ci-cd.yml does not publish packages"
        for step in j.get("steps", []):
            uses = step.get("uses", "")
            assert not uses.startswith("docker/login-action"), name
            if uses.startswith("docker/build-push-action"):
                assert (
                    step.get("with", {}).get("push") is False
                ), f"{name}: push must be false"
            assert not re.search(
                r"\bdocker\s+(push|login)\b", step.get("run", "")
            ), name
    assert not re.search(r"^\s*push:\s*true\b", raw, re.M)


# --- W0.23: one pinned Trivy everywhere, secrets gated, nothing waived --------
#
# The checks below are functions returning a list of problems, so that each
# can be run on the real files and on mutated copies (the mutation tests prove
# the check would catch the loophole, not just that today's files are clean).

IMAGE_JOBS = ("build-agent-image", JOB)
ALL_SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
TRIVY_STEP_INPUTS_THAT_HIDE_FINDINGS = (
    "trivyignores",
    "skip-dirs",
    "skip-files",
    "secret-config",
    "trivy-config",
    "ignore-policy",
)
# Files Trivy reads from the working directory without being told to.
DEFAULT_IGNORE_FILES = (".trivyignore", ".trivyignore.yaml", "trivy.yaml")
SECRET_CONFIG = REPO / "trivy-secret.yaml"
# The text Trivy's gcp-service-account rule matches, spelled loosely so this
# file does not match it itself.
KEY_FILE_SHAPE = re.compile(r'"type"\s*:\s*"service_account"')
# One literal file path: anchored, characters a path uses, `.` only escaped.
LITERAL_PATH = re.compile(r"^\^(?:[A-Za-z0-9_/-]|\\\.)+\$$")
# A literal string: no metacharacter unless backslash-escaped punctuation.
LITERAL_REGEX = re.compile(r"^(?:[^\\.^$*+?{}\[\]|()]|\\[^A-Za-z0-9])+$")


def _trivy_steps(ci: dict) -> list[tuple[str, dict]]:
    return [
        (name, step)
        for name, j in ci["jobs"].items()
        for step in j.get("steps", [])
        if "trivy" in step.get("uses", "").lower()
    ]


def _gate_problems(ci: dict) -> list[str]:
    """Each image job: a fixable-CRITICAL vuln gate and an any-secret gate."""
    problems = []
    for name in IMAGE_JOBS:
        steps = ci["jobs"][name]["steps"]
        vuln = _step({"steps": steps}, "Trivy — fail on fixable CRITICAL")
        secret = _step({"steps": steps}, "Trivy — fail on any secret")
        if len(vuln) != 1 or len(secret) != 1:
            problems.append(f"{name}: needs one vuln gate and one secret gate")
            continue
        v, sg = vuln[0], secret[0]
        vw, sw = v.get("with", {}), sg.get("with", {})
        if vw.get("scanners") != "vuln" or vw.get("severity") != "CRITICAL":
            problems.append(f"{name}: vuln gate must be vuln / CRITICAL")
        if vw.get("ignore-unfixed") is not True:
            problems.append(f"{name}: vuln gate must ignore unfixed")
        if sw.get("scanners") != "secret":
            problems.append(f"{name}: secret gate must scan secrets only")
        if set(str(sw.get("severity", "")).split(",")) != ALL_SEVERITIES:
            problems.append(f"{name}: secret gate must fail on every severity")
        if "ignore-unfixed" in sw:
            problems.append(f"{name}: ignore-unfixed has no meaning for secrets")
        for step in (v, sg):
            if str(step.get("with", {}).get("exit-code")) != "1":
                problems.append(f"{name}/{step['name']}: exit-code must be 1")
            if "continue-on-error" in step or "if" in step:
                problems.append(f"{name}/{step['name']}: must always run and fail")
    return problems


def _hiding_problems(ci: dict) -> list[str]:
    """No input or TRIVY_* environment variable anywhere can waive a finding.

    Trivy reads every flag from a TRIVY_<FLAG> variable too (TRIVY_SKIP_DIRS,
    TRIVY_IGNOREFILE, TRIVY_SECRET_CONFIG, ...), so the variable is forbidden
    at workflow, job and step level whatever its name.
    """
    problems = []
    scopes = [("workflow", ci.get("env") or {})]
    for name, j in ci["jobs"].items():
        scopes.append((name, j.get("env") or {}))
        for step in j.get("steps", []):
            scopes.append((f"{name}/{step.get('name', '?')}", step.get("env") or {}))
    for where, env in scopes:
        for key in env:
            if str(key).upper().startswith("TRIVY_"):
                problems.append(f"{where}: env {key} reaches Trivy")
    for name, step in _trivy_steps(ci):
        w = step.get("with", {})
        for key in TRIVY_STEP_INPUTS_THAT_HIDE_FINDINGS:
            if key in w:
                problems.append(f"{name}/{step['name']}: {key} would hide findings")
    return problems


def _allow_list_problems(doc: dict) -> list[str]:
    """A trivy-secret.yaml may only allow one literal string in one file."""
    problems = []
    if doc.get("disable-rules"):
        problems.append("disable-rules waives a rule everywhere")
    if doc.get("disable-allow-rules"):
        problems.append("disable-allow-rules")
    for rule in doc.get("allow-rules") or []:
        rid = rule.get("id") or "?"
        if not rule.get("id") or not rule.get("description"):
            problems.append(f"{rid}: needs id and description")
        regex = rule.get("regex")
        if not regex or not LITERAL_REGEX.match(str(regex)):
            problems.append(f"{rid}: regex must be a literal string, not {regex!r}")
        path = rule.get("path")
        if not path or not LITERAL_PATH.match(str(path)):
            problems.append(f"{rid}: path must be one literal file, not {path!r}")
    return problems


def test_no_unpinned_trivy_anywhere(raw: str, ci: dict) -> None:
    steps = _trivy_steps(ci)
    assert len(steps) == 6, "each image job: report, vuln gate, secret gate"
    assert {name for name, _ in steps} == set(IMAGE_JOBS)
    refs = {s["uses"] for _, s in steps}
    versions = {s.get("with", {}).get("version") for _, s in steps}
    assert len(refs) == 1, f"one trivy-action pin for every step: {refs}"
    assert len(versions) == 1, f"one Trivy version for every step: {versions}"
    (ref,) = refs
    (version,) = versions
    assert SHA_PIN.match(ref), ref
    assert version and re.match(r"^v\d+\.\d+\.\d+$", version), version
    # no floating ref in any spelling, in steps or comments
    assert not re.search(r"trivy[\w/-]*@(master|main|latest)\b", raw, re.I)
    assert not re.search(r"^\s*version:\s*['\"]?latest", raw, re.M | re.I)
    for line in raw.splitlines():
        if "uses:" in line and "trivy" in line.lower():
            assert re.search(r"@[0-9a-f]{40} # v\d+\.\d+\.\d+$", line), line


def test_every_image_gates_fixable_critical_vulns_and_any_secret(ci: dict) -> None:
    assert _gate_problems(ci) == []


def test_nothing_waives_a_finding(raw: str, ci: dict) -> None:
    assert _hiding_problems(ci) == []
    # belt and braces: no TRIVY_ variable even in a run: script
    code = [ln for ln in raw.splitlines() if not ln.lstrip().startswith("#")]
    assert not [ln for ln in code if "TRIVY_" in ln]


def test_no_secret_allow_list_exists() -> None:
    """W0.23 fixed the one finding at the source instead of allow-listing it.

    A trivy-secret.yaml at the repo root is read by Trivy by default, so one
    added later would waive findings without touching ci-cd.yml. If one is ever
    needed it must pass _allow_list_problems: one literal string in one file.
    """
    for name in DEFAULT_IGNORE_FILES:
        assert not (REPO / name).exists(), f"{name} is read by default"
    if SECRET_CONFIG.exists():
        doc = yaml.safe_load(SECRET_CONFIG.read_text(encoding="utf-8")) or {}
        assert _allow_list_problems(doc) == []


def test_web_ui_ships_no_key_file_shaped_text() -> None:
    """The SPA is in the backend image; key-shaped placeholders trip the gate."""
    src = REPO / "clients" / "web" / "src"
    hits = [
        str(p.relative_to(REPO))
        for p in src.rglob("*")
        if p.suffix in {".ts", ".tsx", ".js", ".jsx", ".json", ".html"}
        and "generated" not in p.parts
        and KEY_FILE_SHAPE.search(p.read_text(encoding="utf-8", errors="replace"))
    ]
    assert hits == [], hits


# --- mutation tests: each loophole the checks above must catch ---------------


def _gate(ci: dict, job_name: str, prefix: str) -> dict:
    (step,) = _step(ci["jobs"][job_name], prefix)
    return step


@pytest.mark.parametrize("job_name", IMAGE_JOBS)
@pytest.mark.parametrize(
    "mutate",
    [
        # the W0.23 verifier's case: a HIGH secret (PEM key) passed a CRITICAL gate
        lambda s: s["with"].__setitem__("severity", "CRITICAL"),
        lambda s: s["with"].__setitem__("severity", "HIGH,CRITICAL"),
        lambda s: s["with"].__setitem__("scanners", "vuln"),
        lambda s: s["with"].__setitem__("exit-code", "0"),
        lambda s: s.__setitem__("continue-on-error", True),
        lambda s: s["with"].__setitem__("ignore-unfixed", True),
    ],
    ids=[
        "critical-only",
        "high-critical",
        "no-secret-scanner",
        "exit-0",
        "coe",
        "unfixed",
    ],
)
def test_mutation_weak_secret_gate_is_caught(ci: dict, job_name: str, mutate) -> None:
    bad = copy.deepcopy(ci)
    mutate(_gate(bad, job_name, "Trivy — fail on any secret"))
    assert _gate_problems(bad)


@pytest.mark.parametrize("job_name", IMAGE_JOBS)
def test_mutation_missing_secret_gate_is_caught(ci: dict, job_name: str) -> None:
    bad = copy.deepcopy(ci)
    steps = bad["jobs"][job_name]["steps"]
    steps.remove(_gate(bad, job_name, "Trivy — fail on any secret"))
    assert _gate_problems(bad)


@pytest.mark.parametrize("scope", ["workflow", "job", "step"])
@pytest.mark.parametrize(
    "var",
    [
        "TRIVY_SKIP_DIRS",
        "TRIVY_SKIP_FILES",
        "TRIVY_IGNOREFILE",
        "TRIVY_SECRET_CONFIG",
        "trivy_severity",
    ],
)
def test_mutation_trivy_env_is_caught(ci: dict, scope: str, var: str) -> None:
    bad = copy.deepcopy(ci)
    if scope == "workflow":
        target = bad
    elif scope == "job":
        target = bad["jobs"][JOB]
    else:
        target = _gate(bad, JOB, "Trivy — fail on any secret")
    target.setdefault("env", {})[var] = "app"
    assert _hiding_problems(bad)


@pytest.mark.parametrize("key", TRIVY_STEP_INPUTS_THAT_HIDE_FINDINGS)
def test_mutation_hiding_input_is_caught(ci: dict, key: str) -> None:
    bad = copy.deepcopy(ci)
    _gate(bad, "build-agent-image", "Trivy — fail on any secret")["with"][key] = "x"
    assert _hiding_problems(bad)


NARROW_RULE = {
    "id": "spa-placeholder",
    "description": "example of the only shape allowed",
    "regex": r"example\-placeholder",
    "path": r"^app/clients/web/build/index\.html$",
}


def test_a_narrow_allow_rule_passes() -> None:
    assert _allow_list_problems({"allow-rules": [NARROW_RULE]}) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("regex", ".*"),
        ("regex", ".+"),
        ("regex", r"\S+"),
        ("regex", "a|b"),
        ("regex", "[a-z]{20}"),
        ("regex", ""),
        ("path", r"^app/[^z]*$"),
        ("path", ".*"),
        ("path", r"^app/.*\.js$"),
        ("path", r"^app/clients/web/build/assets/statusLine-.+\.js$"),
        ("path", r"app/clients/web/build/index\.html"),  # unanchored
        ("path", r"^app/clients/web/build/index.html$"),  # bare `.`
        ("path", r"^app/(a|b)\.js$"),
        ("path", r"^app/\w+\.js$"),
        ("path", ""),
        ("description", ""),
    ],
)
def test_mutation_broad_allow_rule_is_caught(field: str, value: str) -> None:
    rule = dict(NARROW_RULE, **{field: value})
    assert _allow_list_problems({"allow-rules": [rule]})


@pytest.mark.parametrize("key", ["disable-rules", "disable-allow-rules"])
def test_mutation_disabling_rules_is_caught(key: str) -> None:
    assert _allow_list_problems({key: ["private-key"]})
