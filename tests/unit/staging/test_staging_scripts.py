"""infra/staging: the single-VM staging install (WP w0.6).

There is no VM, k3s or Helm binary in CI, so the scripts are exercised with
stub `git`/`docker`/`helm`/`kubectl`/`k3s` on PATH (each logs its argv) and a
fake AutoSecOps API (fake_api.py) that answers the endpoints the scripts call.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.unit.staging.fake_api import FakeApi

REPO = Path(__file__).resolve().parents[3]
STAGING = REPO / "infra" / "staging"
CHART_VALUES = REPO / "infra" / "helm" / "vigil" / "values.yaml"
SCRIPTS = sorted(STAGING.glob("*.sh")) + sorted((STAGING / "lib").glob("*.sh"))

ADMIN_ENV = {
    "STAGING_ADMIN_USER": "staging-admin",
    "STAGING_ADMIN_EMAIL": "staging-admin@autosecops.local",
    "STAGING_ADMIN_PASSWORD": "Xq7-very-long-test-password-01",
}


def _env(tmp_path: Path, **extra: str) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("STAGING_", "SMOKE_", "DEMO_", "REPLAY_"))}
    env.update(
        STAGING_ETC_DIR=str(tmp_path / "etc"),
        STAGING_STATE_DIR=str(tmp_path / "state"),
        STAGING_SRC_DIR=str(tmp_path / "src"),
        STAGING_POLL_INTERVAL="0.2",
    )
    env.update(extra)
    return env


def _run(cmd, env, timeout=120, cwd=None):
    return subprocess.run(
        cmd, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout
    )


# --------------------------------------------------------------------------
# Static checks
# --------------------------------------------------------------------------


def test_expected_files_exist():
    for rel in (
        "README.md", "bootstrap.sh", "nightly.sh", "smoke.sh", "seed-demo.sh",
        "replay.sh", "values-staging.yaml", "staging.env.example",
        "manifests/llm.yaml", "lib/common.sh", "lib/api.sh", "lib/cluster.sh",
        "lib/corpus_to_findings.py", "lib/replay_report.py", "lib/register_local_model.py",
        "systemd/autosecops-staging-nightly.service", "systemd/autosecops-staging-nightly.timer",
        "systemd/autosecops-staging-replay.service", "systemd/autosecops-staging-replay.timer",
    ):
        assert (STAGING / rel).is_file(), rel


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_bash_syntax(script):
    r = _run(["bash", "-n", str(script)], env=os.environ)
    assert r.returncode == 0, r.stderr


def test_entry_scripts_are_executable():
    for script in STAGING.glob("*.sh"):
        assert os.stat(script).st_mode & stat.S_IXUSR, script.name


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed")
def test_shellcheck_clean():
    r = _run(["shellcheck", "-x", *map(str, SCRIPTS)], env=os.environ, cwd=STAGING)
    assert r.returncode == 0, r.stdout + r.stderr


def _key_paths(doc, prefix=()):
    if isinstance(doc, dict):
        for k, v in doc.items():
            yield prefix + (k,)
            yield from _key_paths(v, prefix + (k,))


def _has_path(doc, path):
    cur = doc
    for i, part in enumerate(path):
        if isinstance(cur, list):
            # list items (e.g. ingress.hosts[0]) are free-form below this point
            return True
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    return True


def test_values_staging_keys_exist_in_chart():
    """Stand-in for `helm template` here: a mistyped key would be silently
    ignored by Helm, so every key path must exist in the chart's values.yaml
    (extraConfig is the chart's free-form env map)."""
    chart = yaml.safe_load(CHART_VALUES.read_text())
    staging = yaml.safe_load((STAGING / "values-staging.yaml").read_text())
    missing = [
        ".".join(map(str, p)) for p in _key_paths(staging)
        if p[0] != "extraConfig" and not _has_path(chart, p)
    ]
    assert missing == []


def test_values_staging_safe_defaults_and_no_secrets():
    staging = yaml.safe_load((STAGING / "values-staging.yaml").read_text())
    cfg = staging["config"]
    assert cfg["DEV_MODE"] == "false"
    assert cfg["DAEMON_AUTO_RESPONSE"] == "false"
    assert cfg["DAEMON_DRY_RUN"] == "true"
    assert cfg["DAEMON_AUTO_TRIAGE"] == "true"
    assert cfg["OLLAMA_URL"] == "http://ollama:11434"
    assert cfg["BIFROST_URL"] == "http://bifrost:8080"
    assert "secrets" not in staging, "secrets come from /etc/autosecops-staging/secrets.yaml"
    assert staging["fullnameOverride"] == "autosecops"


def test_llm_manifest_services_and_pins():
    docs = [d for d in yaml.safe_load_all((STAGING / "manifests" / "llm.yaml").read_text()) if d]
    services = {d["metadata"]["name"]: d for d in docs if d["kind"] == "Service"}
    assert set(services) == {"ollama", "bifrost"}
    for svc in services.values():
        assert svc["spec"]["type"] == "ClusterIP"
    assert services["ollama"]["spec"]["ports"][0]["port"] == 11434
    assert services["bifrost"]["spec"]["ports"][0]["port"] == 8080
    assert not [d for d in docs if d["kind"] == "Ingress"]
    images = [
        c["image"] for d in docs if d["kind"] == "Deployment"
        for c in d["spec"]["template"]["spec"]["containers"]
    ]
    assert len(images) == 2
    for image in images:
        assert ":" in image and not image.endswith(":latest"), image
    cm = next(d for d in docs if d["kind"] == "ConfigMap")
    bifrost_cfg = json.loads(cm["data"]["config.json"])
    assert set(bifrost_cfg["providers"]) == {"ollama"}


def test_systemd_units():
    timer = (STAGING / "systemd" / "autosecops-staging-nightly.timer").read_text()
    assert "OnCalendar=" in timer and "Persistent=true" in timer
    assert "Unit=autosecops-staging-nightly.service" in timer
    svc = (STAGING / "systemd" / "autosecops-staging-nightly.service").read_text()
    assert "ExecStart=/opt/autosecops-staging/src/infra/staging/nightly.sh" in svc
    assert "Type=oneshot" in svc
    rsvc = (STAGING / "systemd" / "autosecops-staging-replay.service").read_text()
    assert "ExecStart=/opt/autosecops-staging/src/infra/staging/replay.sh" in rsvc


# --------------------------------------------------------------------------
# bootstrap.sh
# --------------------------------------------------------------------------


def test_bootstrap_dry_run_plans_and_writes_nothing(tmp_path):
    env = _env(tmp_path, DRY_RUN="1")
    r = _run(["bash", str(STAGING / "bootstrap.sh")], env)
    assert r.returncode == 0, r.stderr
    out = r.stdout + r.stderr
    for needle in ("k3s", "helm", "autosecops-staging-nightly.timer", "secrets.yaml", "admin.env"):
        assert needle in out, needle
    assert "sha256sum" in out  # helm download is verified
    assert not (tmp_path / "etc").exists()
    assert not (tmp_path / "state").exists()


def test_bootstrap_does_not_overwrite_existing_config(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir()
    for name in ("staging.env", "secrets.yaml", "admin.env"):
        (etc / name).write_text("# KEEP\n")
    r = _run(["bash", str(STAGING / "bootstrap.sh")], _env(tmp_path, DRY_RUN="1"))
    assert r.returncode == 0, r.stderr
    assert "write " + str(etc) not in r.stdout
    for name in ("staging.env", "secrets.yaml", "admin.env"):
        assert (etc / name).read_text() == "# KEEP\n"


def test_bootstrap_generators_produce_valid_secrets(tmp_path):
    """The generators bootstrap.sh uses for secrets.yaml / admin.env."""
    script = (
        f'source "{STAGING}/lib/common.sh"; '
        f'eval "$(sed -n "/^gen_secrets_yaml()/,/^}}/p;/^gen_admin_env()/,/^}}/p" "{STAGING}/bootstrap.sh")"; '
        'STAGING_ADMIN_USER=u STAGING_ADMIN_EMAIL=u@x.local; '
        'gen_secrets_yaml > "$1"; gen_admin_env > "$2"'
    )
    r = _run(["bash", "-c", script, "_", str(tmp_path / "s.yaml"), str(tmp_path / "a.env")],
             _env(tmp_path))
    assert r.returncode == 0, r.stderr
    secrets = yaml.safe_load((tmp_path / "s.yaml").read_text())["secrets"]
    assert len(secrets["postgresPassword"]) >= 24
    assert len(secrets["jwtSecretKey"]) >= 64
    assert len(secrets["agentInternalToken"]) >= 48
    admin = dict(
        line.split("=", 1) for line in (tmp_path / "a.env").read_text().splitlines()
        if line and not line.startswith("#")
    )
    assert len(admin["STAGING_ADMIN_PASSWORD"]) >= 24


# --------------------------------------------------------------------------
# smoke.sh against the fake API
# --------------------------------------------------------------------------


def test_smoke_passes_end_to_end(tmp_path):
    report = tmp_path / "smoke.json"
    with FakeApi(mode="triage", triage_after=2) as api:
        env = _env(tmp_path, STAGING_BASE_URL=api.url, SMOKE_REPORT=str(report),
                   SMOKE_TRIAGE_TIMEOUT="20", **ADMIN_ENV)
        r = _run([str(STAGING / "smoke.sh")], env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert "SMOKE: PASS" in r.stdout
        # first admin created, logged in, one finding stored
        assert list(api.state.users) == ["staging-admin"]
        assert len(api.state.findings) == 1
        fid = next(iter(api.state.findings))
        assert fid.startswith("smoke-") and len(fid) <= 50
        assert "POST /api/ingest/ingest-string" in api.state.requests
    doc = json.loads(report.read_text())
    assert doc["result"] == "PASS" and doc["recommended_action"] == "investigate"
    # the password never appears in output
    assert ADMIN_ENV["STAGING_ADMIN_PASSWORD"] not in r.stdout + r.stderr


def test_smoke_second_run_reuses_admin(tmp_path):
    with FakeApi(mode="triage", triage_after=0) as api:
        env = _env(tmp_path, STAGING_BASE_URL=api.url, SMOKE_TRIAGE_TIMEOUT="20", **ADMIN_ENV)
        assert _run([str(STAGING / "smoke.sh")], env).returncode == 0
        r = _run([str(STAGING / "smoke.sh")], env)
        assert r.returncode == 0, r.stderr
        assert api.state.requests.count("POST /api/auth/bootstrap") == 1
        assert len(api.state.findings) == 2


def test_smoke_reads_admin_env_file(tmp_path):
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "admin.env").write_text("".join(f"{k}={v}\n" for k, v in ADMIN_ENV.items()))
    with FakeApi(triage_after=0) as api:
        r = _run([str(STAGING / "smoke.sh")],
                 _env(tmp_path, STAGING_BASE_URL=api.url, SMOKE_TRIAGE_TIMEOUT="20"))
        assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("mode", ["never", "error"])
def test_smoke_fails_when_triage_never_arrives(tmp_path, mode):
    report = tmp_path / "smoke.json"
    with FakeApi(mode=mode, triage_after=0) as api:
        env = _env(tmp_path, STAGING_BASE_URL=api.url, SMOKE_REPORT=str(report),
                   SMOKE_TRIAGE_TIMEOUT="2", **ADMIN_ENV)
        r = _run([str(STAGING / "smoke.sh")], env)
    assert r.returncode != 0
    assert "SMOKE: FAIL triage" in r.stdout
    assert json.loads(report.read_text())["step"] == "triage"
    if mode == "error":
        assert "LLM gateway unavailable" in r.stderr


def test_smoke_fails_on_auth_bypass(tmp_path):
    with FakeApi(auth_bypassed=True) as api:
        r = _run([str(STAGING / "smoke.sh")],
                 _env(tmp_path, STAGING_BASE_URL=api.url, **ADMIN_ENV))
    assert r.returncode != 0 and "SMOKE: FAIL health" in r.stdout


def test_smoke_fails_on_wrong_password(tmp_path):
    with FakeApi() as api:
        api.state.users["staging-admin"] = {"password": "something-else-entirely"}
        r = _run([str(STAGING / "smoke.sh")],
                 _env(tmp_path, STAGING_BASE_URL=api.url, **ADMIN_ENV))
    assert r.returncode != 0 and "SMOKE: FAIL login" in r.stdout


def test_smoke_skip_triage(tmp_path):
    with FakeApi(mode="never") as api:
        r = _run([str(STAGING / "smoke.sh")],
                 _env(tmp_path, STAGING_BASE_URL=api.url, SMOKE_SKIP_TRIAGE="1", **ADMIN_ENV))
    assert r.returncode == 0, r.stderr


# --------------------------------------------------------------------------
# Demo seed + replay
# --------------------------------------------------------------------------


def test_seed_demo_is_idempotent(tmp_path):
    with FakeApi() as api:
        env = _env(tmp_path, STAGING_BASE_URL=api.url, DEMO_SUITES="dev,injection",
                   DEMO_LIMIT="5", **ADMIN_ENV)
        r1 = _run([str(STAGING / "seed-demo.sh")], env)
        assert r1.returncode == 0, r1.stderr
        assert "SEED: imported=10 skipped=0" in r1.stdout
        r2 = _run([str(STAGING / "seed-demo.sh")], env)
        assert r2.returncode == 0, r2.stderr
        assert "SEED: imported=0 skipped=10" in r2.stdout
        assert all(fid.startswith("demo-") for fid in api.state.findings)
        # labels and meta never leave the VM
        for f in api.state.findings.values():
            assert set(f) <= {
                "anomaly_score", "data_source", "description", "entity_context", "external_id",
                "finding_id", "mitre_predictions", "raw_event", "severity", "status",
                "timestamp", "title"}


def test_corpus_to_findings(tmp_path):
    out = tmp_path / "out"
    r = _run([sys.executable, str(STAGING / "lib" / "corpus_to_findings.py"),
              "--suites", "test,test_unseen,injection", "--tag", "r2610131200",
              "--out-dir", str(out), "--batch", "7"], os.environ)
    assert r.returncode == 0, r.stderr
    total = int(r.stdout.strip())
    assert total == 432 + 720 + 240
    labels = [json.loads(x) for x in (out / "labels.jsonl").read_text().splitlines()]
    assert len(labels) == total
    assert {lab["verdict"] for lab in labels} <= {"malicious", "benign"}
    rows = [json.loads(x) for p in sorted(out.glob("batch-*.jsonl")) for x in p.read_text().splitlines()]
    assert len(rows) == total
    assert max(len(open(p, "rb").read().splitlines()) for p in out.glob("batch-*.jsonl")) <= 7
    ids = [row["finding_id"] for row in rows]
    assert len(set(ids)) == total
    assert all(i.startswith("r2610131200-") and len(i) <= 50 for i in ids)
    assert all(row["external_id"].startswith("r2610131200-") for row in rows)
    # largest batch at the default size stays well under the 1 MiB form-part limit
    r = _run([sys.executable, str(STAGING / "lib" / "corpus_to_findings.py"),
              "--suites", "train", "--tag", "demo", "--out-dir", str(tmp_path / "big")], os.environ)
    assert r.returncode == 0, r.stderr
    assert max(p.stat().st_size for p in (tmp_path / "big").glob("batch-*.jsonl")) < 512 * 1024


def test_corpus_to_findings_rejects_tampered_corpus(tmp_path):
    corpus = tmp_path / "corpus"
    shutil.copytree(REPO / "eval" / "corpus" / "v1", corpus)
    with open(corpus / "dev.jsonl", "a") as fh:
        fh.write("\n")
    r = _run([sys.executable, str(STAGING / "lib" / "corpus_to_findings.py"),
              "--suites", "dev", "--tag", "demo", "--out-dir", str(tmp_path / "o"),
              "--corpus-dir", str(corpus)], os.environ)
    assert r.returncode != 0 and "sha256" in r.stderr


def test_replay_scores_against_labels(tmp_path):
    with FakeApi(mode="triage", triage_after=0) as api:
        env = _env(tmp_path, STAGING_BASE_URL=api.url, REPLAY_SUITES="test",
                   REPLAY_LIMIT="6", REPLAY_TAG="rtest", REPLAY_WAIT_MINUTES="1",
                   REPLAY_MIN_COVERAGE="1.0", **ADMIN_ENV)
        r = _run([str(STAGING / "replay.sh")], env)
        assert r.returncode == 0, r.stdout + r.stderr
        assert len(api.state.findings) == 6
    report = json.loads((tmp_path / "state" / "replay" / "rtest" / "report.json").read_text())
    assert report["total"] == 6 and report["triaged"] == 6 and report["coverage"] == 1.0
    # the fake always answers "investigate" -> malicious
    assert report["outcomes"] == {"malicious": 6}
    assert (tmp_path / "state" / "replay" / "latest.json").resolve() == (
        tmp_path / "state" / "replay" / "rtest" / "report.json")
    assert "replay: total=6 triaged=6" in r.stdout


def test_replay_fails_below_min_coverage(tmp_path):
    with FakeApi(mode="never") as api:
        env = _env(tmp_path, STAGING_BASE_URL=api.url, REPLAY_SUITES="dev",
                   REPLAY_LIMIT="3", REPLAY_TAG="rnone", REPLAY_WAIT_MINUTES="0",
                   REPLAY_MIN_COVERAGE="0.5", **ADMIN_ENV)
        r = _run([str(STAGING / "replay.sh")], env)
    assert r.returncode != 0
    report = json.loads((tmp_path / "state" / "replay" / "rnone" / "report.json").read_text())
    assert report["outcomes"] == {"pending": 3}


def test_replay_report_verdict_mapping():
    sys.path.insert(0, str(STAGING / "lib"))
    try:
        import replay_report as rr
    finally:
        sys.path.pop(0)

    def tri(action):
        return {"ai_enrichment": {"ai_triage": {"result": {"recommended_action": action}}}}

    findings = {"a": tri("isolate"), "b": tri("dismiss"), "c": tri("weird"),
                "d": {"ai_enrichment": {"ai_triage_error": "x"}}}
    labels = [{"finding_id": "a", "verdict": "malicious"},
              {"finding_id": "b", "verdict": "malicious"},
              {"finding_id": "c", "verdict": "benign"},
              {"finding_id": "d", "verdict": "benign"},
              {"finding_id": "e", "verdict": "benign"}]
    rep = rr.score(labels, findings.get)
    assert rep["outcomes"] == {"malicious": 1, "benign": 1, "inconclusive": 1,
                               "pending": 1, "missing": 1}
    assert rep["false_benign"] == 1
    assert rep["decided_accuracy"] == 0.5
    assert rep["triaged"] == 3 and rep["total"] == 5


# --------------------------------------------------------------------------
# nightly.sh with stub tools
# --------------------------------------------------------------------------

STUB = """#!/usr/bin/env bash
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$STUB_LOG"
case "$(basename "$0") $*" in
  "git "*"rev-parse --short=12 HEAD") echo 0123456789ab ;;
esac
# swallow stdin for `kubectl exec -i ... python -` and `k3s ctr images import -`
case " $* " in *" - "*) cat >/dev/null ;; esac
if [ -n "${STUB_FAIL:-}" ] && [ "$(basename "$0") $1" = "$STUB_FAIL" ]; then exit 1; fi
exit 0
"""


@pytest.fixture
def nightly_env(tmp_path):
    src = tmp_path / "src"
    (src / "infra").mkdir(parents=True)
    shutil.copytree(STAGING, src / "infra" / "staging")
    shutil.copytree(REPO / "eval" / "corpus" / "v1", src / "eval" / "corpus" / "v1")
    shutil.copytree(REPO / "eval" / "suites", src / "eval" / "suites")
    (src / ".git").mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("git", "docker", "helm", "kubectl", "k3s"):
        p = bindir / tool
        p.write_text(STUB)
        p.chmod(0o755)
    etc = tmp_path / "etc"
    etc.mkdir()
    (etc / "secrets.yaml").write_text('secrets:\n  postgresPassword: "x"\n')
    (etc / "staging.env").write_text("STAGING_HOST=demo.example.test\nSTAGING_LOCAL_MODEL=qwen2.5:0.5b\n")
    log = tmp_path / "calls.log"
    env = _env(tmp_path, PATH=f"{bindir}:{os.environ['PATH']}", STUB_LOG=str(log),
               SMOKE_TRIAGE_TIMEOUT="20", DEMO_LIMIT="3", **ADMIN_ENV)
    return src, env, log


def test_nightly_full_run_with_stubs(tmp_path, nightly_env):
    src, env, log = nightly_env
    with FakeApi(triage_after=0) as api:
        env["STAGING_BASE_URL"] = api.url
        r = _run([str(src / "infra" / "staging" / "nightly.sh")], env, timeout=180)
        assert r.returncode == 0, r.stdout + r.stderr
        assert any(f.startswith("smoke-") for f in api.state.findings)
        assert sum(f.startswith("demo-") for f in api.state.findings) == 3
    calls = log.read_text().splitlines()
    joined = "\n".join(calls)
    # phase 1: update from main
    assert calls[0].startswith("git -C") and "fetch --prune origin main" in calls[0]
    assert "reset -q --hard origin/main" in joined
    # images: three components, tagged with the commit, imported into k3s
    for comp in ("backend", "daemon", "agent"):
        assert f"Dockerfile.{comp} -t staging.local/autosecops/vigil-{comp}:0123456789ab" in joined
    assert joined.count("k3s ctr -n k8s.io images import -") == 3
    # chart rendered before install; install is atomic with staging values + VM secrets
    helm_install = next(c for c in calls if c.startswith("helm upgrade --install"))
    assert calls.index(next(c for c in calls if c.startswith("helm template"))) < calls.index(helm_install)
    for needle in ("--atomic", "--wait", "values-staging.yaml", str(tmp_path / "etc" / "secrets.yaml"),
                   "backend.image.tag=0123456789ab", "agentServe.image.tag=0123456789ab",
                   "global.imageRegistry=staging.local", "ingress.hosts[0].host=demo.example.test",
                   "-n autosecops-staging"):
        assert needle in helm_install, needle
    # local model
    assert "ollama pull qwen2.5:0.5b" in joined
    assert "STAGING_LOCAL_MODEL=qwen2.5:0.5b python -" in joined
    assert calls.index(next(c for c in calls if "manifests/llm.yaml" in c)) < calls.index(helm_install)
    status = json.loads((tmp_path / "state" / "last-run.json").read_text())
    assert status["result"] == "pass" and status["sha"] == "0123456789ab"
    assert status["smoke"]["result"] == "PASS"

    # second run on the same commit: no rebuild, smoke still runs
    log.write_text("")
    with FakeApi(triage_after=0) as api:
        env["STAGING_BASE_URL"] = api.url
        r = _run([str(src / "infra" / "staging" / "nightly.sh")], env, timeout=180)
        assert r.returncode == 0, r.stderr
        assert any(f.startswith("smoke-") for f in api.state.findings)
    assert "docker build" not in log.read_text()
    assert "helm upgrade" not in log.read_text()


def test_nightly_local_registry_pushes(tmp_path, nightly_env):
    src, env, log = nightly_env
    env["STAGING_LOCAL_REGISTRY"] = "1"
    with FakeApi(triage_after=0) as api:
        env["STAGING_BASE_URL"] = api.url
        r = _run([str(src / "infra" / "staging" / "nightly.sh"), "--no-update"], env, timeout=180)
    assert r.returncode == 0, r.stderr
    text = log.read_text()
    assert "docker push -q 127.0.0.1:5000/autosecops/vigil-backend:0123456789ab" in text
    assert "k3s ctr" not in text
    assert "git -C" in text and "fetch" not in text  # --no-update skips phase 1


def test_nightly_helm_failure_marks_run_failed(tmp_path, nightly_env):
    src, env, log = nightly_env
    env["STUB_FAIL"] = "helm upgrade"
    env["STAGING_BASE_URL"] = "http://127.0.0.1:9"  # never reached
    r = _run([str(src / "infra" / "staging" / "nightly.sh"), "--no-update"], env, timeout=180)
    assert r.returncode != 0
    status = json.loads((tmp_path / "state" / "last-run.json").read_text())
    assert status["result"] == "fail" and status["step"] == "helm"
    assert "NIGHTLY: FAIL" in r.stderr


def test_nightly_requires_secrets_file(tmp_path, nightly_env):
    src, env, log = nightly_env
    (tmp_path / "etc" / "secrets.yaml").unlink()
    r = _run([str(src / "infra" / "staging" / "nightly.sh"), "--no-update"], env)
    assert r.returncode != 0 and "secrets.yaml" in r.stderr
