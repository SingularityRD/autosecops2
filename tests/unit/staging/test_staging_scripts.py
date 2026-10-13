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
        "lib/pins.sh", "systemd/autosecops-staging-nightly.service", "systemd/autosecops-staging-nightly.timer",
        "systemd/autosecops-staging-replay.service", "systemd/autosecops-staging-replay.timer",
    ):
        assert (STAGING / rel).is_file(), rel


LIB_FILES = {
    "api.sh", "cluster.sh", "common.sh", "pins.sh",
    "corpus_to_findings.py", "register_local_model.py", "replay_report.py",
}


@pytest.mark.skipif(not (REPO / ".git").exists(), reason="not a git checkout (e.g. git archive export)")
def test_lib_dir_is_tracked_by_git():
    """Root .gitignore has a Python-template `lib/` rule; infra/staging/lib must
    be negated out of it or a clean clone has no helpers and every script fails."""
    r = _run(["git", "ls-files", "infra/staging/lib"], env=os.environ, cwd=REPO)
    assert r.returncode == 0, r.stderr
    tracked = {Path(line).name for line in r.stdout.splitlines()}
    assert LIB_FILES <= tracked, sorted(LIB_FILES - tracked)
    r = _run(["git", "check-ignore", "-q", "infra/staging/lib/new_helper.sh"], env=os.environ, cwd=REPO)
    assert r.returncode == 1, "new files under infra/staging/lib would be ignored"


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
    # templates: bootstrap.sh fills in the paths it set up
    assert "ExecStart=@STAGING_SRC_DIR@/infra/staging/nightly.sh" in svc
    assert "/opt/autosecops-staging" not in svc
    assert "Type=oneshot" in svc
    rsvc = (STAGING / "systemd" / "autosecops-staging-replay.service").read_text()
    assert "ExecStart=@STAGING_SRC_DIR@/infra/staging/replay.sh" in rsvc
    for unit in (svc, rsvc):
        for var in ("STAGING_SRC_DIR", "STAGING_ETC_DIR", "STAGING_STATE_DIR"):
            assert f"Environment={var}=@{var}@" in unit


def test_bootstrap_renders_units_with_custom_src_dir(tmp_path):
    """Units must run the checkout bootstrap made, not a hard-coded /opt path."""
    sysd = tmp_path / "systemd"
    sysd.mkdir()
    custom = tmp_path / "custom-src"
    env = _env(tmp_path, DRY_RUN="1", STAGING_SRC_DIR=str(custom), SYSTEMD_DIR=str(sysd))
    r = _run(["bash", str(STAGING / "bootstrap.sh")], env)
    assert r.returncode == 0, r.stderr
    assert f"ExecStart={custom}/infra/staging/nightly.sh" in r.stdout
    assert f"ExecStart={custom}/infra/staging/replay.sh" in r.stdout
    assert f"Environment=STAGING_ETC_DIR={tmp_path / 'etc'}" in r.stdout
    assert "@STAGING_" not in r.stdout
    assert "/opt/autosecops-staging" not in r.stdout
    assert list(sysd.iterdir()) == []  # dry run writes nothing


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
    # downloads come from pinned URLs and are checked against committed sha256s
    assert "get.k3s.io" not in out
    assert "raw.githubusercontent.com/k3s-io/k3s/v1.31.4%2Bk3s1/install.sh" in out
    assert "releases/download/v1.31.4%2Bk3s1/k3s" in out
    assert "INSTALL_K3S_SKIP_DOWNLOAD=true" in out
    pins = (STAGING / "lib" / "pins.sh").read_text()
    for var in ("K3S_INSTALL_SH_SHA256", "K3S_BIN_SHA256_amd64", "HELM_SHA256_amd64"):
        sha = pins.split(f"{var}:=", 1)[1][:64]
        assert len(sha) == 64 and all(c in "0123456789abcdef" for c in sha), var
    assert f"sha256 check /tmp/autosecops-k3s/install.sh == {pins.split('K3S_INSTALL_SH_SHA256:=', 1)[1][:64]}" in out
    assert ".sha256sum" not in out  # helm is checked against the pin, not a fetched sum
    assert "sha256 check /tmp/autosecops-helm/helm-v3.16.4-linux-" in out
    assert not (tmp_path / "etc").exists()
    assert not (tmp_path / "state").exists()


def test_bootstrap_refuses_unpinned_k3s_version(tmp_path):
    env = _env(tmp_path, DRY_RUN="1", K3S_VERSION="v1.99.0+k3s1",
               PATH=f"{_no_k3s_path(tmp_path)}")
    r = _run(["bash", str(STAGING / "bootstrap.sh")], env)
    assert r.returncode != 0
    assert "K3S_INSTALL_SH_SHA256" in r.stderr
    assert "curl" not in r.stdout  # refused before downloading anything


def test_verify_sha256(tmp_path):
    f = tmp_path / "blob"
    f.write_bytes(b"hello\n")
    good = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
    script = (f'source "{STAGING}/lib/common.sh"; source "{STAGING}/lib/pins.sh"; '
              'verify_sha256 "$1" "$2" && echo OK')
    ok = _run(["bash", "-c", script, "_", str(f), good], _env(tmp_path))
    assert ok.returncode == 0 and "OK" in ok.stdout, ok.stderr
    bad = _run(["bash", "-c", script, "_", str(f), "0" * 64], _env(tmp_path))
    assert bad.returncode != 0 and "uyuşmuyor" in bad.stderr
    empty = _run(["bash", "-c", script, "_", str(f), ""], _env(tmp_path))
    assert empty.returncode != 0 and "sabitlenmiş sha256 yok" in empty.stderr


def _no_k3s_path(tmp_path: Path) -> str:
    """PATH without a k3s binary, so ensure_k3s always plans an install."""
    return ":".join(p for p in os.environ["PATH"].split(":")
                    if not (Path(p) / "k3s").exists())


def test_write_once_is_atomic_and_rejects_empty(tmp_path):
    """write_once generates to a temp file, refuses an empty/failed result and
    leaves no partial file behind; a good result lands 0600."""
    etc = tmp_path / "etc"
    etc.mkdir()
    fn = 'eval "$(sed -n "/^write_once()/,/^}}/p" "{0}/bootstrap.sh")"; '.format(STAGING)
    base = f'source "{STAGING}/lib/common.sh"; {fn}'
    for gen in ("empty_gen() {{ :; }}", "empty_gen() {{ echo partial; return 1; }}"):
        script = base + gen.format() + '; write_once "$1" empty_gen'
        r = _run(["bash", "-c", script, "_", str(etc / "secrets.yaml")], _env(tmp_path))
        assert r.returncode != 0, gen
        assert list(etc.iterdir()) == [], gen
    # a failing secret source must not produce a file with empty secrets
    gens = 'eval "$(sed -n "/^gen_secrets_yaml()/,/^}}/p" "{0}/bootstrap.sh")"; '.format(STAGING)
    script = base + gens + 'gen_secret() { return 1; }; write_once "$1" gen_secrets_yaml'
    r = _run(["bash", "-c", script, "_", str(etc / "secrets.yaml")], _env(tmp_path))
    assert r.returncode != 0 and list(etc.iterdir()) == []
    script = base + 'good_gen() { echo "a: 1"; }; write_once "$1" good_gen'
    r = _run(["bash", "-c", script, "_", str(etc / "secrets.yaml")], _env(tmp_path))
    assert r.returncode == 0, r.stderr
    assert (etc / "secrets.yaml").read_text() == "a: 1\n"
    assert stat.S_IMODE(os.stat(etc / "secrets.yaml").st_mode) == 0o600
    assert [p.name for p in etc.iterdir()] == ["secrets.yaml"]


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
# record whether the instance still has no admin when helm installs
if [ "$(basename "$0") $1" = "helm upgrade" ] && [ -n "${STAGING_BASE_URL:-}" ]; then
  printf 'bootstrap-state %s\\n' "$(curl -s --max-time 2 "$STAGING_BASE_URL/api/auth/bootstrap" || true)" >> "$STUB_LOG"
fi
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
    installs = [i for i, c in enumerate(calls) if c.startswith("helm upgrade --install")]
    assert len(installs) == 2, installs
    first, second = (calls[i] for i in installs)
    assert calls.index(next(c for c in calls if c.startswith("helm template"))) < installs[0]
    # first install: ingress OFF and no admin yet; the admin is created over the
    # loopback port-forward before the second install turns the ingress on
    assert first.rstrip().endswith("--atomic --wait --timeout 20m")
    assert "--set ingress.enabled=false" in first
    assert '"required": true' in calls[installs[0] + 1] or '"required":true' in calls[installs[0] + 1]
    assert "ingress.enabled=false" not in second
    assert '"required": false' in calls[installs[1] + 1] or '"required":false' in calls[installs[1] + 1]
    assert (tmp_path / "state" / "admin-bootstrapped").is_file()
    helm_install = second
    for needle in ("--atomic", "--wait", "values-staging.yaml", str(tmp_path / "etc" / "secrets.yaml"),
                   "backend.image.tag=0123456789ab", "agentServe.image.tag=0123456789ab",
                   "global.imageRegistry=staging.local",
                   'ingress.hosts=[{"host":"demo.example.test","paths":[{"path":"/","pathType":"Prefix"}]}]',
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


def test_nightly_existing_admin_single_install(tmp_path, nightly_env):
    """Once the first admin is recorded, upgrades keep the ingress on throughout."""
    src, env, log = nightly_env
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "admin-bootstrapped").write_text("x\n")
    with FakeApi(triage_after=0) as api:
        env["STAGING_BASE_URL"] = api.url
        r = _run([str(src / "infra" / "staging" / "nightly.sh"), "--no-update"], env, timeout=180)
    assert r.returncode == 0, r.stderr
    installs = [c for c in log.read_text().splitlines() if c.startswith("helm upgrade --install")]
    assert len(installs) == 1 and "ingress.enabled=false" not in installs[0]


def test_nightly_exec_failure_records_status(tmp_path, nightly_env):
    """The EXIT trap stays armed across exec: if the updated nightly.sh cannot
    be exec'd, last-run.json still says fail at step exec."""
    src, env, log = nightly_env
    script = src / "infra" / "staging" / "nightly.sh"
    script.chmod(0o644)  # run via bash; the exec of the same path then fails
    r = _run(["bash", str(script)], env)
    assert r.returncode != 0
    status = json.loads((tmp_path / "state" / "last-run.json").read_text())
    assert status["result"] == "fail" and status["step"] == "exec"
    assert "NIGHTLY: FAIL" in r.stderr


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


def test_nightly_rejects_bad_host(tmp_path, nightly_env):
    src, env, log = nightly_env
    (tmp_path / "etc" / "staging.env").write_text("STAGING_HOST='evil\"],\"x\":[\"'\n")
    r = _run([str(src / "infra" / "staging" / "nightly.sh"), "--no-update"], env)
    assert r.returncode != 0 and "geçersiz STAGING_HOST" in r.stderr
    assert "helm" not in log.read_text()
