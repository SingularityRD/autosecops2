"""Helm: daemon hot standby and the database backup CronJob (W3.9).

The static tests read values.yaml and the templates; the render tests need the
helm binary (skipped without it) and render a copy of the chart without its
subcharts, as test_medic_helm_flag.py does.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

CHART = Path(__file__).resolve().parents[3] / "infra" / "helm" / "vigil"
TEMPLATES = CHART / "templates"
SCRIPT = CHART / "files" / "backup" / "pg-backup.sh"
needs_helm = pytest.mark.skipif(shutil.which("helm") is None, reason="needs helm")


# -- static -------------------------------------------------------------------------


def _values() -> dict:
    return yaml.safe_load((CHART / "values.yaml").read_text())


def test_leader_election_is_on_by_default_with_sane_timings():
    le = _values()["daemon"]["leaderElection"]
    assert le["enabled"] is True
    assert 0 < le["retrySeconds"] < le["leaseSeconds"]
    assert le["leaseSeconds"] >= 3


def test_replica_count_follows_leader_election_and_is_not_a_value():
    sts = (TEMPLATES / "daemon-statefulset.yaml").read_text()
    assert "replicas: {{ if $ha }}2{{ else }}1{{ end }}" in sts
    assert "replicaCount" not in _values()["daemon"]
    for name in (
        "DAEMON_LEADER_ELECTION_ENABLED",
        "DAEMON_LEADER_LEASE_SECONDS",
        "DAEMON_LEADER_RETRY_SECONDS",
    ):
        assert name in sts


def test_backup_is_off_by_default_and_needs_a_destination():
    backup = _values()["backup"]
    assert backup["enabled"] is False
    assert backup["keepLast"] >= 1
    cron = (TEMPLATES / "backup-cronjob.yaml").read_text()
    assert "concurrencyPolicy: Forbid" in cron
    assert 'files/backup/pg-backup.sh' in cron
    assert "fail " in cron  # no destination / no bucket is refused


def test_postgres_network_policy_admits_the_backup_pod():
    policy = (TEMPLATES / "networkpolicy.yaml").read_text()
    assert '"component" "backup"' in policy


def test_backup_script_is_posix_sh():
    sh = shutil.which("dash") or shutil.which("sh")
    done = subprocess.run([sh, "-n", str(SCRIPT)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


# -- rendered -----------------------------------------------------------------------


@pytest.fixture(scope="module")
def chart(tmp_path_factory) -> Path:
    dest = tmp_path_factory.mktemp("chart") / "vigil"
    shutil.copytree(CHART, dest, ignore=shutil.ignore_patterns("medic-tests"))
    meta = yaml.safe_load((dest / "Chart.yaml").read_text())
    meta.pop("dependencies", None)
    (dest / "Chart.yaml").write_text(yaml.safe_dump(meta))
    (dest / "Chart.lock").unlink(missing_ok=True)
    return dest


def _render(chart: Path, template: str, *sets: str) -> list[dict]:
    done = subprocess.run(
        [
            "helm",
            "template",
            "t",
            str(chart),
            "--set",
            "secrets.jwtSecretKey=x",
            "--show-only",
            f"templates/{template}",
            *[a for s in sets for a in ("--set", s)],
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return [d for d in yaml.safe_load_all(done.stdout) if d]


def _fails(chart: Path, template: str, *sets: str) -> str:
    done = subprocess.run(
        ["helm", "template", "t", str(chart), "--set", "secrets.jwtSecretKey=x"]
        + [a for s in sets for a in ("--set", s)]
        + ["--show-only", f"templates/{template}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode != 0
    return done.stderr


def _daemon_env(sts: dict) -> dict:
    env = sts["spec"]["template"]["spec"]["containers"][0]["env"]
    return {e["name"]: e.get("value") for e in env}


@needs_helm
def test_rendered_statefulset_runs_two_replicas_with_election(chart):
    [sts] = _render(chart, "daemon-statefulset.yaml")
    assert sts["spec"]["replicas"] == 2
    assert sts["spec"]["podManagementPolicy"] == "Parallel"
    env = _daemon_env(sts)
    assert env["DAEMON_LEADER_ELECTION_ENABLED"] == "true"
    assert env["DAEMON_LEADER_LEASE_SECONDS"] == "15"
    assert env["DAEMON_LEADER_RETRY_SECONDS"] == "2"
    anti = sts["spec"]["template"]["spec"]["affinity"]["podAntiAffinity"]
    assert anti["preferredDuringSchedulingIgnoredDuringExecution"]


@needs_helm
def test_rendered_statefulset_is_single_without_election(chart):
    [sts] = _render(chart, "daemon-statefulset.yaml", "daemon.leaderElection.enabled=false")
    assert sts["spec"]["replicas"] == 1
    assert sts["spec"]["podManagementPolicy"] == "OrderedReady"
    assert _daemon_env(sts)["DAEMON_LEADER_ELECTION_ENABLED"] == "false"
    assert "affinity" not in sts["spec"]["template"]["spec"]


@needs_helm
def test_backup_renders_nothing_when_disabled(chart):
    done = subprocess.run(
        ["helm", "template", "t", str(chart), "--set", "secrets.jwtSecretKey=x"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    kinds = [d["kind"] for d in yaml.safe_load_all(done.stdout) if d]
    assert "CronJob" not in kinds


@needs_helm
def test_backup_renders_cronjob_pvc_and_script(chart):
    docs = _render(chart, "backup-cronjob.yaml", "backup.enabled=true")
    by_kind = {d["kind"]: d for d in docs}
    assert set(by_kind) == {"ConfigMap", "PersistentVolumeClaim", "CronJob"}
    assert by_kind["ConfigMap"]["data"]["pg-backup.sh"] == SCRIPT.read_text()
    job = by_kind["CronJob"]["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    [dump] = job["containers"]
    env = {e["name"]: e.get("value") for e in dump["env"]}
    assert env["BACKUP_KEEP_LAST"] == "14" and env["BACKUP_RETENTION_DAYS"] == "30"
    password = next(e for e in dump["env"] if e["name"] == "PGPASSWORD")
    assert "secretKeyRef" in password["valueFrom"]
    claim = [v for v in job["volumes"] if v["name"] == "backup"][0]
    assert claim["persistentVolumeClaim"]["claimName"] == by_kind[
        "PersistentVolumeClaim"
    ]["metadata"]["name"]


@needs_helm
def test_backup_object_store_uploads_after_the_dump(chart):
    docs = _render(
        chart,
        "backup-cronjob.yaml",
        "backup.enabled=true",
        "backup.persistence.enabled=false",
        "backup.objectStore.enabled=true",
        "backup.objectStore.bucket=b",
    )
    kinds = [d["kind"] for d in docs]
    assert "PersistentVolumeClaim" not in kinds
    cron = next(d for d in docs if d["kind"] == "CronJob")
    job = cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    assert [c["name"] for c in job["initContainers"]] == ["pg-dump"]
    assert [c["name"] for c in job["containers"]] == ["upload"]


@needs_helm
def test_backup_without_destination_or_bucket_fails(chart):
    assert "backup.persistence.enabled" in _fails(
        chart, "backup-cronjob.yaml", "backup.enabled=true", "backup.persistence.enabled=false"
    )
    assert "bucket" in _fails(
        chart, "backup-cronjob.yaml", "backup.enabled=true", "backup.objectStore.enabled=true"
    )
