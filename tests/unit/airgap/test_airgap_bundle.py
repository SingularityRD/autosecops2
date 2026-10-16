"""Air-gapped install bundle (infra/airgap): build, verify, tamper, install.

Fully offline: image archives are fixture bytes, rule corpora are fake clones,
docker/helm/kubectl/ctr are stubs that record their calls. The bundle is signed
with a throwaway OpenSSL Ed25519 key.
"""

from __future__ import annotations

import hashlib
import json
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
AIRGAP = REPO / "infra" / "airgap"
BUILD = AIRGAP / "build-bundle.sh"
INSTALL = AIRGAP / "install.sh"
VERSION = "0.7.1"
PLACEHOLDER = "registry.airgap.local:5000"
LOCAL_REG = "reg.example.internal:5000"
LOADERS = ("docker", "helm", "kubectl", "ctr")

sys.path.insert(0, str(AIRGAP))
import airgap_images  # noqa: E402

STUB = """#!/usr/bin/env bash
printf '%s' "$(basename "$0")" >>"$CALLS/calls.log"
printf ' %s' "$@" >>"$CALLS/calls.log"
printf '\\n' >>"$CALLS/calls.log"
if [ -n "${WAIT_FOR:-}" ]; then
  for _ in $(seq 600); do [ -e "$WAIT_FOR" ] && break; sleep 0.1; done
fi
prev=""
for a in "$@"; do
  if [ "$prev" = "-f" ] && [ -f "$a" ]; then cp "$a" "$CALLS/$(basename "$0")-$(basename "$a")"; fi
  if [ -f "$a" ]; then
    printf '%s %s %s\n' "$(basename "$0")" "$a" "$(sha256sum "$a" | cut -d' ' -f1)" >>"$CALLS/hashes.log"
  fi
  prev="$a"
done
if [ "$(basename "$0")" = kubectl ] && [ "${1:-}" = create ]; then echo "kind: Namespace"; fi
case " $* " in *" -f - "*) cat >/dev/null ;; esac
exit 0
"""


def _path_without(*tools: str) -> str:
    keep = [
        d
        for d in os.environ.get("PATH", "").split(os.pathsep)
        if d and not any(os.path.exists(os.path.join(d, t)) for t in tools)
    ]
    return os.pathsep.join(keep)


def _stubs(tmp: Path) -> tuple[Path, Path]:
    bin_dir, calls = tmp / "stubbin", tmp / "calls"
    bin_dir.mkdir()
    calls.mkdir()
    for tool in LOADERS:
        (bin_dir / tool).write_text(STUB)
        (bin_dir / tool).chmod(0o755)
    return bin_dir, calls


def _env(bin_dir: Path, calls: Path, path: str | None = None) -> dict:
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{path if path is not None else env['PATH']}"
    env["CALLS"] = str(calls)
    env["AIRGAP_PYTHON"] = sys.executable
    return env


def _keypair(dest: Path, name: str) -> tuple[Path, Path]:
    key, pub = dest / f"{name}.key", dest / f"{name}.pub"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)], check=True
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True
    )
    return key, pub


def _calls(calls: Path) -> list[str]:
    log = calls / "calls.log"
    return log.read_text().splitlines() if log.exists() else []


def _hashes(calls: Path) -> dict[str, str]:
    """{path argument: sha256 of that file when the stub tool ran}."""
    log = calls / "hashes.log"
    out = {}
    for line in log.read_text().splitlines() if log.exists() else []:
        _tool, path, digest = line.rsplit(" ", 2)
        out[path] = digest
    return out


def _sums(bundle: Path) -> dict[str, str]:
    return {
        rel: digest
        for digest, rel in (
            line.split("  ", 1)
            for line in (bundle / "SHA256SUMS").read_text().splitlines()
        )
    }


def _images():
    return airgap_images.Enumerator(REPO, VERSION).run()


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("airgap")
    key, pub = _keypair(tmp, "release")
    images_dir = tmp / "image-archives"
    images_dir.mkdir()
    for entry in _images():
        (images_dir / Path(entry["file"]).name).write_bytes(
            b"fake docker-archive for " + entry["ref"].encode() + os.urandom(64)
        )
    rules = tmp / "security-detections"
    for clone in ("sigma", "security_content"):
        (rules / clone / "rules").mkdir(parents=True)
        (rules / clone / "rules" / "r.yml").write_text(f"title: {clone}\n")
    # An in-tree file symlink and a hard link: stored as plain files.
    (rules / "sigma" / "rules" / "link.yml").symlink_to("r.yml")
    os.link(rules / "sigma" / "rules" / "r.yml", rules / "sigma" / "hard.yml")
    bin_dir, calls = _stubs(tmp)
    (bin_dir / "helm").unlink()  # no helm: the chart is packaged with tar
    out = tmp / "dist"
    proc = subprocess.run(
        [
            str(BUILD),
            "--version",
            VERSION,
            "--out",
            str(out),
            "--images-from",
            str(images_dir),
            "--skip-ollama-model",
            "--rules-dir",
            str(rules),
            "--key",
            str(key),
            "--no-tar",
        ],
        env=_env(bin_dir, calls, _path_without("helm")),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert _calls(calls) == [], "the build called docker/helm despite --images-from"
    return {
        "bundle": out / f"autosecops-airgap-{VERSION}",
        "key": key,
        "pub": pub,
        "tmp": tmp,
        "images_dir": images_dir,
    }


@pytest.fixture
def bundle(built, tmp_path):
    copy = tmp_path / "bundle"
    shutil.copytree(built["bundle"], copy, symlinks=True)
    return copy


@pytest.fixture
def stubs(tmp_path):
    return _stubs(tmp_path)


def _run(
    cmd: str, bundle: Path, pub: Path, stubs, *extra: str, path: str | None = None
):
    bin_dir, calls = stubs
    args = [str(INSTALL), cmd, "--bundle", str(bundle), "--pubkey", str(pub)]
    if cmd == "install":
        args += ["--registry", LOCAL_REG]
    return subprocess.run(
        args + list(extra),
        env=_env(bin_dir, calls, path),
        capture_output=True,
        text=True,
    )


def _resign(bundle: Path, key: Path) -> None:
    """Rewrite SHA256SUMS from the files on disk and sign it with *key*."""
    lines = []
    for f in sorted(p for p in bundle.rglob("*") if p.is_file()):
        rel = f.relative_to(bundle).as_posix()
        if rel.startswith("SHA256SUMS"):
            continue
        digest = subprocess.run(
            ["sha256sum", str(f)], capture_output=True, text=True, check=True
        ).stdout.split()[0]
        lines.append(f"{digest}  {rel}\n")
    (bundle / "SHA256SUMS").write_text("".join(lines))
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(key),
            "-rawin",
            "-in",
            str(bundle / "SHA256SUMS"),
            "-out",
            str(bundle / "SHA256SUMS.sig"),
        ],
        check=True,
    )


# --- bundle contents ----------------------------------------------------------


def test_bundle_layout_and_manifest(built):
    b = built["bundle"]
    manifest = json.loads((b / "manifest.json").read_text())
    assert manifest["schema"] == "autosecops.airgap/v1"
    assert manifest["version"] == VERSION
    assert manifest["signing"] == {"method": "openssl"}
    assert manifest["ollama_model"] == {"name": None, "file": None}
    refs = {i["ref"] for i in manifest["images"]}
    assert refs == {e["ref"] for e in _images()}
    for img in manifest["images"]:
        assert (b / img["file"]).is_file()
    for path in (
        "chart/vigil-0.7.1.tgz",
        "values-airgap.yaml",
        "airgap.env",
        "k8s/llm-stack.yaml",
        "install.sh",
        "images.tsv",
        "docs/README-airgap.md",
        "docs/autosecops-docs.tar.gz",
        "SHA256SUMS",
        "SHA256SUMS.sig",
    ):
        assert (b / path).is_file(), path
    corpora = {r["clone_name"]: r["file"] for r in manifest["rule_corpora"]}
    assert corpora["sigma"] == "rules/sigma.tar.gz"
    assert corpora["security_content"] == "rules/security_content.tar.gz"
    assert corpora["detection-rules"] is None  # no local clone -> recorded as absent
    sums = dict(
        reversed(line.split("  ", 1))
        for line in (b / "SHA256SUMS").read_text().splitlines()
    )
    assert set(sums) == {f["path"] for f in manifest["files"]} | {"manifest.json"}


def test_packaged_chart_has_version_and_no_subcharts(built, tmp_path):
    subprocess.run(
        [
            "tar",
            "-xzf",
            str(built["bundle"] / "chart" / "vigil-0.7.1.tgz"),
            "-C",
            str(tmp_path),
        ],
        check=True,
    )
    chart = yaml.safe_load((tmp_path / "vigil" / "Chart.yaml").read_text())
    assert chart["version"] == chart["appVersion"] == VERSION
    assert "dependencies" not in chart
    assert not (tmp_path / "vigil" / "Chart.lock").exists()


def test_rule_snapshot_unpacks_to_clone(built, tmp_path):
    subprocess.run(
        [
            "tar",
            "-xzf",
            str(built["bundle"] / "rules" / "sigma.tar.gz"),
            "-C",
            str(tmp_path),
        ],
        check=True,
    )
    assert (tmp_path / "sigma" / "rules" / "r.yml").read_text() == "title: sigma\n"


def test_rule_snapshot_has_no_links(built):
    listing = subprocess.run(
        ["tar", "-tzvf", str(built["bundle"] / "rules" / "sigma.tar.gz")],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    assert listing and all(line[0] in "-d" for line in listing), listing
    names = " ".join(listing)
    assert "sigma/rules/link.yml" in names and "sigma/hard.yml" in names


def test_bundled_airgap_env_is_the_w34_profile(built):
    assert (built["bundle"] / "airgap.env").read_bytes() == (
        AIRGAP / "airgap.env"
    ).read_bytes()


@pytest.mark.parametrize("target", ["outside", "dangling", "directory"])
def test_build_refuses_rule_symlink_it_cannot_inline(target, built, tmp_path, stubs):
    rules = tmp_path / "security-detections"
    (rules / "sigma").mkdir(parents=True)
    (rules / "sigma" / "r.yml").write_text("title: x\n")
    secret = tmp_path / "build-machine-secret"
    secret.write_text("do not ship\n")
    link = rules / "sigma" / "evil"
    (stubs[0] / "helm").unlink()  # no helm: the chart is packaged with tar
    if target == "outside":
        link.symlink_to(secret)
    elif target == "dangling":
        link.symlink_to(tmp_path / "nope")
    else:
        (rules / "sigma" / "sub").mkdir()
        link.symlink_to("sub")
    proc = subprocess.run(
        [
            str(BUILD),
            "--version",
            VERSION,
            "--out",
            str(tmp_path / "o"),
            "--images-from",
            str(built["images_dir"]),
            "--skip-ollama-model",
            "--rules-dir",
            str(rules),
            "--key",
            str(built["key"]),
            "--no-tar",
        ],
        env=_env(stubs[0], stubs[1], _path_without("helm")),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stderr
    assert "symlink" in proc.stderr and str(link) in proc.stderr, proc.stderr


# --- verification -------------------------------------------------------------


def test_verify_accepts_untampered_bundle(bundle, built, stubs):
    proc = _run("verify", bundle, built["pub"], stubs)
    assert proc.returncode == 0, proc.stderr
    assert "bundle verified (openssl" in proc.stderr
    assert _calls(stubs[1]) == []


def _flip_byte(b: Path, _key: Path) -> None:
    f = next((b / "images").iterdir())
    data = bytearray(f.read_bytes())
    data[10] ^= 0x01
    f.write_bytes(bytes(data))


def _delete_file(b: Path, _key: Path) -> None:
    (b / "values-airgap.yaml").unlink()


def _add_unlisted(b: Path, _key: Path) -> None:
    (b / "images" / "extra.tar").write_bytes(b"smuggled")


def _edit_sums(b: Path, _key: Path) -> None:
    s = b / "SHA256SUMS"
    text = s.read_text()
    s.write_text(("0" * 64) + text[64:])


def _drop_signature(b: Path, _key: Path) -> None:
    (b / "SHA256SUMS.sig").unlink()


def _sign_with_attacker_key(b: Path, _key: Path) -> None:
    attacker, _ = _keypair(b.parent, "attacker")
    _flip_byte(b, attacker)
    _resign(b, attacker)


def _manifest_digest_changed_and_resigned(b: Path, key: Path) -> None:
    m = b / "manifest.json"
    text = m.read_text()
    m.write_text(
        re.sub(
            r'("path": "values-airgap.yaml", "sha256": ")[0-9a-f]{64}',
            lambda x: x.group(1) + "f" * 64,
            text,
        )
    )
    _resign(b, key)  # even with a valid signature the manifest must agree


def _images_tsv_redirected_and_resigned(b: Path, key: Path) -> None:
    t = b / "images.tsv"
    t.write_text(
        t.read_text().replace("postgres:16-alpine\t", "evil/postgres:16-alpine\t", 1)
    )
    _resign(b, key)


def _symlink_added(b: Path, _key: Path) -> None:
    (b / "docs" / "link").symlink_to("/etc/passwd")


def _traversal_entry_resigned(b: Path, key: Path) -> None:
    _resign(b, key)
    s = b / "SHA256SUMS"
    s.write_text(s.read_text() + ("a" * 64) + "  ../outside\n")
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            str(key),
            "-rawin",
            "-in",
            str(s),
            "-out",
            str(b / "SHA256SUMS.sig"),
        ],
        check=True,
    )


def _fifo_added(b: Path, _key: Path) -> None:
    os.mkfifo(b / "docs" / "pipe")


def _empty_dir_added(b: Path, _key: Path) -> None:
    (b / "extra").mkdir()


def _nested_empty_dir_added(b: Path, _key: Path) -> None:
    (b / "images" / "sub").mkdir()


def _replace_resigned(b: Path, key: Path, rel: str, data: bytes) -> None:
    """Swap *rel* for *data*, fix its manifest digest and re-sign (a signer
    who shipped a hostile archive)."""
    old = _sums(b)[rel]
    (b / rel).write_bytes(data)
    new = hashlib.sha256(data).hexdigest()
    m = b / "manifest.json"
    m.write_text(m.read_text().replace(old, new))
    _resign(b, key)


def _rule_tar(tmp: Path, member: str) -> bytes:
    src = tmp / "rt"
    (src / "sigma").mkdir(parents=True)
    (src / "sigma" / "r.yml").write_text("x\n")
    if member == "symlink":
        (src / "sigma" / "evil").symlink_to("/etc/passwd")
    else:
        os.link(src / "sigma" / "r.yml", src / "sigma" / "hard")
    out = tmp / "rt.tar.gz"
    subprocess.run(["tar", "-C", str(src), "-czf", str(out), "sigma"], check=True)
    shutil.rmtree(src)
    data = out.read_bytes()
    out.unlink()
    return data


def _rule_tar_with_symlink_resigned(b: Path, key: Path) -> None:
    _replace_resigned(b, key, "rules/sigma.tar.gz", _rule_tar(b.parent, "symlink"))


def _rule_tar_with_hardlink_resigned(b: Path, key: Path) -> None:
    _replace_resigned(b, key, "rules/sigma.tar.gz", _rule_tar(b.parent, "hardlink"))


TAMPERS = {
    "fifo": (_fifo_added, "non-regular file"),
    "empty-dir": (_empty_dir_added, "directory not listed"),
    "nested-empty-dir": (_nested_empty_dir_added, "directory not listed"),
    "rule-tar-symlink": (_rule_tar_with_symlink_resigned, "not a regular file"),
    "rule-tar-hardlink": (_rule_tar_with_hardlink_resigned, "not a regular file"),
    "byte-flipped-image": (_flip_byte, "checksum mismatch"),
    "deleted-file": (_delete_file, "missing file"),
    "unlisted-file": (_add_unlisted, "not listed"),
    "edited-SHA256SUMS": (_edit_sums, "signature"),
    "signature-removed": (_drop_signature, "SHA256SUMS.sig missing"),
    "attacker-key": (_sign_with_attacker_key, "signature"),
    "manifest-digest": (
        _manifest_digest_changed_and_resigned,
        "manifest.json disagrees",
    ),
    "images-tsv-redirect": (
        _images_tsv_redirected_and_resigned,
        "manifest.json disagrees",
    ),
    "symlink": (_symlink_added, "symlink"),
    "path-traversal": (_traversal_entry_resigned, "unsafe path"),
}


@pytest.mark.parametrize("cmd", ["verify", "install"])
@pytest.mark.parametrize("tamper", sorted(TAMPERS))
def test_tampered_bundle_is_refused_before_any_loader(
    tamper, cmd, bundle, built, stubs
):
    mutate, reason = TAMPERS[tamper]
    mutate(bundle, built["key"])
    proc = _run(cmd, bundle, built["pub"], stubs)
    assert proc.returncode == 1, proc.stderr
    assert "REFUSED" in proc.stderr and reason in proc.stderr, proc.stderr
    assert _calls(stubs[1]) == [], f"{cmd} called a loader on a tampered bundle"


def test_wrong_public_key_is_refused(bundle, built, stubs, tmp_path):
    _, other_pub = _keypair(tmp_path, "other")
    proc = _run("install", bundle, other_pub, stubs)
    assert proc.returncode == 1 and "does not verify" in proc.stderr
    assert _calls(stubs[1]) == []


def test_public_key_inside_bundle_is_not_trusted(bundle, built, stubs, tmp_path):
    attacker, attacker_pub = _keypair(tmp_path, "attacker")
    shutil.copy(attacker_pub, bundle / "docs" / "release.pub")
    _resign(bundle, attacker)
    proc = _run("verify", bundle, built["pub"], stubs)
    assert proc.returncode == 1


@pytest.mark.parametrize(
    "tool,first_line",
    [
        ("minisign", "untrusted comment: minisign public key ABCD"),
    ],
)
def test_minisign_key_without_minisign_is_an_explicit_error(
    bundle, stubs, tmp_path, tool, first_line
):
    pub = tmp_path / "mini.pub"
    pub.write_text(
        first_line + "\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3\n"
    )
    proc = _run("verify", bundle, pub, stubs, path=_path_without(tool))
    assert proc.returncode == 1 and f"{tool} is not installed" in proc.stderr


def test_cosign_key_without_cosign_is_an_explicit_error(bundle, stubs, tmp_path):
    key = tmp_path / "p256.key"
    pub = tmp_path / "p256.pub"
    subprocess.run(
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            str(key),
        ],
        check=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True
    )
    proc = _run("verify", bundle, pub, stubs, path=_path_without("cosign"))
    assert proc.returncode == 1 and "cosign is not installed" in proc.stderr


@pytest.mark.parametrize("method", ["minisign", "cosign"])
def test_build_with_missing_signer_fails_clearly(method, tmp_path, stubs):
    key = tmp_path / "k"
    key.write_text("dummy\n")
    proc = subprocess.run(
        [
            str(BUILD),
            "--version",
            VERSION,
            "--out",
            str(tmp_path / "o"),
            "--key",
            str(key),
            "--sign-method",
            method,
        ],
        env=_env(*stubs, _path_without(method)),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1 and f"{method} is not installed" in proc.stderr
    assert _calls(stubs[1]) == []


# --- install --------------------------------------------------------------------


def test_install_with_registry_loader(bundle, built, stubs):
    bin_dir, calls = stubs
    proc = _run(
        "install",
        bundle,
        built["pub"],
        stubs,
        "--namespace",
        "soc",
        "--release",
        "autosecops",
        "--",
        "--set",
        "backend.replicaCount=1",
    )
    assert proc.returncode == 0, proc.stderr
    log = _calls(calls)
    hashes = _hashes(calls)
    sums = _sums(bundle)
    loads = [line.split()[-1] for line in log if line.startswith("docker load -i ")]
    assert len(loads) == len(_images())
    for path in loads:
        # Loaded from the private staging copy, never from the bundle directory.
        assert not path.startswith(str(bundle)), path
        rel = path.split("/images/", 1)[1]
        assert hashes[path] == sums["images/" + rel]
    assert not Path(loads[0]).exists(), "staging copy not cleaned up"
    for entry in _images():
        target = airgap_images.localize(entry["ref"], LOCAL_REG)
        assert any(p.endswith("/" + entry["file"]) for p in loads)
        assert f"docker tag {entry['ref']} {target}" in log
        assert f"docker push {target}" in log
    assert any(line.startswith("kubectl -n soc apply -f ") for line in log)
    # W0.36: after the chart minted the signing keys, their public halves.
    exports = [line for line in log if "core.audit.signing_keys export" in line]
    assert exports == [
        "kubectl -n soc exec statefulset/autosecops-vigil-daemon -- python -m "
        "core.audit.signing_keys export --purpose audit_checkpoints",
        "kubectl -n soc exec deployment/autosecops-vigil-backend -- python -m "
        "core.audit.signing_keys export --purpose evidence_packs",
    ]
    assert log.index(exports[0]) > next(
        i for i, line in enumerate(log) if line.startswith("helm ")
    )
    helm = [line for line in log if line.startswith("helm ")]
    assert len(helm) == 1
    assert re.match(
        rf"helm upgrade --install autosecops \S+/chart/vigil-{VERSION}\.tgz --namespace soc -f ",
        helm[0],
    ), helm[0]
    assert str(bundle) not in helm[0]
    assert "values-airgap.yaml" in helm[0] and helm[0].endswith(
        "--set backend.replicaCount=1"
    )
    # The order: images first, then the cluster.
    first_kube = next(
        i for i, line in enumerate(log) if line.startswith(("kubectl", "helm"))
    )
    assert all(line.startswith("docker") for line in log[:first_kube])

    values = (calls / "helm-values-airgap.yaml").read_text()
    assert PLACEHOLDER not in values and LOCAL_REG in values
    stack = yaml.safe_load_all((calls / "kubectl-llm-stack.yaml").read_text())
    stack_images = {img for doc in stack for img in airgap_images._images_in(doc)}
    assert stack_images == {
        airgap_images.localize(e["ref"], LOCAL_REG)
        for e in _images()
        if any(s.startswith("llm-stack:") for s in e["sources"])
    }


def test_install_ctr_loader_and_rules_dir(bundle, built, stubs, tmp_path):
    rules = tmp_path / "rules-out"
    proc = _run(
        "install",
        bundle,
        built["pub"],
        stubs,
        "--loader",
        "ctr",
        "--rules-dir",
        str(rules),
    )
    assert proc.returncode == 0, proc.stderr
    log = _calls(stubs[1])
    assert not any(line.startswith("docker") for line in log)
    assert sum(line.startswith("ctr -n k8s.io images import") for line in log) == len(
        _images()
    )
    assert (rules / "sigma" / "rules" / "r.yml").is_file()


def test_bundle_swapped_after_verification_installs_verified_bytes(
    bundle, built, stubs, tmp_path
):
    """TOCTOU: a writer replaces every image (and the chart) in the bundle
    directory right after "bundle verified"; the loaders must still get the
    verified bytes."""
    bin_dir, calls = stubs
    go = tmp_path / "go"
    env = _env(bin_dir, calls)
    env["WAIT_FOR"] = str(go)
    sums = _sums(bundle)
    proc = subprocess.Popen(
        [
            str(INSTALL),
            "install",
            "--bundle",
            str(bundle),
            "--pubkey",
            str(built["pub"]),
            "--registry",
            LOCAL_REG,
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    err = []
    try:
        for line in proc.stderr:
            err.append(line)
            if "bundle verified" in line:
                break
        assert any("bundle verified" in e for e in err), "".join(err)
        evil = b"attacker image " + os.urandom(16)
        for f in (bundle / "images").iterdir():
            f.unlink()
            f.write_bytes(evil)
        (bundle / f"chart/vigil-{VERSION}.tgz").write_bytes(evil)
        go.touch()
        err.append(proc.stderr.read())
        assert proc.wait(timeout=300) == 0, "".join(err)
    finally:
        if proc.poll() is None:
            proc.kill()
    hashes = _hashes(calls)
    evil_digest = hashlib.sha256(evil).hexdigest()
    assert evil_digest not in hashes.values()
    loads = [ln.split()[-1] for ln in _calls(calls) if ln.startswith("docker load -i ")]
    assert len(loads) == len(_images())
    for path in loads:
        rel = "images/" + path.split("/images/", 1)[1]
        assert hashes[path] == sums[rel]
    charts = [p for p in hashes if p.endswith(f"/chart/vigil-{VERSION}.tgz")]
    assert charts and all(hashes[p] == sums[f"chart/vigil-{VERSION}.tgz"] for p in charts)


def test_staging_directory_is_private(bundle, built, stubs, tmp_path):
    """The verified copy lives in a fresh 0700 directory under $TMPDIR."""
    bin_dir, calls = stubs
    tmpdir = tmp_path / "tmpdir"
    tmpdir.mkdir()
    probe = bin_dir / "docker"
    probe.write_text(
        STUB.replace(
            "exit 0\n",
            'case "$1" in load) stat -c "%a %n" "$(dirname "$(dirname "$3")")" '
            '>>"$CALLS/stage.log" ;; esac\nexit 0\n',
        )
    )
    env = _env(bin_dir, calls)
    env["TMPDIR"] = str(tmpdir)
    proc = subprocess.run(
        [
            str(INSTALL),
            "install",
            "--bundle",
            str(bundle),
            "--pubkey",
            str(built["pub"]),
            "--registry",
            LOCAL_REG,
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    modes = {line.split()[0] for line in (calls / "stage.log").read_text().splitlines()}
    assert modes == {"700"}
    dirs = {line.split()[1] for line in (calls / "stage.log").read_text().splitlines()}
    assert all(d.startswith(str(tmpdir) + "/") for d in dirs)
    assert list(tmpdir.iterdir()) == [], "staging directories left behind"


def test_install_dry_run_prints_and_calls_nothing(bundle, built, stubs):
    proc = _run("install", bundle, built["pub"], stubs, "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert "+ helm upgrade --install autosecops" in proc.stdout
    assert (
        "+ kubectl -n autosecops exec statefulset/autosecops-vigil-daemon -- "
        "python -m core.audit.signing_keys export --purpose audit_checkpoints"
    ) in proc.stdout
    assert _calls(stubs[1]) == []


def test_install_requires_registry(bundle, built, stubs):
    bin_dir, calls = stubs
    proc = subprocess.run(
        [
            str(INSTALL),
            "install",
            "--bundle",
            str(bundle),
            "--pubkey",
            str(built["pub"]),
        ],
        env=_env(bin_dir, calls),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2 and _calls(calls) == []


# --- dry-run enumeration ---------------------------------------------------------


def test_build_dry_run_enumerates_without_docker(stubs):
    proc = subprocess.run(
        [str(BUILD), "--dry-run", "--version", VERSION],
        env=_env(*stubs),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    refs = {line.split("\t")[0] for line in proc.stdout.splitlines()}
    for expected in (
        "ghcr.io/singularityrd/autosecops-backend:0.7.1",
        "ghcr.io/singularityrd/autosecops-daemon:0.7.1",
        "ghcr.io/singularityrd/autosecops-agent:0.7.1",
        "postgres:16-alpine",
        "redis:7-alpine",
        "maximhq/bifrost:v2.2.1",
        "curlimages/curl:8.10.1",
    ):
        assert expected in refs
    assert any(r.startswith("ollama/ollama:") for r in refs)
    assert _calls(stubs[1]) == []


def test_dry_run_json_and_ollama_override(stubs):
    proc = subprocess.run(
        [
            str(BUILD),
            "--dry-run",
            "--version",
            "1.2.3",
            "--format",
            "json",
            "--ollama-image",
            "ollama/ollama:0.9.0",
        ],
        env=_env(*stubs),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    refs = {e["ref"] for e in json.loads(proc.stdout)}
    assert (
        "ollama/ollama:0.9.0" in refs
        and "ghcr.io/singularityrd/autosecops-backend:1.2.3" in refs
    )


# --- values-airgap.yaml and chart ----------------------------------------------------


@pytest.mark.parametrize(
    "ref,expected",
    [
        ("ghcr.io/singularityrd/autosecops-backend:1", "R/singularityrd/autosecops-backend:1"),
        ("postgres:16-alpine", "R/library/postgres:16-alpine"),
        ("maximhq/bifrost:v2.2.1", "R/maximhq/bifrost:v2.2.1"),
        ("localhost/x:1", "R/library/x:1"),
        ("reg:5000/a/b:1", "R/a/b:1"),
    ],
)
def test_localize(ref, expected, stubs):
    assert airgap_images.localize(ref, "R") == expected
    out = subprocess.run(
        [
            sys.executable,
            str(AIRGAP / "airgap_images.py"),
            "localize",
            "--registry",
            "R",
            ref,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == expected


def _overlay():
    return yaml.safe_load((AIRGAP / "values-airgap.yaml").read_text())


def test_overlay_images_are_the_localized_bundle_images():
    en = airgap_images.Enumerator(REPO, VERSION)
    en.chart()
    overlay = _overlay()
    g = overlay["global"]
    rendered = set()
    for path, suffix, enabled in airgap_images.APP_COMPONENTS:
        if en._enabled(enabled):
            rendered.add(
                f"{g['imageRegistry']}/{g['imageNamespace']}-{suffix}:{VERSION}"
            )
    for path, _ in airgap_images.THIRD_PARTY:
        img = airgap_images.dig(overlay, path + ("image",))
        if img and any(
            "helm:" + ".".join(path) in e["sources"] for e in en.images.values()
        ):
            rendered.add(f"{img['repository']}:{img['tag']}")
    expected = {airgap_images.localize(ref, PLACEHOLDER) for ref in en.images}
    assert rendered == expected


def test_overlay_turns_off_remote_and_telemetry():
    o = _overlay()
    c = o["config"]
    assert c["MCP_AUTO_CONNECT_ON_STARTUP"] == "false"
    assert c["VIGIL_MCP_ENABLED"] == "false"
    assert c["VIGIL_OTEL_ENABLED"] == "false"
    assert o["otelCollector"]["enabled"] is False
    assert o["observability"]["serviceMonitor"]["enabled"] is False
    assert o["networkPolicies"]["enabled"] is True
    assert o["networkPolicies"]["egress"]["inClusterOnly"] is True
    text = (AIRGAP / "values-airgap.yaml").read_text()
    for public in ("ghcr.io", "docker.io", "quay.io"):
        assert public not in re.sub(r"#.*", "", text)


def _airgap_env() -> dict[str, str]:
    env = {}
    for line in (AIRGAP / "airgap.env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            env[key] = value
    return env


def test_overlay_switches_match_airgap_env():
    """values-airgap.yaml (Helm) and airgap.env (host/Compose, W3.4) turn the
    same things off: every on/off switch in airgap.env that the code reads is
    in the overlay with the same value, and no shared key disagrees."""
    from tests.unit._ratchets.test_helm_env_names_are_read import _read_names

    env, config = _airgap_env(), _overlay()["config"]
    switches = {
        k: v
        for k, v in env.items()
        if v in ("false", "true", "console") and k in _read_names()
    }
    assert switches, "airgap.env has no switches?"
    missing = sorted(k for k in switches if k not in config)
    assert not missing, f"airgap.env switches missing from values-airgap.yaml: {missing}"
    differ = sorted(
        k
        for k in set(env) & set(config)
        if not k.endswith("_URL") and env[k] != config[k]
    )
    assert not differ, f"values-airgap.yaml and airgap.env disagree on {differ}"


def test_overlay_config_keys_are_read_by_the_code():
    from tests.unit._ratchets.test_helm_env_names_are_read import _read_names

    unread = sorted(set(_overlay()["config"]) - _read_names())
    assert not unread, f"values-airgap.yaml config keys nothing reads: {unread}"


def test_bifrost_tag_matches_compose():
    compose = (REPO / "infra" / "docker" / "docker-compose.yml").read_text()
    tag = re.search(r"maximhq/bifrost:\$\{BIFROST_IMAGE_TAG:-([^}]+)\}", compose).group(
        1
    )
    assert (
        f"image: maximhq/bifrost:{tag}"
        in (AIRGAP / "k8s" / "llm-stack.yaml").read_text()
    )


def test_rule_clone_names_follow_the_service():
    names = airgap_images.rule_clone_names(REPO)
    assert names and "sigma" in names
    src = (REPO / "core" / "detections" / "detection_rules_service.py").read_text()
    for n in names:
        assert f'"clone_name": "{n}"' in src


def test_networkpolicy_default_branch_unchanged():
    tpl = (
        REPO / "infra" / "helm" / "vigil" / "templates" / "networkpolicy.yaml"
    ).read_text()
    m = re.search(
        r"\{\{- if \(\.Values\.networkPolicies\.egress\)\.inClusterOnly \}\}(.*?)"
        r"\{\{- else \}\}\n(.*?)\{\{- end \}\}",
        tpl,
        re.S,
    )
    assert m, "inClusterOnly branch not found"
    in_cluster, default = m.groups()
    assert [ln.strip() for ln in default.strip().splitlines()][-2:] == [
        "egress:",
        "- {}",
    ]
    assert "namespaceSelector: {}" in in_cluster
    assert "0.0.0.0/0" not in in_cluster and "- {}" not in in_cluster
    values = yaml.safe_load(
        (REPO / "infra" / "helm" / "vigil" / "values.yaml").read_text()
    )
    assert values["networkPolicies"]["egress"] == {
        "inClusterOnly": False,
        "extraCIDRs": [],
    }


def test_image_namespace_reaches_the_bundled_overlay(tmp_path):
    """--image-namespace moves where the app images are pushed (images.tsv);
    the bundled values-airgap.yaml must name the same namespace, or every app
    pod pulls an app image path that the registry does not hold."""
    ns = "example/other"
    key, _pub = _keypair(tmp_path, "release")
    images_dir = tmp_path / "image-archives"
    images_dir.mkdir()
    entries = airgap_images.Enumerator(REPO, VERSION, image_namespace=ns).run()
    for entry in entries:
        (images_dir / Path(entry["file"]).name).write_bytes(b"fake " + os.urandom(16))
    bin_dir, calls = _stubs(tmp_path)
    (bin_dir / "helm").unlink()
    out = tmp_path / "dist"
    proc = subprocess.run(
        [str(BUILD), "--version", VERSION, "--out", str(out), "--images-from",
         str(images_dir), "--image-namespace", ns, "--skip-ollama-model",
         "--rules-dir", str(tmp_path / "no-rules"), "--key", str(key), "--no-tar"],
        env=_env(bin_dir, calls, _path_without("helm")),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    overlay = yaml.safe_load(
        (out / f"autosecops-airgap-{VERSION}" / "values-airgap.yaml").read_text()
    )
    assert overlay["global"]["imageNamespace"] == ns
    pushed = {e["local_path"] for e in entries}
    assert f"{ns}-backend:{VERSION}" in pushed


def test_bad_image_namespace_is_refused(tmp_path):
    proc = subprocess.run(
        [str(BUILD), "--version", VERSION, "--image-namespace", "a#b", "--key", "x"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "bad --image-namespace" in proc.stderr


# --- image names agree with what the release publishes ------------------------------

RELEASE_WORKFLOW = REPO / ".github" / "workflows" / "release.yml"


def _release_images(version: str) -> set[str]:
    """<IMAGE_PREFIX>-<component>:<version> for every image release.yml builds."""
    wf = yaml.safe_load(RELEASE_WORKFLOW.read_text())
    prefix = wf["env"]["IMAGE_PREFIX"]
    comps = [i["component"] for i in wf["jobs"]["build-images"]["strategy"]["matrix"]["include"]]
    assert prefix and comps
    return {f"{prefix}-{c}:{version}" for c in comps}


def _app_refs(refs) -> set[str]:
    """App images: those named after a release component (not third-party)."""
    return {r for r in refs if r.startswith("ghcr.io/")}


def test_airgap_bundle_pulls_the_release_images():
    refs = {e["ref"] for e in airgap_images.Enumerator(REPO, VERSION).run()}
    assert _app_refs(refs) == _release_images(VERSION)


@pytest.mark.skipif(shutil.which("helm") is None, reason="needs helm")
@pytest.mark.parametrize("airgap", [False, True], ids=["default", "values-airgap"])
def test_helm_chart_renders_the_release_images(tmp_path, airgap):
    chart = tmp_path / "vigil"
    shutil.copytree(REPO / "infra" / "helm" / "vigil", chart,
                    ignore=shutil.ignore_patterns("medic-tests", "charts"))
    meta = yaml.safe_load((chart / "Chart.yaml").read_text())
    meta.pop("dependencies", None)
    (chart / "Chart.yaml").write_text(yaml.safe_dump(meta))
    (chart / "Chart.lock").unlink(missing_ok=True)
    version = str(meta["appVersion"])
    args = ["helm", "template", "t", str(chart), "--set", "secrets.jwtSecretKey=x"]
    if airgap:
        args += ["-f", str(AIRGAP / "values-airgap.yaml")]
    else:
        args += ["--set", "postgresql.bitnami.enabled=false",
                 "--set", "redis.bitnami.enabled=false",
                 "--set", "otelCollector.enabled=false"]
    done = subprocess.run(args, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    images = set(re.findall(r'image:\s*"?([^"\s]+)', done.stdout))
    expected = _release_images(version)
    if airgap:
        expected = {airgap_images.localize(r, PLACEHOLDER) for r in expected}
        app = {i for i in images if "-backend:" in i or "-daemon:" in i or "-agent:" in i}
    else:
        app = _app_refs(images)
    assert app == expected


# --- build failures and the model pull ----------------------------------------------


def _archives(tmp: Path, **kw) -> Path:
    d = tmp / "image-archives"
    d.mkdir()
    for entry in airgap_images.Enumerator(REPO, VERSION, **kw).run():
        (d / Path(entry["file"]).name).write_bytes(b"fake " + os.urandom(16))
    return d


def test_failed_build_leaves_no_partial_bundle(tmp_path, stubs):
    key, _pub = _keypair(tmp_path, "release")
    images_dir = _archives(tmp_path)
    victim = sorted(images_dir.iterdir())[-1]
    victim.unlink()  # the build dies on this image, after creating the bundle
    out = tmp_path / "dist"
    args = [str(BUILD), "--version", VERSION, "--out", str(out), "--images-from",
            str(images_dir), "--skip-ollama-model", "--rules-dir",
            str(tmp_path / "no-rules"), "--key", str(key)]
    (stubs[0] / "helm").unlink()  # the chart is packaged with tar
    env = _env(*stubs, path=_path_without("helm"))
    proc = subprocess.run(args, env=env, capture_output=True, text=True)
    assert proc.returncode == 1
    assert f"has no {victim.name}" in proc.stderr
    assert list(out.iterdir()) == []
    # ... so the next run is not stopped by "already exists".
    victim.write_bytes(b"fake")
    proc = subprocess.run(args, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert (out / f"autosecops-airgap-{VERSION}.tar").is_file()


def test_model_pull_gets_the_proxy_and_the_overridden_ollama_image(tmp_path):
    key, _pub = _keypair(tmp_path, "release")
    image = "example/ollama-cpu:1.0"
    images_dir = _archives(tmp_path, ollama_image=image)
    bin_dir, calls = _stubs(tmp_path)
    # docker run (the pull) fails: the build goes on without a model.
    (bin_dir / "docker").write_text(STUB.replace("exit 0", "exit 1"))
    ca = tmp_path / "proxy-ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    env = _env(bin_dir, calls, _path_without("helm"))
    env.update(HTTPS_PROXY="http://127.0.0.1:3128", NO_PROXY="localhost",
               AIRGAP_CA_BUNDLE=str(ca))
    for v in ("http_proxy", "HTTP_PROXY", "https_proxy", "no_proxy"):
        env.pop(v, None)
    (bin_dir / "helm").unlink()
    out = tmp_path / "dist"
    proc = subprocess.run(
        [str(BUILD), "--version", VERSION, "--out", str(out), "--images-from",
         str(images_dir), "--ollama-image", image, "--ollama-model", "m:1",
         "--rules-dir", str(tmp_path / "no-rules"), "--key", str(key), "--no-tar"],
        env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "could not pull Ollama model m:1" in proc.stderr
    runs = [c for c in _calls(calls) if c.startswith("docker run")]
    assert len(runs) == 1
    run = runs[0]
    assert " -e HTTPS_PROXY " in run and " -e NO_PROXY " in run
    assert " --network host " in run
    assert f" -v {ca}:/airgap-ca.crt:ro -e SSL_CERT_FILE=/airgap-ca.crt " in run
    assert f" {image} " in run and run.endswith(" m:1")
