#!/usr/bin/env bash
# Build the AutoSecOps air-gapped install bundle (run on a machine WITH network).
#
#   infra/airgap/build-bundle.sh --version V [options]
#
# Produces <out>/autosecops-airgap-<V>/ (and a .tar of it unless --no-tar):
#   images/*.tar            one `docker save` archive per image the Helm chart,
#                           Compose (default + --compose-profiles) and the
#                           in-cluster LLM stack use
#   images.tsv              ref <TAB> local path <TAB> archive (install.sh reads it)
#   chart/vigil-<V>.tgz     the chart, version/appVersion = V, no subcharts
#   values-airgap.yaml      overlay pointing every image at the local registry
#   airgap.env              W3.4 environment profile for host-native / Compose
#   k8s/llm-stack.yaml      Bifrost + Ollama for the cluster
#   models/ollama-models.tar  Ollama model store (only if the model was pulled)
#   rules/<clone>.tar.gz    snapshots of local DetectionRulesService clones
#                           (regular files and directories only: in-tree file
#                           symlinks are dereferenced, any other link refuses)
#   docs/                   offline docs (this README and docs/ as a tarball)
#   install.sh              the installer (verify it before trusting it, README)
#   manifest.json           what is in the bundle, with every sha256
#   SHA256SUMS              GNU sha256sum list of every file above
#   SHA256SUMS.sig|.minisig signature over SHA256SUMS
#
# Options:
#   --version V             release version (image tags, chart version) [required]
#   --out DIR               output directory [dist/airgap]
#   --dry-run               print the enumerated images and exit; nothing is pulled
#   --format tsv|json       dry-run output format [tsv]
#   --images-from DIR       take images/<archive>.tar from DIR instead of pulling
#                           (archive names as printed by --dry-run)
#   --image-registry R      registry of the app images [values.yaml global]
#   --image-namespace N     namespace of the app images [values.yaml global]
#   --compose-profiles P    comma-separated Compose profiles to include [daemon]
#   --ollama-image REF      override the Ollama image in k8s/llm-stack.yaml
#   --ollama-model M        model to pull into the bundle [llama3.1:8b]
#   --ollama-models-dir D   use an existing Ollama model store (~/.ollama) instead
#                           of pulling
#   --skip-ollama-model     do not bundle a model (recorded as absent)
#   --rules-dir DIR         where the rule clones live [~/security-detections]
#   --sign-method M         auto|cosign|minisign|openssl [auto: from --key's format]
#   --key FILE              signing key (cosign / minisign secret key, or PEM
#                           Ed25519 private key for openssl)  [required unless dry-run]
#   --no-tar                leave the bundle as a directory only
#
# Env: AIRGAP_PYTHON (python with PyYAML) [python3]; COSIGN_PASSWORD for cosign.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${AIRGAP_PYTHON:-python3}"

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-2}"; }
die() { echo "build-bundle: $*" >&2; exit 1; }
log() { echo "build-bundle: $*" >&2; }

version="" out="$REPO/dist/airgap" dry=0 format=tsv images_from="" registry="" namespace=""
profiles="daemon" ollama_image="" ollama_model="llama3.1:8b" models_dir="" skip_model=0
rules_dir="${HOME:-/root}/security-detections" sign_method=auto key="" make_tar=1
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="${2:?--version needs a value}"; shift 2 ;;
    --out) out="${2:?}"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    --format) format="${2:?}"; shift 2 ;;
    --images-from) images_from="${2:?}"; shift 2 ;;
    --image-registry) registry="${2:?}"; shift 2 ;;
    --image-namespace) namespace="${2:?}"; shift 2 ;;
    --compose-profiles) profiles="${2-}"; shift 2 ;;
    --ollama-image) ollama_image="${2:?}"; shift 2 ;;
    --ollama-model) ollama_model="${2:?}"; shift 2 ;;
    --ollama-models-dir) models_dir="${2:?}"; shift 2 ;;
    --skip-ollama-model) skip_model=1; shift ;;
    --rules-dir) rules_dir="${2:?}"; shift 2 ;;
    --sign-method) sign_method="${2:?}"; shift 2 ;;
    --key) key="${2:?}"; shift 2 ;;
    --no-tar) make_tar=0; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$version" ] || { echo "--version is required" >&2; usage; }
[[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._+-]*$ ]] || die "bad --version '$version'"
[ -z "$namespace" ] || [[ "$namespace" =~ ^[a-z0-9]([a-z0-9._/-]*[a-z0-9])?$ ]] || die "bad --image-namespace '$namespace'"
case "$format" in tsv|json) ;; *) die "--format must be tsv or json" ;; esac

list_args=(list --version "$version" --repo "$REPO" --compose-profiles "$profiles")
[ -z "$registry" ] || list_args+=(--image-registry "$registry")
[ -z "$namespace" ] || list_args+=(--image-namespace "$namespace")
[ -z "$ollama_image" ] || list_args+=(--ollama-image "$ollama_image")

if [ "$dry" = 1 ]; then
  exec "$PY" "$HERE/airgap_images.py" "${list_args[@]}" --format "$format"
fi

# --- signing key ------------------------------------------------------------
[ -n "$key" ] || die "--key is required (see README: İmzalama anahtarı)"
[ -r "$key" ] || die "cannot read key $key"
if [ "$sign_method" = auto ]; then
  first="$(head -n 1 "$key")"
  case "$first" in
    *minisign*) sign_method=minisign ;;
    *SIGSTORE*|*COSIGN*) sign_method=cosign ;;
    "-----BEGIN PRIVATE KEY-----")
      key_text="$(openssl pkey -in "$key" -noout -text 2>/dev/null || true)"
      [[ "$key_text" == ED25519* ]] || die "$key is a PEM key but not Ed25519"
      sign_method=openssl ;;
    *) die "cannot tell the key type of $key; pass --sign-method" ;;
  esac
fi
case "$sign_method" in
  cosign|minisign) command -v "$sign_method" >/dev/null || die "$sign_method is not installed" ;;
  openssl) command -v openssl >/dev/null || die "openssl is not installed" ;;
  *) die "--sign-method must be auto, cosign, minisign or openssl" ;;
esac

# --- link-free archives -----------------------------------------------------
# install.sh refuses any archive member that is not a regular file or a
# directory, so the rule and model tarballs are built without links: a symlink
# to a file inside the tree is stored as that file's contents; a symlink that
# dangles, points to a directory, or leaves the tree (it could pull in a file
# of this build machine) stops the build. Hard links are stored as copies.
check_links() {
  local root link target
  root="$(cd "$1" && pwd -P)"
  while IFS= read -r -d '' link; do
    target="$(realpath -e -- "$link" 2>/dev/null)" || die "dangling symlink $link"
    case "$target" in "$root"/*) ;; *) die "symlink $link points outside $root ($target)" ;; esac
    [ ! -d "$target" ] || die "symlink $link points to a directory; not bundled"
  done < <(find "$root" -type l -print0)
}
# tar_tree ARCHIVE PARENT NAME [tar flag]: archive PARENT/NAME without links.
tar_tree() {
  local archive="$1" parent="$2" name="$3" z="${4:-}" bad
  check_links "$parent/$name"
  tar -C "$parent" --sort=name --owner=0 --group=0 --numeric-owner \
    --dereference --hard-dereference -c"${z}"f "$archive" "$name"
  bad="$(tar -t"${z}"vf "$archive" | grep -v '^[-d]' | head -n 1 || true)"
  [ -z "$bad" ] || die "$archive has a member that is not a file or directory: $bad"
}

# --- layout -----------------------------------------------------------------
name="autosecops-airgap-$version"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
bundle="$out/$name"
[ ! -e "$bundle" ] || die "$bundle already exists; remove it or pick another --out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$bundle"/{images,chart,k8s,rules,docs,models}

images_json="$work/images.json"
"$PY" "$HERE/airgap_images.py" "${list_args[@]}" --format json >"$images_json"
mapfile -t image_rows < <("$PY" -c '
import json, sys
for e in json.load(open(sys.argv[1])):
    print("\t".join((e["ref"], e["local_path"], e["file"])))
' "$images_json")
[ "${#image_rows[@]}" -gt 0 ] || die "no images enumerated"

# --- 1. images --------------------------------------------------------------
: >"$bundle/images.tsv"
for row in "${image_rows[@]}"; do
  IFS=$'\t' read -r ref local_path file <<<"$row"
  dest="$bundle/$file"
  if [ -n "$images_from" ] && [ -f "$images_from/$(basename "$file")" ]; then
    log "image $ref <- $images_from"
    cp "$images_from/$(basename "$file")" "$dest"
  elif [ -n "$images_from" ]; then
    die "$images_from has no $(basename "$file") for $ref"
  else
    command -v docker >/dev/null || die "docker is needed to pull $ref (or use --images-from)"
    log "image $ref: pull + save"
    docker pull "$ref" >&2
    docker save -o "$dest" "$ref"
  fi
  printf '%s\t%s\t%s\n' "$ref" "$local_path" "$file" >>"$bundle/images.tsv"
done

# --- 2. chart ---------------------------------------------------------------
cp -R "$REPO/infra/helm/vigil" "$work/vigil"
rm -rf "$work/vigil/charts" "$work/vigil/Chart.lock" "$work/vigil/medic-tests"
"$PY" - "$work/vigil/Chart.yaml" "$version" <<'EOF'
import sys, yaml
path, version = sys.argv[1], sys.argv[2]
chart = yaml.safe_load(open(path))
chart["version"] = version
chart["appVersion"] = version
# Bitnami postgresql/redis and the OTEL collector are off in the air-gap
# profile; their charts are not in the bundle.
chart.pop("dependencies", None)
open(path, "w").write(yaml.safe_dump(chart, sort_keys=False))
EOF
if command -v helm >/dev/null; then
  helm package "$work/vigil" --destination "$bundle/chart" >&2
else
  log "helm not found: packaging the chart with tar"
  tar -C "$work" --sort=name --owner=0 --group=0 --numeric-owner -czf "$bundle/chart/vigil-$version.tgz" vigil
fi
[ -f "$bundle/chart/vigil-$version.tgz" ] || die "chart package missing"
# The overlay names the app images <registry>/<global.imageNamespace>-<c>; with
# --image-namespace the bundle (and install.sh) pushes them under that
# namespace, so the bundled overlay must say the same or every app pod pulls a
# path that is not in the local registry.
if [ -n "$namespace" ]; then
  sed -E "s#^(  imageNamespace:).*#\\1 $namespace#" "$HERE/values-airgap.yaml" >"$bundle/values-airgap.yaml"
  grep -qxF "  imageNamespace: $namespace" "$bundle/values-airgap.yaml" \
    || die "could not set global.imageNamespace in the bundled values-airgap.yaml"
else
  cp "$HERE/values-airgap.yaml" "$bundle/values-airgap.yaml"
fi
cp "$HERE/airgap.env" "$bundle/airgap.env"
if [ -n "$ollama_image" ]; then
  sed -E "s#^([[:space:]]*image:[[:space:]]*)ollama/ollama:.*#\\1$ollama_image#" \
    "$HERE/k8s/llm-stack.yaml" >"$bundle/k8s/llm-stack.yaml"
else
  cp "$HERE/k8s/llm-stack.yaml" "$bundle/k8s/llm-stack.yaml"
fi

# --- 3. Ollama model ----------------------------------------------------------
model_file=""
if [ "$skip_model" = 1 ]; then
  log "ollama model: skipped"
elif [ -n "$models_dir" ]; then
  [ -d "$models_dir/models" ] || die "$models_dir has no models/ directory"
  tar_tree "$bundle/models/ollama-models.tar" "$models_dir" models
  model_file="models/ollama-models.tar"
else
  ollama_ref="$(awk -F'\t' '$1 ~ /ollama\/ollama:/ { print $1; exit }' "$bundle/images.tsv")"
  mkdir -p "$work/ollama"
  if command -v docker >/dev/null && [ -n "$ollama_ref" ] && docker run --rm \
      -v "$work/ollama:/root/.ollama" --entrypoint /bin/sh "$ollama_ref" \
      -c 'ollama serve >/dev/null 2>&1 & sleep 3; ollama pull "$0"' "$ollama_model" >&2; then
    tar_tree "$bundle/models/ollama-models.tar" "$work/ollama" models
    model_file="models/ollama-models.tar"
  else
    log "WARNING: could not pull Ollama model $ollama_model; bundle has no model (manifest: file=null)"
  fi
fi

# --- 4. rule corpora ----------------------------------------------------------
rules_tsv="$work/rules.tsv"
: >"$rules_tsv"
while read -r clone; do
  [ -n "$clone" ] || continue
  if [ -d "$rules_dir/$clone" ]; then
    log "rules: $clone"
    tar_tree "$bundle/rules/$clone.tar.gz" "$rules_dir" "$clone" z
    printf '%s\trules/%s.tar.gz\n' "$clone" "$clone" >>"$rules_tsv"
  else
    log "WARNING: no local clone $rules_dir/$clone; not in the bundle"
    printf '%s\t\n' "$clone" >>"$rules_tsv"
  fi
done < <("$PY" "$HERE/airgap_images.py" rules --repo "$REPO")

# --- 5. docs + installer --------------------------------------------------------
cp "$HERE/README.md" "$bundle/docs/README-airgap.md"
docs=()
for d in README.md docs infra/helm/vigil/README.md; do [ -e "$REPO/$d" ] && docs+=("$d"); done
tar -C "$REPO" --exclude='docs/wp' --sort=name --owner=0 --group=0 --numeric-owner \
  -czf "$bundle/docs/autosecops-docs.tar.gz" "${docs[@]}"
cp "$HERE/install.sh" "$bundle/install.sh"
chmod 0755 "$bundle/install.sh"
rmdir "$bundle/models" 2>/dev/null || true
rmdir "$bundle/rules" 2>/dev/null || true

# --- 6. manifest + SHA256SUMS --------------------------------------------------
"$PY" - "$bundle" "$version" "$sign_method" "$images_json" "$rules_tsv" "$ollama_model" \
  "$model_file" "$skip_model" <<'EOF'
import datetime, hashlib, json, os, sys
bundle, version, method, images_json, rules_tsv, model, model_file, skipped = sys.argv[1:]

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

files = []
for root, _, names in os.walk(bundle):
    for n in names:
        rel = os.path.relpath(os.path.join(root, n), bundle)
        if rel in ("manifest.json", "SHA256SUMS", "SHA256SUMS.sig", "SHA256SUMS.minisig"):
            continue
        files.append({"path": rel, "sha256": sha(os.path.join(bundle, rel)),
                      "size": os.path.getsize(os.path.join(bundle, rel))})
files.sort(key=lambda f: f["path"])
digest = {f["path"]: f["sha256"] for f in files}
images = []
for e in json.load(open(images_json)):
    images.append({"ref": e["ref"], "local_path": e["local_path"], "file": e["file"],
                   "sha256": digest[e["file"]], "sources": e["sources"]})
rules = []
for line in open(rules_tsv):
    clone, _, path = line.rstrip("\n").partition("\t")
    rules.append({"clone_name": clone, "file": path or None})
manifest = {
    "schema": "autosecops.airgap/v1",
    "version": version,
    "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "signing": {"method": method},
    "ollama_model": {"name": None if skipped == "1" else model, "file": model_file or None},
    "rule_corpora": rules,
}
# One entry per line so install.sh can cross-check it with grep (it has no JSON parser).
lines = ["{"]
for key, value in manifest.items():
    lines.append(f"  {json.dumps(key)}: {json.dumps(value)},")
lines.append('  "images": [')
lines.append(",\n".join("    " + json.dumps(i) for i in images))
lines.append("  ],")
lines.append('  "files": [')
lines.append(",\n".join("    " + json.dumps(f) for f in files))
lines.append("  ]")
lines.append("}")
with open(os.path.join(bundle, "manifest.json"), "w") as fh:
    fh.write("\n".join(lines) + "\n")
json.load(open(os.path.join(bundle, "manifest.json")))  # well-formed
sums = dict(digest, **{"manifest.json": sha(os.path.join(bundle, "manifest.json"))})
with open(os.path.join(bundle, "SHA256SUMS"), "w") as fh:
    for path in sorted(sums):
        fh.write(f"{sums[path]}  {path}\n")
EOF

# --- 7. sign ----------------------------------------------------------------------
case "$sign_method" in
  openssl)
    openssl pkeyutl -sign -inkey "$key" -rawin -in "$bundle/SHA256SUMS" -out "$bundle/SHA256SUMS.sig" ;;
  minisign)
    minisign -S -s "$key" -m "$bundle/SHA256SUMS" -x "$bundle/SHA256SUMS.minisig" ;;
  cosign)
    cosign sign-blob --yes --key "$key" --tlog-upload=false \
      --output-signature "$bundle/SHA256SUMS.sig" "$bundle/SHA256SUMS" >&2 ;;
esac
log "signed SHA256SUMS ($sign_method)"

if [ "$make_tar" = 1 ]; then
  tar -C "$out" -cf "$out/$name.tar" "$name"
  log "bundle: $out/$name.tar"
fi
echo "$bundle"
