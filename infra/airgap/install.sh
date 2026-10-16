#!/usr/bin/env bash
# Verify and install an AutoSecOps air-gapped bundle.
#
#   install.sh verify  --pubkey KEY [--bundle DIR]
#   install.sh install --pubkey KEY --registry HOST[:PORT] [options] [-- helm args]
#
# The bundle directory is never used in place. Every file is first copied into
# a private staging directory (mktemp -d, mode 0700, under $TMPDIR, which needs
# room for a second copy of the bundle); the checks below run on that copy and
# only that copy is loaded, applied and installed, so changing the bundle
# directory after "bundle verified" has no effect. Nothing is loaded, pushed,
# applied or installed until the copy verifies:
#   1. SHA256SUMS carries a valid signature by KEY. KEY is the public key you got
#      out of band; a key shipped inside the bundle is never used. The method
#      comes from KEY's format: minisign public key -> minisign, PEM Ed25519 ->
#      openssl, any other PEM public key -> cosign.
#   2. Every SHA256SUMS line is a safe relative path and every file matches it.
#   3. The bundle directory holds nothing but the listed regular files, the
#      directories they sit in and SHA256SUMS(.sig|.minisig): no unlisted file,
#      symlink, FIFO, socket, device or empty/unlisted directory.
#   4. manifest.json and images.tsv agree with SHA256SUMS.
#   5. The rule and model archives contain only regular files and directories
#      (no symlink, hard link or device) with safe relative member names.
# Any failure exits 1 without calling docker, ctr, kubectl or helm.
#
# install options:
#   --bundle DIR          bundle directory [the directory of this script]
#   --registry R          local registry images are pushed to / tagged for [required]
#   --loader L            registry (docker load+tag+push, default) | ctr (ctr -n
#                         k8s.io import + tag, on each node) | docker (load + tag)
#   --namespace NS        Kubernetes namespace [autosecops]
#   --release NAME        Helm release name [autosecops]
#   --rules-dir DIR       also unpack the rule corpora into DIR (e.g. a hostPath or
#                         the Compose host's ~/security-detections)
#   --rules-into-backend  stream the rule corpora into the backend pod's
#                         ~/security-detections after the install
#   --skip-model          do not copy the bundled Ollama model into the ollama pod
#   --signing-keys-out F  after the install, write the public signing keys (audit
#                         checkpoints, evidence packs) for the auditor to F
#                         [default: print them]. The chart mints the private
#                         keys into a Secret (W0.36); they never leave the cluster.
#   --dry-run             verify, then print the commands instead of running them
#   -- ARGS               extra arguments for `helm upgrade --install`
#
# Exit codes: 0 success, 1 verification or install failure, 2 usage.
set -euo pipefail

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-2}"; }
fail() { echo "install: REFUSED: $*" >&2; exit 1; }
log() { echo "install: $*" >&2; }

PLACEHOLDER_REGISTRY="registry.airgap.local:5000"

cmd="${1:-}"
case "$cmd" in
  verify|install) shift ;;
  -h|--help) usage 0 ;;
  *) echo "first argument must be verify or install" >&2; usage ;;
esac

bundle="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pubkey="" registry="" loader=registry namespace=autosecops release=autosecops
rules_dir="" rules_into_backend=0 skip_model=0 dry=0
signing_keys_out=""
helm_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) bundle="${2:?--bundle needs a directory}"; shift 2 ;;
    --pubkey) pubkey="${2:?--pubkey needs a file}"; shift 2 ;;
    --registry) registry="${2:?--registry needs a value}"; shift 2 ;;
    --loader) loader="${2:?}"; shift 2 ;;
    --namespace) namespace="${2:?}"; shift 2 ;;
    --release) release="${2:?}"; shift 2 ;;
    --rules-dir) rules_dir="${2:?}"; shift 2 ;;
    --rules-into-backend) rules_into_backend=1; shift ;;
    --skip-model) skip_model=1; shift ;;
    --signing-keys-out) signing_keys_out="${2:?--signing-keys-out needs a file}"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    --) shift; helm_args=("$@"); break ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ -n "$pubkey" ] || { echo "--pubkey is required" >&2; usage; }
if [ "$cmd" = install ]; then
  [ -n "$registry" ] || { echo "--registry is required" >&2; usage; }
  [[ "$registry" =~ ^[A-Za-z0-9.-]+(:[0-9]+)?(/[a-z0-9._/-]+)?$ ]] || { echo "bad --registry '$registry'" >&2; usage; }
  case "$loader" in registry|ctr|docker) ;; *) echo "bad --loader '$loader'" >&2; usage ;; esac
  [[ "$namespace" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || { echo "bad --namespace" >&2; usage; }
  [[ "$release" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || { echo "bad --release" >&2; usage; }
fi
[ -d "$bundle" ] || fail "bundle directory $bundle does not exist"
[ -r "$pubkey" ] || fail "cannot read public key $pubkey"
pubkey="$(cd "$(dirname "$pubkey")" && pwd)/$(basename "$pubkey")"

# src: the bundle as delivered; anyone with write access to it may change it at
# any time, so it is only ever read once, file by file, into $bundle (the
# private staging copy). Everything after the copy reads $bundle only.
src="$(cd "$bundle" && pwd)"
stage="" work=""
cleanup() { rm -rf "$stage" "$work"; }
trap cleanup EXIT
stage="$(mktemp -d "${TMPDIR:-/tmp}/autosecops-airgap.XXXXXXXXXX")"
work="$(mktemp -d "${TMPDIR:-/tmp}/autosecops-airgap-work.XXXXXXXXXX")"
chmod 0700 "$stage" "$work"
bundle="$stage"

# stage_file REL: copy $src/REL to $bundle/REL. dd opens the source with
# O_NOFOLLOW (a symlink swapped in fails) and O_NONBLOCK (a FIFO swapped in
# reads as empty instead of hanging); the copy is hashed afterwards anyway.
stage_file() {
  local rel="$1"
  [ -f "$src/$rel" ] && [ ! -L "$src/$rel" ] || return 1
  mkdir -p "$bundle/$(dirname "$rel")"
  dd if="$src/$rel" of="$bundle/$rel" bs=4M iflag=nofollow,nonblock \
    conv=excl status=none 2>"$work/dd.err" \
    || fail "cannot copy $rel into the staging directory ($(head -n 1 "$work/dd.err")): changed while being copied, or TMPDIR full?"
  [ -f "$bundle/$rel" ] && [ ! -L "$bundle/$rel" ]
}

# --- 1. signature -------------------------------------------------------------
verify_signature() {
  local sums="$bundle/SHA256SUMS" first key_text f
  stage_file SHA256SUMS || fail "SHA256SUMS missing"
  for f in SHA256SUMS.sig SHA256SUMS.minisig; do
    [ ! -e "$src/$f" ] && [ ! -L "$src/$f" ] || stage_file "$f" || fail "$f is not a regular file"
  done
  first="$(head -n 1 "$pubkey")"
  case "$first" in
    *minisign*)
      command -v minisign >/dev/null || fail "public key is a minisign key but minisign is not installed"
      [ -f "$bundle/SHA256SUMS.minisig" ] || fail "SHA256SUMS.minisig missing"
      minisign -V -q -p "$pubkey" -m "$sums" -x "$bundle/SHA256SUMS.minisig" >/dev/null 2>&1 \
        || fail "minisign signature on SHA256SUMS does not verify"
      sig_method=minisign ;;
    "-----BEGIN PUBLIC KEY-----")
      [ -f "$bundle/SHA256SUMS.sig" ] || fail "SHA256SUMS.sig missing"
      key_text="$(openssl pkey -pubin -in "$pubkey" -noout -text 2>/dev/null || true)"
      if [[ "$key_text" == ED25519* ]]; then
        openssl pkeyutl -verify -pubin -inkey "$pubkey" -rawin -in "$sums" \
          -sigfile "$bundle/SHA256SUMS.sig" >/dev/null 2>&1 \
          || fail "Ed25519 signature on SHA256SUMS does not verify"
        sig_method=openssl
      else
        command -v cosign >/dev/null || fail "public key is not Ed25519 (cosign key?) and cosign is not installed"
        cosign verify-blob --key "$pubkey" --signature "$bundle/SHA256SUMS.sig" \
          --insecure-ignore-tlog=true "$sums" >/dev/null 2>&1 \
          || fail "cosign signature on SHA256SUMS does not verify"
        sig_method=cosign
      fi ;;
    *) fail "unrecognised public key format in $pubkey" ;;
  esac
}

# --- 2-4. checksums, completeness, manifest -------------------------------------
declare -A SUM=() DIRS=()
# check_archive REL [z]: members of $bundle/REL are only regular files and
# directories with safe relative names (extraction must not create links,
# devices, or write outside the target directory).
check_archive() {
  local rel="$1" z="${2:-}" line name
  tar -t"${z}"vf "$bundle/$rel" >"$work/members.v" 2>/dev/null || fail "$rel: not a readable archive"
  tar -t"${z}"f "$bundle/$rel" >"$work/members" 2>/dev/null || fail "$rel: not a readable archive"
  while IFS= read -r line; do
    case "${line:0:1}" in
      -|d) ;;
      *) fail "$rel: archive member is not a regular file or directory (link/device): $line" ;;
    esac
  done <"$work/members.v"
  while IFS= read -r name; do
    case "/$name/" in //*|*/../*) fail "$rel: unsafe archive member name: $name" ;; esac
  done <"$work/members"
}

verify_contents() {
  local line hash path n=0 f entry type d
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" =~ ^([0-9a-f]{64})\ \ ([A-Za-z0-9._/+-]+)$ ]] || fail "malformed SHA256SUMS line: $line"
    hash="${BASH_REMATCH[1]}" path="${BASH_REMATCH[2]}"
    case "/$path/" in */../*|*/./*|//*) fail "unsafe path in SHA256SUMS: $path" ;; esac
    case "$path" in SHA256SUMS|SHA256SUMS.sig|SHA256SUMS.minisig) fail "SHA256SUMS lists $path" ;; esac
    [ -z "${SUM[$path]+x}" ] || fail "duplicate SHA256SUMS entry: $path"
    SUM[$path]="$hash"
    n=$((n + 1))
  done <"$bundle/SHA256SUMS"
  [ "$n" -gt 0 ] || fail "SHA256SUMS is empty"
  for path in "${!SUM[@]}"; do
    d="$(dirname "$path")"
    while [ "$d" != . ]; do DIRS[$d]=1; d="$(dirname "$d")"; done
  done

  # Everything in the delivered directory, of every type, must be accounted for.
  find "$src" -mindepth 1 -printf '%y %P\0' >"$work/tree" || fail "cannot list $src"
  while IFS= read -r -d '' entry; do
    type="${entry:0:1}" path="${entry:2}"
    case "$type" in
      f) case "$path" in SHA256SUMS|SHA256SUMS.sig|SHA256SUMS.minisig) continue ;; esac
         [ -n "${SUM[$path]+x}" ] || fail "file not listed in SHA256SUMS: $path" ;;
      d) [ -n "${DIRS[$path]+x}" ] || fail "directory not listed in SHA256SUMS (empty or extra): $path" ;;
      l) fail "symlink in bundle: $path" ;;
      *) fail "non-regular file in bundle (type $type: FIFO, socket or device): $path" ;;
    esac
  done <"$work/tree"

  # Copy each listed file once into the private stage, then check the copy.
  for path in "${!SUM[@]}"; do
    stage_file "$path" || fail "missing file: $path"
    hash="$(sha256sum "$bundle/$path" | cut -d' ' -f1)"
    [ "$hash" = "${SUM[$path]}" ] || fail "checksum mismatch: $path"
  done

  # manifest.json: every listed file appears with the same digest, and nothing else.
  local manifest="$bundle/manifest.json" listed
  [ -n "${SUM[manifest.json]+x}" ] || fail "manifest.json not in SHA256SUMS"
  grep -q '"schema": "autosecops.airgap/v1"' "$manifest" || fail "manifest.json: unknown schema"
  for path in "${!SUM[@]}"; do
    [ "$path" = manifest.json ] && continue
    grep -qF "{\"path\": \"$path\", \"sha256\": \"${SUM[$path]}\"," "$manifest" \
      || fail "manifest.json disagrees with SHA256SUMS on $path"
  done
  listed="$(grep -c '^    {"path": ' "$manifest" || true)"
  [ "$listed" -eq $((n - 1)) ] || fail "manifest.json lists $listed files, SHA256SUMS $((n - 1))"
  local m_method
  m_method="$(sed -n 's/^  "signing": {"method": "\([a-z]*\)"},$/\1/p' "$manifest")"
  [ "$m_method" = "$sig_method" ] || fail "manifest.json says signing method '$m_method', key verified '$sig_method'"

  # images.tsv: every archive is in SHA256SUMS and in the manifest with that digest.
  [ -n "${SUM[images.tsv]+x}" ] || fail "images.tsv not in SHA256SUMS"
  local ref local_path file count=0
  while IFS=$'\t' read -r ref local_path file; do
    [ -n "$ref" ] || continue
    [[ "$file" =~ ^images/[A-Za-z0-9._-]+\.tar$ ]] || fail "images.tsv: bad archive $file"
    [[ "$local_path" =~ ^[a-z0-9._/-]+:[A-Za-z0-9._-]+$ ]] || fail "images.tsv: bad local path $local_path"
    [ -n "${SUM[$file]+x}" ] || fail "images.tsv: $file not in SHA256SUMS"
    grep -qF "\"ref\": \"$ref\", \"local_path\": \"$local_path\", \"file\": \"$file\", \"sha256\": \"${SUM[$file]}\"" "$manifest" \
      || fail "manifest.json disagrees with images.tsv on $ref"
    count=$((count + 1))
  done <"$bundle/images.tsv"
  [ "$count" -gt 0 ] || fail "images.tsv is empty"
  [ "$(grep -c '^    {"ref": ' "$manifest" || true)" -eq "$count" ] || fail "manifest.json and images.tsv list different images"

  # Archives install.sh extracts.
  for path in "${!SUM[@]}"; do
    case "$path" in
      rules/*.tar.gz) check_archive "$path" z ;;
      models/*.tar) check_archive "$path" ;;
    esac
  done
}

sig_method=""
verify_signature
verify_contents
log "bundle verified ($sig_method signature, ${#SUM[@]} files)"
[ "$cmd" = verify ] && exit 0

# --- install --------------------------------------------------------------------
run() {
  if [ "$dry" = 1 ]; then printf '+'; printf ' %q' "$@"; printf '\n'; else "$@"; fi
}
# stdin-redirecting variant: run_in FILE cmd...
run_in() {
  local input="$1"; shift
  if [ "$dry" = 1 ]; then printf '+'; printf ' %q' "$@"; printf ' < %q\n' "$input"; else "$@" <"$input"; fi
}
localize() {  # same rule as airgap_images.py localize
  local ref="$1" first rest
  first="${ref%%/*}"
  if [ "$first" != "$ref" ] && { [[ "$first" == *.* ]] || [[ "$first" == *:* ]] || [ "$first" = localhost ]; }; then
    rest="${ref#*/}"
  else
    rest="$ref"
  fi
  [[ "$rest" == */* ]] || rest="library/$rest"
  printf '%s/%s\n' "${registry%/}" "$rest"
}

version="$(sed -n 's/^  "version": "\(.*\)",$/\1/p' "$bundle/manifest.json")"
chart="$bundle/chart/vigil-$version.tgz"
[ -n "${SUM[chart/vigil-$version.tgz]+x}" ] || fail "chart/vigil-$version.tgz missing"

log "loading images with --loader $loader into $registry"
while IFS=$'\t' read -r ref local_path file <&3; do
  [ -n "$ref" ] || continue
  target="${registry%/}/$local_path"
  case "$loader" in
    registry)
      run docker load -i "$bundle/$file"
      run docker tag "$ref" "$target"
      run docker push "$target" ;;
    docker)
      run docker load -i "$bundle/$file"
      run docker tag "$ref" "$target" ;;
    ctr)
      run ctr -n k8s.io images import "$bundle/$file"
      run ctr -n k8s.io images tag --force "$ref" "$target" ;;
  esac
done 3<"$bundle/images.tsv"

# Point the overlay and the LLM stack at the local registry.
sed "s#$PLACEHOLDER_REGISTRY#${registry%/}#g" "$bundle/values-airgap.yaml" >"$work/values-airgap.yaml"
: >"$work/llm-stack.yaml"
while IFS= read -r line || [ -n "$line" ]; do
  if [[ "$line" =~ ^([[:space:]]*image:[[:space:]]*)([^[:space:]#]+)[[:space:]]*$ ]]; then
    printf '%s%s\n' "${BASH_REMATCH[1]}" "$(localize "${BASH_REMATCH[2]}")" >>"$work/llm-stack.yaml"
  else
    printf '%s\n' "$line" >>"$work/llm-stack.yaml"
  fi
done <"$bundle/k8s/llm-stack.yaml"

if [ "$dry" = 1 ]; then
  printf '+ kubectl create namespace %q --dry-run=client -o yaml | kubectl apply -f -\n' "$namespace"
else
  kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -
fi
run kubectl -n "$namespace" apply -f "$work/llm-stack.yaml"

if [ "$skip_model" = 0 ] && [ -f "$bundle/models/ollama-models.tar" ]; then
  run kubectl -n "$namespace" rollout status deployment/ollama --timeout=600s
  run_in "$bundle/models/ollama-models.tar" kubectl -n "$namespace" exec -i deployment/ollama -- tar -xf - -C /root/.ollama
fi

run helm upgrade --install "$release" "$chart" --namespace "$namespace" \
  -f "$work/values-airgap.yaml" --wait --timeout 15m "${helm_args[@]}"

if [ -n "$rules_dir" ] || [ "$rules_into_backend" = 1 ]; then
  fullname="$release"
  [[ "$release" == *vigil* ]] || fullname="$release-vigil"
  for tarball in "$bundle"/rules/*.tar.gz; do
    [ -f "$tarball" ] || continue
    if [ -n "$rules_dir" ]; then
      run mkdir -p "$rules_dir"
      run tar --no-same-owner -xzf "$tarball" -C "$rules_dir"
    fi
    if [ "$rules_into_backend" = 1 ]; then
      # shellcheck disable=SC2016  # $HOME expands in the pod, not here
      run_in "$tarball" kubectl -n "$namespace" exec -i "deployment/$fullname-backend" -- \
        sh -c 'mkdir -p "$HOME/security-detections" && tar -xzf - -C "$HOME/security-detections"'
    fi
  done
fi
# W0.36: the public halves of the signing keys the chart minted, for the auditor.
# Best effort: a pod that is not up yet leaves a warning, not a failed install.
export_signing_keys() {
  local fullname="$release" target purpose out="${signing_keys_out:-/dev/stdout}"
  [[ "$release" == *vigil* ]] || fullname="$release-vigil"
  if [ "$dry" = 1 ]; then
    printf '+ kubectl -n %q exec statefulset/%q -- python -m core.audit.signing_keys export --purpose audit_checkpoints\n' \
      "$namespace" "$fullname-daemon"
    printf '+ kubectl -n %q exec deployment/%q -- python -m core.audit.signing_keys export --purpose evidence_packs\n' \
      "$namespace" "$fullname-backend"
    return 0
  fi
  if [ -n "$signing_keys_out" ]; then
    : >"$signing_keys_out" || { log "WARNING: cannot write $signing_keys_out"; return 0; }
  fi
  for target in "statefulset/$fullname-daemon audit_checkpoints" "deployment/$fullname-backend evidence_packs"; do
    purpose="${target#* }" target="${target%% *}"
    kubectl -n "$namespace" exec "$target" -- python -m core.audit.signing_keys export \
      --purpose "$purpose" >>"$out" 2>/dev/null \
      || log "WARNING: could not read the $purpose public key from $target; later: kubectl -n $namespace exec $target -- python -m core.audit.signing_keys export"
  done
  log "public signing keys ${signing_keys_out:+written to $signing_keys_out }(give them to the auditor out of band)"
}
export_signing_keys

log "done: release $release in namespace $namespace"
