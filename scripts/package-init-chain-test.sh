#!/usr/bin/env bash
set -euo pipefail

# Qualify the chart's signed-package init sequence without touching a live
# installation. A disposable key signs the probe package; the package travels
# through the offline bundle into a short-lived local registry. Only the
# pinned image pulls and the registry hops use networking; key generation,
# signing and every verification stage run with --network none.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"

for command in docker oras jq curl shasum timeout python3 go; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
platform="${NATIVE_INIT_PLATFORM:-$(docker_platform)}"
case "$platform" in
  linux/amd64 | linux/arm64) ;;
  *) echo "signed package qualification supports only linux/amd64 or linux/arm64" >&2; exit 1 ;;
esac
for image in "$oras_image" "$cosign_image" "$registry_image"; do
  require_image "$image" "$platform"
done
# quiet hides a step's progress chatter but replays it when the step fails.
quiet() {
  local output
  if ! output="$("$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi
}

workspace="$(mktemp -d "${TMPDIR:-/tmp}/package-init-chain.XXXXXX")"
run_id="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
runtime_image="stellwerk-plugin-runtime-init-chain:$run_id"
registry="package-init-registry-$run_id"
plugin="package-init-plugin-$run_id"
cleanup() {
  docker rm -f "package-init-tampered-$run_id" "package-init-wrong-$run_id" "$plugin" "$registry" >/dev/null 2>&1 || true
  docker image rm "$runtime_image" >/dev/null 2>&1 || true
  rm -rf -- "$workspace"
}
trap cleanup EXIT
chmod 0755 "$workspace"

mkdir -p "$workspace/context"
CGO_ENABLED=0 GOOS=linux GOARCH="${platform#linux/}" GOWORK=off \
  go build -trimpath -o "$workspace/context/runtime-linux-${platform#linux/}" "$root/runtime"
cp "$root/Dockerfile.runtime" "$workspace/context/Dockerfile.runtime"
timeout -k 5s 120s docker build --quiet --network=none --platform "$platform" \
  --file "$workspace/context/Dockerfile.runtime" --tag "$runtime_image" "$workspace/context" >/dev/null

# Disposable publisher keys. Empty passwords are acceptable only because the
# keys never leave this workspace.
"$root/scripts/build-package.sh" 1.0.0 "$workspace/source" >/dev/null
for key in approved wrong; do
  mkdir -m 0700 "$workspace/$key"
  COSIGN_PASSWORD='' quiet offline_cosign --mount "type=bind,src=$workspace/$key,dst=/keys" --workdir /keys \
    -- generate-key-pair
done
if cmp -s "$workspace/approved/cosign.pub" "$workspace/wrong/cosign.pub"; then
  echo "wrong-key fixture equals the approved key" >&2
  exit 1
fi
COSIGN_PASSWORD='' quiet "$root/scripts/sign-layout-manifest.sh" "$workspace/source" "$workspace/approved/cosign.key"

# Offline transfer: bundle, unpack elsewhere, verify before anything is pushed.
"$root/scripts/offline-bundle.sh" "$workspace/source" "$workspace/bundle.tar" >/dev/null
mkdir "$workspace/transfer"
tar -C "$workspace/transfer" -xf "$workspace/bundle.tar"
quiet "$root/scripts/verify-layout-manifest.sh" "$workspace/transfer" "$workspace/approved/cosign.pub"
if "$root/scripts/verify-layout-manifest.sh" "$workspace/transfer" "$workspace/wrong/cosign.pub" >/dev/null 2>&1; then
  echo "offline verification accepted the wrong public key" >&2
  exit 1
fi
cp -R "$workspace/transfer" "$workspace/transfer-tampered"
plugin_layer="$(jq -er '.layers[] | select(.mediaType == "application/vnd.stellwerk.plugin.executable.v1") | .digest' \
  "$workspace/transfer/oci-manifest.json" | head -n 1)"
tampered_blob="$workspace/transfer-tampered/oci-layout/blobs/sha256/${plugin_layer#sha256:}"
chmod u+w "$tampered_blob"
printf 'x' >>"$tampered_blob"
if "$root/scripts/verify-layout-manifest.sh" "$workspace/transfer-tampered" "$workspace/approved/cosign.pub" >/dev/null 2>&1; then
  echo "offline verification accepted a tampered executable blob" >&2
  exit 1
fi

release="$workspace/transfer/release.json"
digest="$(jq -er '.packageDigest | select(test("^sha256:[0-9a-f]{64}$"))' "$release")"
manifest_hash="$(jq -er '.manifestSHA256 | select(test("^[0-9a-f]{64}$"))' "$release")"
plugin_id="$(jq -er '.pluginId' "$release")"
plugin_version="$(jq -er '.pluginVersion' "$release")"
test "sha256:$(shasum -a 256 "$workspace/transfer/oci-manifest.json" | awk '{print $1}')" = "$digest"

mkdir -m 0777 "$workspace/package" "$workspace/tampered" "$workspace/wrong-key"
mkdir -m 0755 "$workspace/trust" "$workspace/trust-sigstore" "$workspace/trust-wrong" "$workspace/signature"
mkdir -m 0777 "$workspace/verify" "$workspace/verify-refused"
# Operator trust bootstraps: the approved key under managed-key-no-tlog, the
# same key under the default sigstore policy, and a foreign key.
bootstrap() {
  python3 - "$@" <<'PY'
import base64, datetime, hashlib, json, sys
output, policy, public_key, plugin_id = sys.argv[1:]
pem = open(public_key, encoding="ascii").read()
body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
now = datetime.datetime.now(datetime.timezone.utc)
stamp = lambda moment: moment.strftime("%Y-%m-%dT%H:%M:%SZ")
key = {"keyId": base64.b64encode(hashlib.sha256(base64.b64decode(body)).digest()).decode(),
       "algorithm": "ecdsa-p256-sha256", "publicKey": pem,
       "validFrom": stamp(now - datetime.timedelta(days=1)), "validUntil": stamp(now + datetime.timedelta(days=1))}
with open(output, "w", encoding="utf-8") as file:
    json.dump({"schemaVersion": 1, "publishers": [{"id": "stellwerk", "policy": policy, "pluginIds": [plugin_id], "keys": [key]}]}, file)
PY
}
bootstrap "$workspace/trust/publishers.json" managed-key-no-tlog "$workspace/approved/cosign.pub" "$plugin_id"
bootstrap "$workspace/trust-sigstore/publishers.json" sigstore "$workspace/approved/cosign.pub" "$plugin_id"
bootstrap "$workspace/trust-wrong/publishers.json" managed-key-no-tlog "$workspace/wrong/cosign.pub" "$plugin_id"
cp "$workspace/wrong/cosign.pub" "$workspace/trust/wrong.pub"
cp "$workspace/transfer/oci-manifest.sigstore.json" "$workspace/signature/oci-manifest.sigstore.json"
chmod 0444 "$workspace/trust/"* "$workspace/trust-sigstore/"* "$workspace/trust-wrong/"* "$workspace/signature/oci-manifest.sigstore.json"
publisher_gate() {
  local trust="$1" verify="$2"
  timeout -k 5s 30s docker run "${container_base[@]}" --network none \
    --mount "type=bind,src=$workspace/package,dst=/package,readonly" \
    --mount "type=bind,src=$workspace/$trust,dst=/trust,readonly" \
    --mount "type=bind,src=$workspace/signature,dst=/signature,readonly" \
    --mount "type=bind,src=$workspace/$verify,dst=/verify" "$runtime_image" \
    verify-publisher --trust-bootstrap=/trust/publishers.json --bundle=/signature/oci-manifest.sigstore.json \
    --oci-manifest=/package/oci-manifest.json --plugin-id="$plugin_id" --key-out=/verify/publisher.pub
}

timeout -k 5s 30s docker run --detach --pull=never --name "$registry" \
  --publish 127.0.0.1::5000 "$registry_image" >/dev/null
registry_address="$(docker port "$registry" 5000/tcp | head -n 1)"
for _ in {1..30}; do
  if curl --fail --silent --max-time 1 "http://$registry_address/v2/" >/dev/null; then
    break
  fi
  sleep 0.1
done
curl --fail --silent --max-time 2 "http://$registry_address/v2/" >/dev/null
host_reference="$registry_address/native-probe:$plugin_version"
timeout -k 5s 60s oras cp --from-oci-layout --to-plain-http \
  "$workspace/transfer/oci-layout:$plugin_version" "$host_reference" >/dev/null
test "$(timeout -k 5s 30s oras resolve --plain-http "$host_reference")" = "$digest"
container_reference="localhost:5000/native-probe@$digest"

container_base=(--rm --pull=never --platform "$platform" --user 65532:65532 --read-only --cap-drop ALL
  --security-opt no-new-privileges --pids-limit 32 --memory 256m --cpus 0.5
  --tmpfs '/tmp:rw,noexec,nosuid,size=16m,mode=1777')
runtime_common=(--package-dir=/package --manifest=/package/plugin-manifest.json
  --state-file=/package/runtime-state.json --plugin-id="$plugin_id"
  --plugin-version="$plugin_version" --manifest-sha256="$manifest_hash")

# The first and fourth stages are the chart's ORAS registry operations. The
# registry is an isolated, short-lived container; no publisher endpoint exists.
timeout -k 5s 45s docker run "${container_base[@]}" --network "container:$registry" \
  --mount "type=bind,src=$workspace/package,dst=/package" "$oras_image" \
  manifest fetch --output=/package/oci-manifest.json --plain-http "$container_reference" >/dev/null
cmp "$workspace/transfer/oci-manifest.json" "$workspace/package/oci-manifest.json"
timeout -k 5s 30s docker run "${container_base[@]}" --network none \
  --mount "type=bind,src=$workspace/package,dst=/package,readonly" "$runtime_image" \
  verify-envelope --oci-manifest=/package/oci-manifest.json \
  --package-digest="$digest" --manifest-sha256="$manifest_hash" >/dev/null
# managed-key-no-tlog: the runtime gate checks the bootstrap policy and the
# signature offline and hands only the pinned key to Cosign, which verifies
# the same bytes again. The same signature fails for a publisher pinned with
# the default sigstore policy and for a bootstrap pinning another key.
publisher_gate trust verify >/dev/null
for refused in "trust-sigstore:requires transparency-log verification" "trust-wrong:does not pin"; do
  if output="$(publisher_gate "${refused%%:*}" verify-refused 2>&1)"; then
    echo "the publisher gate accepted ${refused%%:*}" >&2
    exit 1
  fi
  if [[ "$output" != *"${refused#*:}"* ]]; then
    echo "the publisher gate refused ${refused%%:*} for the wrong reason: $output" >&2
    exit 1
  fi
done
test ! -e "$workspace/verify-refused/publisher.pub"
quiet timeout -k 5s 45s docker run "${container_base[@]}" --network none \
  --mount "type=bind,src=$workspace/package,dst=/package,readonly" \
  --mount "type=bind,src=$workspace/verify,dst=/verify,readonly" \
  --mount "type=bind,src=$workspace/signature,dst=/signature,readonly" "$cosign_image" \
  verify-blob --insecure-ignore-tlog --key=/verify/publisher.pub \
  --bundle=/signature/oci-manifest.sigstore.json /package/oci-manifest.json
timeout -k 5s 60s docker run "${container_base[@]}" --network "container:$registry" \
  --mount "type=bind,src=$workspace/package,dst=/package" "$oras_image" \
  pull --no-tty --output=/package --plain-http "$container_reference" >/dev/null
timeout -k 5s 30s docker run "${container_base[@]}" --network none \
  --mount "type=bind,src=$workspace/package,dst=/package" "$runtime_image" \
  validate "${runtime_common[@]}" --trust-state=verified-local-key >/dev/null
test "$(jq -r .trustState "$workspace/package/runtime-state.json")" = verified-local-key

# The verified package actually runs from the read-only mount. The plugin
# container gets a loopback-published port only so this script can query it.
timeout -k 5s 30s docker run --detach --pull=never --platform "$platform" --name "$plugin" \
  --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 32 --memory 256m --cpus 0.5 --tmpfs '/tmp:rw,noexec,nosuid,size=16m,mode=1777' \
  --tmpfs '/state:rw,noexec,nosuid,size=16m,uid=65532,gid=65532,mode=0700' \
  --publish 127.0.0.1::8080 \
  --mount "type=bind,src=$workspace/package,dst=/package,readonly" "$runtime_image" \
  run "${runtime_common[@]}" --plugin-state=/state --listen=0.0.0.0:8080 >/dev/null
python3 - "$(docker port "$plugin" 8080/tcp | head -n 1)" "$plugin_id" "$plugin_version" <<'PY'
import json
import sys
import time
import urllib.request

address, plugin_id, version = sys.argv[1:]
for _ in range(50):
    try:
        with urllib.request.urlopen(f"http://{address}/v1/info", timeout=1) as response:
            info = json.load(response)
        break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("verified plugin did not become ready")
assert info["id"] == plugin_id and info["version"] == version, info
assert info["trust"] == "verified-local-key", info
assert info["uid"] == 65532 and info["pid"] == 1, info
PY
timeout -k 5s 30s docker stop --timeout 5 "$plugin" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$plugin")" = 0

# Preserve real pulled package bytes in both negatives, but remove the receipt.
# A failed init stage must never leave authority to execute the launcher.
cp -R "$workspace/package/." "$workspace/tampered/"
cp -R "$workspace/package/." "$workspace/wrong-key/"
rm -- "$workspace/tampered/runtime-state.json" "$workspace/wrong-key/runtime-state.json"
printf ' ' >>"$workspace/tampered/oci-manifest.json"
if timeout -k 5s 30s docker run "${container_base[@]}" --network none \
  --mount "type=bind,src=$workspace/tampered,dst=/package,readonly" "$runtime_image" \
  verify-envelope --oci-manifest=/package/oci-manifest.json \
  --package-digest="$digest" --manifest-sha256="$manifest_hash" >/dev/null 2>&1; then
  echo "tampered OCI manifest passed the digest gate" >&2
  exit 1
fi
# A real ORAS directory layer is an archive that the pull would unpack. The
# envelope gate refuses it before any content is fetched.
mkdir -p "$workspace/archive/files/ui"
cp "$workspace/source/files/plugin-manifest.json" "$workspace/archive/files/plugin-manifest.json"
printf '<!doctype html>\n' >"$workspace/archive/files/ui/index.html"
(
  cd "$workspace/archive/files"
  oras push --oci-layout "$workspace/archive/layout:$plugin_version" \
    --artifact-type application/vnd.stellwerk.plugin.package.v1 \
    --export-manifest "$workspace/archive/oci-manifest.json" \
    plugin-manifest.json:application/vnd.stellwerk.plugin.manifest.v1+json \
    ui:application/vnd.stellwerk.plugin.ui.asset.v1 >/dev/null
)
archive_digest="sha256:$(shasum -a 256 "$workspace/archive/oci-manifest.json" | awk '{print $1}')"
if output="$(timeout -k 5s 30s docker run "${container_base[@]}" --network none \
  --mount "type=bind,src=$workspace/archive,dst=/package,readonly" "$runtime_image" \
  verify-envelope --oci-manifest=/package/oci-manifest.json \
  --package-digest="$archive_digest" --manifest-sha256="$manifest_hash" 2>&1)"; then
  echo "archive layer passed the envelope gate" >&2
  exit 1
fi
if [[ "$output" != *"is an archive"* ]]; then
  echo "archive layer was not rejected as an archive: $output" >&2
  exit 1
fi
if timeout -k 5s 30s docker run "${container_base[@]}" --network none \
  --mount "type=bind,src=$workspace/wrong-key,dst=/package,readonly" \
  --mount "type=bind,src=$workspace/trust,dst=/trust,readonly" \
  --mount "type=bind,src=$workspace/signature,dst=/signature,readonly" "$cosign_image" \
  verify-blob --insecure-ignore-tlog --key=/trust/wrong.pub \
  --bundle=/signature/oci-manifest.sigstore.json /package/oci-manifest.json >/dev/null 2>&1; then
  echo "wrong public key passed the signature gate" >&2
  exit 1
fi
for case_name in tampered wrong-key; do
  test ! -e "$workspace/$case_name/runtime-state.json"
  if output="$(timeout -k 5s 10s docker run "${container_base[@]}" \
    --name "package-init-${case_name%-key}-$run_id" --network none \
    --mount "type=bind,src=$workspace/$case_name,dst=/package,readonly" "$runtime_image" \
    run "${runtime_common[@]}" --plugin-state=/state 2>&1)"; then
    echo "$case_name package unexpectedly reached the launcher" >&2
    exit 1
  fi
  if [[ "$output" != *"validated runtime state unavailable"* ]]; then
    echo "$case_name launcher did not fail at the missing validation receipt" >&2
    exit 1
  fi
done

echo "Signed package init chain passed: $digest ($platform); managed-key-no-tlog gate and Cosign verified offline, verified package ran; default-policy publisher, foreign key, tampered manifest/blob, archive layer and wrong key fail closed."
