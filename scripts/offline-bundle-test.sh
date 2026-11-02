#!/usr/bin/env bash
set -euo pipefail

# offline-bundle-test.sh builds a complete offline bundle (signed and attested
# probe package, multi-platform runtime image, ORAS and Cosign images, chart,
# trust bootstrap) and imports it with import-offline-bundle.sh running in
# the pinned ORAS image on an internal Docker network whose only peer is a
# fresh registry. The import container proves it has no other route. Then:
# every manifest the registry serves is byte-identical to the bundle, tags,
# platform manifests and referrers are preserved and Helm pulls the chart by
# digest. Tampered bundles are refused before anything is pushed: a missing
# component, altered bytes, a missing or foreign referrer, a foreign blob, a
# wrong architecture set, an unpinned trust bootstrap or publisher, and a tag
# that already names another digest.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"

for command in docker oras helm jq go python3 shasum curl timeout git; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
platform="$(docker_platform)"
for image in "$oras_image" "$cosign_image" "$registry_image"; do
  require_image "$image" "$platform"
done

run_id="$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
registry="swbundle-registry-$run_id"
network="swbundle-airgap-$run_id"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/offline-bundle-test.XXXXXX")"
cleanup() {
  docker rm -f "$registry" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  chmod -R u+w "$workspace" 2>/dev/null || true
  rm -rf -- "$workspace"
}
trap cleanup EXIT
chmod 0755 "$workspace"
plugin_id=dev.stellwerk.native-probe
tag="$plugin_id-1.0.0"

# Publisher side: disposable keys, the signed and attested package, the
# runtime image, the trust bootstrap and the bundle. The scripts run outside
# the checkout with paths relative to their working directory.
cd "$workspace"
for key in approved foreign; do
  mkdir -m 0700 "$workspace/$key"
  COSIGN_PASSWORD='' quiet offline_cosign --mount "type=bind,src=$workspace/$key,dst=/keys" --workdir /keys \
    -- generate-key-pair
done
"$root/scripts/build-package.sh" 1.0.0 package >/dev/null
COSIGN_PASSWORD='' quiet "$root/scripts/sign-layout-manifest.sh" "$workspace/package" "$workspace/approved/cosign.key"
sbom_fixture "$workspace/sbom.spdx.json" 1.0.0
COSIGN_PASSWORD='' quiet "$root/scripts/attest-layout-manifest.sh" "$workspace/package" "$workspace/approved/cosign.key" \
  "$workspace/sbom.spdx.json"
runtime_digest="$("$root/scripts/build-runtime-image.sh" runtime)"
trust_bootstrap "$workspace/publishers.json" managed-key-no-tlog "$workspace/approved/cosign.pub" "$plugin_id"
bundle="$workspace/bundle"
COSIGN_PASSWORD='' quiet "$root/scripts/offline-bundle.sh" --package package \
  --runtime-image "runtime@$runtime_digest" --key approved/cosign.key \
  --trust-bootstrap publishers.json --minimum-core-version 1.0.0 bundle
pin="sha256:$(shasum -a 256 "$bundle/publishers.json" | awk '{print $1}')"
# Variants hard-link the bundle's blobs; read-only files make an accidental
# in-place edit fail instead of corrupting the original.
chmod -R a-w "$bundle"
field() { jq -er "$1" "$bundle/bundle.json"; }
blob() { echo "$1/oci/blobs/sha256/${2#sha256:}"; }
test "$(field .images.runtime.digest)" = "$runtime_digest"
test "$(field .package.digest)" = "$(jq -er .packageDigest "$workspace/package/release.json")"
test "$(field .minimumCoreVersion)/$(field .minimumChartVersion)/$(field .chart.version)" = 1.0.0/0.1.1/0.1.1
# The licence travels separately; the bundle holds exactly these entries.
test "$(cd "$bundle" && find . -maxdepth 1 ! -name . | sort | tr '\n' ' ')" = \
  "./bundle.json ./bundle.sigstore.json ./oci ./publishers.json "
for name in runtime oras cosign; do
  test "$(jq -c '[.manifests[].platform | "\(.os)/\(.architecture)"] | sort' "$(blob "$bundle" "$(field ".images.$name.digest")")")" = \
    '["linux/amd64","linux/arm64"]'
done
# The helper images keep their upstream platform manifests.
for name in oras cosign; do
  upstream="${name}_image"
  test "$(oras manifest fetch "${!upstream}" | jq -c '[.manifests[] | select(.platform.os == "linux" and
      (.platform.architecture == "amd64" or .platform.architecture == "arm64")) | .digest] | sort')" = \
    "$(jq -c '[.manifests[].digest] | sort' "$(blob "$bundle" "$(field ".images.$name.digest")")")"
done
echo "bundle: package, 3 referrers, runtime/oras/cosign for linux/amd64+arm64, chart $(field .chart.version), signed"

# Customer side: a fresh registry, reachable from the host for the checks
# and from an internal network that has no route anywhere else.
timeout -k 5s 30s docker run --detach --pull=never --name "$registry" \
  --publish 127.0.0.1::5000 "$registry_image" >/dev/null
docker network create --internal "$network" >/dev/null
docker network connect "$network" "$registry"
host="$(docker port "$registry" 5000/tcp | head -n 1)"
for _ in {1..50}; do
  if curl --fail --silent --max-time 1 "http://$host/v2/" >/dev/null; then break; fi
  sleep 0.1
done
mkdir "$workspace/verifier"
CGO_ENABLED=0 GOOS=linux GOARCH="${platform#linux/}" GOWORK=off \
  go -C "$root" build -trimpath -o "$workspace/verifier/runtime" ./runtime

# import_bundle BUNDLE PREFIX PIN [probe] imports BUNDLE into the registry
# under PREFIX from the internal network (airgap_import).
import_bundle() {
  mkdir -p "$workspace/out-$2"
  airgap_import "$network" "$registry:5000/$2" "$1" "$workspace/verifier/runtime" "$workspace/out-$2" "$3" "${4:-}"
}
catalog() { curl --fail --silent --max-time 5 "http://$host/v2/_catalog?n=1000" | jq -r '.repositories[]'; }

output="$(import_bundle "$bundle" mirror "$pin" probe 2>&1)" || { printf '%s\n' "$output" >&2; exit 1; }
[[ "$output" == *"imported into $registry:5000/mirror"* ]] || { printf '%s\n' "$output" >&2; exit 1; }
test "$(catalog | grep '^mirror/' | tr '\n' ' ')" = \
  "mirror/charts/native-plugin-runtime mirror/cosign mirror/$plugin_id mirror/native-plugin-runtime mirror/oras "

# same REPOSITORY DIGEST: the registry serves the bundle's exact manifest bytes.
same() {
  timeout -k 5s 30s oras manifest fetch --plain-http "$host/mirror/$1@$2" >"$workspace/fetched"
  cmp -s "$workspace/fetched" "$(blob "$bundle" "$2")" || { echo "$1@$2 differs from the bundle" >&2; exit 1; }
}
same "$plugin_id" "$(field .package.digest)"
for referrer in signature sbom provenance; do same "$plugin_id" "$(field ".package.$referrer")"; done
test "$(oras discover --plain-http --format json "$host/mirror/$plugin_id@$(field .package.digest)" | jq -c '[.referrers[].digest] | sort')" = \
  "$(jq -c '[.package.signature, .package.sbom, .package.provenance] | sort' "$bundle/bundle.json")"
for name in runtime oras cosign; do
  repository="$name"
  if [ "$name" = runtime ]; then repository=native-plugin-runtime; fi
  index="$(field ".images.$name.digest")"
  same "$repository" "$index"
  for child in $(jq -r '.manifests[].digest' "$(blob "$bundle" "$index")"); do same "$repository" "$child"; done
  test "$(oras repo tags --plain-http "$host/mirror/$repository")" = "$tag"
  test "$(oras resolve --plain-http "$host/mirror/$repository:$tag")" = "$index"
done
same charts/native-plugin-runtime "$(field .chart.digest)"
test "$(oras resolve --plain-http "$host/mirror/$plugin_id:$tag")" = "$(field .package.digest)"
mkdir "$workspace/chart"
timeout -k 5s 60s helm pull --plain-http "oci://$host/mirror/charts/native-plugin-runtime@$(field .chart.digest)" \
  --destination "$workspace/chart" >/dev/null 2>&1
test "sha256:$(shasum -a 256 "$workspace"/chart/*.tgz | awk '{print $1}')" = \
  "$(jq -er '.layers[0].digest' "$(blob "$bundle" "$(field .chart.digest)")")"
jq -e --slurpfile bundle "$bundle/bundle.json" --arg prefix "$registry:5000/mirror" '$bundle[0] as $b |
  .enabled and .trust.mode == "managed-key-no-tlog" and .package.plainHTTP and
  .package.reference == "\($prefix)/\($b.pluginId)@\($b.package.digest)" and
  .package.manifestSHA256 == $b.package.manifestSHA256 and
  .package.attestations == {sbom: $b.package.sbom, provenance: $b.package.provenance} and
  .images == {runtime: "\($prefix)/native-plugin-runtime@\($b.images.runtime.digest)",
              oras: "\($prefix)/oras@\($b.images.oras.digest)", cosign: "\($prefix)/cosign@\($b.images.cosign.digest)"}' \
  "$workspace/out-mirror/values.json" >/dev/null
cmp -s "$workspace/out-mirror/publishers.json" "$bundle/publishers.json"
cmp -s "$workspace/out-mirror/oci-manifest.sigstore.json" "$workspace/package/oci-manifest.sigstore.json"
# Importing the same bundle again, now from the host with the verifier built
# from this checkout and relative paths, changes nothing.
"$root/scripts/import-offline-bundle.sh" bundle "$host/mirror" --trust-bootstrap-digest "$pin" --plain-http \
  --out out-host >/dev/null
test "$(catalog | grep -c '^mirror/')" = 5
echo "import: no egress but the registry; manifests, tags, platform manifests, referrers and chart preserved; idempotent"

# variant NAME prints a hard-linked copy of the bundle with writable
# directories; mutations replace files, never edit them.
variant() {
  python3 - "$bundle" "$workspace/variants/$1" <<'PY'
import os, shutil, sys
shutil.copytree(sys.argv[1], sys.argv[2], copy_function=os.link)
for directory, _, _ in os.walk(sys.argv[2]):
    os.chmod(directory, 0o755)
PY
  echo "$workspace/variants/$1"
}
replace() { cat >"$1.new"; mv -f -- "$1.new" "$1"; }
# edit_json FILE FILTER [JQ_ARGS...]; filters use jq variables (SC2016).
edit_json() { local file="$1" filter="$2"; shift 2; jq "$@" "$filter" "$file" | replace "$file"; }
resign() {
  rm -f "$1/bundle.sigstore.json"
  COSIGN_PASSWORD='' quiet offline_cosign \
    --mount "type=bind,src=$workspace/$2,dst=/key,readonly" --mount "type=bind,src=$1,dst=/bundle" \
    --mount "type=bind,src=$root/scripts/signing-config-no-tlog.json,dst=/config/signing-config.json,readonly" \
    -- sign-blob --yes --signing-config=/config/signing-config.json --key /key/cosign.key \
    --bundle /bundle/bundle.sigstore.json /bundle/bundle.json
}
# writable_index VARIANT gives ORAS an index.json of its own to rewrite.
writable_index() { cat "$1/oci/index.json" >"$1/index.json.copy"; mv -f -- "$1/index.json.copy" "$1/oci/index.json"; }
# shellcheck disable=SC2016
unlist() { edit_json "$1/oci/index.json" '.manifests |= map(select(.digest != $digest))' --arg digest "$2"; }

missing_component="$(variant missing-component)"
unlist "$missing_component" "$(field .images.cosign.digest)"
rm -f "$(blob "$missing_component" "$(field .images.cosign.digest)")"

altered_bytes="$(variant altered-bytes)"
altered="$(blob "$altered_bytes" "$(jq -er '.layers[0].digest' "$(blob "$bundle" \
  "$(jq -er '.manifests[] | select(.platform.architecture == "amd64") | .digest' "$(blob "$bundle" "$runtime_digest")")")")")"
{ cat "$altered"; printf x; } | replace "$altered"

missing_referrer="$(variant missing-referrer)"
unlist "$missing_referrer" "$(field .package.sbom)"
rm -f "$(blob "$missing_referrer" "$(field .package.sbom)")"

# A well-formed Sigstore bundle referrer of the package that bundle.json
# does not record.
foreign_referrer="$(variant foreign-referrer)"
writable_index "$foreign_referrer"
attach_bundle "$foreign_referrer/oci@$(field .package.digest)" "$workspace/package/attestations/provenance.sigstore.json" \
  "$provenance_predicate_type" --oci-layout >/dev/null
rmdir "$foreign_referrer/oci/ingest" 2>/dev/null || true

foreign_blob="$(variant foreign-blob)"
printf 'smuggled' >"$(blob "$foreign_blob" "sha256:$(printf smuggled | shasum -a 256 | awk '{print $1}')")"

# The publisher's own mistake: a validly signed bundle whose runtime index
# holds linux/amd64 only.
wrong_architecture="$(variant wrong-architecture)"
jq -c '.manifests |= map(select(.platform.architecture == "amd64"))' "$(blob "$bundle" "$runtime_digest")" \
  >"$workspace/amd64-only.json"
amd64_only="sha256:$(shasum -a 256 "$workspace/amd64-only.json" | awk '{print $1}')"
cp "$workspace/amd64-only.json" "$(blob "$wrong_architecture" "$amd64_only")"
# shellcheck disable=SC2016
edit_json "$wrong_architecture/oci/index.json" \
  '.manifests |= map(if .digest == $old then .digest = $new | .size = $size else . end)' \
  --arg old "$runtime_digest" --arg new "$amd64_only" --argjson size "$(wc -c <"$workspace/amd64-only.json" | tr -d ' ')"
# shellcheck disable=SC2016
edit_json "$wrong_architecture/bundle.json" '.images.runtime.digest = $digest' --arg digest "$amd64_only"
resign "$wrong_architecture" approved

unpinned_key="$(variant unpinned-key)"
resign "$unpinned_key" foreign

# The pinned bootstrap pins the publisher key, but for another plugin.
unpinned_plugin="$(variant unpinned-plugin)"
rm -f "$unpinned_plugin/publishers.json"
trust_bootstrap "$unpinned_plugin/publishers.json" managed-key-no-tlog "$workspace/approved/cosign.pub" dev.stellwerk.other
other_pin="sha256:$(shasum -a 256 "$unpinned_plugin/publishers.json" | awk '{print $1}')"
# shellcheck disable=SC2016
edit_json "$unpinned_plugin/bundle.json" '.trustBootstrap = $pin' --arg pin "$other_pin"
resign "$unpinned_plugin" approved

# A tag in the target repository that already names another digest.
timeout -k 5s 60s oras cp --no-tty --from-oci-layout "$bundle/oci@$(field .chart.digest)" \
  --to-plain-http "$host/neg-moved-tag/$plugin_id:$tag" >/dev/null

for refused in \
  "missing-component|$missing_component|$pin|image cosign $(field .images.cosign.digest) is missing from the bundle" \
  "altered-bytes|$altered_bytes|$pin|does not match its digest or size" \
  "missing-referrer|$missing_referrer|$pin|package SBOM referrer $(field .package.sbom) is missing from the bundle" \
  "foreign-referrer|$foreign_referrer|$pin|foreign manifest" \
  "foreign-blob|$foreign_blob|$pin|foreign blob" \
  "wrong-architecture|$wrong_architecture|$pin|image runtime must hold exactly the platforms linux/amd64 and linux/arm64, found linux/amd64" \
  "unpinned-trust|$bundle|$other_pin|is not the one the operator pinned" \
  "unpinned-key|$unpinned_key|$pin|which publisher stellwerk does not pin" \
  "unpinned-plugin|$unpinned_plugin|$other_pin|no publisher is pinned for plugin $plugin_id" \
  "moved-tag|$bundle|$pin|already names $(field .chart.digest); refusing to move it"; do
  IFS='|' read -r name bundle_dir bundle_pin reason <<<"$refused"
  if output="$(import_bundle "$bundle_dir" "neg-$name" "$bundle_pin" 2>&1)"; then
    echo "the import accepted the $name bundle" >&2
    exit 1
  fi
  if [[ "$output" != *"$reason"* ]]; then
    printf 'the import refused the %s bundle for the wrong reason:\n%s\n' "$name" "$output" >&2
    exit 1
  fi
  expected=""
  if [ "$name" = moved-tag ]; then expected="neg-moved-tag/$plugin_id"; fi
  if [ "$(catalog | grep "^neg-$name/" || true)" != "$expected" ]; then
    echo "the refused $name import pushed to the registry" >&2
    exit 1
  fi
done
echo "refused before pushing: missing component, altered bytes, missing and foreign referrer, foreign blob,"
echo "  wrong architecture set, unpinned trust bootstrap, unpinned key, unpinned plugin, moved tag"
echo "Offline bundle test passed ($platform)."
