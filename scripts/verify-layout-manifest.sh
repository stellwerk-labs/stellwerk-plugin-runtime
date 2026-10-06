#!/usr/bin/env bash
set -euo pipefail

package_output="${1:?usage: verify-layout-manifest.sh PACKAGE_OUTPUT PUBLIC_KEY}"
public_key="${2:?usage: verify-layout-manifest.sh PACKAGE_OUTPUT PUBLIC_KEY}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"

manifest="$package_output/oci-manifest.json"
bundle="$package_output/oci-manifest.sigstore.json"
test -s "$public_key"
for directory in "$package_output" "$package_output/oci-layout" "$package_output/oci-layout/blobs" "$package_output/oci-layout/blobs/sha256"; do
  if [ ! -d "$directory" ] || [ -L "$directory" ]; then
    echo "missing or symlinked package directory" >&2
    exit 1
  fi
done
for file in "$manifest" "$bundle" "$package_output/release.json" "$package_output/oci-layout/oci-layout" "$package_output/oci-layout/index.json"; do
  if [ ! -f "$file" ] || [ -L "$file" ]; then
    echo "missing or symlinked package metadata" >&2
    exit 1
  fi
done

# Development local-key bundles deliberately contain no public transparency-log
# entry. This flag does not skip the public-key signature check.
require_image "$cosign_image" "$(docker_platform)"
offline_cosign \
  --mount "type=bind,src=$(cd "$(dirname "$public_key")" && pwd),dst=/trust,readonly" \
  --mount "type=bind,src=$(cd "$package_output" && pwd),dst=/package,readonly" \
  -- verify-blob --insecure-ignore-tlog --key "/trust/$(basename "$public_key")" \
  --bundle /package/oci-manifest.sigstore.json /package/oci-manifest.json

# The signature authenticates descriptors, not the bytes beside them. Validate
# the selected OCI content as well before calling this an offline package proof.
manifest_sha="$(shasum -a 256 "$manifest" | awk '{print $1}')"
jq -e --arg digest "sha256:$manifest_sha" '.packageDigest == $digest' "$package_output/release.json" >/dev/null
manifest_size="$(wc -c < "$manifest" | tr -d ' ')"
layout="$package_output/oci-layout"
jq -e '.imageLayoutVersion == "1.0.0"' "$layout/oci-layout" >/dev/null
if ! jq -e --arg sbom "$sbom_predicate_type" --arg provenance "$provenance_predicate_type" '
  (.attestations // {}) | type == "object" and all(to_entries[];
    ((.key == "sbom" and .value.predicateType == $sbom) or (.key == "provenance" and .value.predicateType == $provenance)) and
    (.value.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")))' "$package_output/release.json" >/dev/null; then
  echo "release metadata records malformed attestations" >&2
  exit 1
fi
# The index selects the signed manifest once and otherwise only the
# attestation referrers release.json records.
if ! jq -e --arg digest "sha256:$manifest_sha" --argjson size "$manifest_size" \
  --slurpfile release "$package_output/release.json" '
  .schemaVersion == 2 and ([.manifests[] | select(.digest == $digest and .size == $size)] | length == 1) and
  ([.manifests[].digest | select(. != $digest)] | sort) == ([($release[0].attestations // {})[].digest] | sort)' \
  "$layout/index.json" >/dev/null; then
  echo "OCI index does not select exactly the signed manifest and its recorded attestations" >&2
  exit 1
fi

# check_blob DIGEST SIZE: the layout holds a regular blob of exactly this
# digest and size.
check_blob() {
  local digest="$1" size="$2" blob actual
  if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || ! [[ "$size" =~ ^[0-9]+$ ]]; then
    echo "invalid OCI descriptor" >&2
    exit 1
  fi
  blob="$layout/blobs/sha256/${digest#sha256:}"
  if [ ! -f "$blob" ] || [ -L "$blob" ]; then
    echo "missing or symlinked OCI blob" >&2
    exit 1
  fi
  actual="$(shasum -a 256 "$blob" | awk '{print $1}')"
  if [ "sha256:$actual" != "$digest" ] || [ "$(wc -c < "$blob" | tr -d ' ')" != "$size" ]; then
    echo "OCI blob digest or size mismatch" >&2
    exit 1
  fi
}
check_blob "sha256:$manifest_sha" "$manifest_size"
cmp "$manifest" "$layout/blobs/sha256/$manifest_sha"
jq -e '.schemaVersion == 2 and .artifactType == "application/vnd.stellwerk.plugin.package.v1" and (.layers | type == "array" and length > 0) and (.config | type == "object")' "$manifest" >/dev/null
descriptors="$(jq -er '[.config] + .layers | .[] | [.digest, .size] | @tsv' "$manifest")"
while IFS=$'\t' read -r digest size; do
  check_blob "$digest" "$size"
done <<< "$descriptors"
plugin_digest="$(jq -er '[.layers[] | select(.mediaType == "application/vnd.stellwerk.plugin.manifest.v1+json")] | if length == 1 then .[0].digest else error("exactly one plugin manifest layer is required") end' "$manifest")"
if ! jq -e --slurpfile release "$package_output/release.json" --arg hash "${plugin_digest#sha256:}" \
  '.schemaVersion == 1 and $release[0].schemaVersion == 1 and
   $release[0].pluginId == .pluginId and $release[0].pluginVersion == .pluginVersion and
   $release[0].manifestSHA256 == $hash and $release[0].trustState == "untrusted-development"' \
  "$package_output/oci-layout/blobs/sha256/${plugin_digest#sha256:}" >/dev/null; then
  echo "release metadata does not match signed plugin manifest or development trust policy" >&2
  exit 1
fi

# Each recorded attestation is a referrer of exactly this manifest holding one
# Sigstore bundle, which Cosign verifies as a statement about the package
# digest with the same key. Whether a publisher requires them is the trust
# bootstrap's decision, enforced by the runtime's publisher gate.
attestations="$(jq -r '(.attestations // {}) | to_entries[] | [.key, .value.digest, .value.predicateType] | @tsv' \
  "$package_output/release.json")"
verified=0
while IFS=$'\t' read -r name referrer predicate_type; do
  if [ -z "$name" ]; then continue; fi
  check_blob "$referrer" "$(jq -er --arg digest "$referrer" '.manifests[] | select(.digest == $digest) | .size' "$layout/index.json")"
  referrer_manifest="$layout/blobs/sha256/${referrer#sha256:}"
  if ! jq -e --arg digest "sha256:$manifest_sha" --argjson size "$manifest_size" \
    --arg bundle "$sigstore_bundle_type" --arg predicate "$predicate_type" '
    .mediaType == "application/vnd.oci.image.manifest.v1+json" and .artifactType == $bundle and
    .subject.digest == $digest and .subject.size == $size and
    .annotations["dev.sigstore.bundle.predicateType"] == $predicate and
    (.layers | length == 1) and .layers[0].mediaType == $bundle' "$referrer_manifest" >/dev/null; then
    echo "the $name attestation is not a Sigstore bundle referrer of the signed manifest" >&2
    exit 1
  fi
  bundle_digest="$(jq -er '.layers[0].digest' "$referrer_manifest")"
  check_blob "$bundle_digest" "$(jq -er '.layers[0].size' "$referrer_manifest")"
  if ! output="$(offline_cosign \
    --mount "type=bind,src=$(cd "$(dirname "$public_key")" && pwd),dst=/trust,readonly" \
    --mount "type=bind,src=$(cd "$package_output" && pwd),dst=/package,readonly" \
    -- verify-blob-attestation --insecure-ignore-tlog --key "/trust/$(basename "$public_key")" \
    --type "$predicate_type" --bundle "/package/oci-layout/blobs/sha256/${bundle_digest#sha256:}" \
    /package/oci-manifest.json 2>&1)"; then
    printf '%s\n' "$output" >&2
    echo "the $name attestation does not verify" >&2
    exit 1
  fi
  verified=$((verified + 1))
done <<< "$attestations"
echo "Offline signature, $verified attestations and OCI content verified."
