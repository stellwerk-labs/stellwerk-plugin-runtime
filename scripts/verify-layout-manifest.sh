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
jq -e '.imageLayoutVersion == "1.0.0"' "$package_output/oci-layout/oci-layout" >/dev/null
if ! jq -e --arg digest "sha256:$manifest_sha" --argjson size "$manifest_size" \
  '.schemaVersion == 2 and (.manifests | length == 1) and .manifests[0].digest == $digest and .manifests[0].size == $size' \
  "$package_output/oci-layout/index.json" >/dev/null; then
  echo "OCI index does not select the signed manifest" >&2
  exit 1
fi
manifest_blob="$package_output/oci-layout/blobs/sha256/$manifest_sha"
if [ ! -f "$manifest_blob" ] || [ -L "$manifest_blob" ]; then
  echo "missing or symlinked manifest blob" >&2
  exit 1
fi
cmp "$manifest" "$manifest_blob"
jq -e '.schemaVersion == 2 and .artifactType == "application/vnd.stellwerk.plugin.package.v1" and (.layers | type == "array" and length > 0) and (.config | type == "object")' "$manifest" >/dev/null
descriptors="$(jq -er '[.config] + .layers | .[] | [.digest, .size] | @tsv' "$manifest")"
while IFS=$'\t' read -r digest size; do
  if ! [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || ! [[ "$size" =~ ^[0-9]+$ ]]; then
    echo "invalid OCI descriptor" >&2
    exit 1
  fi
  blob="$package_output/oci-layout/blobs/sha256/${digest#sha256:}"
  if [ ! -f "$blob" ] || [ -L "$blob" ]; then
    echo "missing or symlinked OCI blob" >&2
    exit 1
  fi
  actual="$(shasum -a 256 "$blob" | awk '{print $1}')"
  if [ "sha256:$actual" != "$digest" ] || [ "$(wc -c < "$blob" | tr -d ' ')" != "$size" ]; then
    echo "OCI blob digest or size mismatch" >&2
    exit 1
  fi
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
echo "Offline signature and OCI content verified."
