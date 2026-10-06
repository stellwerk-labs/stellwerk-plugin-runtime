#!/usr/bin/env bash
set -euo pipefail

usage="usage: attest-layout-manifest.sh PACKAGE_OUTPUT PRIVATE_KEY SPDX_SBOM"
package_output="${1:?$usage}"
private_key="${2:?$usage}"
sbom="${3:?$usage}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"

for command in docker oras jq shasum; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
package_dir="$(cd "$package_output" && pwd)"
key_dir="$(cd "$(dirname "$private_key")" && pwd)"
release="$package_dir/release.json"
provenance="$package_dir/source-provenance.json"
test -s "$package_dir/oci-manifest.json"
test -s "$private_key"
digest="$(jq -er '.packageDigest | select(test("^sha256:[0-9a-f]{64}$"))' "$release")"
if [ "sha256:$(shasum -a 256 "$package_dir/oci-manifest.json" | awk '{print $1}')" != "$digest" ]; then
  echo "oci-manifest.json is not the package manifest recorded in release.json" >&2
  exit 1
fi
if ! jq -e '.attestations == null' "$release" >/dev/null; then
  echo "the package already carries attestations; rebuild it to attest again" >&2
  exit 1
fi
# The SBOM comes from the publisher's SBOM generator; no pinned tool here
# produces one. The provenance is the source-provenance document the build
# wrote. Both must be what the runtime's publisher gate accepts.
jq -e '(.spdxVersion | test("^SPDX-2\\.[0-9]+$")) and .SPDXID == "SPDXRef-DOCUMENT"' "$sbom" >/dev/null ||
  { echo "the SBOM must be an SPDX 2 JSON document" >&2; exit 1; }
jq -e '.schemaVersion == 1 and (.sources | type == "array" and length > 0) and
  all(.sources[]; .commit | type == "string" and test("^([0-9a-f]{40}|[0-9a-f]{64})$"))' "$provenance" >/dev/null ||
  { echo "the source provenance needs schemaVersion 1 and sources with full git commit IDs" >&2; exit 1; }
require_image "$cosign_image" "$(docker_platform)"

predicates="$(mktemp -d "${TMPDIR:-/tmp}/attest-predicates.XXXXXX")"
trap 'rm -rf -- "$predicates"' EXIT
cp "$sbom" "$predicates/sbom.json"
cp "$provenance" "$predicates/provenance.json"
mkdir -p "$package_dir/attestations"

# managed-key-no-tlog, like the package signature: an in-toto statement whose
# only subject is the exact OCI manifest (the package digest), in a DSSE
# envelope signed with the publisher's managed key, no transparency log.
for name in sbom provenance; do
  predicate_type="$sbom_predicate_type"
  if [ "$name" = provenance ]; then predicate_type="$provenance_predicate_type"; fi
  if ! output="$(offline_cosign \
    --mount "type=bind,src=$key_dir,dst=/key,readonly" \
    --mount "type=bind,src=$predicates,dst=/predicate,readonly" \
    --mount "type=bind,src=$package_dir,dst=/package" \
    --mount "type=bind,src=$root/scripts/signing-config-no-tlog.json,dst=/config/signing-config.json,readonly" \
    -- attest-blob --yes --signing-config=/config/signing-config.json \
    --key "/key/$(basename "$private_key")" --type "$predicate_type" --predicate "/predicate/$name.json" \
    --bundle "/package/attestations/$name.sigstore.json" /package/oci-manifest.json 2>&1)"; then
    printf '%s\n' "$output" >&2
    exit 1
  fi
done

# Attach both bundles as referrers of the package manifest, so `oras cp -r`
# and the offline bundle carry them, and record their digests for the chart
# (package.attestations).
sbom_digest="$(attach_bundle "$package_dir/oci-layout@$digest" "$package_dir/attestations/sbom.sigstore.json" \
  "$sbom_predicate_type" --oci-layout)"
provenance_digest="$(attach_bundle "$package_dir/oci-layout@$digest" "$package_dir/attestations/provenance.sigstore.json" \
  "$provenance_predicate_type" --oci-layout)"
jq --arg sbomDigest "$sbom_digest" --arg sbomType "$sbom_predicate_type" \
  --arg provenanceDigest "$provenance_digest" --arg provenanceType "$provenance_predicate_type" \
  '.attestations = {sbom: {digest: $sbomDigest, predicateType: $sbomType},
                    provenance: {digest: $provenanceDigest, predicateType: $provenanceType}}' \
  "$release" >"$release.new"
mv -- "$release.new" "$release"
echo "$release"
