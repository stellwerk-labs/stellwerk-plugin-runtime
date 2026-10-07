#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:?usage: build-package.sh VERSION OUTPUT_DIRECTORY}"
output="${2:?usage: build-package.sh VERSION OUTPUT_DIRECTORY}"

command -v oras >/dev/null || { echo "oras is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
commit="$(git -C "$root" rev-parse --verify HEAD 2>/dev/null)" ||
  { echo "the source provenance needs a git checkout" >&2; exit 1; }

mkdir -p "$output"
output="$(cd "$output" && pwd)"
case "$output" in
  "$root" | /) echo "refusing unsafe output directory" >&2; exit 1 ;;
esac
fixture="$output/files"
layout="$output/oci-layout"
manifest_hash="$("$root/scripts/build-fixture.sh" "$version" "$fixture")"

(
  cd "$fixture"
  oras push --oci-layout "$layout:$version" \
    --artifact-type application/vnd.stellwerk.plugin.package.v1 \
    --annotation "org.opencontainers.image.title=Stellwerk native plugin probe" \
    --annotation "org.opencontainers.image.version=$version" \
    --export-manifest "$output/oci-manifest.json" \
    plugin-manifest.json:application/vnd.stellwerk.plugin.manifest.v1+json \
    bin/linux/amd64/plugin:application/vnd.stellwerk.plugin.executable.v1 \
    bin/linux/arm64/plugin:application/vnd.stellwerk.plugin.executable.v1 \
    >/dev/null
)

package_digest="$(oras resolve --oci-layout "$layout:$version")"
jq -n \
  --arg pluginId dev.stellwerk.native-probe \
  --arg pluginVersion "$version" \
  --arg packageDigest "$package_digest" \
  --arg manifestSHA256 "$manifest_hash" \
  --arg trustState untrusted-development \
  '{schemaVersion:1,pluginId:$pluginId,pluginVersion:$pluginVersion,packageDigest:$packageDigest,manifestSHA256:$manifestSHA256,trustState:$trustState}' \
  >"$output/release.json"
# Source provenance (https://stellwerk.dev/attestation/source-provenance/v1):
# the exact commit this package was built from and whether the worktree held
# uncommitted changes. attest-layout-manifest.sh signs it as an attestation
# about the package digest.
dirty=false
if [ -n "$(git -C "$root" status --porcelain)" ]; then
  dirty=true
fi
jq -n --arg commit "$commit" --argjson dirty "$dirty" --arg go "$(go env GOVERSION)" \
  '{schemaVersion:1,sources:[{path:".",commit:$commit,dirty:$dirty}],tools:{go:$go}}' \
  >"$output/source-provenance.json"

echo "$output/release.json"
