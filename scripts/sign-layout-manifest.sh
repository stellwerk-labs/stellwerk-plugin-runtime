#!/usr/bin/env bash
set -euo pipefail

package_output="${1:?usage: sign-layout-manifest.sh PACKAGE_OUTPUT PRIVATE_KEY}"
private_key="${2:?usage: sign-layout-manifest.sh PACKAGE_OUTPUT PRIVATE_KEY}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"

for command in docker oras jq shasum; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
test -s "$package_output/oci-manifest.json"
test -s "$private_key"
package_dir="$(cd "$package_output" && pwd)"
key_dir="$(cd "$(dirname "$private_key")" && pwd)"
release="$package_dir/release.json"
digest="$(jq -er '.packageDigest | select(test("^sha256:[0-9a-f]{64}$"))' "$release")"
if [ "sha256:$(shasum -a 256 "$package_dir/oci-manifest.json" | awk '{print $1}')" != "$digest" ]; then
  echo "oci-manifest.json is not the package manifest recorded in release.json" >&2
  exit 1
fi
if ! jq -e '.signature == null' "$release" >/dev/null; then
  echo "the package is already signed; rebuild it to sign again" >&2
  exit 1
fi
require_image "$cosign_image" "$(docker_platform)"

# managed-key-no-tlog: authenticate the exact exported OCI manifest with the
# publisher's managed key and no transparency log, timestamp authority or
# registry upload. The signing config lists no services, which is Cosign's
# current mechanism (--tlog-upload=false is deprecated). The chart consumes
# this detached bundle and fetches the same manifest by digest; publication
# must preserve that digest.
offline_cosign \
  --mount "type=bind,src=$key_dir,dst=/key,readonly" \
  --mount "type=bind,src=$package_dir,dst=/package" \
  --mount "type=bind,src=$root/scripts/signing-config-no-tlog.json,dst=/config/signing-config.json,readonly" \
  -- sign-blob --yes --signing-config=/config/signing-config.json \
  --key "/key/$(basename "$private_key")" \
  --bundle /package/oci-manifest.sigstore.json /package/oci-manifest.json >/dev/null

# The same bundle also travels as a referrer of the package manifest
# (Cosign's bundle referrer convention), so that `oras cp -r` mirrors and the
# offline bundle carry it; release.json records its digest.
signature_digest="$(attach_bundle "$package_dir/oci-layout@$digest" "$package_dir/oci-manifest.sigstore.json" \
  "$signature_predicate_type" --oci-layout)"
jq --arg digest "$signature_digest" '.signature = {digest: $digest}' "$release" >"$release.new"
mv -- "$release.new" "$release"
echo "$package_dir/oci-manifest.sigstore.json"
