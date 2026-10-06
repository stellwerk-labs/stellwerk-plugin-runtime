#!/usr/bin/env bash
set -euo pipefail

package_output="${1:?usage: sign-layout-manifest.sh PACKAGE_OUTPUT PRIVATE_KEY}"
private_key="${2:?usage: sign-layout-manifest.sh PACKAGE_OUTPUT PRIVATE_KEY}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"

test -s "$package_output/oci-manifest.json"
test -s "$private_key"
package_dir="$(cd "$package_output" && pwd)"
key_dir="$(cd "$(dirname "$private_key")" && pwd)"
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
echo "$package_dir/oci-manifest.sigstore.json"
