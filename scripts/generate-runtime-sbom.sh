#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"
source "$root/scripts/release-tools.sh"
output="$(cd "${1:?usage: generate-runtime-sbom.sh RELEASE_DIRECTORY}" && pwd)"
digest="$(jq -er '.image.digest' "$output/release.json")"
created="$(jq -er '.source.created' "$output/release.json")"
require_image "$syft_image" "$(docker_platform)"
for arch in amd64 arm64; do
  # Syft's OCI-directory source does not accept --platform. Select the exact
  # platform manifest into its own layout before cataloguing it.
  oras cp --no-tty --from-oci-layout --to-oci-layout \
    "$output/runtime-image:runtime-$arch" "$output/sbom-image-$arch:runtime" >/dev/null
  # Syft reads the exact platform image and the same filesystem placed into
  # its release archive. The container has no network and cannot read source.
  for kind in image archive; do
    source="oci-dir:/release/sbom-image-$arch"
    if [ "$kind" = archive ]; then source="dir:/release/filesystems/$arch"; fi
    docker run --rm --pull=never --network none --read-only --cap-drop ALL \
      --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
      --tmpfs /tmp:rw,noexec,nosuid,size=128m,mode=1777 --env HOME=/tmp \
      --env XDG_CACHE_HOME=/tmp/.cache --env SYFT_CHECK_FOR_APP_UPDATE=false \
      --mount "type=bind,src=$output,dst=/release" "$syft_image" scan "$source" \
      --select-catalogers +go-module-binary-cataloger \
      --source-name "stellwerk-plugin-runtime-$kind-linux-$arch" \
      -o "spdx-json=/release/runtime-$kind-linux-$arch.spdx.json"
    sbom="$output/runtime-$kind-linux-$arch.spdx.json"
    jq -e '.spdxVersion == "SPDX-2.3" and .SPDXID == "SPDXRef-DOCUMENT" and
      any(.packages[]; .name == "golang.org/x/sys") and
      any(.packages[]; .name == "stdlib" and .versionInfo == "go1.26.2")' "$sbom" >/dev/null
    # Syft creates a random document UUID and wall-clock timestamp. Bind the
    # document namespace and creation time to the immutable source/image.
    jq --arg created "$created" --arg namespace "https://stellwerk.dev/sbom/runtime/${digest#sha256:}/$kind/linux/$arch" \
      '.creationInfo.created = $created | .documentNamespace = $namespace' "$sbom" >"$sbom.normalized"
    mv "$sbom.normalized" "$sbom"
  done
done
# Attachments name their subject explicitly; the publisher signs these exact
# SPDX bytes as attestations for the index and each archive's checksum.
jq -n --arg digest "$digest" --arg generator "$syft_image" \
  '{imageDigest:$digest,generator:$generator}' >"$output/sbom-subject.json"
