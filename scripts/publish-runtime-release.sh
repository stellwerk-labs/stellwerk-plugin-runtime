#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"
output="$(cd "${1:?usage: publish-runtime-release.sh VERIFIED_RELEASE_DIRECTORY}" && pwd)"
# Repeat identity, signed tag, review configuration and duplicate checks under
# the workflow's publication concurrency after the required human review.
python3 "$root/scripts/release_policy.py" preflight
version="$RELEASE_VERSION"
source_sha="$RELEASE_SOURCE_SHA"
image=ghcr.io/stellwerk-labs/stellwerk-plugin-runtime
chart=ghcr.io/stellwerk-labs/charts/native-plugin-runtime
digest="$(jq -er --arg commit "$source_sha" --arg version "$version" \
  'select(.source.commit == $commit and .source.dirty == false and .version == $version) | .image.digest' "$output/release.json")"
test "$(shasum -a 256 "$output/BUILD-SHA256SUMS" | awk '{print $1}')" = "$RELEASE_CHECKSUMS_SHA256"
(cd "$output" && shasum -a 256 --check BUILD-SHA256SUMS >/dev/null)
"$root/scripts/scan-release-content.sh" "$output" "$RELEASE_FORBIDDEN_LITERAL"
python3 "$root/scripts/release_content.py" export "$output/runtime-image" "$digest" "$RUNNER_TEMP/publication-filesystems"
"$root/scripts/scan-release-content.sh" "$RUNNER_TEMP/publication-filesystems" "$RELEASE_FORBIDDEN_LITERAL"

export DOCKER_CONFIG="$RUNNER_TEMP/runtime-release-docker"
export HELM_REGISTRY_CONFIG="$RUNNER_TEMP/runtime-release-helm.json"
mkdir -m 0700 "$DOCKER_CONFIG"
printf '%s' "$GH_TOKEN" | docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin >/dev/null
printf '%s' "$GH_TOKEN" | oras login ghcr.io --username "$GITHUB_ACTOR" --password-stdin >/dev/null
printf '%s' "$GH_TOKEN" | helm registry login ghcr.io --username "$GITHUB_ACTOR" --password-stdin >/dev/null
require_image "$cosign_image" "$(docker_platform)"
identity="https://github.com/stellwerk-labs/stellwerk-plugin-runtime/.github/workflows/release.yaml@refs/heads/main"
issuer=https://token.actions.githubusercontent.com
verification=(--certificate-identity "$identity" --certificate-oidc-issuer "$issuer" --certificate-github-workflow-sha "$source_sha")
cosign_release() {
  timeout -k 5s 120s docker run --rm --pull=never --read-only --cap-drop ALL \
    --security-opt no-new-privileges --user "$(id -u):$(id -g)" \
    --tmpfs /tmp:rw,noexec,nosuid,size=32m,mode=1777 --env HOME=/tmp --env DOCKER_CONFIG=/docker \
    --env GITHUB_ACTIONS --env ACTIONS_ID_TOKEN_REQUEST_URL --env ACTIONS_ID_TOKEN_REQUEST_TOKEN \
    --mount "type=bind,src=$DOCKER_CONFIG,dst=/docker,readonly" \
    --mount "type=bind,src=$output,dst=/release" "$cosign_image" "$@"
}

# A preapproved signed tag already exists. --verify-tag forbids gh from
# silently creating an unsigned replacement. A failed run leaves this draft
# and any uploaded bytes intact for inspection; it is never retried in place.
release_args=(--verify-tag --draft --title "Stellwerk plugin runtime v$version" --notes-file "$output/release-notes.md")
if [[ "$version" == *-rc.* ]]; then release_args+=(--prerelease); fi
gh release create "v$version" "${release_args[@]}" --repo "$GITHUB_REPOSITORY" >/dev/null
oras cp --no-tty --from-oci-layout "$output/runtime-image@$digest" "$image:v$version" >/dev/null
test "$(oras resolve "$image:v$version")" = "$digest"
helm push "$output/native-plugin-runtime-$version.tgz" oci://ghcr.io/stellwerk-labs/charts >/dev/null
chart_digest="$(oras resolve "$chart:$version")"

sign_image() {
  local subject="$1"
  cosign_release sign --yes --oidc-provider github-actions "$subject" >/dev/null
  cosign_release attest --yes --oidc-provider github-actions --type slsaprovenance1 \
    --predicate /release/source-provenance.json "$subject" >/dev/null
  cosign_release verify "${verification[@]}" "$subject" >/dev/null
  cosign_release verify-attestation "${verification[@]}" --type slsaprovenance1 \
    --output json "$subject" >"$output/verified-provenance.json"
  python3 "$root/scripts/release_policy.py" statement "$output/verified-provenance.json" \
    "${subject##*@}" https://slsa.dev/provenance/v1 "$output/source-provenance.json"
}
sign_image "$image@$digest"
sign_image "$chart@$chart_digest"
for arch in amd64 arm64; do
  platform_digest="$(oras resolve --oci-layout "$output/runtime-image:runtime-$arch")"
  sign_image "$image@$platform_digest"
  for subject in "$image@$digest" "$image@$platform_digest"; do
    cosign_release attest --yes --oidc-provider github-actions --type spdxjson \
      --predicate "/release/runtime-image-linux-$arch.spdx.json" "$subject" >/dev/null
    cosign_release verify-attestation "${verification[@]}" --type spdxjson --output json "$subject" >"$output/verified-sbom.json"
    python3 "$root/scripts/release_policy.py" statement "$output/verified-sbom.json" \
      "${subject##*@}" https://spdx.dev/Document "$output/runtime-image-linux-$arch.spdx.json"
  done
done

# Sign the checksum manifest and each downloadable archive. SPDX/provenance
# bundles bind their predicates to the archive's own digest, not the image.
for file in "$output/SHA256SUMS" "$output/"*.tar.gz "$output/"*.tgz; do
  name="$(basename "$file")"
  cosign_release sign-blob --yes --oidc-provider github-actions --bundle "/release/$name.sigstore.json" "/release/$name" >/dev/null
  cosign_release verify-blob "${verification[@]}" --bundle "/release/$name.sigstore.json" "/release/$name" >/dev/null
  if [ "$name" = SHA256SUMS ]; then continue; fi
  file_digest="$(shasum -a 256 "$file" | awk '{print $1}')"
  cosign_release attest-blob --yes --oidc-provider github-actions --type slsaprovenance1 \
    --predicate /release/source-provenance.json --bundle "/release/$name.provenance.sigstore.json" "/release/$name" >/dev/null
  cosign_release verify-blob-attestation "${verification[@]}" --type slsaprovenance1 \
    --bundle "/release/$name.provenance.sigstore.json" "/release/$name" >/dev/null
  python3 "$root/scripts/release_policy.py" statement "$output/$name.provenance.sigstore.json" \
    "$file_digest" https://slsa.dev/provenance/v1 "$output/source-provenance.json"
  if [[ "$name" == *.tar.gz ]]; then
    arch="${name%.tar.gz}"; arch="${arch##*_}"
    cosign_release attest-blob --yes --oidc-provider github-actions --type spdxjson \
      --predicate "/release/runtime-archive-linux-$arch.spdx.json" \
      --bundle "/release/$name.sbom.sigstore.json" "/release/$name" >/dev/null
    cosign_release verify-blob-attestation "${verification[@]}" --type spdxjson \
      --bundle "/release/$name.sbom.sigstore.json" "/release/$name" >/dev/null
    python3 "$root/scripts/release_policy.py" statement "$output/$name.sbom.sigstore.json" \
      "$file_digest" https://spdx.dev/Document "$output/runtime-archive-linux-$arch.spdx.json"
  fi
done

# Prove anonymous distribution while the release is still a draft. The clean
# registry config contains no workflow token. Signatures still check the exact
# producer identity, source SHA, subjects and predicates above.
anonymous="$RUNNER_TEMP/runtime-anonymous"
mkdir -m 0700 "$anonymous"
test "$(DOCKER_CONFIG="$anonymous" oras resolve "$image:v$version")" = "$digest"
test "$(DOCKER_CONFIG="$anonymous" oras resolve "$chart:$version")" = "$chart_digest"
DOCKER_CONFIG="$anonymous" cosign_release verify "${verification[@]}" "$image@$digest" >/dev/null
DOCKER_CONFIG="$anonymous" cosign_release verify "${verification[@]}" "$chart@$chart_digest" >/dev/null
assets=("$output/"*.tar.gz "$output/"*.tgz "$output/"*.spdx.json \
  "$output/"*.sigstore.json "$output/SHA256SUMS" "$output/release.json" \
  "$output/source-provenance.json")
# Include generated signature/attestation bundles in the final staged scan too.
"$root/scripts/scan-release-content.sh" "$output" "$RELEASE_FORBIDDEN_LITERAL"
gh release upload "v$version" "${assets[@]}" --repo "$GITHUB_REPOSITORY"
# Download the reserved assets and compare the original bytes before publishing.
download="$RUNNER_TEMP/runtime-upload-proof"
mkdir "$download"
gh release download "v$version" --repo "$GITHUB_REPOSITORY" --dir "$download"
for file in "${assets[@]}"; do cmp "$file" "$download/$(basename "$file")"; done
gh release view "v$version" --repo "$GITHUB_REPOSITORY" --json body | \
  jq -e --rawfile notes "$output/release-notes.md" '.body == $notes' >/dev/null
gh release edit "v$version" --repo "$GITHUB_REPOSITORY" --draft=false
