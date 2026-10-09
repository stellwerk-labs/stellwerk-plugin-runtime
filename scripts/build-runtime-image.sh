#!/usr/bin/env bash
set -euo pipefail

# build-runtime-image.sh OUTPUT_LAYOUT builds the generic runtime image for
# linux/amd64 and linux/arm64 as one OCI image index into an OCI image
# layout, tagged "runtime", and prints the index digest. It needs no Docker
# daemon or emulation and builds what Dockerfile.runtime describes: FROM
# scratch, the static /runtime, /licenses, USER 65532:65532 and /runtime entrypoint.
# Layers are written deterministically and the creation time is the commit
# time, so the same commit and Go toolchain give the same digests.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:?usage: build-runtime-image.sh OUTPUT_LAYOUT [CONTENT_DIRECTORY]}"
context="${2:-}"

for command in go oras jq python3 git; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
mkdir -p "$output"
output="$(cd "$output" && pwd)"
case "$output" in
  "$root" | /) echo "refusing unsafe output directory" >&2; exit 1 ;;
esac
created="$(TZ=UTC git -C "$root" log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ)"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/runtime-image.XXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT
if [ -z "$context" ]; then
  context="$workspace/content"
  "$root/scripts/build-runtime-files.sh" "$context"
fi
python3 "$root/scripts/release_content.py" notices "$context/licenses"

for architecture in amd64 arm64; do
  mkdir "$workspace/$architecture"
  diff_id="$(python3 "$root/scripts/release_content.py" layer "$context" "$architecture" "$workspace/$architecture/layer.tar.gz")"
  jq -n --arg architecture "$architecture" --arg diffId "$diff_id" --arg created "$created" '{
    created: $created, architecture: $architecture, os: "linux",
    config: {User: "65532:65532", Entrypoint: ["/runtime"]},
    rootfs: {type: "layers", diff_ids: [$diffId]}}' >"$workspace/$architecture/config.json"
  (
    cd "$workspace/$architecture"
    oras push --no-tty --oci-layout "$output:runtime-$architecture" \
      --annotation "org.opencontainers.image.created=$created" \
      --config config.json:application/vnd.oci.image.config.v1+json \
      layer.tar.gz:application/vnd.oci.image.layer.v1.tar+gzip >/dev/null
  )
done
oras manifest index create --oci-layout "$output:runtime" runtime-amd64 runtime-arm64 >/dev/null
oras resolve --oci-layout "$output:runtime"
