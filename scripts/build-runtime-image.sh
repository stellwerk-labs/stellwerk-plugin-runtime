#!/usr/bin/env bash
set -euo pipefail

# build-runtime-image.sh OUTPUT_LAYOUT builds the generic runtime image for
# linux/amd64 and linux/arm64 as one OCI image index into an OCI image
# layout, tagged "runtime", and prints the index digest. It needs no Docker
# daemon or emulation and builds what Dockerfile.runtime describes: FROM
# scratch, the static /runtime, USER 65532:65532, ENTRYPOINT ["/runtime"].
# Layers are written deterministically and the creation time is the commit
# time, so the same commit and Go toolchain give the same digests.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:?usage: build-runtime-image.sh OUTPUT_LAYOUT}"

for command in go oras jq python3 git; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
case "$output" in
  "$root" | / | "") echo "refusing unsafe output directory" >&2; exit 1 ;;
esac
created="$(TZ=UTC git -C "$root" log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ)"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/runtime-image.XXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT

for architecture in amd64 arm64; do
  mkdir "$workspace/$architecture"
  CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" GOWORK=off \
    go build -trimpath -o "$workspace/$architecture/runtime" "$root/runtime"
  # One gzip layer holding /runtime (root-owned, 0755, epoch mtime).
  diff_id="$(python3 - "$workspace/$architecture" <<'PY'
import gzip, hashlib, io, sys, tarfile
directory = sys.argv[1]
data = open(f"{directory}/runtime", "rb").read()
raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
    entry = tarfile.TarInfo("runtime")
    entry.size, entry.mode, entry.mtime = len(data), 0o755, 0
    archive.addfile(entry, io.BytesIO(data))
layer = raw.getvalue()
with open(f"{directory}/layer.tar.gz", "wb") as output:
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        compressed.write(layer)
print("sha256:" + hashlib.sha256(layer).hexdigest())
PY
)"
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
