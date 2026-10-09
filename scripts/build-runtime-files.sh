#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/release-tools.sh"
output="${1:?usage: build-runtime-files.sh OUTPUT_DIRECTORY}"
test ! -e "$output" || { echo "runtime content destination already exists" >&2; exit 1; }
mkdir -p "$output"
export GOTOOLCHAIN="$release_go_version" GOWORK=off GOENV=off CGO_ENABLED=0 GOOS=linux GOAMD64=v1 GOARM64=v8.0
unset GOFLAGS GOEXPERIMENT
for arch in amd64 arm64; do
  GOARCH="$arch" go -C "$root" build -trimpath -buildvcs=true -o "$output/runtime-linux-$arch" ./runtime
done
"$root/scripts/collect-licenses.sh" "$output/licenses"
