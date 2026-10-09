#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/release-tools.sh"
output="${1:?usage: collect-licenses.sh OUTPUT_DIRECTORY}"
test ! -e "$output" || { echo "license destination already exists" >&2; exit 1; }
command -v go-licenses >/dev/null
go version -m "$(command -v go-licenses)" | grep -F "$go_licenses_module" | grep -F "$go_licenses_version" >/dev/null
export GOTOOLCHAIN="$release_go_version" GOWORK=off GOENV=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64
unset GOFLAGS
cd "$root"
# The application's EUPL text is copied explicitly. go-licenses collects the
# shipped third-party packages; tests and tool dependencies are not shipped.
go-licenses save ./runtime --ignore github.com/stellwerk-labs/stellwerk-plugin-runtime --save_path "$output"
mkdir -p "$output/stellwerk-plugin-runtime" "$output/go"
cp LICENSE "$output/stellwerk-plugin-runtime/LICENSE"
goroot="$(go env GOROOT)"
cp "$goroot/LICENSE" "$output/go/LICENSE"
cp "$goroot/PATENTS" "$output/go/PATENTS"
# go-licenses copies LICENSE and NOTICE, but not Go's additional patent grant.
sysdir="$(go list -m -f '{{.Dir}}' golang.org/x/sys)"
cp "$sysdir/PATENTS" "$output/golang.org/x/sys/PATENTS"
python3 "$root/scripts/release_content.py" notices "$output"
