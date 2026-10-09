#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/release-tools.sh"
version="${1:?usage: build-runtime-release.sh VERSION OUTPUT_DIRECTORY}"
output="${2:?usage: build-runtime-release.sh VERSION OUTPUT_DIRECTORY}"
if ! [[ "$version" =~ ^0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$ ]]; then
  echo "expected a canonical pre-1.0 version (optionally -rc.N)" >&2
  exit 1
fi
chart_version="$(helm show chart "$root/charts/native-plugin-runtime" | awk '/^version: / {print $2}')"
test "${version%%-rc.*}" = "$chart_version" || { echo "release version must match the source chart version" >&2; exit 1; }
test ! -e "$output" || { echo "release destination already exists" >&2; exit 1; }
mkdir -p "$output"
output="$(cd "$output" && pwd)"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/runtime-release.XXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT
"$root/scripts/build-runtime-files.sh" "$workspace/content"
digest="$("$root/scripts/build-runtime-image.sh" "$output/runtime-image" "$workspace/content")"
python3 "$root/scripts/release_content.py" export "$output/runtime-image" "$digest" "$output/filesystems"
for arch in amd64 arm64; do
  python3 "$root/scripts/release_content.py" archive "$workspace/content" "$arch" \
    "$output/stellwerk-plugin-runtime_${version}_linux_${arch}.tar.gz" >/dev/null
done
helm package "$root/charts/native-plugin-runtime" --version "$version" --app-version "$version" --destination "$workspace" >/dev/null
python3 "$root/scripts/release_content.py" chart "$workspace/native-plugin-runtime-$version.tgz" \
  "$output/native-plugin-runtime-$version.tgz"
dirty=false
if [ -n "$(git -C "$root" status --porcelain)" ]; then dirty=true; fi
jq -n --arg version "$version" --arg commit "$(git -C "$root" rev-parse HEAD)" \
  --arg created "$(TZ=UTC git -C "$root" log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ)" \
  --arg image "$digest" --arg go "$release_go_version" --argjson dirty "$dirty" \
  '{schemaVersion:1,version:$version,source:{commit:$commit,dirty:$dirty,created:$created},
    tools:{go:$go},image:{digest:$image,platforms:["linux/amd64","linux/arm64"]}}' >"$output/release.json"
"$root/scripts/scan-release-content.sh" "$output" "${RELEASE_FORBIDDEN_LITERAL:-}"
echo "$output/release.json"
