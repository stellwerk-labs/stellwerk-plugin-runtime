#!/usr/bin/env bash
set -euo pipefail

package_output="${1:?usage: offline-bundle.sh PACKAGE_OUTPUT OUTPUT_TAR}"
output_tar="${2:?usage: offline-bundle.sh PACKAGE_OUTPUT OUTPUT_TAR}"

test -d "$package_output/oci-layout"
test -s "$package_output/release.json"
case "$output_tar" in /|"") echo "refusing unsafe output path" >&2; exit 1 ;; esac

staging="$(mktemp -d "${TMPDIR:-/tmp}/native-plugin-offline.XXXXXX")"
trap 'rm -rf -- "$staging"' EXIT
cp -R "$package_output/oci-layout" "$staging/oci-layout"
cp "$package_output/release.json" "$package_output/oci-manifest.json" "$staging/"
if [ -s "$package_output/oci-manifest.sigstore.json" ]; then
  cp "$package_output/oci-manifest.sigstore.json" "$staging/"
fi
tar -C "$staging" -cf "$output_tar" .
echo "$output_tar"
