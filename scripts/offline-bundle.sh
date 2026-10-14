#!/usr/bin/env bash
set -euo pipefail

# offline-bundle.sh assembles the offline bundle for one plugin release: one
# OCI image layout with the signed package and its signature, SBOM and
# provenance referrers, the runtime, ORAS and Cosign image indexes for
# linux/amd64 and linux/arm64 and the runtime Helm chart, plus the public
# trust bootstrap and bundle.json, which pins every component by digest and
# is signed with the publisher's managed key (managed-key-no-tlog). The
# runtime's verify-bundle documents the layout; import-offline-bundle.sh
# verifies and imports it. No licence and no source goes into a bundle.
#
# Only the ORAS and Cosign images come from the network, from their pinned
# upstream indexes (scripts/images.sh); their linux/amd64 and linux/arm64
# manifests keep their upstream digests under a new two-platform index.
usage="usage: offline-bundle.sh --package PACKAGE_OUTPUT --runtime-image LAYOUT@DIGEST --key PRIVATE_KEY
       --trust-bootstrap PUBLISHERS_JSON --minimum-core-version VERSION [--minimum-chart-version VERSION] OUTPUT_DIRECTORY"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"

package="" runtime_image="" key="" trust="" minimum_core="" minimum_chart="" output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --package | --runtime-image | --key | --trust-bootstrap | --minimum-core-version | --minimum-chart-version)
      [ "$#" -ge 2 ] || { echo "$usage" >&2; exit 2; }
      case "$1" in
        --package) package="$2" ;;
        --runtime-image) runtime_image="$2" ;;
        --key) key="$2" ;;
        --trust-bootstrap) trust="$2" ;;
        --minimum-core-version) minimum_core="$2" ;;
        --minimum-chart-version) minimum_chart="$2" ;;
      esac
      shift 2
      ;;
    -*) echo "$usage" >&2; exit 2 ;;
    *) [ -z "$output" ] || { echo "$usage" >&2; exit 2; }; output="$1"; shift ;;
  esac
done
for value in "$package" "$runtime_image" "$key" "$trust" "$minimum_core" "$output"; do
  [ -n "$value" ] || { echo "$usage" >&2; exit 2; }
done
for command in docker oras helm jq go python3 shasum; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done
if [ -e "$output" ]; then
  echo "$output already exists" >&2
  exit 1
fi
release="$package/release.json"
package_digest="$(jq -er '.packageDigest | select(test("^sha256:[0-9a-f]{64}$"))' "$release")"
jq -e '.signature.digest and .attestations.sbom.digest and .attestations.provenance.digest' "$release" >/dev/null ||
  { echo "the package must be signed and attested (sign-layout-manifest.sh, attest-layout-manifest.sh)" >&2; exit 1; }

workspace="$(mktemp -d "${TMPDIR:-/tmp}/offline-bundle.XXXXXX")"
complete=false
cleanup() {
  rm -rf -- "$workspace"
  if [ "$complete" != true ]; then rm -rf -- "$output"; fi
}
trap cleanup EXIT
mkdir -p "$output"
output="$(cd "$output" && pwd)"
case "$output" in
  *:* | *@*) echo "refusing an output directory with ':' or '@' (ORAS reads them as a reference)" >&2; exit 1 ;;
esac
layout="$output/oci"

# The package with its referrers, the runtime image as built.
timeout -k 5s 60s oras cp --no-tty -r --from-oci-layout --to-oci-layout \
  "$package/oci-layout@$package_digest" "$layout:package" >/dev/null
timeout -k 5s 60s oras cp --no-tty --from-oci-layout --to-oci-layout "$runtime_image" "$layout:runtime" >/dev/null

# Helper images: the upstream linux/amd64 and linux/arm64 manifests under a
# two-platform index.
for name in oras cosign; do
  source_image="${name}_image"
  for architecture in amd64 arm64; do
    timeout -k 5s 240s oras cp --no-tty --platform "linux/$architecture" "${!source_image}" \
      --to-oci-layout "$layout:$name-$architecture" >/dev/null
  done
  timeout -k 5s 30s oras manifest index create --oci-layout "$layout:$name" "$name-amd64" "$name-arm64" >/dev/null
done

# The chart as the OCI artifact `helm push` writes. Its configuration is the
# chart metadata as JSON; Chart.yaml holds flat scalars only.
helm package "$root/charts/native-plugin-runtime" --destination "$workspace" >/dev/null
chart_archive="$(echo "$workspace"/native-plugin-runtime-*.tgz)"
helm show chart "$chart_archive" | python3 "$root/scripts/chart-config.py" >"$workspace/chart-config.json"
chart_version="$(jq -er '.version' "$workspace/chart-config.json")"
created="$(TZ=UTC git -C "$root" log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ)"
(
  cd "$workspace"
  timeout -k 5s 60s oras push --no-tty --oci-layout "$layout:chart" \
    --annotation "org.opencontainers.image.created=$created" \
    --config chart-config.json:application/vnd.cncf.helm.config.v1+json \
    "$(basename "$chart_archive"):application/vnd.cncf.helm.chart.content.v1.tar+gzip" >/dev/null
)

# The index lists the five components and the package's three referrers,
# nothing else; ORAS's working directory goes.
rmdir "$layout/ingest" 2>/dev/null || true
jq --slurpfile release "$release" '
  ($release[0] | [.signature.digest, .attestations.sbom.digest, .attestations.provenance.digest]) as $referrers
  | .manifests |= map(select(
      (.annotations["org.opencontainers.image.ref.name"] | IN("package", "runtime", "oras", "cosign", "chart"))
      or (.digest | IN($referrers[]))))' "$layout/index.json" >"$workspace/index.json"
mv -- "$workspace/index.json" "$layout/index.json"
test "$(jq '.manifests | length' "$layout/index.json")" = 8

cp "$trust" "$output/publishers.json"
resolve() { oras resolve --oci-layout "$layout:$1"; }
jq -n --slurpfile release "$release" \
  --arg trust "sha256:$(shasum -a 256 "$output/publishers.json" | awk '{print $1}')" \
  --arg minimumCore "$minimum_core" --arg minimumChart "${minimum_chart:-$chart_version}" \
  --arg runtime "$(resolve runtime)" --arg oras "$(resolve oras)" --arg cosign "$(resolve cosign)" \
  --arg orasSource "$oras_image" --arg cosignSource "$cosign_image" \
  --arg chartVersion "$chart_version" --arg chart "$(resolve chart)" '
  $release[0] as $r | {
    schemaVersion: 1, pluginId: $r.pluginId, pluginVersion: $r.pluginVersion,
    minimumCoreVersion: $minimumCore, minimumChartVersion: $minimumChart, trustBootstrap: $trust,
    package: {digest: $r.packageDigest, manifestSHA256: $r.manifestSHA256, signature: $r.signature.digest,
              sbom: $r.attestations.sbom.digest, provenance: $r.attestations.provenance.digest},
    images: {runtime: {digest: $runtime}, oras: {digest: $oras, source: $orasSource},
             cosign: {digest: $cosign, source: $cosignSource}},
    chart: {version: $chartVersion, digest: $chart}}' >"$output/bundle.json"

# bundle.json is signed like the package: the publisher's managed key, no
# transparency log.
require_image "$cosign_image" "$(docker_platform)"
offline_cosign \
  --mount "type=bind,src=$(cd "$(dirname "$key")" && pwd),dst=/key,readonly" \
  --mount "type=bind,src=$output,dst=/bundle" \
  --mount "type=bind,src=$root/scripts/signing-config-no-tlog.json,dst=/config/signing-config.json,readonly" \
  -- sign-blob --yes --signing-config=/config/signing-config.json --key "/key/$(basename "$key")" \
  --bundle /bundle/bundle.sigstore.json /bundle/bundle.json >/dev/null

# Verify the result exactly as the customer's import will.
GOWORK=off go -C "$root" build -trimpath -o "$workspace/runtime" ./runtime
"$workspace/runtime" verify-bundle --bundle "$output" \
  --trust-bootstrap-digest "$(jq -r .trustBootstrap "$output/bundle.json")" >/dev/null
complete=true
echo "$output"
