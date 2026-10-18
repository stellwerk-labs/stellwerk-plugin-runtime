# First-time runtime package setup

This is an operator runbook, not publication authorization or an automatic
workflow. The release workflow deliberately requires two already-public GHCR
packages. GHCR creates a package on its first OCI upload, so an operator must
bootstrap those destinations separately before the first release. Do not enable
the release workflow to discover or repair this prerequisite.

## Approval and receipts

Obtain explicit approval for the public repository/source export and, separately,
the two bootstrap uploads and package-visibility/access changes below. The
approval must name:

- the exact signed, qualified public source commits for the image and chart,
  recorded separately as `APPROVED_IMAGE_SOURCE_SHA` and
  `APPROVED_CHART_SOURCE_SHA`, with their immutable build-artifact IDs/digests,
  clean-source release metadata and passing content scans; a chart-only change
  must not relabel an unchanged image as built from the newer chart commit;
- `ghcr.io/stellwerk-labs/stellwerk-plugin-runtime`, its exact qualified two-platform
  image index digest and both platform digests;
- `ghcr.io/stellwerk-labs/charts/native-plugin-runtime`, the exact qualified Helm
  OCI manifest digest, chart version and SHA-256 of its original `.tgz` payload;
- the distinct non-release tags `bootstrap-image-<APPROVED_IMAGE_SOURCE_SHA>`
  and `bootstrap-chart-<APPROVED_CHART_SOURCE_SHA>` on their respective packages,
  public visibility, and release-workflow access for the public runtime repository.

No stable/RC/latest tag, Git tag, GitHub release, signing operation or package
deletion is part of bootstrap. Keep the immutable bootstrap tags and receipt.
Do not use test keys or upload test-key signatures to a transparency log.

## Preserve the exact chart payload

Use an already qualified, separately authorized private or local staging registry
for the chart. Normal `helm push` derives its destination tag from `Chart.version`.
Do not edit that version, invent a bootstrap release version or repackage the
chart. Export its existing OCI artifact by the approved digest instead:

```sh
oras cp --no-tty --to-oci-layout \
  "$APPROVED_CHART_STAGING_REFERENCE@$APPROVED_CHART_DIGEST" \
  "$CHART_LAYOUT:qualified"
test "$(oras resolve --oci-layout "$CHART_LAYOUT:qualified")" = "$APPROVED_CHART_DIGEST"
oras manifest fetch --oci-layout "$CHART_LAYOUT@$APPROVED_CHART_DIGEST" > "$RECEIPTS/chart-manifest.json"
layer="$(jq -er '.layers | select(length == 1) | .[0] | select(.mediaType == "application/vnd.cncf.helm.chart.content.v1.tar+gzip") | .digest' "$RECEIPTS/chart-manifest.json")"
oras blob fetch --oci-layout "$CHART_LAYOUT@$layer" --output "$RECEIPTS/chart.tgz"
cmp "$APPROVED_CHART_ARCHIVE" "$RECEIPTS/chart.tgz"
```

If a qualified chart OCI manifest does not yet exist, stage the already-qualified
archive either in a local Helm-format OCI layout using the config and media types
in `scripts/offline-bundle.sh`, or with normal `helm push` in a separately
authorized private/local registry. Qualify the exact manifest/config/layer,
archive readback and digest before requesting public bootstrap approval. Local
layout preparation alone is not hosted release qualification. ORAS copying by
digest preserves the Helm OCI manifest/config/layer bytes while assigning a
different registry tag. See the [ORAS copy documentation](https://oras.land/docs/commands/oras_cp/).

## Operator-only public stage

Before any upload, repeat source/artifact identity and complete staged-content
checks. Confirm the target organization/repository and credential scopes. Establish
that **both exact bootstrap tags are absent** using authenticated registry reads:
only an actual HTTP 404 establishes absence. Authorization, transport, rate-limit
or server failures do not. Record the read receipts without credentials. An
existing tag, including one pointing at matching bytes, stops this write stage.

Only after the specific approval and absence checks, an operator may run:

```sh
image_bootstrap="bootstrap-image-$APPROVED_IMAGE_SOURCE_SHA"
chart_bootstrap="bootstrap-chart-$APPROVED_CHART_SOURCE_SHA"
image=ghcr.io/stellwerk-labs/stellwerk-plugin-runtime
chart=ghcr.io/stellwerk-labs/charts/native-plugin-runtime
test "$(oras resolve --oci-layout "$IMAGE_LAYOUT:runtime")" = "$APPROVED_IMAGE_DIGEST"
jq -e --arg digest "$APPROVED_IMAGE_DIGEST" '
  .manifests | any(.digest == $digest
    and .mediaType == "application/vnd.oci.image.index.v1+json"
    and .annotations["org.opencontainers.image.ref.name"] == "runtime")
' "$IMAGE_LAYOUT/index.json" >/dev/null
test "$(oras resolve --oci-layout "$CHART_LAYOUT:qualified")" = "$APPROVED_CHART_DIGEST"
jq -e --arg digest "$APPROVED_CHART_DIGEST" '
  .manifests | any(.digest == $digest
    and .mediaType == "application/vnd.oci.image.manifest.v1+json"
    and .annotations["org.opencontainers.image.ref.name"] == "qualified")
' "$CHART_LAYOUT/index.json" >/dev/null
oras cp --no-tty --from-oci-layout \
  "$IMAGE_LAYOUT:runtime" "$image:$image_bootstrap"
oras cp --no-tty --from-oci-layout \
  "$CHART_LAYOUT:qualified" "$chart:$chart_bootstrap"
test "$(oras resolve "$image:$image_bootstrap")" = "$APPROVED_IMAGE_DIGEST"
test "$(oras resolve "$chart:$chart_bootstrap")" = "$APPROVED_CHART_DIGEST"
```

Configure each package's public visibility and public runtime workflow access
through the approved owner-controlled settings. Verify each package metadata API
reports `visibility: public`. No script here changes visibility or grants access.

Then repeat distribution checks with an empty registry credential directory:

```sh
anonymous="$(mktemp -d)"
DOCKER_CONFIG="$anonymous" oras cp --no-tty --to-oci-layout \
  "$image@$APPROVED_IMAGE_DIGEST" "$anonymous/image:qualified"
DOCKER_CONFIG="$anonymous" oras cp --no-tty --to-oci-layout \
  "$chart@$APPROVED_CHART_DIGEST" "$anonymous/chart:qualified"
test "$(oras resolve --oci-layout "$anonymous/image:qualified")" = "$APPROVED_IMAGE_DIGEST"
test "$(oras resolve --oci-layout "$anonymous/chart:qualified")" = "$APPROVED_CHART_DIGEST"
```

Fetch the anonymous chart layer as above and compare it with the original archive;
verify its unchanged chart/app version. Record public package IDs/visibility,
bootstrap tags, source/build identities, image index/platform and chart manifest
digests, archive checksum, anonymous-read receipts and the approving operator.
Keep release destinations `vVERSION` (image) and `VERSION` (chart) absent. Only
then consider the separate normal release approval and reviewer-protected workflow.

## Failure and retry rules

On any failure or partial upload, stop and retain receipts and original bytes.
Inspect occupied tags read-only. Never move or overwrite a tag, repeat an upload
over an occupied destination, rebuild replacement bytes, change the chart version,
delete a package or weaken the visibility gate. Matching existing digests may be
verified read-only; any further mutation needs a fresh, specific operator approval.
This bootstrap does not itself qualify or publish a release.
