# Decisions

- First-package setup uses independently approved image/chart source SHAs and
  non-release bootstrap tags. Keep normal RC/stable destinations untouched,
  verify named source descriptors and exact digests, and reconcile each public
  upload/visibility/access/readback before enabling the normal publisher.
- Local chart packaging and OCI staging are preparation evidence only. Retain
  original source, archive and scan identities; do not claim a hosted producer,
  signature or public consumption result from an offline layout copy.

- Enforce Kubernetes 1.30 as the native-runtime chart minimum in both chart
  metadata and template validation. Disabling the optional preStop delay must
  not lower the supported platform floor. Supported-version workload manifests
  remain unchanged; runtime application and image inputs are untouched.
- Convert Helm's own flat chart metadata to accurate OCI config strings using
  the existing Python standard library. Reject malformed, duplicate, nested and
  unsupported scalar forms instead of retaining YAML quote delimiters in JSON.

- Add optional `package.registryCASecret: {name: "", key: ca.crt}`. Preserve
  existing behavior when its name is empty, reject plain HTTP with a configured
  CA, and validate Secret names and keys before rendering.
- Project only the selected public CA key at `/registry/ca.crt`, read-only and
  only into the shared ORAS init fetch chain. Package, attestation and blob
  transfer use the same TLS policy; runtime and migration share that chain.
- Leave publisher verification, application code, image production and release
  authority unchanged. Secret updates apply at the next Pod start.

## HTTPS package transport

- Add an explicit `package.transport=https` path alongside default `oci`. Ship
  one plain tar containing only the existing package/referrer OCI closure. Pin
  the transport hash from an independently approved release record, and keep the
  inner envelope, publisher, evidence and independent Cosign gates unchanged.
- Reuse single-host dockerconfigjson Basic credentials and public CA Secrets in
  the fetch init container. Require the CA Secret for the chart's scratch image;
  operator CLI use can retain host system roots. Publisher trust stays separate.
- Permit one HTTPS object-store redirect only to an exact operator allowlist.
  Clear all original headers, including authorization and referer, even on a
  same-host redirect. No proxy, cookie jar, wildcard host or additional hop.
- Bound archive and extraction by existing complete-package limits, reject
  non-closure files and links, and stage only in an owned temporary directory.
  Keep the original OCI install chain and installed-digest policy compatible.

## Runtime 0.1.3

- Publish the zero-replica chart validation correction as a coordinated 0.1.3
  successor, retaining normal native image/archive/chart production and all
  existing release gates. Do not relabel or overwrite 0.1.2 artifacts.
- Keep historical compatibility minima and release-specific security records
  scoped to their original versions. Only current version consumers advance.
- The normal security gate rejects Go 1.26.10 for GO-2026-6859. Advance CI,
  release tooling and SPDX compiler checks together to Go 1.26.11; retain the
  existing security gate and unchanged application dependencies.
