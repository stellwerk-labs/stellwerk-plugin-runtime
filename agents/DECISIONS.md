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
