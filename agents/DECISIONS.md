# Decisions

- Add optional `package.registryCASecret: {name: "", key: ca.crt}`. Preserve
  existing behavior when its name is empty, reject plain HTTP with a configured
  CA, and validate Secret names and keys before rendering.
- Project only the selected public CA key at `/registry/ca.crt`, read-only and
  only into the shared ORAS init fetch chain. Package, attestation and blob
  transfer use the same TLS policy; runtime and migration share that chain.
- Leave publisher verification, application code, image production and release
  authority unchanged. Secret updates apply at the next Pod start.
