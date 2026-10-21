# Signature metadata regression

`sigstore-inclusion-proof.json` contains a Sigstore v0.3 bundle retrieved from
the public `ghcr.io/stellwerk-labs/stellwerk-plugin-runtime` repository:

- Subject: `sha256:3396677dd9caeee8d6172b349f9a584f97142a9f61fbd431ea16ca08a23f329f`
- Referrer manifest: `sha256:32972077d3f966a3abfb7d577358c9e87939b3553e3e4749967838e176754c80`
- Original layer: `sha256:f5b6af02e20f4c66aa2c9ccffde9a407487babb6ce8c3833576f506d78c65447`, 20526 bytes
- Fixture with one trailing newline: `sha256:66ec8fc8fc771950acf65c075ea571a65da891de4283e7387687311c65bec86f`, 20527 bytes

The test removes exactly that newline and verifies the original layer hash.
An encoded Merkle inclusion-proof hash happens to match a short text identifier.
This fixture exercises representation-aware content scanning, not cryptographic
verification or qualification of the historical artifact.

The exclusion is limited to canonical 32-byte hashes at the bundle's exact
inclusion-proof path. Filenames, other fields, concrete private references and
secret scans remain checked. The field definition is in the upstream
[Sigstore Rekor schema](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_rekor.proto).
