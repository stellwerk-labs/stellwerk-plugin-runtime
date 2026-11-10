# HTTPS package delivery

The optional HTTPS transport downloads one `plugin.tar` from a private Generic
Package Registry. It carries the original signed OCI package and its signature,
SBOM and provenance graph. No OCI registry operation, helper image archive or new
signature format is involved. The existing OCI transport remains the default.

Use runtime and chart 0.1.2 or later with `fetch-https` support. An
older runtime fails on the unknown command. Existing direct OCI installations
keep their original fetch, envelope, publisher, independent Cosign and validation
chain. Do not switch a deployment to HTTPS until its runtime image supports it.

## Operator inputs

Obtain the approved release record and public publisher bootstrap independently
of the package download. Map its exact identity, version, package and referrer
pins into Helm values. `deliverySHA256` is the tar hash, whereas
`package.manifestSHA256` identifies the plugin manifest inside the package. Strip
the `sha256:` prefix only for the two `SHA256` values below.

```yaml
plugin:
  id: dev.example.plugin
  version: 1.0.0
package:
  transport: https
  reference: ""
  manifestSHA256: "<approved plugin-manifest hash, 64 lowercase hex>"
  https:
    url: https://gitlab.example/api/v4/projects/123/packages/generic/plugin/1.0.0/plugin.tar
    archiveSHA256: "<approved deliverySHA256, 64 lowercase hex>"
    digest: "sha256:<approved package digest>"
    signatureDigest: "sha256:<approved signature referrer digest>"
    # Exact object-store host, only when GitLab returns a signed redirect.
    redirectHosts: [objects.example]
  attestations:
    sbom: "sha256:<approved SBOM referrer digest>"
    provenance: "sha256:<approved provenance referrer digest>"
  registryConfigSecret:
    name: plugin-package-reader
    key: .dockerconfigjson
  registryCASecret:
    name: independently-trusted-public-ca
    key: ca.crt
trust:
  mode: managed-key-no-tlog
  bootstrapSecret:
    name: independently-approved-publishers
    key: publishers.json
  # HTTPS reads the original signature from the verified archive.
  signatureBundleSecret:
    name: ""
```

The reader Secret is a dockerconfigjson file with exactly one host entry and
only its `auth` field. It contains base64 of `username:deploy-token`, for example
`{"auths":{"gitlab.example":{"auth":"<base64 credentials>"}}}`. Match the
initial URL's exact host, including a nondefault port. Use a product-specific,
expiring GitLab deploy token with `read_package_registry`, rather than
`read_registry`. Keep the token out of values, URLs, command arguments and logs.

The scratch runtime image has no operating-system root certificate store.
The HTTPS chart requires an independent public CA bundle in `registryCASecret`; include the roots
for both GitLab and its approved object-store host. Do not populate this Secret
by trusting an unauthenticated certificate chain from the download endpoint.
The CA is public transport trust, separate from publisher, Core and database
trust. Outside scratch, the command also uses the host's system roots.

The initial URL must use HTTPS without userinfo, query or fragment. One HTTPS
redirect to an exact configured `redirectHosts` entry is allowed. Its signed
query is accepted, and the new request carries no authorization, cookie or
referer headers, including on a same-host redirect. Unknown hosts, further
redirects and TLS failures stop the fetch. Configure existing
`networkPolicy.registryMirrors` for both endpoints as needed. The policy is
per Pod; only the fetch init container receives the reader Secret.

## Verification and storage

The runtime reads the independent bootstrap before network access, downloads to
an owned private temporary file, bounds the whole request to two minutes and
checks the approved tar SHA256 before extraction. It accepts only bounded plain
regular OCI files at the exact paths below, plus optional `blobs/` and
`blobs/sha256/` directory entries. Links, duplicate paths, foreign files/blobs,
oversized entries, incomplete tar files and extra data after the end marker are
refused. Modes, ownership and executable bits from the archive are ignored.

```text
oci-layout
index.json
blobs/sha256/<64 lowercase hex>
```

`index.json` lists exactly the original package manifest and the configured
signature/SBOM/provenance referrer descriptors. The blob directory contains
exactly their transitive closure. The package's original OCI envelope, layer
hashes, plugin identity/version, signed evidence and publisher policy are checked
with the same verifier used by offline bundles. No bootstrap, private source,
keys, runtime/ORAS/Cosign images or Helm chart belongs in this archive.

After verification, the fetch init container writes the original package and
evidence bytes. The chart still runs `verify-package-publisher`, independent
Cosign verification of each configured evidence part, and normal package
validation before migration or launch. `installedDigest` retains the existing
rule for an already installed package; it never bypasses key revocation.

The archive bound follows the existing complete package limits, approximately
605 MiB including tar overhead. HTTPS Pods allow 1280 MiB for temporary archive
and layout storage, in addition to the existing package volume. This is a size
limit, not a storage reservation. Check node and namespace ephemeral-storage
capacity before deployment. OCI Pods retain their 16 MiB temporary limit.
Temporary downloads and extracted layouts are removed when the fetch exits.

Customer delivery projects must contain only approved stable files. GitLab
Generic Package duplication settings do not make an Owner overwrite impossible;
preserve no-overwrite publication and install by the independently approved
archive hash and original publisher signatures.
