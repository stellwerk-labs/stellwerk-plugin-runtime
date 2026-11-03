# Third-party executable disposition for Runtime 0.1.1

## Release decision and limits

On 3 November 2026, the coordinated generic Runtime 0.1.1 and Runner 3.2.0
release was explicitly authorized to proceed with the known residual findings
in the selected official third-party artifacts after a fresh review of the
official release channels found no qualified patched successor for this release.
This acceptance applies to this coordinated release only. It does not declare
these executables vulnerability-free, approve future releases or preapprove
unknown or newly observed findings.

This disposition does not waive vulnerability checks for Stellwerk-owned source
or executables. The normal source, artifact, signature, exact provenance/SPDX,
content, functional, native-platform and installation checks remain required.
Existing signatures, checksums and immutable versions are preserved. No scanner
is disabled, no finding is silently reclassified, and no third-party pin is
changed by this document.

## Selected artifacts and their roles

| Official artifact | Exact selected identity | Role |
| --- | --- | --- |
| [ORAS 1.3.4](https://github.com/oras-project/oras/releases/tag/v1.3.4) Linux AMD64 host archive | `oras_1.3.4_linux_amd64.tar.gz`, SHA-256 `f27adb935022d94df8dc77719c322dda592c78a0d57a6f7dcdd8d900b248c454` | Checksum-verified transport CLI installed by the Runtime producer and publisher; separate from the OCI image. |
| [ORAS 1.3.4](https://github.com/oras-project/oras/releases/tag/v1.3.4) OCI image | `ghcr.io/oras-project/oras@sha256:f7bc056d54d97baa399414ed5048ecc67c3371b750d4bbce1d871827a5758179` | Tested package-fetch/init and offline-bundle helper image. |
| [Cosign 3.1.3](https://github.com/sigstore/cosign/releases/tag/v3.1.3) OCI image | `ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8` | Tested signature/attestation verification in the package init/offline path and signing/verification in the publisher. |

The scratch Runtime image and native Runtime archives contain the Stellwerk
runtime executable and its legal notices. They do not embed ORAS, Cosign or
OpenTofu executables. The chart requires operator-provided qualified digest-pinned Runtime and ORAS
image references, plus a Cosign reference for its managed-key-no-tlog trust
profile. It does not silently choose a different vendor version. Package-fetch credentials remain in
the designated init containers. These boundaries do not remove the findings
from the helper executables or make their use risk-free.

Official release channels reviewed for successors are
[ORAS releases](https://github.com/oras-project/oras/releases),
[Cosign releases](https://github.com/sigstore/cosign/releases) and
[OpenTofu releases](https://github.com/opentofu/opentofu/releases).
A newer version number, source commit, archive or image is not interchangeable
with the exact selected artifact and is not evidence that it is patched.

## Historical symbol findings, not a fresh all-platform scan

The lists below were extracted from retained `govulncheck -mode=binary` symbol
scan results. They identify vulnerable symbols found in those specific binary
samples. They do not establish that every finding is reachable in the tested
commands, that every platform has the same result, or that every deployment is
exploitable. They are historical records, not a fresh scan of all architectures
or a complete inventory of subsequently published advisories. The November 3
release decision retains this distinction.

### ORAS 1.3.4 OCI helper: 9 findings

The 22 October 2026 sample was Linux ARM64 extracted from the exact selected
ORAS OCI image: executable SHA-256
`15585ab786ede91e0a02ac01ddbd11d9d7cef5c0c1b3e32cd469682a049f7e13`,
built with Go 1.27.0. These results do not describe the separately selected
Linux AMD64 host archive or every image platform.

- [GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603)
- [GO-2026-6605](https://pkg.go.dev/vuln/GO-2026-6605)
- [GO-2026-6607](https://pkg.go.dev/vuln/GO-2026-6607)
- [GO-2026-6608](https://pkg.go.dev/vuln/GO-2026-6608)
- [GO-2026-6610](https://pkg.go.dev/vuln/GO-2026-6610)
- [GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611)
- [GO-2026-6613](https://pkg.go.dev/vuln/GO-2026-6613)
- [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617)
- [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)

### Cosign 3.1.3 OCI helper: 28 findings

The 22 October 2026 sample was Linux ARM64 extracted from the exact selected
Cosign OCI image: executable SHA-256
`e8a0e9ccf851863b2e364301c5fbd0b36a1166253c63aac6e8439b99195c5292`,
built with Go 1.26.4. These results do not describe every image platform or a
separate Cosign release archive.

- [GO-2026-4970](https://pkg.go.dev/vuln/GO-2026-4970)
- [GO-2026-5026](https://pkg.go.dev/vuln/GO-2026-5026)
- [GO-2026-5856](https://pkg.go.dev/vuln/GO-2026-5856)
- [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)
- [GO-2026-5942](https://pkg.go.dev/vuln/GO-2026-5942)
- [GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970)
- [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972)
- [GO-2026-6061](https://pkg.go.dev/vuln/GO-2026-6061)
- [GO-2026-6088](https://pkg.go.dev/vuln/GO-2026-6088)
- [GO-2026-6089](https://pkg.go.dev/vuln/GO-2026-6089)
- [GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090)
- [GO-2026-6091](https://pkg.go.dev/vuln/GO-2026-6091)
- [GO-2026-6218](https://pkg.go.dev/vuln/GO-2026-6218)
- [GO-2026-6225](https://pkg.go.dev/vuln/GO-2026-6225)
- [GO-2026-6348](https://pkg.go.dev/vuln/GO-2026-6348)
- [GO-2026-6443](https://pkg.go.dev/vuln/GO-2026-6443)
- [GO-2026-6599](https://pkg.go.dev/vuln/GO-2026-6599)
- [GO-2026-6600](https://pkg.go.dev/vuln/GO-2026-6600)
- [GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603)
- [GO-2026-6605](https://pkg.go.dev/vuln/GO-2026-6605)
- [GO-2026-6607](https://pkg.go.dev/vuln/GO-2026-6607)
- [GO-2026-6608](https://pkg.go.dev/vuln/GO-2026-6608)
- [GO-2026-6610](https://pkg.go.dev/vuln/GO-2026-6610)
- [GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611)
- [GO-2026-6612](https://pkg.go.dev/vuln/GO-2026-6612)
- [GO-2026-6613](https://pkg.go.dev/vuln/GO-2026-6613)
- [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617)
- [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)

### Coordinated Runner only: OpenTofu 1.13.2, 11 findings

[Official OpenTofu 1.13.2](https://github.com/opentofu/opentofu/releases/tag/v1.13.2)
is a separately bundled execution engine in the coordinated Runner release.
It is not a Runtime payload, Runtime init image or Runtime publication tool.
The retained Runner Linux ARM64 engine sample has executable SHA-256
`92fb091345bc9ba9339496663aac81bd9a3686969682d8142d4c08ce18d9b9a8`.
Its separate historical binary-symbol scan reported the following eleven IDs;
this list is not a fresh all-platform engine scan or a claim that every symbol
is reachable in a Runner operation.

- [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)
- [GO-2026-6179](https://pkg.go.dev/vuln/GO-2026-6179)
- [GO-2026-6180](https://pkg.go.dev/vuln/GO-2026-6180)
- [GO-2026-6443](https://pkg.go.dev/vuln/GO-2026-6443)
- [GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603)
- [GO-2026-6610](https://pkg.go.dev/vuln/GO-2026-6610)
- [GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611)
- [GO-2026-6612](https://pkg.go.dev/vuln/GO-2026-6612)
- [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617)
- [GO-2026-6860](https://pkg.go.dev/vuln/GO-2026-6860)
- [GO-2026-6866](https://pkg.go.dev/vuln/GO-2026-6866)

Operators should retain the exact release-set digests and review new official
artifacts and advisories before a later upgrade. This release-specific decision
does not authorize replacing immutable artifacts or bypassing the ordinary
verification and recovery requirements.
