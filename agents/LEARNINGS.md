# Learnings

- A chart-only successor can have different source provenance from a retained
  image. Freeze distinct payload/source identities and test-only destination
  tags rather than assigning one source label to both artifacts.
- Real ORAS local-layout copies can verify descriptor/media-type and blob-graph
  preservation without starting Docker. They do not prove registry behavior or
  replace anonymous public-package verification after an approved upload.

- A conditional native-sidecar or preStop guard is not a chart-wide Kubernetes
  minimum. Exercise the metadata boundary and the template independently, with
  the optional feature disabled as well as enabled.
- `helm show chart` emits a quoted version constraint with YAML single quotes.
  Treating only double quotes specially corrupts the OCI config. Test the actual
  packaged chart's output and reject unsupported shapes before publishing it.

- ORAS 1.3.4 defaults a `localhost` reference to plain HTTP, even with a CA
  file. Explicit `--plain-http=false` enforces HTTPS. A real loopback registry
  fixture caught this; an argument-only test would not.
- A registry CA is server transport trust only. It neither establishes package
  publisher trust nor configures the kubelet's image-pull trust.

References: [ORAS remote options](https://github.com/oras-project/oras/blob/v1.3.4/cmd/oras/internal/option/remote.go),
[Secret key validation](https://github.com/kubernetes/apimachinery/blob/v0.35.0/pkg/util/validation/validation.go).

## HTTPS delivery

- Generic Package downloads can return a signed object-store redirect even when
  initial Basic authentication succeeded. Refusing every redirect breaks this
  normal route. An exact host allowlist and one header-free hop retain scoped
  GitLab credentials without introducing another registry or trust protocol.
- The runtime image is scratch, and the release image is also assembled directly
  as a deterministic OCI layer. A Dockerfile-only CA copy would leave the actual
  release image different. Require independent public CA roots in the chart.
- Archive plus extracted closure coexist before verification completes. Derive
  temporary capacity from both copies: the 604.75 MiB archive cap needs more
  than 1200 MiB, so the HTTPS temporary emptyDir cap is 1280 MiB.
- A real publisher-produced tar and real TLS server caught archive compatibility
  separately from synthetic unit fixtures. Keep exact source/hash scope in the
  qualification receipt; local transport proof is not registry publication.

## Zero-replica release preparation

- Chart version and appVersion also feed the normal CI release build, real Helm
  metadata fixture and offline bundle minimum/version expectations. Advance
  those consumers together; retain older minimum-runtime documentation.
- Keep private log creation separate from the test process umask. Existing
  package fixtures verify exact 0444 modes, so inheriting restrictive 077 changes
  their expected filesystem state. Use normal 022 for tests with private logs.
