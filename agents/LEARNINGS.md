# Learnings

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
