# Stellwerk plugin runtime

Generic runtime for native Stellwerk plugins. One unchanged runtime image runs
any plugin that is delivered as a signed OCI package; a plugin release never
requires a new runtime, control plane or console image.

The repository contains:

- `runtime/`: the launcher. It verifies a package, writes a validation
  receipt, starts the plugin executable and serves the plugin's static UI.
- `charts/native-plugin-runtime/`: the Helm chart that pulls, verifies and runs
  one plugin package as its own Kubernetes workload.
- `scripts/`: package build, offline signing, verification and test tooling.
- `probe/`: a minimal smoke-test plugin. It has no Stellwerk API, IAM, event,
  UI or database integration and proves only that the runtime works.

The plugin contract is `v1alpha` and covers first-party Stellwerk plugins only.
It is not yet a stable partner contract.

## Package format

A package is an OCI Image Specification 1.1 artifact with artifact type
`application/vnd.stellwerk.plugin.package.v1`. Its layers are:

| Media type | Title | Content |
|---|---|---|
| `application/vnd.stellwerk.plugin.manifest.v1+json` | `plugin-manifest.json` | strict plugin manifest |
| `application/vnd.stellwerk.plugin.executable.v1` | `bin/linux/<arch>/plugin` | static Linux executable per platform |
| `application/vnd.stellwerk.plugin.ui.asset.v1` | `ui/...` | optional UI manifest and assets |

The plugin manifest (`schemaVersion` 1, `runtimeProfile` `native-static-v1`,
`protocolVersion` 1) names the plugin ID, canonical SemVer version, one
executable per platform (`linux/amd64`, `linux/arm64`) with its SHA-256, an
optional UI manifest digest and an optional entitlement declaration. Unknown
fields, trailing JSON, non-canonical versions and unexpected paths are
rejected. Tags are an authoring convenience; installations pin the package by
digest.

Every layer must carry its title, a unique clean path from the table above,
within fixed size limits (plugin manifest 256 KiB, executables 256 MiB, UI
files 64 MiB, at most 2001 UI layers and about 577 MiB in total).
Archive layers, such as an ORAS directory push, are refused: a package
contains plain files only. ORAS checks each pulled blob against its
descriptor, so these declared limits bound what a pull can write.

```sh
output="$(mktemp -d)"
./scripts/build-package.sh 1.0.0 "$output"   # probe package as an OCI layout
jq . "$output/release.json"
```

The build also writes `source-provenance.json` (predicate
`https://stellwerk.dev/attestation/source-provenance/v1`): schema version 1,
the git commit the package was built from, whether the worktree had
uncommitted changes, and the Go version.

## Launcher commands

| Command | Purpose |
|---|---|
| `verify-publisher` | Apply the operator's trust bootstrap: accept bundles without transparency-log inclusion only for a publisher pinned with `managed-key-no-tlog`, verify the package signature and the SBOM and provenance attestations offline as one release set and write each part's pinned key for Cosign (`--key-dir`). |
| `verify-bundle` | Verify an offline bundle completely offline against the operator-pinned trust bootstrap digest and, with `--registry` and `--out`, write the import plan and chart values (see Offline bundle). |
| `verify-envelope` | Before any content is pulled, bind the fetched OCI manifest to the pinned package digest and the operator-approved plugin manifest hash, and admit only the layers of the package format. |
| `validate` | Verify the plugin manifest, selected executable and UI assets against their digests and write a read-only validation receipt. |
| `run` | Re-verify package and receipt, then execute the verified bytes from a sealed in-memory copy. |
| `serve-ui` | Serve only manifest-declared, digest-verified UI assets. |
| `refresh-core-token` | Sidecar for the workload token exchange: keep a short-lived Core token in `STELLWERK_CORE_TOKEN_FILE`. |
| `check-core-token` | Probe: succeed only while an unexpired Core token is present. |

Every command requires the plugin ID, version and manifest SHA-256 chosen by
the operator. Package files are read only as bounded regular files; symlinks,
path traversal, oversized files, a missing platform and digest mismatches fail
closed.

### Execution

`run` never executes a package path. It reads the selected executable once
into private memory, checks its SHA-256, copies those bytes into an anonymous
`memfd`, seals it against writes, truncation and growth, and `exec`s the
sealed file through `/proc/self/fd`. Whatever happens to the package
directory after verification, by rename or in-place rewrite, cannot change
what runs. Package files need no execute permission and the package volume may
be mounted `noexec`.

Requirements and consequences:

- Linux with `memfd_create` (3.17+) and a mounted `/proc`. The
  `vm.memfd_noexec` sysctl must not be `2`; the container runtime's default
  seccomp profile allows the calls.
- The sealed copy lives in memory and counts toward the container memory
  limit, so size `resources.limits.memory` for executable size plus working
  set.
- Executables must be static binaries. Interpreter scripts cannot be started
  from a close-on-exec memfd and are not part of `native-static-v1`.

`run` hands the plugin a filtered environment: only `STELLWERK_PLUGIN_*`,
`OTEL_*`, `SSL_CERT_FILE` and `STELLWERK_CORE_TOKEN_FILE` pass through, plus `PLUGIN_ID`,
`PLUGIN_VERSION`, `PLUGIN_LISTEN`, `PLUGIN_STATE` and `PLUGIN_TRUST_STATE`.
The plugin becomes the container's PID 1, so it receives `SIGTERM` directly
and must handle it to shut down cleanly.

## Trust

Package trust and entitlement trust are separate decisions.

In both modes each Pod's fetch init containers first fetch the OCI manifest
by digest and check it with `verify-envelope`; package content is pulled
only afterwards.

- `managed-key-no-tlog`: the trust policy for private commercial packages,
  which are signed with a managed key and never uploaded to a public
  transparency log, so private digests, identities and release cadence stay
  unpublished. Before the pull, `verify-publisher` evaluates the operator's
  trust bootstrap, the detached signature bundle and the SBOM and provenance
  attestations as one release set, and Cosign then verifies each part again
  with the key the gate selected. The receipt records `verified-local-key`.
- `development-untrusted`: skips signature verification and is visible to the
  plugin as `untrusted-development`. It exists for local development only.

The trust bootstrap (`trust.bootstrapSecret`, `publishers.json`) is the
operator's authentic statement of who may sign what. It never comes from a
package:

```json
{"schemaVersion": 1, "publishers": [{
  "id": "stellwerk", "policy": "managed-key-no-tlog",
  "pluginIds": ["dev.stellwerk.example"],
  "keys": [{"keyId": "<base64 SHA-256 of the DER public key>", "algorithm": "ecdsa-p256-sha256",
            "publicKey": "-----BEGIN PUBLIC KEY-----\n...", "validFrom": "2026-10-01T00:00:00Z",
            "validUntil": "2027-10-01T00:00:00Z"}]}],
 "revokedKeyIds": []}
```

- A missing transparency-log inclusion is accepted only when the approved
  plugin ID belongs to a publisher pinned with `managed-key-no-tlog`. A
  publisher without a policy, or with `sigstore`, is on the default Sigstore
  policy and is refused by this verifier; its transparency-log verification
  is not provided by this chart yet.
- Each plugin ID belongs to exactly one publisher and each key to one entry.
  The bundle must name a pinned key by its Cosign hint (`keyId`), carry no
  certificate of its own and hold a message signature over the exact OCI
  manifest. A key shipped in a package or bundle never establishes trust.
- Without a transparency log the signing time is unprovable, so a key's
  validity window gates new installations only. Once an installation
  succeeded, the installer records its digest in `package.installedDigest`;
  re-fetching exactly that digest (Pod restarts, new replicas) keeps
  verifying with the pinned key after the window ended. Any other digest is
  a new installation and needs a key that is valid now. Several keys with
  overlapping windows allow rotation.
- `revokedKeyIds` (top level, key hints) is the compromise list: a revoked
  key blocks new installations and re-fetches of installed digests alike.
- Verification happens at Pod start, so a changed bootstrap (rotation,
  revocation) applies to Pods started after the change; restart the runtime
  (`kubectl rollout restart`) to apply it at once. The chart mounts the
  bootstrap, the signature bundle and the registry config as plain files
  (`subPath`): the runtime refuses symlinks, and a Secret volume exposes
  every key as one.
- A release set is the package signature plus signed in-toto attestations
  about the package digest: an SPDX 2 JSON SBOM (`https://spdx.dev/Document`)
  and the source provenance. Each is a Sigstore v0.3 DSSE bundle signed with
  a pinned key of the same publisher under the same validity and revocation
  rules, and names exactly the package digest as its only subject.
  `requireSBOM` and `requireProvenance` on a publisher default to `true` for
  `managed-key-no-tlog`; a required attestation that is missing fails
  closed, and a supplied one is always verified.
- Publisher signing keys and entitlement issuer keys are separate keys.

Signatures authenticate code; they do not sandbox it. Native plugins share the
node kernel with other workloads. An entitlement declaration in the manifest
states a requirement; the control plane verifies licences against its own
issuer trust, the launcher never sees licence keys.

Offline signing and verification use the digest-pinned official Cosign image
with networking disabled:

```sh
./scripts/sign-layout-manifest.sh "$output" /path/to/cosign.key
./scripts/attest-layout-manifest.sh "$output" /path/to/cosign.key sbom.spdx.json
./scripts/verify-layout-manifest.sh "$output" /path/to/cosign.pub
oras cp -r --from-oci-layout "$output/oci-layout:1.0.0" registry.example/native-probe:1.0.0
```

`attest-layout-manifest.sh` signs the SBOM and the build's
`source-provenance.json` with the same managed key and no transparency log
(`cosign attest-blob`, subject: the exact OCI manifest) and attaches each
bundle as an OCI referrer of the package manifest (Cosign's bundle referrer
convention: artifact type `application/vnd.dev.sigstore.bundle.v0.3+json`,
annotation `dev.sigstore.bundle.predicateType`). `release.json` records the
referrer digests under `attestations`; they go into
`package.attestations.sbom` and `package.attestations.provenance`.
`sign-layout-manifest.sh` attaches the detached signature bundle the same
way (predicate type `https://sigstore.dev/cosign/sign/v1`, content
`message-signature`) and records it as `release.json .signature.digest`.
`verify-layout-manifest.sh` verifies the recorded referrers too, and
`oras cp -r` and the offline bundle carry them with the package.

The SBOM is an input: none of the pinned tools (Cosign, ORAS, the Go
toolchain) generates SPDX, so the publisher's SBOM generator produces an
SPDX 2 JSON document of the package contents.

Signing uses Cosign's signing-config mechanism with a configuration that
lists no transparency log, timestamp authority or certificate authority
(`scripts/signing-config-no-tlog.json`); the deprecated `--tlog-upload=false`
is not used. The signature covers the exact OCI manifest bytes, so publishing
must preserve the manifest digest. Cosign verifies such bundles with
`--insecure-ignore-tlog`, which the chart passes only after the policy gate.

## Helm chart

The chart is disabled by default and creates nothing until `enabled=true`. An
enabled installation requires a digest-pinned package reference, runtime image
and ORAS image (plus a Cosign image for `managed-key-no-tlog`), the exact plugin
manifest hash and an explicit `trust.mode`; there is no default trust mode. No
image, digest, trust root or key is shipped as a default.

It deploys one workload with a dedicated ServiceAccount (token automount
disabled), non-root security contexts, read-only root and package mounts,
bounded resources and a default NetworkPolicy. Secret volumes are mounted `0440`,
the state `emptyDir` is bounded by `stateVolume.sizeLimit` and service links
are disabled. `pluginSecretFiles` mounts operator-owned Secrets into the
plugin container only, never into the fetch init containers.

### Package fetch

Every replica fetches and verifies its own copy of the package in init
containers (`fetch-package-envelope`, `verify-package-envelope`, for
`managed-key-no-tlog` `fetch-package-sbom` and `fetch-package-provenance`
for each configured attestation, `verify-package-publisher`,
`verify-package-signature`, `verify-package-sbom` and
`verify-package-provenance`, then `pull-package` and `validate-package`) into
an `emptyDir` (`packageVolume.sizeLimit`). Replicas therefore need no shared
storage and can run on any node. Attestation referrers are pulled by digest
from the package repository into a small in-memory volume. Registry
credentials and the ORAS image reach only the ORAS init containers, the trust
bootstrap only the publisher gate, and the signature bundle and attestations
only the gate and Cosign; the plugin, UI and token containers mount none of
them and see the package read-only.

Registry egress is limited to the customer's mirror endpoints listed in
`networkPolicy.registryMirrors`: single addresses (`/32` or `/128`) or exact
in-cluster peers (namespace and Pod selector), each with a port. Ranges,
namespace-only peers and free-form rules are rejected, and nothing is open by
default. Residual risk: NetworkPolicy applies per Pod, so the plugin and UI
containers can also reach those mirror endpoints. They hold no registry
credentials, and the mirror should serve only the packages and images this
installation needs. Kubernetes image volumes would let the kubelet fetch the
package with node credentials and remove even that; they are a later option
once the supported Kubernetes minimum includes them as stable.

The NetworkPolicy admits only the configured control plane caller and permits
egress only to the backend Gateway proxy, the plugin database and DNS. The
default selectors match the `platform-orchestrator` release of the Stellwerk
Helm chart (Envoy Gateway proxy target port 10443, CloudNativePG cluster);
override them for other installations. The configured control plane URL must
resolve to that same Gateway. Package fetching fails closed until the
operator lists the registry mirror endpoints (see Package fetch).

### Replicas

`replicaCount` (default 1) sets the runtime replicas. One replica is replaced
with `Recreate`. Several replicas roll one at a time (`RollingUpdate`,
`maxUnavailable: 0`, `maxSurge: 1`), so at least the configured number stays
available during a package upgrade. A PodDisruptionBudget (`minAvailable: 1`,
unhealthy Pods stay evictable) keeps one replica through node drains, and a
preferred anti-affinity on `kubernetes.io/hostname` spreads them; an explicit
`affinity` replaces that default. Every replica serves reads and the UI. The
chart elects no writer: the plugin's fenced database lease admits exactly one,
and every supported plugin binary takes it (`v1alpha` supports fresh
installations only). Replicas keep no local state, so `persistence.enabled`
requires `replicaCount: 1`.

### Migration phase

Database migration is an explicit installer phase, not a startup side effect,
and runs before any runtime Pod runs the new package:

1. Apply the new package with `migration.enabled=true`. The migration Job
   runs; the runtime Deployment is paused, so it creates no Pod from the new
   package. Wait for the Job to succeed and record that result.
2. Apply the same package with `migration.enabled=false`. The Deployment is
   resumed and starts or rolls to the new package.

`migration.compatibility` selects what the runtime does meanwhile:

- `expand-only` (default): the migration only adds to the schema, so the
  previous package keeps working against it. Its replicas keep serving
  through step 1, and step 2 rolls them over. While replicas roll, both
  versions run side by side, so rolling package upgrades require expand-only
  (backward-compatible) migrations.
- `incompatible`: for a package that declares a migration its previous
  version cannot run against. Step 1 scales the runtime to zero, the Job
  migrates, and step 2 scales it back up with the new package. The plugin is
  unavailable in between. Old Pods may still be shutting down (up to
  `terminationGracePeriodSeconds`) while the Job starts, so the migration
  must take the fenced writer lease before it changes the schema.

On a fresh installation step 1 creates the paused Deployment without Pods.
With `persistence.enabled` and a `WaitForFirstConsumer` storage class the
state claim binds only once step 2 starts the first Pod, so wait for the Job
itself rather than for every resource in step 1. The migration profile (`mode: native-migrate`) comes from
`migration.profileSecret`, the migration principal's database URL from a
separate `migration.databaseSecret` mounted at
`/run/secrets/stellwerk-plugin-migration/database-url`. Neither Secret reaches
the fetch init containers or the runtime Deployment, and the chart refuses to
mount them into the runtime. The migration Job fetches and verifies its own
package copy like a runtime replica.

The optional `migration.databaseCASecret` mounts one public CA key read-only at
`/run/config/database-ca/ca.crt` in the migration container only, so the
profile can use `sslmode=verify-full&sslrootcert=/run/config/database-ca/ca.crt`.
It must be a Secret separate from the profile and credential Secrets. Mount a
CA into the runtime through `pluginSecretFiles` if the runtime needs one.

### UI

With `ui.enabled=true` a second container runs `serve-ui` from the same runtime
image and mounts only the read-only package. It serves declared assets under
`/embed/` with a restrictive CSP, allows only `GET` and `HEAD`, issues no
cookies, proxies no API and generates `/embed/config.js` from
`ui.consoleOrigin`. On `SIGTERM` it stops accepting connections, drains
in-flight requests for up to five seconds and exits 0. Route the `ui` port through a TLS Gateway on a hostname
different from the console, and add the exact Gateway peer for that port to
`networkPolicy.additionalIngress`. `ui.gateway.enabled` creates a plugin-owned
Gateway and, with `ui.gateway.issuerName`, a cert-manager Certificate.

### Workload identity

`workloadIdentity.enabled=true` gives the plugin a short-lived Core credential
instead of a long-lived service-user token (`v1alpha`, see
[Plugin workload identity](https://docs.stellwerk.dev/platform-orchestrator/docs/architecture/plugins/plugin-workload-identity/)).
It needs Kubernetes 1.29 or newer, the chart's own ServiceAccount
(`serviceAccount.create=true`) and an IAM workload binding for exactly that
ServiceAccount, its namespace and `workloadIdentity.audience`.

```text
core-token sidecar                    Core gateway -> IAM
  projected SA token (aud, 600 s) --> POST /auth/plugin-workload-token
                                  <-- access_token PWT-..., expires_in <= 900 s
  /run/stellwerk/core-token/token (memory, 0400, atomic rename)
                                       |
plugin container  STELLWERK_CORE_TOKEN_FILE, read per request, read-only mount
```

- The `core-token` native sidecar runs `refresh-core-token` after package
  validation. Its startup probe holds back the plugin until the first
  exchange has succeeded; its readiness probe (`check-core-token`) keeps the
  Pod unready while no unexpired token exists.
- Only the sidecar mounts the projected token (`expirationSeconds` 600, the
  Kubernetes minimum and the contract maximum). The plugin container gets the
  memory-backed token directory read-only and never sees the Kubernetes token.
- Every exchange re-reads the projected token, which kubelet rotates. The token
  is refreshed at two thirds of `expires_in`. Refresh point and expiry are
  wall-clock instants; the sidecar wakes at least every 5 s and decides from
  the wall clock, so after a host suspend or clock jump it refreshes at once
  (removing an expired token first). HTTP 503 and other temporary
  failures are retried with jittered exponential backoff from 1 s up to 30 s;
  a token that expires meanwhile is removed. HTTP 400 `invalid_grant` and other
  refusals remove the token and stop the sidecar with a clear error, so the
  container restarts visibly. No token is ever logged.
- `workloadIdentity.gateway.url` is the https origin of the Core gateway;
  `workloadIdentity.gateway.caSecret` optionally replaces the system roots with
  a public CA bundle. Redirects are refused. The default NetworkPolicy already
  permits egress to the backend Gateway proxy.
- On `SIGTERM` the sidecar stops refreshing and exits 0; the current token
  stays available for the plugin's own shutdown. A deleted Pod's token stays
  valid at IAM until it expires (at most 15 minutes).

## Offline bundle

An air-gapped customer receives one directory per plugin release and
installs it without any vendor network:

```text
bundle/
├── bundle.json           plugin, minimum Core and chart versions, every component's digest
├── bundle.sigstore.json  publisher signature over bundle.json (managed-key-no-tlog)
├── publishers.json       the public trust bootstrap
└── oci/                  one OCI image layout; index.json lists exactly:
    ├── package           the signed package and its signature, SBOM and provenance referrers
    ├── runtime           runtime image index: linux/amd64 and linux/arm64
    ├── oras, cosign      the chart's fetch and verify images, same two platforms
    └── chart             native-plugin-runtime, as the OCI artifact `helm push` writes
```

The licence (entitlement) is delivered separately and is never part of a
bundle; no sources are included. The ORAS and Cosign indexes hold the
upstream linux/amd64 and linux/arm64 manifests of the indexes pinned in
`scripts/images.sh`, with their digests unchanged.

The publisher builds it online from a signed and attested package:

```sh
digest="$(./scripts/build-runtime-image.sh runtime-layout)"
./scripts/offline-bundle.sh --package "$output" --runtime-image "runtime-layout@$digest" \
  --key cosign.key --trust-bootstrap publishers.json --minimum-core-version 1.0.0 bundle
```

`--minimum-chart-version` defaults to the bundled chart's version. The
builder signs `bundle.json` like a package and verifies the result exactly
as the import will.

The customer imports it offline into the registry the cluster uses:

```sh
./scripts/import-offline-bundle.sh bundle registry.customer.example/stellwerk \
  --trust-bootstrap-digest sha256:<from the delivery note> --out import
```

The trust bootstrap digest reaches the operator out of band, with the
licence; it is what makes the bundle's `publishers.json` authentic. Before
anything is pushed, the runtime's `verify-bundle` checks without network:

- the publisher pinned for the plugin under `managed-key-no-tlog` signed
  `bundle.json` with a pinned, valid and unrevoked key;
- the bundle holds exactly the expected files and no symlinks, its OCI index
  lists exactly the recorded components and referrers, every blob matches
  its digest and size, and no unreferenced blob is present;
- the package passes the envelope check, its plugin manifest names the
  recorded plugin and version, and its signature, SBOM and provenance verify
  as one release set, as in the chart's publisher gate;
- each image index holds exactly linux/amd64 and linux/arm64 (arm64 may say
  `v8`), and each platform manifest's configuration agrees;
- the chart is `native-plugin-runtime` at the recorded version, not older
  than the minimum.

Then ORAS copies each component with its referrers (`oras cp -r`), so every
digest is kept, into `<registry>/<pluginId>`, `/native-plugin-runtime`,
`/oras`, `/cosign` and `/charts/native-plugin-runtime`. Each gets the tag
`<pluginId>-<version>`, which keeps untagged-manifest garbage collection away
from it; the import refuses to move such a tag to another digest. Finally it
re-reads the registry (tags, platform manifests, the package's referrer set)
and prints the installation steps. `--out` receives `values.json` (plugin,
package reference and attestation digests, images by digest, `trust.mode`,
Secret names), `publishers.json` and `oci-manifest.sigstore.json` for the
trust Secrets, and `instructions.txt`. The operator adds
`networkPolicy.registryMirrors` and, when needed, the migration Secrets.

`--plain-http`, `--registry-config` and `--ca-file` configure the target
registry. `--verifier` takes a trusted runtime binary; without it the script
builds one from this checkout with Go, since the bundle's own runtime image
cannot vouch for itself. The script is POSIX sh and otherwise needs only
ORAS: `offline-bundle-test.sh` runs it in the pinned ORAS image on a Docker
network whose only peer is the registry.

## Building the runtime image

The image is `FROM scratch` with one static binary and runs as UID 65532.

```sh
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "dist/runtime-linux-$arch" ./runtime
done
docker buildx build --platform linux/amd64,linux/arm64 -f Dockerfile.runtime dist
```

`scripts/build-runtime-image.sh OUTPUT_LAYOUT` builds the same image for both
platforms as one OCI index into an OCI image layout without Docker. Layers
are deterministic and the creation time is the commit time, so a commit and
Go toolchain always give the same digest; `oras cp` publishes it, and the
offline bundle takes it from the layout. `check.sh` keeps it in line with
`Dockerfile.runtime`.

## Checks

Prerequisites: Go, Docker, Helm, ORAS, jq, Python 3 and `timeout`; `kind` and
`kubectl` for the cluster test.

```sh
./scripts/check.sh                  # gofmt, go test -race, go vet, Linux execution tests, chart contract, package build
./scripts/compose-test.sh           # run and serve-ui as non-root PID 1, filtered environment, state, CSP, exit 0 on SIGTERM
./scripts/package-init-chain-test.sh  # sign, attest, transfer, publish locally, run the chart init chain, negatives
./scripts/offline-bundle-test.sh    # build a bundle, import it without egress, digests and referrers kept, tampered bundles refused
./scripts/kind-test.sh development  # untrusted profile: install, package upgrade, restart, rollback on a throwaway kind cluster
./scripts/kind-test.sh production   # managed-key-no-tlog from Secrets, two replicas, PDB, both migration paths, rolling upgrade
./scripts/kind-test.sh airgap       # import a bundle into a fresh registry, install from it alone, node without other egress
```

`LINUX_TEST_PLATFORM=linux/amd64 ./scripts/linux-test.sh` and
`NATIVE_INIT_PLATFORM=linux/amd64 ./scripts/package-init-chain-test.sh` run the
other architecture where Docker can emulate it; emulation is no substitute for
a native runner of that architecture.

All Docker based tests use uniquely named containers, loopback-only random
ports and temporary directories, and remove what they create.

## Limits

- The chart does not register the installation with the control plane.
  Package, service identity and declared operations are registered there
  separately.
- NetworkPolicy selects workloads, not database roles or control plane
  identities. Operators provision separate plugin database runtime and
  migration principals and a scoped control plane identity.
- NetworkPolicy cannot prove that a public hostname maps to the selected
  Gateway Pods. Bind control plane URL, DNS, certificate SAN and the
  `networkPolicy.coreGateway` peer as one verified configuration.
- The chart provides no writer election. Several replicas, a rolling
  upgrade and the shutdown of an incompatible migration's old Pods are safe
  only because the plugin takes its fenced database lease.
- `trustState` in the receipt is consistency metadata, not cryptographic
  evidence on its own.

## License

Licensed under the [European Union Public Licence 1.2](./LICENSE).
