# Work log

## Native chart platform minimum and offline metadata

Add the Kubernetes 1.30 chart metadata constraint and an unconditional template
guard, retaining preStop-delay disabling only as an optional behavior on supported
clusters. Update the operator README and values. New real Helm tests prove 1.29
refusal with delay zero, independent template refusal without metadata, and
identical 1.30/1.35 workload rendering. The supported 1.35 render also matches
the predecessor chart byte-for-byte.

The new field exposed an inaccurate offline-bundle scalar conversion. Replace
that flat conversion with a standard-library helper that decodes Helm's quoted
strings and rejects malformed, duplicate, nested, tag and alias forms. Actual
packaged Helm metadata is compared with the exact OCI config. Keep Python in
the bundle producer's prerequisite checks. No runtime application or image
input changed. See Decisions and Learnings.

Root independently passed chart-config3, Kubernetes-boundary3, host-alias4 and
registry-CA7 tests, including actual pinned ORAS loopback TLS; Helm lint,
ShellCheck, Bash and whitespace checks passed. Full source/consumer qualification
is separate and not claimed from these targeted passes.

## Registry mirror TLS CA

Added chart values/schema, init-only mounts and TLS flags, operator documentation,
and seven focused tests wired into the existing check script. The tests render
real Helm resources and use real ORAS 1.3.4 against a loopback HTTPS OCI registry
for package, attestation and blob fetches, including wrong CA and hostname
refusal before HTTP. No application image build or cluster operation is part of
this increment. See [decisions](DECISIONS.md) and [learnings](LEARNINGS.md).

Validation: `python3 -I -B scripts/registry-ca-test.py -v`, Helm lint, Bash syntax,
ShellCheck, whitespace checks and the unchanged strict source scanner. Three
no-CA baseline renders (managed runtime, plain HTTP and migration) remain
byte-identical to the previous chart. The test environment must supply pinned ORAS
1.3.4, Helm and OpenSSL; missing tools fail, never skip. The existing complete
`scripts/check.sh` also performs Linux execution and image-backed tests; those
remain separate qualification, not a claim of this chart-only test run.
Application/build inputs are unchanged, but release archives and chart content
change. Runtime builds embed the source revision and use its commit time; old
images are not evidence for a new revision.
