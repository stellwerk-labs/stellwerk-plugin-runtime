# Work log

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
