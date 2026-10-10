#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

unformatted="$(gofmt -l runtime probe)"
if [ -n "$unformatted" ]; then
  echo "Go files require gofmt:" >&2
  echo "$unformatted" >&2
  exit 1
fi
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
for arch in amd64 arm64; do
  GOOS=linux GOARCH="$arch" GOWORK=off go vet ./...
done
# Sealed execution needs a Linux kernel. Elsewhere, run the suite in a container.
if [ "$(uname -s)" != Linux ]; then
  "$root/scripts/linux-test.sh"
fi

helm lint charts/native-plugin-runtime
helm template native-probe charts/native-plugin-runtime >/dev/null
python3 "$root/scripts/registry-ca-test.py"

fixture="$(mktemp -d "${TMPDIR:-/tmp}/native-plugin-check.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
for invalid_version in 01.0.0 1.0.0-01; do
  if "$root/scripts/build-fixture.sh" "$invalid_version" "$fixture/invalid-fixture-$invalid_version" >/dev/null 2>&1; then
    echo "fixture builder accepted noncanonical SemVer $invalid_version" >&2
    exit 1
  fi
done

manifest_hash="$("$root/scripts/build-fixture.sh" 1.0.0 "$fixture/package")"
helm lint charts/native-plugin-runtime \
  --set enabled=true \
  --set-string trust.mode=development-untrusted \
  --set-string plugin.id=dev.stellwerk.native-probe \
  --set-string plugin.version=1.0.0 \
  --set-string package.reference=registry.invalid/native-probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --set-string package.manifestSHA256="$manifest_hash" \
  --set-string images.runtime=registry.invalid/runtime@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --set-string images.oras=registry.invalid/oras@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
helm template native-probe charts/native-plugin-runtime \
  --set enabled=true \
  --set-string trust.mode=development-untrusted \
  --set-string plugin.id=dev.stellwerk.native-probe \
  --set-string plugin.version=1.0.0 \
  --set-string package.reference=registry.invalid/native-probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --set-string package.manifestSHA256="$manifest_hash" \
  --set-string images.runtime=registry.invalid/runtime@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --set-string images.oras=registry.invalid/oras@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --set-string probes.path=/healthz \
  >"$fixture/rendered.yaml"

grep -Fq 'runAsUser: 65532' "$fixture/rendered.yaml"
grep -Fq 'readOnly: true' "$fixture/rendered.yaml"
grep -Fq 'automountServiceAccountToken: false' "$fixture/rendered.yaml"
grep -Fq 'untrusted-development' "$fixture/rendered.yaml"
test "$(grep -Fc 'path: "/healthz"' "$fixture/rendered.yaml")" -eq 3
python3 - "$fixture/rendered.yaml" <<'PY'
import re
import sys

rendered = open(sys.argv[1], encoding="utf-8").read()
policy = next(
    document
    for document in rendered.split("\n---")
    if re.search(r"^kind: NetworkPolicy$", document, re.M) and "\n  name: native-probe-native-plugin-runtime\n" in document
)
assert "app.kubernetes.io/name: control-plane" in policy
assert "app.kubernetes.io/instance: platform-orchestrator" in policy
assert "gateway.envoyproxy.io/owning-gateway-namespace: platform-orchestrator" in policy
assert "gateway.envoyproxy.io/owning-gateway-name: platform-orchestrator-backend-gateway" in policy
assert "cnpg.io/cluster: platform-orchestrator-cnpg-databases" in policy
assert "k8s-app: kube-dns" in policy
assert "port: 8080" in policy
assert "port: 10443" in policy
assert "port: 5432" in policy
assert policy.count("port: 53") == 2
assert "kubernetes.io/metadata.name: platform-orchestrator" in policy
assert "kubernetes.io/metadata.name: kube-system" in policy

for peer in re.findall(r"- namespaceSelector:\n(.*?)(?=\n\s+- namespaceSelector:|\n\s+ports:)", policy, re.S):
    assert "podSelector:" in peer, "namespace-only peer would trust every pod"
PY

if helm template native-probe charts/native-plugin-runtime \
  --set enabled=true \
  --set-string plugin.id=dev.stellwerk.native-probe \
  --set-string plugin.version=1.0.0 \
  --set-string package.reference=registry.invalid/native-probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --set-string package.manifestSHA256="$manifest_hash" \
  --set-string images.runtime=registry.invalid/runtime@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --set-string images.oras=registry.invalid/oras@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  >/dev/null 2>&1; then
  echo "chart enabled a plugin without an explicit trust mode" >&2
  exit 1
fi

helm template native-probe charts/native-plugin-runtime \
  --set enabled=true \
  --set-string trust.mode=development-untrusted \
  --set-string plugin.id=dev.stellwerk.native-probe \
  --set-string plugin.version=1.0.0 \
  --set-string package.reference=registry.invalid/native-probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --set-string package.manifestSHA256="$manifest_hash" \
  --set-string images.runtime=registry.invalid/runtime@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --set-string images.oras=registry.invalid/oras@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --set-json 'pluginEnv=[{"name":"STELLWERK_PLUGIN_CONFIG_FILE","value":"/var/run/secrets/stellwerk/plugin-profile/profile.json"}]' \
  --set-json 'pluginSecretFiles=[{"name":"plugin-profile","secretName":"operator-plugin-profile","mountPath":"/var/run/secrets/stellwerk/plugin-profile","items":[{"key":"profile.json","path":"profile.json"}]}]' \
  >"$fixture/secret-rendered.yaml"
grep -Fq 'name: STELLWERK_PLUGIN_CONFIG_FILE' "$fixture/secret-rendered.yaml"
grep -Fq 'value: /var/run/secrets/stellwerk/plugin-profile/profile.json' "$fixture/secret-rendered.yaml"
grep -Fq 'secretName: operator-plugin-profile' "$fixture/secret-rendered.yaml"
grep -Fq 'mountPath: "/var/run/secrets/stellwerk/plugin-profile"' "$fixture/secret-rendered.yaml"
grep -Fq 'key: profile.json' "$fixture/secret-rendered.yaml"
grep -Fq 'path: profile.json' "$fixture/secret-rendered.yaml"

migration_args=(
  --set enabled=true
  --set-string trust.mode=development-untrusted
  --set migration.enabled=true
  --set-string plugin.id=dev.stellwerk.native-probe
  --set-string plugin.version=1.0.0
  --set-string package.reference=registry.invalid/native-probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  --set-string package.manifestSHA256="$manifest_hash"
  --set-string images.runtime=registry.invalid/runtime@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  --set-string images.oras=registry.invalid/oras@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  --set-string migration.profileSecret.name=plugin-migration-profile
  --set-string migration.databaseSecret.name=plugin-migration-database
)
# The migration phase also renders the held runtime (see the installer phase
# checks below); these checks look at the migration Job and its policy.
migration_job=(--show-only templates/migration-job.yaml --show-only templates/migration-networkpolicy.yaml)
helm lint charts/native-plugin-runtime "${migration_args[@]}"
helm template native-probe charts/native-plugin-runtime "${migration_args[@]}" "${migration_job[@]}" >"$fixture/migration-rendered.yaml"
python3 - "$fixture/migration-rendered.yaml" <<'PY'
import re
import sys

rendered = open(sys.argv[1], encoding="utf-8").read()
assert re.search(r"^kind: Job$", rendered, re.M)
assert "app.kubernetes.io/component: migration" in rendered
assert "name: STELLWERK_PLUGIN_CONFIG_FILE" in rendered
assert "value: /run/secrets/stellwerk-plugin-migration/profile.json" in rendered
assert "mountPath: /run/secrets/stellwerk-plugin-migration/database-url" in rendered
assert "secretName: plugin-migration-profile" in rendered
assert "secretName: plugin-migration-database" in rendered
assert rendered.count("defaultMode: 0440") >= 2
job = next(document for document in rendered.split("\n---") if re.search(r"^kind: Job$", document, re.M) and "app.kubernetes.io/component: migration" in document)
init_containers = job.split("\n      initContainers:", 1)[1].split("\n      containers:", 1)[0]
assert "migration-profile" not in init_containers
assert "migration-database" not in init_containers
policy = next(document for document in rendered.split("\n---") if re.search(r"^kind: NetworkPolicy$", document, re.M) and "-migration\n" in document)
assert "platform-orchestrator-cnpg-databases" in policy
assert "k8s-app: kube-dns" in policy
assert "owning-gateway" not in policy
assert "migration-database-ca" not in rendered
PY

helm template native-probe charts/native-plugin-runtime "${migration_args[@]}" "${migration_job[@]}" \
  --set-string migration.databaseCASecret.name=public-database-ca \
  --set-string migration.databaseCASecret.key=trust.pem >"$fixture/migration-ca.yaml"
python3 - "$fixture/migration-ca.yaml" <<'PY'
import re
import sys

rendered = open(sys.argv[1], encoding="utf-8").read()
job = next(document for document in rendered.split("\n---") if re.search(r"^kind: Job$", document, re.M) and "app.kubernetes.io/component: migration" in document)
init, executor = job.split("      containers:\n", 1)
assert "migration-database-ca" not in init
assert "mountPath: /run/config/database-ca" in executor
assert "secretName: public-database-ca" in executor
assert "key: trust.pem" in executor and "path: ca.crt" in executor
assert "readOnly: true" in executor
PY
for invalid_ca in name=plugin-migration-profile name=plugin-migration-database key= unknown=true; do
  if helm template native-probe charts/native-plugin-runtime "${migration_args[@]}" \
    --set-string "migration.databaseCASecret.$invalid_ca" >/dev/null 2>&1; then
    echo "chart accepted invalid migration database CA setting: $invalid_ca" >&2
    exit 1
  fi
done
helm template native-probe charts/native-plugin-runtime "${migration_args[@]}" \
  --set migration.enabled=false \
  --set-string migration.databaseCASecret.name=public-database-ca >"$fixture/runtime-without-migration-ca.yaml"
if grep -Fq 'public-database-ca' "$fixture/runtime-without-migration-ca.yaml"; then
  echo "runtime inherited the migration-only database CA" >&2
  exit 1
fi

if helm template native-probe charts/native-plugin-runtime \
  "${migration_args[@]}" \
  --set-string migration.profileSecret.name=plugin-migration-database >/dev/null 2>&1; then
  echo "chart allowed one Secret to hold the migration profile and database credential" >&2
  exit 1
fi

if helm template native-probe charts/native-plugin-runtime \
  "${migration_args[@]}" \
  --set-json 'pluginSecretFiles=[{"name":"runtime-db","secretName":"plugin-migration-database","mountPath":"/run/secrets/runtime","items":[{"key":"database-url","path":"database-url"}]}]' >/dev/null 2>&1; then
  echo "chart allowed the migration database Secret in the runtime container" >&2
  exit 1
fi

# Replicas and installer phases. One replica is replaced (Recreate); several
# roll one at a time behind a PodDisruptionBudget and prefer distinct nodes.
# The migration phase pauses the runtime Deployment, so no runtime Pod runs a
# package before its migration Job succeeded: expand-only keeps the previous
# replicas serving, incompatible scales them to zero.
runtime_args=("${migration_args[@]}" --set migration.enabled=false)
render_phase() {
  local output="$1"
  shift
  helm template native-probe charts/native-plugin-runtime "$@" >"$output"
}
render_phase "$fixture/phase-single.yaml" "${runtime_args[@]}"
render_phase "$fixture/phase-runtime.yaml" "${runtime_args[@]}" --set replicaCount=3
render_phase "$fixture/phase-runtime-incompatible.yaml" "${runtime_args[@]}" --set replicaCount=3 \
  --set-string migration.compatibility=incompatible
render_phase "$fixture/phase-expand.yaml" "${migration_args[@]}" --set replicaCount=3
render_phase "$fixture/phase-incompatible.yaml" "${migration_args[@]}" --set replicaCount=3 \
  --set-string migration.compatibility=incompatible
render_phase "$fixture/phase-affinity.yaml" "${runtime_args[@]}" --set replicaCount=2 \
  --set-json 'affinity={"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"pool","operator":"In","values":["plugins"]}]}]}}}'
render_phase "$fixture/phase-persistent.yaml" "${migration_args[@]}" --set persistence.enabled=true
python3 - "$fixture" <<'PY'
import re
import sys

fixture = sys.argv[1]


def documents(name):
    rendered = open(f"{fixture}/{name}.yaml", encoding="utf-8").read()
    return {re.search(r"^kind: (\w+)$", doc, re.M).group(1) + "/" + re.search(r"^  name: (\S+)$", doc, re.M).group(1): doc
            for doc in rendered.split("\n---") if re.search(r"^kind: ", doc, re.M)}


def spec(deployment):
    return deployment.split("\nspec:\n", 1)[1].split("\n  template:\n", 1)[0]


name = "native-probe-native-plugin-runtime"
runtime_labels = ("app.kubernetes.io/name: native-plugin-runtime\n", "app.kubernetes.io/instance: native-probe\n",
                  "app.kubernetes.io/component: runtime\n")

single = documents("phase-single")
head = spec(single[f"Deployment/{name}"])
assert "  paused: false\n  replicas: 1\n" in head, head
assert "    type: Recreate\n" in head and "rollingUpdate" not in head, head
assert "affinity:" not in single[f"Deployment/{name}"]
assert not any(key.startswith("PodDisruptionBudget/") for key in single), list(single)
assert not any(key.startswith("Job/") for key in single), list(single)

for variant in ["phase-runtime", "phase-runtime-incompatible"]:
    rendered = documents(variant)
    deployment = rendered[f"Deployment/{name}"]
    head = spec(deployment)
    # The compatibility switch acts only while the migration phase runs.
    assert "  paused: false\n  replicas: 3\n" in head, (variant, head)
    assert "    type: RollingUpdate\n    rollingUpdate:\n      maxUnavailable: 0\n      maxSurge: 1\n" in head, (variant, head)
    affinity = deployment.split("      affinity:\n", 1)[1]
    assert re.match(r"        podAntiAffinity:\n          preferredDuringSchedulingIgnoredDuringExecution:\n"
                    r"            - weight: 100\n              podAffinityTerm:\n"
                    r"                topologyKey: kubernetes.io/hostname\n", affinity), (variant, affinity)
    assert "requiredDuringScheduling" not in affinity, variant
    term = affinity.split("matchLabels:\n", 1)[1]
    assert all(label in term for label in runtime_labels), (variant, term)
    budget = rendered[f"PodDisruptionBudget/{name}"]
    assert "apiVersion: policy/v1\n" in budget
    assert "  minAvailable: 1\n" in budget and "maxUnavailable" not in budget, budget
    assert "  unhealthyPodEvictionPolicy: AlwaysAllow\n" in budget, budget
    assert all(label in budget.split("  selector:\n", 1)[1] for label in runtime_labels), budget
    assert not any(key.startswith("Job/") for key in rendered), (variant, list(rendered))

custom = documents("phase-affinity")[f"Deployment/{name}"]
assert "nodeAffinity:" in custom and "podAntiAffinity" not in custom, "an explicit affinity replaces the default spread"

expand, incompatible = documents("phase-expand"), documents("phase-incompatible")
assert "  paused: true\n  replicas: 3\n" in spec(expand[f"Deployment/{name}"]), "expand-only keeps the previous replicas"
assert "  paused: true\n  replicas: 0\n" in spec(incompatible[f"Deployment/{name}"]), "incompatible stops the runtime"
for rendered in (expand, incompatible):
    # The phase holds the runtime instead of deleting it: its Service, policy,
    # budget and identity stay, and the Job runs next to it.
    for key in [f"Job/{name}-migration", f"Service/{name}", f"NetworkPolicy/{name}", f"NetworkPolicy/{name}-migration",
                f"ServiceAccount/{name}", f"ServiceAccount/{name}-migration", f"PodDisruptionBudget/{name}"]:
        assert key in rendered, (key, list(rendered))
    assert "app.kubernetes.io/component: runtime" not in rendered[f"Job/{name}-migration"]

# A migration phase keeps the single replica's state claim.
persistent = documents("phase-persistent")
assert f"PersistentVolumeClaim/{name}-state" in persistent, list(persistent)
assert f"claimName: {name}-state" in persistent[f"Deployment/{name}"]
PY
for invalid in "--set=replicaCount=0" "--set=replicaCount=2,persistence.enabled=true" \
  "--set-string=migration.compatibility=breaking" "--set=runtime.enabled=false"; do
  if helm template native-probe charts/native-plugin-runtime "${runtime_args[@]}" "$invalid" >/dev/null 2>&1; then
    echo "chart accepted replica or phase setting $invalid" >&2
    exit 1
  fi
done

if grep -Fq 'EXPERIMENT_AMBIENT_CANARY' "$fixture/rendered.yaml"; then
  echo "ambient test value leaked into rendered workload" >&2
  exit 1
fi

if helm lint charts/native-plugin-runtime \
  --set enabled=true \
  --set-string trust.mode=development-untrusted \
  --set-string plugin.id=dev.stellwerk.native-probe \
  --set-string plugin.version=1.0.0 \
  --set-string package.reference=registry.invalid/native-probe:mutable \
  --set-string package.manifestSHA256="$manifest_hash" \
  --set-string images.runtime=registry.invalid/runtime:mutable \
  --set-string images.oras=registry.invalid/oras:mutable >/dev/null 2>&1; then
  echo "chart accepted mutable package/runtime references" >&2
  exit 1
fi

helm template native-probe charts/native-plugin-runtime \
  --set enabled=true \
  --set-string trust.mode=development-untrusted \
  --set-string plugin.id=dev.stellwerk.native-probe \
  --set-string plugin.version=1.0.0 \
  --set-string package.reference=registry.invalid/native-probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --set-string package.manifestSHA256="$manifest_hash" \
  --set-string images.runtime=registry.invalid/runtime@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --set-string images.oras=registry.invalid/oras@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --set-string trust.mode=managed-key-no-tlog \
  --set-string trust.bootstrapSecret.name=fixture-trust \
  --set-string trust.signatureBundleSecret.name=fixture-bundle \
  --set-string images.cosign=registry.invalid/cosign@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  --set-string package.attestations.sbom=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  --set-string package.attestations.provenance=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  >"$fixture/cosign-rendered.yaml"

if helm template native-probe charts/native-plugin-runtime \
  --set enabled=true \
  --set-string trust.mode=development-untrusted \
  --set-string plugin.id=dev.stellwerk.native-probe \
  --set-string plugin.version=1.0.0 \
  --set-string package.reference=registry.invalid/native-probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --set-string package.manifestSHA256="$manifest_hash" \
  --set-string images.runtime=registry.invalid/runtime@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --set-string images.oras=registry.invalid/oras@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --set-string trust.mode=managed-key-no-tlog \
  --set-string trust.bootstrapSecret.name=fixture-trust \
  --set-string images.cosign=registry.invalid/cosign@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  >/dev/null 2>&1; then
  echo "managed-key-no-tlog accepted a missing signature bundle Secret" >&2
  exit 1
fi
if helm template native-probe charts/native-plugin-runtime "${migration_args[@]}" \
  --set-string trust.mode=managed-key-no-tlog \
  --set-string trust.signatureBundleSecret.name=fixture-bundle \
  --set-string images.cosign=registry.invalid/cosign@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  >/dev/null 2>&1; then
  echo "managed-key-no-tlog accepted a missing trust bootstrap Secret" >&2
  exit 1
fi

helm template native-probe charts/native-plugin-runtime \
  "${migration_args[@]}" "${migration_job[@]}" \
  --set-string trust.mode=managed-key-no-tlog \
  --set-string trust.bootstrapSecret.name=fixture-trust \
  --set-string trust.signatureBundleSecret.name=fixture-bundle \
  --set-string images.cosign=registry.invalid/cosign@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  --set-string package.attestations.sbom=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  --set-string package.attestations.provenance=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  >"$fixture/cosign-migration-rendered.yaml"

python3 - "$fixture/cosign-rendered.yaml" "$fixture/cosign-migration-rendered.yaml" <<'PY'
import re
import sys


def blocks(section):
    return dict(re.findall(r"^        - name: ([a-z-]+)\n((?:(?:          .*)?\n)*)", section, re.M))


chain = ["fetch-package-envelope", "verify-package-envelope", "fetch-package-sbom", "fetch-package-provenance",
         "verify-package-publisher", "verify-package-signature", "verify-package-sbom", "verify-package-provenance",
         "pull-package", "validate-package"]
predicate_types = {"sbom": "https://spdx.dev/Document", "provenance": "https://stellwerk.dev/attestation/source-provenance/v1"}
referrers = {"sbom": "sha256:" + "e" * 64, "provenance": "sha256:" + "f" * 64}
for path in sys.argv[1:]:
    rendered = open(path, encoding="utf-8").read()
    pod = next(doc for doc in rendered.split("\n---") if re.search(r"^kind: (Deployment|Job)$", doc, re.M))
    init, rest = pod.split("      initContainers:\n", 1)[1].split("      containers:\n", 1)
    main, volumes = rest.split("      volumes:\n", 1)
    init_blocks, main_blocks = blocks(init), blocks(main)
    assert list(init_blocks) == chain, (path, list(init_blocks))
    for argument in ["- --output=/package/oci-manifest.json", "- verify-envelope", "- --package-digest=sha256:" + "a" * 64,
                     "- verify-publisher", "- --trust-bootstrap=/trust/publishers.json", "- --plugin-id=dev.stellwerk.native-probe",
                     "- --key-dir=/verify", "- verify-blob", "- --insecure-ignore-tlog", "- --key=/verify/package.pub",
                     "- --bundle=/signature/oci-manifest.sigstore.json", "- /package/oci-manifest.json"]:
        assert argument in init, argument
    gate = init_blocks["verify-package-publisher"]
    for name, predicate_type in predicate_types.items():
        bundle = f"/attestations/{name}/{name}.sigstore.json"
        fetch, cosign = init_blocks[f"fetch-package-{name}"], init_blocks[f"verify-package-{name}"]
        for argument in ["- pull", f"- --output=/attestations/{name}", f'- "registry.invalid/native-probe@{referrers[name]}"']:
            assert argument in fetch, (path, name, argument)
        assert f"- --{name}-bundle={bundle}" in gate, (path, name)
        for argument in ["- verify-blob-attestation", "- --insecure-ignore-tlog", f"- --key=/verify/{name}.pub",
                         f"- --type={predicate_type}", f"- --bundle={bundle}", "- /package/oci-manifest.json"]:
            assert argument in cosign, (path, name, argument)
        assert re.search(r"- name: attestations\n\s+mountPath: /attestations\n\s+readOnly: true", cosign), (path, name)
    assert re.search(r"- name: attestations\n\s+mountPath: /attestations\n\s+readOnly: true", gate)
    # Kubelet exposes Secret keys as symlinks into ..data and the runtime
    # refuses symlinks, so the operator's files are mounted as plain files.
    trust = r"- name: trust\n\s+mountPath: /trust/publishers.json\n\s+subPath: publishers.json\n\s+readOnly: true\n"
    bundle = (r"- name: signature-bundle\n\s+mountPath: /signature/oci-manifest.sigstore.json\n"
              r"\s+subPath: oci-manifest.sigstore.json\n\s+readOnly: true\n")
    assert re.search(trust, gate) and re.search(bundle, gate), path
    assert re.search(bundle, init_blocks["verify-package-signature"]), path
    assert not re.search(r"mountPath: /(trust|signature)\n", init), path
    assert "- --trust-state=verified-local-key" in init_blocks["validate-package"]
    assert "--installed-digest" not in pod, "no installation recorded in this render"
    # Trust material and registry access stay in their init containers.
    fetchers = {"fetch-package-envelope", "fetch-package-sbom", "fetch-package-provenance", "pull-package"}
    cosigns = {"verify-package-signature", "verify-package-sbom", "verify-package-provenance"}
    owners = {"mountPath: /trust": {"verify-package-publisher"},
              "name: signature-bundle": {"verify-package-publisher", "verify-package-signature"},
              "name: attestations\n": {"fetch-package-sbom", "fetch-package-provenance", "verify-package-publisher",
                                       "verify-package-sbom", "verify-package-provenance"},
              "name: verify\n": {"verify-package-publisher"} | cosigns,
              "name: registry-config": fetchers,
              "registry.invalid/oras": fetchers,
              "registry.invalid/cosign": cosigns}
    for marker, allowed in owners.items():
        holders = {name for name, body in {**init_blocks, **main_blocks}.items() if marker in body}
        # registry-config exists only with a registry Secret; the rest always.
        assert holders <= allowed and (holders == allowed or marker == "name: registry-config"), (path, marker, holders)
    for name in cosigns:
        assert re.search(r"- name: verify\n\s+mountPath: /verify\n\s+readOnly: true", init_blocks[name]), (path, name)
    for name, limit in {"verify": "1Mi", "attestations": "3Mi"}.items():
        volume = re.search(rf"^        - name: {name}\n((?:          .*\n)+)", volumes, re.M)
        assert volume and "medium: Memory" in volume.group(1) and f"sizeLimit: {limit}" in volume.group(1), (path, name)
    assert "secretName: fixture-trust" in volumes and "secretName: fixture-bundle" in volumes
    assert "--offline" not in rendered and "--development-untrusted" not in rendered
PY

# An installer records the installed digest; only the gate receives it.
installed_args=("${migration_args[@]}" --set-string trust.mode=managed-key-no-tlog
  --set-string trust.bootstrapSecret.name=fixture-trust --set-string trust.signatureBundleSecret.name=fixture-bundle
  --set-string images.cosign=registry.invalid/cosign@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd)
helm template native-probe charts/native-plugin-runtime "${installed_args[@]}" "${migration_job[@]}" \
  --set-string package.installedDigest=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >"$fixture/installed.yaml"
test "$(grep -c -- '--installed-digest=' "$fixture/installed.yaml")" -eq 1
# Without configured attestations nothing is fetched for them and the gate
# gets no attestation bundle, so a publisher requiring one fails closed.
python3 - "$fixture/installed.yaml" <<'PY'
import re
import sys
rendered = open(sys.argv[1], encoding="utf-8").read()
gate = rendered.split("        - name: verify-package-publisher\n", 1)[1].split("        - name:", 1)[0]
assert "- --installed-digest=sha256:" + "a" * 64 in gate
init = rendered.split("      initContainers:\n", 1)[1].split("      containers:\n", 1)[0]
assert re.findall(r"^        - name: ([a-z-]+)$", init, re.M) == [
    "fetch-package-envelope", "verify-package-envelope", "verify-package-publisher",
    "verify-package-signature", "pull-package", "validate-package"], init
for forbidden in ["-bundle=/attestations/", "verify-blob-attestation", "--output=/attestations"]:
    assert forbidden not in rendered, forbidden
PY
for invalid in sha256:ABC "sha256:$(printf 'a%.0s' {1..63})" "md5:$(printf 'a%.0s' {1..32})"; do
  for value in package.installedDigest package.attestations.sbom package.attestations.provenance; do
    if helm template native-probe charts/native-plugin-runtime "${installed_args[@]}" \
      --set-string "$value=$invalid" >/dev/null 2>&1; then
      echo "chart accepted $value=$invalid" >&2
      exit 1
    fi
  done
done

# Without signature trust the package layout is still checked before the pull,
# and nothing skips a transparency log.
python3 - "$fixture/rendered.yaml" "$fixture/migration-rendered.yaml" <<'PY'
import re
import sys

for path in sys.argv[1:]:
    rendered = open(path, encoding="utf-8").read()
    pod = next(doc for doc in rendered.split("\n---") if re.search(r"^kind: (Deployment|Job)$", doc, re.M))
    init = pod.split("      initContainers:\n", 1)[1].split("      containers:\n", 1)[0]
    assert re.findall(r"^        - name: ([a-z-]+)$", init, re.M) == [
        "fetch-package-envelope", "verify-package-envelope", "pull-package", "validate-package"], (path, init)
    assert "- verify-envelope" in init
    for forbidden in ["- verify-blob", "- verify-publisher", "insecure-ignore-tlog", "- name: trust\n", "- name: verify\n",
                      "- name: attestations\n"]:
        assert forbidden not in rendered, (path, forbidden)
PY

# Pod hardening: every Secret volume is 0440, plugin state is bounded and no
# service links reach any container.
helm template native-probe charts/native-plugin-runtime \
  --set enabled=true \
  --set-string plugin.id=dev.stellwerk.native-probe \
  --set-string plugin.version=1.0.0 \
  --set-string package.reference=registry.invalid/native-probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --set-string package.manifestSHA256="$manifest_hash" \
  --set-string images.runtime=registry.invalid/runtime@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --set-string images.oras=registry.invalid/oras@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --set-string trust.mode=managed-key-no-tlog \
  --set-string trust.bootstrapSecret.name=fixture-trust \
  --set-string trust.signatureBundleSecret.name=fixture-bundle \
  --set-string images.cosign=registry.invalid/cosign@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  --set-string package.registryConfigSecret.name=registry-pull \
  --set-json 'pluginSecretFiles=[{"name":"plugin-profile","secretName":"operator-plugin-profile","mountPath":"/run/secrets/profile","items":[{"key":"profile.json","path":"profile.json"}]}]' \
  >"$fixture/hardened.yaml"
python3 - "$fixture/hardened.yaml" "$fixture/cosign-migration-rendered.yaml" <<'PY'
import re
import sys

for path in sys.argv[1:]:
    rendered = open(path, encoding="utf-8").read()
    pods = [doc for doc in rendered.split("\n---") if re.search(r"^kind: (Deployment|Job)$", doc, re.M)]
    assert len(pods) == 1, path
    pod = pods[0]
    assert "      enableServiceLinks: false\n" in pod, path
    assert "      automountServiceAccountToken: false\n" in pod, path
    secrets = re.findall(r"^          secret:\n((?:            .*\n)+)", pod, re.M)
    assert len(secrets) >= 2, (path, secrets)
    for volume in secrets:
        assert "            defaultMode: 0440\n" in volume, (path, volume)
    state = re.search(r"^        - name: state\n((?:          .*\n)+)", pod, re.M)
    assert state and "emptyDir:" in state.group(1) and "sizeLimit: 128Mi" in state.group(1), (path, state)
    package = re.search(r"^        - name: package\n((?:          .*\n)+)", pod, re.M)
    assert package and "emptyDir:" in package.group(1) and "sizeLimit: 640Mi" in package.group(1), (path, package)
PY

package_output="$fixture/package-output"
release="$("$root/scripts/build-package.sh" 1.0.0 "$package_output")"
jq -e '.trustState == "untrusted-development" and (.packageDigest | test("^sha256:[0-9a-f]{64}$"))' "$release" >/dev/null
# The build records its exact source commit for the provenance attestation.
jq -e --arg commit "$(git -C "$root" rev-parse --verify HEAD)" '.schemaVersion == 1 and (.sources | length == 1) and
  .sources[0].commit == $commit and .sources[0].path == "." and (.sources[0].dirty | type == "boolean")' \
  "$package_output/source-provenance.json" >/dev/null
oras manifest fetch --oci-layout "$package_output/oci-layout:1.0.0" | jq -e '
  .artifactType == "application/vnd.stellwerk.plugin.package.v1" and
  ([.layers[].mediaType] | sort) == ([
    "application/vnd.stellwerk.plugin.executable.v1",
    "application/vnd.stellwerk.plugin.executable.v1",
    "application/vnd.stellwerk.plugin.manifest.v1+json"
  ] | sort)
' >/dev/null

# The runtime image the offline bundle carries is built without Docker. It
# must stay the image Dockerfile.runtime describes, for exactly linux/amd64
# and linux/arm64, and rebuilding the same commit gives the same digest.
runtime_digest="$("$root/scripts/build-runtime-image.sh" "$fixture/runtime-image")"
test "$("$root/scripts/build-runtime-image.sh" "$fixture/runtime-image-again")" = "$runtime_digest"
oras manifest fetch --oci-layout "$fixture/runtime-image@$runtime_digest" |
  jq -e '[.manifests[].platform | "\(.os)/\(.architecture)"] | sort == ["linux/amd64", "linux/arm64"]' >/dev/null
grep -qx 'USER 65532:65532' Dockerfile.runtime
grep -qx 'ENTRYPOINT \["/runtime"\]' Dockerfile.runtime
for architecture in amd64 arm64; do
  oras manifest fetch-config --oci-layout "$fixture/runtime-image:runtime-$architecture" | jq -e --arg architecture "$architecture" '
    .os == "linux" and .architecture == $architecture and .config == {User: "65532:65532", Entrypoint: ["/runtime"]} and
    (.rootfs.diff_ids | length == 1)' >/dev/null
done

ui_args=(
  --set enabled=true --set ui.enabled=true
  --set-string trust.mode=development-untrusted
  --set-string ui.consoleOrigin=https://console.example.test
  --set-string plugin.id=dev.stellwerk.native-probe
  --set-string plugin.version=1.0.0
  --set-string package.reference=registry.invalid/native-probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  --set-string package.manifestSHA256="$manifest_hash"
  --set-string images.runtime=registry.invalid/runtime@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  --set-string images.oras=registry.invalid/oras@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
  --set probes.scheme=HTTPS --set probes.path=/healthz
  --set ui.gateway.enabled=true --set ui.gateway.className=envoy-gateway
  --set ui.gateway.hostname=plugins.example.test --set ui.gateway.certificateSecretName=plugin-ui-tls
  --set ui.gateway.issuerName=existing-issuer
  --set-json 'networkPolicy.additionalIngress=[{"from":[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"envoy-gateway-system"}},"podSelector":{"matchLabels":{"gateway.envoyproxy.io/owning-gateway-name":"native-plugin-ui"}}}],"ports":[{"protocol":"TCP","port":8081}]}]'
  --set-json 'pluginSecretFiles=[{"name":"backend-only","secretName":"backend-credentials","mountPath":"/run/secrets/backend","items":[{"key":"token","path":"token"}]}]'
)
helm template native-ui charts/native-plugin-runtime "${ui_args[@]}" >"$fixture/ui.yaml"
python3 - "$fixture/ui.yaml" <<'PY'
import re
import sys
rendered = open(sys.argv[1], encoding="utf-8").read()
deployment = next(doc for doc in rendered.split("\n---") if re.search(r"^kind: Deployment$", doc, re.M))
ui = deployment.split("        - name: ui\n", 1)[1].split("      volumes:", 1)[0]
assert "- serve-ui" in ui
assert "--console-origin=https://console.example.test" in ui
assert "registry.invalid/runtime@sha256:" in ui
assert "backend-credentials" not in ui and "backend-only" not in ui
assert "mountPath: /state" not in ui and "env:" not in ui
assert ui.count("mountPath:") == 1 and "mountPath: /package" in ui
assert "readOnly: true" in ui and "readOnlyRootFilesystem: true" in ui
assert deployment.count("scheme: HTTPS") == 3
service = next(doc for doc in rendered.split("\n---") if re.search(r"^kind: Service$", doc, re.M))
assert "targetPort: ui" in service
policy = next(doc for doc in rendered.split("\n---") if re.search(r"^kind: NetworkPolicy$", doc, re.M) and "\n  name: native-ui-native-plugin-runtime\n" in doc)
assert "gateway.envoyproxy.io/owning-gateway-name: native-plugin-ui" in policy
assert "port: 8081" in policy
assert "kind: Gateway" in rendered and "kind: Certificate" in rendered
assert "hostname: \"plugins.example.test\"" in rendered
assert "value: /embed/" in rendered and "port: 8081" in rendered
assert "scheme: https, statusCode: 301" in rendered
PY
if helm template native-ui charts/native-plugin-runtime "${ui_args[@]}" --set ui.port=8080 >/dev/null 2>&1; then
  echo "chart accepted a UI/backend port collision" >&2
  exit 1
fi
if helm template native-ui charts/native-plugin-runtime "${ui_args[@]}" --set-string ui.consoleOrigin=http://console.example.test >/dev/null 2>&1; then
  echo "chart accepted an insecure Console origin" >&2
  exit 1
fi
if helm template native-ui charts/native-plugin-runtime "${ui_args[@]}" --set ui.gateway.hostname=console.example.test >/dev/null 2>&1; then
  echo "chart accepted the Console hostname for plugin UI" >&2
  exit 1
fi
if helm template native-ui charts/native-plugin-runtime "${ui_args[@]}" --set-json 'networkPolicy.additionalIngress=[]' >/dev/null 2>&1; then
  echo "chart accepted UI networking without an explicit Gateway ingress rule" >&2
  exit 1
fi

# Workload token exchange: only the core-token native
# sidecar mounts the projected ServiceAccount token; the plugin gets the
# memory-backed Core token file and nothing else.
for document in rendered ui migration-rendered; do
  if grep -E -q 'core-token|serviceAccountToken|STELLWERK_CORE_TOKEN_FILE|STELLWERK_INSTALLATION_ID' "$fixture/$document.yaml"; then
    echo "$document.yaml carries workload identity although it is disabled" >&2
    exit 1
  fi
done
installation_id=0b7e6c1a-3f52-4d8e-9a41-6c2f0e8d5b17
workload_args=(
  "${ui_args[@]}"
  --set workloadIdentity.enabled=true
  --set-string workloadIdentity.audience=stellwerk-plugin-workload
  --set-string workloadIdentity.gateway.url=https://api.example.test
  --set-string workloadIdentity.gateway.caSecret.name=gateway-ca
  --set-string installationId="$installation_id"
)
helm lint charts/native-plugin-runtime "${workload_args[@]}" >/dev/null
helm template native-ui charts/native-plugin-runtime "${workload_args[@]}" >"$fixture/workload.yaml"
python3 - "$fixture/workload.yaml" <<'PY'
import re
import sys

rendered = open(sys.argv[1], encoding="utf-8").read()
deployment = next(doc for doc in rendered.split("\n---") if re.search(r"^kind: Deployment$", doc, re.M))
init, rest = deployment.split("      initContainers:\n", 1)[1].split("      containers:\n", 1)
main, volumes = rest.split("      volumes:\n", 1)


def blocks(section):
    return dict(re.findall(r"^        - name: ([a-z-]+)\n((?:(?:          .*)?\n)*)", section, re.M))


init_blocks, main_blocks, volume_blocks = blocks(init), blocks(main), blocks(volumes)
assert list(init_blocks) == ["fetch-package-envelope", "verify-package-envelope", "pull-package",
                             "validate-package", "core-token"], list(init_blocks)
sidecar = init_blocks["core-token"]
assert "restartPolicy: Always" in sidecar
assert sidecar.count("command: [/runtime, check-core-token, --token-file=/run/stellwerk/core-token/token]") == 2
assert "startupProbe:" in sidecar and "readinessProbe:" in sidecar
for argument in ["- refresh-core-token", "- --gateway-url=https://api.example.test",
                 "- --subject-token-file=/var/run/secrets/stellwerk/workload/token",
                 "- --token-file=/run/stellwerk/core-token/token", "- --ca-file=/run/stellwerk/gateway-ca/ca.crt"]:
    assert argument in sidecar, argument
assert re.search(r"- name: workload-token\n\s+mountPath: /var/run/secrets/stellwerk/workload\n\s+readOnly: true", sidecar)
assert re.search(r"- name: core-token\n\s+mountPath: /run/stellwerk/core-token\n(?!\s+readOnly)", sidecar)
assert "readOnlyRootFilesystem: true" in sidecar and "drop: [ALL]" in sidecar
for name, block in {**init_blocks, **main_blocks}.items():
    if name != "core-token":
        assert "workload-token" not in block and "gateway-ca" not in block, name
for name in ["fetch-package-envelope", "verify-package-envelope", "pull-package", "validate-package", "ui"]:
    assert "core-token" not in {**init_blocks, **main_blocks}[name], name
plugin = main_blocks["plugin"]
assert "- name: STELLWERK_CORE_TOKEN_FILE\n              value: /run/stellwerk/core-token/token" in plugin
# The installation UUID Core assigned reaches the plugin container only.
assert '- name: STELLWERK_INSTALLATION_ID\n              value: "0b7e6c1a-3f52-4d8e-9a41-6c2f0e8d5b17"' in plugin
assert deployment.count("STELLWERK_INSTALLATION_ID") == 1
assert re.search(r"- name: core-token\n\s+mountPath: /run/stellwerk/core-token\n\s+readOnly: true", plugin)
projected = volume_blocks["workload-token"]
for expected in ['audience: "stellwerk-plugin-workload"', "expirationSeconds: 600", "path: token", "defaultMode: 0440"]:
    assert expected in projected, expected
assert "medium: Memory" in volume_blocks["core-token"] and "sizeLimit: 1Mi" in volume_blocks["core-token"]
assert "secretName: gateway-ca" in volume_blocks["gateway-ca"] and "defaultMode: 0440" in volume_blocks["gateway-ca"]
assert "      serviceAccountName: native-ui-native-plugin-runtime\n" in deployment
assert "      automountServiceAccountToken: false\n" in deployment
PY
helm template native-probe charts/native-plugin-runtime "${migration_args[@]}" "${migration_job[@]}" \
  --set workloadIdentity.enabled=true --set-string workloadIdentity.audience=stellwerk-plugin-workload \
  --set-string workloadIdentity.gateway.url=https://api.example.test \
  --set-string installationId="$installation_id" >"$fixture/migration-workload.yaml"
if grep -E -q 'core-token|serviceAccountToken|STELLWERK_INSTALLATION_ID' "$fixture/migration-workload.yaml"; then
  echo "the migration Job received the Core token exchange or the installation UUID" >&2
  exit 1
fi
# Helm applies --set-string after --set, so string overrides use --set-string.
for invalid in "--set-string=workloadIdentity.audience=" "--set-string=workloadIdentity.gateway.url=" \
  "--set-string=workloadIdentity.gateway.url=http://api.example.test" \
  "--set-string=workloadIdentity.gateway.url=https://api.example.test/iam" \
  "--set=workloadIdentity.expirationSeconds=3600" "--set=workloadIdentity.expirationSeconds=599" \
  "--set=serviceAccount.create=false,serviceAccount.name=shared" "--set=serviceAccount.projectedIdentity.enabled=true" \
  "--set-string=installationId=" "--set-string=installationId=0B7E6C1A-3F52-4D8E-9A41-6C2F0E8D5B17" \
  "--set-string=installationId=0b7e6c1a3f524d8e9a416c2f0e8d5b17" "--set-string=installationId=installation-1"; do
  if helm template native-ui charts/native-plugin-runtime "${workload_args[@]}" "$invalid" >/dev/null 2>&1; then
    echo "chart accepted workload identity setting $invalid" >&2
    exit 1
  fi
done
# Without workload identity the installation UUID is optional, and a given
# one must still be canonical.
helm template native-probe charts/native-plugin-runtime "${runtime_args[@]}" \
  --set-string installationId="$installation_id" >"$fixture/installation.yaml"
grep -Fq "value: \"$installation_id\"" "$fixture/installation.yaml"
if helm template native-probe charts/native-plugin-runtime "${runtime_args[@]}" \
  --set-string installationId=0B7E6C1A-3F52-4D8E-9A41-6C2F0E8D5B17 >/dev/null 2>&1; then
  echo "chart accepted a non-canonical installation UUID" >&2
  exit 1
fi
if helm template native-ui charts/native-plugin-runtime "${workload_args[@]}" --kube-version 1.28.0 >/dev/null 2>&1; then
  echo "chart rendered the native token sidecar for Kubernetes 1.28" >&2
  exit 1
fi

# Graceful termination: the plugin and UI keep serving for the preStop delay
# while the endpoint removal propagates, then drain within the grace period.
# Fetch init containers and the token sidecar (which must outlive the
# plugin's shutdown) get no delay.
helm template native-ui charts/native-plugin-runtime "${workload_args[@]}" \
  --set preStopDelaySeconds=10 --set terminationGracePeriodSeconds=15 >"$fixture/prestop-custom.yaml"
helm template native-ui charts/native-plugin-runtime "${workload_args[@]}" \
  --set preStopDelaySeconds=0 --kube-version 1.29.0 >"$fixture/prestop-off.yaml"
python3 - "$fixture" <<'PY'
import re
import sys


def containers(path):
    rendered = open(f"{sys.argv[1]}/{path}", encoding="utf-8").read()
    deployment = next(doc for doc in rendered.split("\n---") if re.search(r"^kind: Deployment$", doc, re.M))
    grace = re.search(r"^      terminationGracePeriodSeconds: (\d+)$", deployment, re.M).group(1)
    pod = deployment.split("      initContainers:\n", 1)[1].split("      volumes:\n", 1)[0]
    return int(grace), dict(re.findall(r"^        - name: ([a-z-]+)\n((?:(?:          .*)?\n)*)", pod, re.M))


def pre_stop(seconds):
    return f"          lifecycle:\n            preStop:\n              sleep:\n                seconds: {seconds}\n"


for path, delay in [("workload.yaml", 5), ("ui.yaml", 5), ("prestop-custom.yaml", 10), ("prestop-off.yaml", 0)]:
    grace, blocks = containers(path)
    assert grace == 15, (path, grace)
    assert {"plugin", "ui"} <= set(blocks), (path, list(blocks))
    for name, block in blocks.items():
        delayed = delay > 0 and name in {"plugin", "ui"}
        assert (pre_stop(delay) in block) == delayed, (path, name)
        assert block.count("lifecycle:") == delayed, (path, name)
assert "core-token" in containers("workload.yaml")[1]
PY
for invalid in "--set=preStopDelaySeconds=11" "--set=terminationGracePeriodSeconds=9" "--set=preStopDelaySeconds=-1" \
  "--set-string=preStopDelaySeconds=5" "--kube-version=1.29.0"; do
  if helm template native-ui charts/native-plugin-runtime "${workload_args[@]}" "$invalid" >/dev/null 2>&1; then
    echo "chart accepted the termination setting $invalid" >&2
    exit 1
  fi
done

# Fetch isolation: registry credentials and ORAS stay in the fetch init
# containers, and Pod egress reaches only the configured mirror endpoints.
# NetworkPolicy is per Pod, so the plugin can reach those endpoints but holds
# no credentials. Broad rules are refused.
mirrors='[{"cidr":"203.0.113.10/32","port":5000},{"namespaceSelector":{"kubernetes.io/metadata.name":"registry-mirror"},"podSelector":{"app.kubernetes.io/name":"mirror"},"port":5000}]'
helm template native-ui charts/native-plugin-runtime "${workload_args[@]}" \
  --set-string package.registryConfigSecret.name=registry-pull \
  --set-json "networkPolicy.registryMirrors=$mirrors" >"$fixture/egress-runtime.yaml"
helm template native-ui charts/native-plugin-runtime "${migration_args[@]}" "${migration_job[@]}" \
  --set-string package.registryConfigSecret.name=registry-pull \
  --set-json "networkPolicy.registryMirrors=$mirrors" >"$fixture/egress-migration.yaml"
python3 - "$fixture/egress-runtime.yaml" "$fixture/egress-migration.yaml" "$fixture/workload.yaml" <<'PY'
import re
import sys

for path in sys.argv[1:]:
    configured = "egress-" in path
    documents = open(path, encoding="utf-8").read().split("\n---")
    policies = [doc for doc in documents if re.search(r"^kind: NetworkPolicy$", doc, re.M)]
    assert len(policies) == 1, path
    egress = policies[0].split("  egress:\n", 1)[1]
    rules = re.split(r"(?m)^    - to:\n", egress)[1:]
    assert rules, path
    for rule in rules:
        assert "      ports:\n" in rule, (path, "an egress rule without ports")
        for cidr in re.findall(r"cidr: \"?([^\"\n]+)\"?", rule):
            assert cidr == "203.0.113.10/32", (path, f"egress to {cidr}")
    mirror_rules = [rule for rule in rules if "203.0.113.10/32" in rule or "registry-mirror" in rule]
    assert len(mirror_rules) == (2 if configured else 0), (path, len(mirror_rules))
    for rule in mirror_rules:
        assert "port: 5000" in rule
    if "registry-mirror" in egress:
        peer = egress.split("kubernetes.io/metadata.name: registry-mirror", 1)[1].split("      ports:", 1)[0]
        assert "podSelector:" in peer and "app.kubernetes.io/name: mirror" in peer
    pod = next(doc for doc in documents if re.search(r"^kind: (Deployment|Job)$", doc, re.M))
    init, main = pod.split("      initContainers:\n", 1)[1].split("      containers:\n", 1)
    main = main.split("      volumes:\n", 1)[0]
    for marker in ["registry-config", "registry.invalid/oras", "--registry-config", "pull-package", "/trust", "signature-bundle"]:
        assert marker not in main, (path, marker)
    if configured:
        assert "secretName: registry-pull" in pod and "registry-config" in init
        for name, body in re.findall(r"^        - name: ([a-z-]+)\n((?:(?:          .*)?\n)*)", init, re.M):
            assert ("name: registry-config" in body) == (name in {"fetch-package-envelope", "pull-package"}), (path, name)
            if "name: registry-config" in body:
                assert re.search(r"- name: registry-config\n\s+mountPath: /registry/config.json\n"
                                 r"\s+subPath: config.json\n\s+readOnly: true\n", body), (path, name)
PY
for broad in '[{"cidr":"0.0.0.0/0","port":443}]' '[{"cidr":"10.0.0.0/8","port":443}]' '[{"cidr":"203.0.113.10/32"}]' \
  '[{"namespaceSelector":{"kubernetes.io/metadata.name":"registry-mirror"},"port":5000}]' \
  '[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}]}]' '[{"cidr":"::/0","port":443}]'; do
  if helm template native-ui charts/native-plugin-runtime "${workload_args[@]}" \
    --set-json "networkPolicy.registryMirrors=$broad" >/dev/null 2>&1; then
    echo "chart accepted the broad registry rule $broad" >&2
    exit 1
  fi
done

# Every rendered profile: args and command entries are single list items. A
# deeper-indented entry would fold into the previous argument and still be
# valid YAML.
python3 - "$fixture"/*.yaml <<'PY'
import re
import sys

# A list item indented deeper than its siblings folds into the previous
# scalar: still valid YAML, but the container gets one merged argument.
for path in sys.argv[1:]:
    lines = open(path, encoding="utf-8").read().split("\n")
    for number, line in enumerate(lines):
        key = re.match(r"^( *)(?:- )?(args|command):$", line)
        if not key:
            continue
        base = len(line) - len(line.lstrip()) + (2 if line.lstrip().startswith("- ") else 0)
        following = number + 1
        while following < len(lines) and lines[following].strip() and len(lines[following]) - len(lines[following].lstrip()) > base:
            item = lines[following]
            assert item.lstrip().startswith("- ") and len(item) - len(item.lstrip()) == base + 2, \
                f"{path}:{following + 1}: {key.group(2)} entry is not a single list item: {item.strip()[:60]}"
            following += 1
PY

echo "All native runtime, package and chart checks passed."
