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
    if re.search(r"^kind: NetworkPolicy$", document, re.M)
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
  --set runtime.enabled=false
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
helm lint charts/native-plugin-runtime "${migration_args[@]}"
helm template native-probe charts/native-plugin-runtime "${migration_args[@]}" >"$fixture/migration-rendered.yaml"
python3 - "$fixture/migration-rendered.yaml" <<'PY'
import re
import sys

rendered = open(sys.argv[1], encoding="utf-8").read()
assert re.search(r"^kind: Job$", rendered, re.M)
assert not re.search(r"^kind: Deployment$", rendered, re.M)
assert not re.search(r"^kind: Service$", rendered, re.M)
assert "app.kubernetes.io/component: migration" in rendered
assert "name: STELLWERK_PLUGIN_CONFIG_FILE" in rendered
assert "value: /run/secrets/stellwerk-plugin-migration/profile.json" in rendered
assert "mountPath: /run/secrets/stellwerk-plugin-migration/database-url" in rendered
assert "secretName: plugin-migration-profile" in rendered
assert "secretName: plugin-migration-database" in rendered
assert rendered.count("defaultMode: 0440") >= 2
job = next(document for document in rendered.split("\n---") if re.search(r"^kind: Job$", document, re.M))
init_containers = job.split("\n      initContainers:", 1)[1].split("\n      containers:", 1)[0]
assert "migration-profile" not in init_containers
assert "migration-database" not in init_containers
policy = next(document for document in rendered.split("\n---") if re.search(r"^kind: NetworkPolicy$", document, re.M))
assert "platform-orchestrator-cnpg-databases" in policy
assert "k8s-app: kube-dns" in policy
assert "owning-gateway" not in policy
assert "migration-database-ca" not in rendered
PY

helm template native-probe charts/native-plugin-runtime "${migration_args[@]}" \
  --set-string migration.databaseCASecret.name=public-database-ca \
  --set-string migration.databaseCASecret.key=trust.pem >"$fixture/migration-ca.yaml"
python3 - "$fixture/migration-ca.yaml" <<'PY'
import re
import sys

rendered = open(sys.argv[1], encoding="utf-8").read()
job = next(document for document in rendered.split("\n---") if re.search(r"^kind: Job$", document, re.M))
init, executor = job.split("      containers:\n", 1)
assert "migration-database-ca" not in init
assert "mountPath: /run/config/database-ca" in executor
assert "secretName: public-database-ca" in executor
assert "key: trust.pem" in executor and "path: ca.crt" in executor
assert "readOnly: true" in executor
assert not re.search(r"^kind: Deployment$", rendered, re.M)
PY
for invalid_ca in name=plugin-migration-profile name=plugin-migration-database key= unknown=true; do
  if helm template native-probe charts/native-plugin-runtime "${migration_args[@]}" \
    --set-string "migration.databaseCASecret.$invalid_ca" >/dev/null 2>&1; then
    echo "chart accepted invalid migration database CA setting: $invalid_ca" >&2
    exit 1
  fi
done
helm template native-probe charts/native-plugin-runtime "${migration_args[@]}" \
  --set migration.enabled=false --set runtime.enabled=true \
  --set-string migration.databaseCASecret.name=public-database-ca >"$fixture/runtime-without-migration-ca.yaml"
if grep -Fq 'public-database-ca' "$fixture/runtime-without-migration-ca.yaml"; then
  echo "runtime inherited the migration-only database CA" >&2
  exit 1
fi

if helm template native-probe charts/native-plugin-runtime \
  "${migration_args[@]}" --set runtime.enabled=true >/dev/null 2>&1; then
  echo "chart allowed runtime and migration phases concurrently" >&2
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
  --set-string trust.mode=cosign-key \
  --set-string trust.cosign.publicKeySecret.name=fixture-trust \
  --set-string trust.cosign.signatureBundleSecret.name=fixture-bundle \
  --set-string images.cosign=registry.invalid/cosign@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
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
  --set-string trust.mode=cosign-key \
  --set-string trust.cosign.publicKeySecret.name=fixture-trust \
  --set-string images.cosign=registry.invalid/cosign@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  >/dev/null 2>&1; then
  echo "Cosign trust profile accepted a missing signature bundle Secret" >&2
  exit 1
fi

helm template native-probe charts/native-plugin-runtime \
  "${migration_args[@]}" \
  --set-string trust.mode=cosign-key \
  --set-string trust.cosign.publicKeySecret.name=fixture-trust \
  --set-string trust.cosign.signatureBundleSecret.name=fixture-bundle \
  --set-string images.cosign=registry.invalid/cosign@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  >"$fixture/cosign-migration-rendered.yaml"

python3 - "$fixture/cosign-rendered.yaml" "$fixture/cosign-migration-rendered.yaml" <<'PY'
import re
import sys

expected = [
    "fetch-package-envelope", "verify-package-envelope",
    "verify-package-signature", "pull-package", "validate-package",
]
for path in sys.argv[1:]:
    rendered = open(path, encoding="utf-8").read()
    init = rendered.split("      initContainers:\n", 1)[1].split("      containers:\n", 1)[0]
    actual = re.findall(r"^        - name: ([a-z-]+)$", init, re.M)
    assert actual == expected, (path, actual)
    assert "- --output=/package/oci-manifest.json" in init
    assert "- verify-envelope" in init
    assert "- --package-digest=sha256:" + "a" * 64 in init
    assert "- verify-blob" in init
    assert "- --insecure-ignore-tlog" in init
    assert "- --bundle=/signature/oci-manifest.sigstore.json" in init
    assert "- /package/oci-manifest.json" in init
    assert "secretName: fixture-trust" in rendered
    assert "secretName: fixture-bundle" in rendered
    assert "--offline" not in rendered
    assert "--development-untrusted" not in rendered
PY

# Without signature trust the package layout is still checked before the pull.
python3 - "$fixture/rendered.yaml" "$fixture/migration-rendered.yaml" <<'PY'
import re
import sys

expected = ["fetch-package-envelope", "verify-package-envelope", "pull-package", "validate-package"]
for path in sys.argv[1:]:
    rendered = open(path, encoding="utf-8").read()
    init = rendered.split("      initContainers:\n", 1)[1].split("      containers:\n", 1)[0]
    actual = re.findall(r"^        - name: ([a-z-]+)$", init, re.M)
    assert actual == expected, (path, actual)
    assert "- verify-envelope" in init and "- verify-blob" not in init
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
  --set-string trust.mode=cosign-key \
  --set-string trust.cosign.publicKeySecret.name=fixture-trust \
  --set-string trust.cosign.signatureBundleSecret.name=fixture-bundle \
  --set-string images.cosign=registry.invalid/cosign@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd \
  --set-string package.registryConfigSecret.name=registry-pull \
  --set-json 'pluginSecretFiles=[{"name":"plugin-profile","secretName":"operator-plugin-profile","mountPath":"/run/secrets/profile","items":[{"key":"profile.json","path":"profile.json"}]}]' \
  >"$fixture/hardened.yaml"
python3 - "$fixture/hardened.yaml" "$fixture/cosign-migration-rendered.yaml" <<'PY'
import re
import sys

for path in sys.argv[1:]:
    rendered = open(path, encoding="utf-8").read()
    pod = next(doc for doc in rendered.split("\n---") if re.search(r"^kind: (Deployment|Job)$", doc, re.M))
    assert "      enableServiceLinks: false\n" in pod, path
    assert "      automountServiceAccountToken: false\n" in pod, path
    secrets = re.findall(r"^          secret:\n((?:            .*\n)+)", pod, re.M)
    assert len(secrets) >= 2, (path, secrets)
    for volume in secrets:
        assert "            defaultMode: 0440\n" in volume, (path, volume)
    state = re.search(r"^        - name: state\n((?:          .*\n)+)", pod, re.M)
    assert state and "emptyDir:" in state.group(1) and "sizeLimit: 128Mi" in state.group(1), (path, state)
PY

package_output="$fixture/package-output"
release="$("$root/scripts/build-package.sh" 1.0.0 "$package_output")"
jq -e '.trustState == "untrusted-development" and (.packageDigest | test("^sha256:[0-9a-f]{64}$"))' "$release" >/dev/null
oras manifest fetch --oci-layout "$package_output/oci-layout:1.0.0" | jq -e '
  .artifactType == "application/vnd.stellwerk.plugin.package.v1" and
  ([.layers[].mediaType] | sort) == ([
    "application/vnd.stellwerk.plugin.executable.v1",
    "application/vnd.stellwerk.plugin.executable.v1",
    "application/vnd.stellwerk.plugin.manifest.v1+json"
  ] | sort)
' >/dev/null

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
policy = next(doc for doc in rendered.split("\n---") if re.search(r"^kind: NetworkPolicy$", doc, re.M))
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

echo "All native runtime, package and chart checks passed."
