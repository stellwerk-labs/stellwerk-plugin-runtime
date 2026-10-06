#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"
run_id="$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
cluster="swnative-$run_id"
context="kind-$cluster"
registry="swnative-registry-$run_id"
namespace="native-plugin-test"
release="native-probe"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/native-plugin-kind.XXXXXX")"
kubeconfig="$workspace/kubeconfig"
registry_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
runtime_tag="localhost:$registry_port/native-runtime:$run_id"
oras_tag="localhost:$registry_port/oras:$run_id"
port_forward_pid=""
runtime_reference=""
oras_reference=""
checks=()

cleanup() {
  if [ -n "$port_forward_pid" ]; then kill "$port_forward_pid" >/dev/null 2>&1 || true; fi
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  docker rm -f "$registry" >/dev/null 2>&1 || true
  if [ -n "$runtime_tag" ]; then docker image rm "$runtime_tag" >/dev/null 2>&1 || true; fi
  if [ -n "$oras_tag" ]; then docker image rm "$oras_tag" >/dev/null 2>&1 || true; fi
  rm -rf -- "$workspace"
}
trap cleanup EXIT

for command in docker kind kubectl helm oras go jq python3; do
  command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }
done

kube() { kubectl --kubeconfig "$kubeconfig" --context "$context" "$@"; }
random_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

require_image "$registry_image" "$(docker_platform)"
require_image "$oras_image" "$(docker_platform)"
docker run --detach --pull=never \
  --publish "127.0.0.1:$registry_port:5000" --name "$registry" "$registry_image" >/dev/null

# This follows kind's documented local-registry adapter. The unique kubeconfig
# and explicit context prevent accidental contact with a user/remote cluster.
printf '%s\n' \
  'kind: Cluster' \
  'apiVersion: kind.x-k8s.io/v1alpha4' \
  'containerdConfigPatches:' \
  '- |-' \
  '  [plugins."io.containerd.grpc.v1.cri".registry]' \
  '    config_path = "/etc/containerd/certs.d"' \
  >"$workspace/kind.yaml"
kind create cluster --name "$cluster" --kubeconfig "$kubeconfig" --config "$workspace/kind.yaml"

for node in $(kind get nodes --name "$cluster"); do
  registry_directory="/etc/containerd/certs.d/localhost:$registry_port"
  docker exec "$node" mkdir -p "$registry_directory"
  printf '[host."http://%s:5000"]\n' "$registry" | docker exec -i "$node" cp /dev/stdin "$registry_directory/hosts.toml"
done
docker network connect kind "$registry"
checks+=("dedicated kind cluster and registry")

architecture="$(docker info --format '{{.Architecture}}')"
case "$architecture" in
  amd64|x86_64) go_arch=amd64 ;;
  arm64|aarch64) go_arch=arm64 ;;
  *) echo "unsupported Docker architecture: $architecture" >&2; exit 1 ;;
esac
mkdir -p "$workspace/runtime-context"
CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" GOWORK=off \
  go build -trimpath -o "$workspace/runtime-context/runtime-linux-$go_arch" "$root/runtime"
cp "$root/Dockerfile.runtime" "$workspace/runtime-context/Dockerfile.runtime"
docker build --network=none --build-arg "TARGETARCH=$go_arch" \
  --file "$workspace/runtime-context/Dockerfile.runtime" --tag "$runtime_tag" "$workspace/runtime-context" >/dev/null
docker push "$runtime_tag" >/dev/null
runtime_reference="$(docker image inspect --format '{{index .RepoDigests 0}}' "$runtime_tag")"

docker tag "$oras_image" "$oras_tag"
docker push "$oras_tag" >/dev/null
oras_reference="$(docker image inspect --format '{{index .RepoDigests 0}}' "$oras_tag")"
checks+=("digest-pinned generic runtime and ORAS images")

publish_package() {
  local version="$1" output digest
  output="$workspace/package-$version"
  "$root/scripts/build-package.sh" "$version" "$output" >/dev/null
  oras cp --from-oci-layout --to-plain-http \
    "$output/oci-layout:$version" "localhost:$registry_port/native-probe:$version" >/dev/null
  digest="$(oras resolve --plain-http "localhost:$registry_port/native-probe:$version")"
  jq -r .manifestSHA256 "$output/release.json"
  printf '%s\n' "$digest"
}

package_v1="$(publish_package 1.0.0)"
package_v2="$(publish_package 1.1.0)"
manifest_v1="$(printf '%s\n' "$package_v1" | sed -n '1p')"; digest_v1="$(printf '%s\n' "$package_v1" | sed -n '2p')"
manifest_v2="$(printf '%s\n' "$package_v2" | sed -n '1p')"; digest_v2="$(printf '%s\n' "$package_v2" | sed -n '2p')"
checks+=("two independently packaged OCI versions")

registry_ip="$(docker inspect --format '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$registry")"
additional_egress="[{\"to\":[{\"ipBlock\":{\"cidr\":\"$registry_ip/32\"}}],\"ports\":[{\"protocol\":\"TCP\",\"port\":5000}]}]"

helm_apply() {
  local version="$1" digest="$2" manifest="$3"
  helm upgrade --install "$release" "$root/charts/native-plugin-runtime" \
    --kubeconfig "$kubeconfig" --kube-context "$context" \
    --namespace "$namespace" --create-namespace --wait --timeout 2m \
    --set enabled=true \
    --set-string trust.mode=development-untrusted \
    --set persistence.enabled=true \
    --set-string plugin.id=dev.stellwerk.native-probe \
    --set-string plugin.version="$version" \
    --set-string package.reference="$registry:5000/native-probe@$digest" \
    --set-string package.manifestSHA256="$manifest" \
    --set package.plainHTTP=true \
    --set-string images.runtime="$runtime_reference" \
    --set-string images.oras="$oras_reference" \
    --set-json networkPolicy.additionalEgress="$additional_egress" >/dev/null
}

helm_apply 1.0.0 "$digest_v1" "$manifest_v1"
kube --namespace "$namespace" rollout status deployment/native-probe-native-plugin-runtime --timeout=90s >/dev/null
runtime_before="$(kube --namespace "$namespace" get pod -l app.kubernetes.io/instance="$release" -o jsonpath='{.items[0].spec.containers[0].image}')"
checks+=("Helm install and ORAS init pull")

probe_port="$(random_port)"
kube --namespace "$namespace" port-forward service/native-probe-native-plugin-runtime "$probe_port:8080" >"$workspace/port-forward.log" 2>&1 &
port_forward_pid=$!
python3 - "$probe_port" 1.0.0 write <<'PY'
import json, sys, time, urllib.request
port, version, action = sys.argv[1:]
base = f"http://127.0.0.1:{port}"
for _ in range(100):
    try:
        with urllib.request.urlopen(base + "/health", timeout=1): break
    except OSError: time.sleep(.1)
else: raise SystemExit("plugin port-forward did not become ready")
if action == "write":
    with urllib.request.urlopen(urllib.request.Request(base + "/v1/note", data=b"persistent kind state", method="POST"), timeout=2): pass
with urllib.request.urlopen(base + "/v1/info", timeout=2) as response: info=json.load(response)
assert info["version"] == version, info
assert info["uid"] == 65532 and info["pid"] == 1, info
assert info["trust"] == "untrusted-development", info
assert info["note"] == "persistent kind state", info
PY
kill "$port_forward_pid" >/dev/null 2>&1 || true
wait "$port_forward_pid" 2>/dev/null || true
port_forward_pid=""
checks+=("non-root runtime and persistent probe state")

helm_apply 1.1.0 "$digest_v2" "$manifest_v2"
kube --namespace "$namespace" rollout status deployment/native-probe-native-plugin-runtime --timeout=90s >/dev/null
runtime_after="$(kube --namespace "$namespace" get pod -l app.kubernetes.io/instance="$release" -o jsonpath='{.items[0].spec.containers[0].image}')"
test "$runtime_before" = "$runtime_after"
checks+=("package upgrade with identical runtime image digest")

old_pod="$(kube --namespace "$namespace" get pod -l app.kubernetes.io/instance="$release" -o jsonpath='{.items[0].metadata.name}')"
kube --namespace "$namespace" delete pod "$old_pod" --wait=true >/dev/null
kube --namespace "$namespace" rollout status deployment/native-probe-native-plugin-runtime --timeout=90s >/dev/null
checks+=("pod crash/restart recovery")

helm rollback "$release" 1 --kubeconfig "$kubeconfig" --kube-context "$context" \
  --namespace "$namespace" --wait --timeout 2m >/dev/null
kube --namespace "$namespace" rollout status deployment/native-probe-native-plugin-runtime --timeout=90s >/dev/null
checks+=("explicit compatible package rollback")

probe_port="$(random_port)"
kube --namespace "$namespace" port-forward service/native-probe-native-plugin-runtime "$probe_port:8080" >"$workspace/port-forward.log" 2>&1 &
port_forward_pid=$!
python3 - "$probe_port" 1.0.0 read <<'PY'
import json, sys, time, urllib.request
port, version, _ = sys.argv[1:]
base = f"http://127.0.0.1:{port}"
for _ in range(100):
    try:
        with urllib.request.urlopen(base + "/v1/info", timeout=1) as response: info=json.load(response)
        break
    except OSError: time.sleep(.1)
else: raise SystemExit("rolled-back plugin did not become ready")
assert info["version"] == version and info["note"] == "persistent kind state", info
PY
checks+=("state retained across upgrade, restart and rollback")

jq -n \
  --arg status passed \
  --arg cluster "$cluster" \
  --arg runtimeImage "$runtime_before" \
  --arg trustState untrusted-development \
  --argjson checks "$(printf '%s\n' "${checks[@]}" | jq -R . | jq -s .)" \
  '{status:$status,scope:"disposable local kind cluster; probe smoke plugin only",cluster:$cluster,runtimeImage:$runtimeImage,trustState:$trustState,checks:$checks}'

echo "Kind native runtime lifecycle passed (explicitly untrusted development profile)."
