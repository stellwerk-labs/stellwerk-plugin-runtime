#!/usr/bin/env bash
set -euo pipefail

# kind-test.sh [development|production] runs one scenario on its own throwaway
# kind cluster; without an argument it runs both in turn.
#
#   development  untrusted development profile, one replica: install, package
#                upgrade, sealed memfd, NetworkPolicy, restart, rollback and
#                persistent state
#   production   the production trust path: packages signed under
#                managed-key-no-tlog with SBOM and provenance referrers,
#                verified by the chart's init chain from the operator's Secrets;
#                two replicas behind a PodDisruptionBudget; installer phases
#                with an expand-only and an incompatible migration; a rolling
#                upgrade that keeps a replica available
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scenario="${1:-all}"
case "$scenario" in
  all)
    "$root/scripts/kind-test.sh" development
    exec "$root/scripts/kind-test.sh" production
    ;;
  development | production) ;;
  *) echo "usage: kind-test.sh [development|production]" >&2; exit 2 ;;
esac

source "$root/scripts/images.sh"
run_id="$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
cluster="swnative-$run_id"
context="kind-$cluster"
registry="swnative-registry-$run_id"
namespace="native-plugin-test"
release="native-probe"
deployment="native-probe-native-plugin-runtime"
runtime_selector="app.kubernetes.io/instance=$release,app.kubernetes.io/component=runtime"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/native-plugin-kind.XXXXXX")"
kubeconfig="$workspace/kubeconfig"
registry_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
runtime_tag="localhost:$registry_port/native-runtime:$run_id"
oras_tag="localhost:$registry_port/oras:$run_id"
cosign_tag=""
port_forward_pid=""
monitor_pid=""
runtime_reference=""
oras_reference=""
checks=()

# On failure, show what the test namespace looked like before the cluster
# goes away. Every call is time-boxed and its output bounded.
diagnostics() {
  echo "kind test ($scenario) failed; diagnostics for namespace $namespace:" >&2
  local step
  for step in "get pods -o wide" "describe pods" "get events --sort-by=.lastTimestamp" \
    "logs --all-containers --prefix --tail=200 -l app.kubernetes.io/instance=$release"; do
    echo "--- kubectl $step" >&2
    # shellcheck disable=SC2086 # each step is a fixed kubectl argument list
    timeout -k 5s 30s kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" $step 2>&1 | head -n 300 >&2 || true
  done
  # A failed init container stops the logs above at the next waiting one.
  local pod container previous
  timeout -k 5s 30s kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" get pods -o json 2>/dev/null |
    jq -r '.items[] | .metadata.name as $pod | .status.initContainerStatuses[]?
      | if (.state.terminated.exitCode // 0) != 0 then "\($pod) \(.name) --previous=false"
        elif (.lastState.terminated.exitCode // 0) != 0 then "\($pod) \(.name) --previous=true" else empty end' |
    while read -r pod container previous; do
      echo "--- failed init container $pod/$container" >&2
      timeout -k 5s 30s kubectl --kubeconfig "$kubeconfig" --context "$context" --namespace "$namespace" \
        logs "$pod" -c "$container" "$previous" --tail=50 2>&1 | head -n 50 >&2 || true
    done
}

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ] && [ -s "$kubeconfig" ]; then diagnostics; fi
  if [ -n "$port_forward_pid" ]; then kill "$port_forward_pid" >/dev/null 2>&1 || true; fi
  if [ -n "$monitor_pid" ]; then kill "$monitor_pid" >/dev/null 2>&1 || true; fi
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  docker rm -f "$registry" >/dev/null 2>&1 || true
  for tag in "$runtime_tag" "$oras_tag" "$cosign_tag"; do
    if [ -n "$tag" ]; then docker image rm "$tag" >/dev/null 2>&1 || true; fi
  done
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
kind create cluster --name "$cluster" --kubeconfig "$kubeconfig" --config "$workspace/kind.yaml" \
  --image "${KIND_NODE_IMAGE:-$kind_node_image}"

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
quiet docker build --network=none --build-arg "TARGETARCH=$go_arch" \
  --file "$workspace/runtime-context/Dockerfile.runtime" --tag "$runtime_tag" "$workspace/runtime-context"
docker push "$runtime_tag" >/dev/null
runtime_reference="$(docker image inspect --format '{{index .RepoDigests 0}}' "$runtime_tag")"

docker tag "$oras_image" "$oras_tag"
docker push "$oras_tag" >/dev/null
oras_reference="$(docker image inspect --format '{{index .RepoDigests 0}}' "$oras_tag")"
checks+=("digest-pinned generic runtime and ORAS images")

# publish_package VERSION [PRIVATE_KEY] builds the probe package into
# $workspace/package-VERSION, signs it and attaches signed SBOM and provenance
# referrers when a key is given, and pushes it with its referrers.
publish_package() {
  local version="$1" key="${2:-}" output="$workspace/package-$1"
  "$root/scripts/build-package.sh" "$version" "$output" >/dev/null
  if [ -n "$key" ]; then
    COSIGN_PASSWORD='' quiet "$root/scripts/sign-layout-manifest.sh" "$output" "$key"
    sbom_fixture "$workspace/sbom-$version.spdx.json" "$version"
    COSIGN_PASSWORD='' quiet "$root/scripts/attest-layout-manifest.sh" "$output" "$key" "$workspace/sbom-$version.spdx.json"
  fi
  oras cp -r --from-oci-layout --to-plain-http \
    "$output/oci-layout:$version" "localhost:$registry_port/native-probe:$version" >/dev/null
  test "$(oras resolve --plain-http "localhost:$registry_port/native-probe:$version")" = "$(package_field "$version" .packageDigest)"
}
# package_field VERSION FILTER reads the release record of a published package.
package_field() { jq -er "$2" "$workspace/package-$1/release.json"; }

registry_ip="$(docker inspect --format '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$registry")"
registry_mirrors="[{\"cidr\":\"$registry_ip/32\",\"port\":5000}]"

development_scenario() {
  publish_package 1.0.0
  publish_package 1.1.0
  checks+=("two independently packaged OCI versions")

  helm_apply() {
    local version="$1"
    helm upgrade --install "$release" "$root/charts/native-plugin-runtime" \
      --kubeconfig "$kubeconfig" --kube-context "$context" \
      --namespace "$namespace" --create-namespace --wait --timeout 2m \
      --set enabled=true \
      --set-string trust.mode=development-untrusted \
      --set persistence.enabled=true \
      --set-string plugin.id=dev.stellwerk.native-probe \
      --set-string plugin.version="$version" \
      --set-string package.reference="$registry:5000/native-probe@$(package_field "$version" .packageDigest)" \
      --set-string package.manifestSHA256="$(package_field "$version" .manifestSHA256)" \
      --set package.plainHTTP=true \
      --set-string images.runtime="$runtime_reference" \
      --set-string images.oras="$oras_reference" \
      --set-json networkPolicy.registryMirrors="$registry_mirrors" >/dev/null
  }

  helm_apply 1.0.0
  kube --namespace "$namespace" rollout status "deployment/$deployment" --timeout=90s >/dev/null
  runtime_before="$(kube --namespace "$namespace" get pod -l "$runtime_selector" -o jsonpath='{.items[0].spec.containers[0].image}')"
  checks+=("Helm install, init-container package fetch and mirror-only registry egress")

  probe_port="$(random_port)"
  kube --namespace "$namespace" port-forward "service/$deployment" "$probe_port:8080" >"$workspace/port-forward.log" 2>&1 &
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

  # Sealed execution in a real node: the probe process runs from the memfd.
  node="$(kind get nodes --name "$cluster" | head -n 1)"
  memfd_noexec="$(docker exec "$node" cat /proc/sys/vm/memfd_noexec)"
  plugin_executable="$(docker exec "$node" sh -c 'for process in /proc/[0-9]*; do readlink "$process/exe"; done 2>/dev/null' |
    grep -m 1 -F '/memfd:stellwerk-plugin' || true)"
  if [ -z "$plugin_executable" ]; then
    echo "no plugin process runs from the sealed memfd on $node" >&2
    exit 1
  fi
  checks+=("plugin runs from the sealed memfd (vm.memfd_noexec=$memfd_noexec)")

  # NetworkPolicy enforcement: the same client is refused from an arbitrary
  # namespace and admitted as the configured control plane peer.
  netcheck() {
    local name="$1" client_namespace="$2" labels="$3" phase
    kube --namespace "$client_namespace" run "$name" --image="$registry_image" --restart=Never --labels="$labels" \
      --command -- sh -c "wget -q -T 5 -O /dev/null http://$deployment.$namespace:8080/health" >/dev/null
    for _ in {1..60}; do
      phase="$(kube --namespace "$client_namespace" get pod "$name" -o jsonpath='{.status.phase}')"
      case "$phase" in Succeeded | Failed) break ;; esac
      sleep 1
    done
    echo "$phase"
  }
  kube create namespace platform-orchestrator >/dev/null
  denied="$(netcheck netcheck-other "$namespace" app=netcheck)"
  admitted="$(netcheck netcheck-core platform-orchestrator \
    app.kubernetes.io/name=control-plane,app.kubernetes.io/instance=platform-orchestrator)"
  if [ "$denied" != Failed ] || [ "$admitted" != Succeeded ]; then
    echo "NetworkPolicy not enforced as specified: other=$denied, control plane=$admitted" >&2
    exit 1
  fi
  checks+=("NetworkPolicy enforced: arbitrary client refused, control plane peer admitted")

  helm_apply 1.1.0
  kube --namespace "$namespace" rollout status "deployment/$deployment" --timeout=90s >/dev/null
  runtime_after="$(kube --namespace "$namespace" get pod -l "$runtime_selector" -o jsonpath='{.items[0].spec.containers[0].image}')"
  test "$runtime_before" = "$runtime_after"
  checks+=("package upgrade with identical runtime image digest")

  old_pod="$(kube --namespace "$namespace" get pod -l "$runtime_selector" -o jsonpath='{.items[0].metadata.name}')"
  kube --namespace "$namespace" delete pod "$old_pod" --wait=true >/dev/null
  kube --namespace "$namespace" rollout status "deployment/$deployment" --timeout=90s >/dev/null
  checks+=("pod crash/restart recovery")

  helm rollback "$release" 1 --kubeconfig "$kubeconfig" --kube-context "$context" \
    --namespace "$namespace" --wait --timeout 2m >/dev/null
  kube --namespace "$namespace" rollout status "deployment/$deployment" --timeout=90s >/dev/null
  checks+=("explicit compatible package rollback")

  probe_port="$(random_port)"
  kube --namespace "$namespace" port-forward "service/$deployment" "$probe_port:8080" >"$workspace/port-forward.log" 2>&1 &
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
    --arg memfdNoexec "$memfd_noexec" \
    --arg pluginExecutable "$plugin_executable" \
    --arg runtimeImage "$runtime_before" \
    --arg trustState untrusted-development \
    --argjson checks "$(printf '%s\n' "${checks[@]}" | jq -R . | jq -s .)" \
    '{status:$status,scenario:"development",scope:"disposable local kind cluster; probe smoke plugin only",cluster:$cluster,memfdNoexec:$memfdNoexec,pluginExecutable:$pluginExecutable,runtimeImage:$runtimeImage,trustState:$trustState,checks:$checks}'

  echo "Kind native runtime lifecycle passed (explicitly untrusted development profile)."
}

production_scenario() {
  require_image "$cosign_image" "$(docker_platform)"
  cosign_tag="localhost:$registry_port/cosign:$run_id"
  docker tag "$cosign_image" "$cosign_tag"
  docker push "$cosign_tag" >/dev/null
  local cosign_reference
  cosign_reference="$(docker image inspect --format '{{index .RepoDigests 0}}' "$cosign_tag")"

  mkdir -m 0700 "$workspace/key"
  COSIGN_PASSWORD='' quiet offline_cosign --mount "type=bind,src=$workspace/key,dst=/keys" --workdir /keys \
    -- generate-key-pair
  local version
  for version in 1.0.0 1.1.0 1.2.0; do
    publish_package "$version" "$workspace/key/cosign.key"
  done
  checks+=("three packages signed under managed-key-no-tlog with SBOM and provenance referrers")

  # The operator's Secrets: the trust bootstrap pinning the publisher key, the
  # detached signature bundle of each package, and the migration profile and
  # credential. Kubelet exposes every Secret key as a symlink; the chart must
  # hand the runtime plain files.
  kube create namespace "$namespace" >/dev/null
  trust_bootstrap "$workspace/publishers.json" managed-key-no-tlog "$workspace/key/cosign.pub" dev.stellwerk.native-probe
  kube --namespace "$namespace" create secret generic plugin-trust \
    --from-file=publishers.json="$workspace/publishers.json" >/dev/null
  for version in 1.0.0 1.1.0 1.2.0; do
    kube --namespace "$namespace" create secret generic "signature-$version" \
      --from-file=oci-manifest.sigstore.json="$workspace/package-$version/oci-manifest.sigstore.json" >/dev/null
  done
  printf '{"mode":"native-migrate"}\n' >"$workspace/profile.json"
  kube --namespace "$namespace" create secret generic migration-profile \
    --from-file=profile.json="$workspace/profile.json" >/dev/null
  kube --namespace "$namespace" create secret generic migration-database \
    --from-literal=database-url=postgres://migration@database.invalid/plugin >/dev/null

  # production_apply VERSION [HELM_ARGS...] applies the chart with two
  # replicas under managed-key-no-tlog for a published package.
  production_apply() {
    local version="$1"
    shift
    helm upgrade --install "$release" "$root/charts/native-plugin-runtime" \
      --kubeconfig "$kubeconfig" --kube-context "$context" \
      --namespace "$namespace" --wait --timeout 3m \
      --set enabled=true \
      --set replicaCount=2 \
      --set-string trust.mode=managed-key-no-tlog \
      --set-string trust.bootstrapSecret.name=plugin-trust \
      --set-string trust.signatureBundleSecret.name="signature-$version" \
      --set-string plugin.id=dev.stellwerk.native-probe \
      --set-string plugin.version="$version" \
      --set-string package.reference="$registry:5000/native-probe@$(package_field "$version" .packageDigest)" \
      --set-string package.manifestSHA256="$(package_field "$version" .manifestSHA256)" \
      --set-string package.attestations.sbom="$(package_field "$version" .attestations.sbom.digest)" \
      --set-string package.attestations.provenance="$(package_field "$version" .attestations.provenance.digest)" \
      --set package.plainHTTP=true \
      --set-string images.runtime="$runtime_reference" \
      --set-string images.oras="$oras_reference" \
      --set-string images.cosign="$cosign_reference" \
      --set-string migration.profileSecret.name=migration-profile \
      --set-string migration.databaseSecret.name=migration-database \
      --set-json networkPolicy.registryMirrors="$registry_mirrors" \
      "$@" >/dev/null
  }

  # migrate VERSION [HELM_ARGS...] runs the migration phase for VERSION and
  # waits for its Job, which verifies and runs the same signed package.
  migrate() {
    local version="$1"
    production_apply "$@" --set migration.enabled=true
    kube --namespace "$namespace" wait --for=condition=complete "job/$deployment-migration" --timeout=120s >/dev/null
    kube --namespace "$namespace" logs "job/$deployment-migration" -c migrate | grep -Fqx "migrated to $version" ||
      { echo "the migration Job did not run package $version" >&2; exit 1; }
  }

  # runtime_pods prints the names of the runtime Pods that are not terminating.
  runtime_pods() {
    kube --namespace "$namespace" get pods -l "$runtime_selector" -o json |
      jq -r '.items[] | select(.metadata.deletionTimestamp == null) | .metadata.name'
  }

  # pod_info POD prints the probe's /v1/info of one Pod.
  pod_info() {
    local port
    port="$(random_port)"
    kube --namespace "$namespace" port-forward "pod/$1" "$port:8080" >"$workspace/port-forward.log" 2>&1 &
    port_forward_pid=$!
    python3 - "$port" <<'PY'
import sys, time, urllib.request
base = f"http://127.0.0.1:{sys.argv[1]}"
for _ in range(100):
    try:
        with urllib.request.urlopen(base + "/v1/info", timeout=1) as response:
            sys.stdout.write(response.read().decode())
            break
    except OSError: time.sleep(.1)
else: raise SystemExit("plugin port-forward did not become ready")
PY
    kill "$port_forward_pid" >/dev/null 2>&1 || true
    wait "$port_forward_pid" 2>/dev/null || true
    port_forward_pid=""
  }

  # expect_runtime VERSION: exactly two ready runtime Pods serve VERSION under
  # verified trust, each after its complete init chain succeeded.
  expect_runtime() {
    local version="$1" pod
    kube --namespace "$namespace" get pods -l "$runtime_selector" -o json | jq -e '
      [.items[] | select(.metadata.deletionTimestamp == null)] as $pods
      | ($pods | length) == 2
        and all($pods[];
          any(.status.conditions[]?; .type == "Ready" and .status == "True")
          and ([.status.initContainerStatuses[] | select(.state.terminated.exitCode == 0) | .name]
               == ["fetch-package-envelope", "verify-package-envelope", "fetch-package-sbom", "fetch-package-provenance",
                   "verify-package-publisher", "verify-package-signature", "verify-package-sbom",
                   "verify-package-provenance", "pull-package", "validate-package"]))' >/dev/null ||
      { echo "expected two ready runtime Pods with a completed verification chain" >&2; exit 1; }
    for pod in $(runtime_pods); do
      pod_info "$pod" | jq -e --arg version "$version" \
        '.version == $version and .trust == "verified-local-key" and .uid == 65532 and .pid == 1' >/dev/null ||
        { echo "$pod does not serve $version under verified trust" >&2; exit 1; }
    done
  }

  # Fresh installation: the migration phase creates the paused runtime without
  # Pods, then the runtime phase starts both replicas.
  migrate 1.0.0
  test "$(kube --namespace "$namespace" get pods -l "$runtime_selector" -o name | wc -l | tr -d ' ')" = 0
  production_apply 1.0.0
  kube --namespace "$namespace" rollout status "deployment/$deployment" --timeout=120s >/dev/null
  expect_runtime 1.0.0
  checks+=("managed-key-no-tlog through the chart: trust bootstrap and signature bundle from Secrets, SBOM and provenance verified")
  checks+=("fresh installation: migration Job before any runtime Pod, then two ready replicas")

  # The budget admits evicting one replica and refuses the second while the
  # replacement is not ready yet.
  local pods
  mapfile -t pods < <(runtime_pods)
  evict() {
    printf '{"apiVersion":"policy/v1","kind":"Eviction","metadata":{"name":"%s","namespace":"%s"}}' "$1" "$namespace" |
      kube create --raw "/api/v1/namespaces/$namespace/pods/$1/eviction" -f - >/dev/null 2>&1
  }
  evict "${pods[0]}" || { echo "PodDisruptionBudget refused evicting one of two ready replicas" >&2; exit 1; }
  if evict "${pods[1]}"; then
    echo "PodDisruptionBudget allowed evicting the last available replica" >&2
    exit 1
  fi
  kube --namespace "$namespace" rollout status "deployment/$deployment" --timeout=120s >/dev/null
  expect_runtime 1.0.0
  checks+=("PodDisruptionBudget: one eviction admitted, the last available replica protected")

  # Expand-only upgrade: during the migration phase the previous replicas keep
  # serving and no ReplicaSet exists for the new package.
  mapfile -t pods < <(runtime_pods)
  migrate 1.1.0
  kube --namespace "$namespace" get deployment "$deployment" -o json |
    jq -e '.spec.paused == true and .spec.replicas == 2' >/dev/null
  test "$(kube --namespace "$namespace" get replicasets -l "$runtime_selector" -o name | wc -l | tr -d ' ')" = 1
  test "$(runtime_pods | sort)" = "$(printf '%s\n' "${pods[@]}" | sort)"
  expect_runtime 1.0.0
  checks+=("expand-only migration phase: previous replicas keep serving, no Pod runs the new package")

  # Rolling upgrade: sample the ready, non-terminating replicas throughout.
  sample_ready() {
    while :; do
      kube --namespace "$namespace" get pods -l "$runtime_selector" -o json 2>/dev/null |
        jq '[.items[] | select(.metadata.deletionTimestamp == null)
             | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length'
      sleep 0.2
    done
  }
  sample_ready >"$workspace/ready-samples" &
  monitor_pid=$!
  production_apply 1.1.0
  kube --namespace "$namespace" rollout status "deployment/$deployment" --timeout=180s >/dev/null
  kill "$monitor_pid" >/dev/null 2>&1 || true
  wait "$monitor_pid" 2>/dev/null || true
  monitor_pid=""
  local samples minimum
  samples="$(grep -c . "$workspace/ready-samples")"
  minimum="$(sort -n "$workspace/ready-samples" | head -n 1)"
  if [ "$samples" -lt 20 ] || [ "$minimum" -lt 1 ]; then
    echo "rolling upgrade availability: $samples samples, minimum $minimum ready replicas" >&2
    exit 1
  fi
  if [ -n "$(comm -12 <(runtime_pods | sort) <(printf '%s\n' "${pods[@]}" | sort))" ]; then
    echo "the rolling upgrade kept a replica of the previous package" >&2
    exit 1
  fi
  expect_runtime 1.1.0
  checks+=("rolling upgrade: minimum $minimum of 2 replicas ready over $samples samples")

  # Incompatible upgrade: the runtime is at zero while the Job migrates, then
  # scales back up with the new package.
  migrate 1.2.0 --set-string migration.compatibility=incompatible
  kube --namespace "$namespace" wait --for=delete pod -l "$runtime_selector" --timeout=60s >/dev/null 2>&1 || true
  test -z "$(kube --namespace "$namespace" get pods -l "$runtime_selector" -o name)"
  kube --namespace "$namespace" get deployment "$deployment" -o json |
    jq -e '.spec.paused == true and .spec.replicas == 0' >/dev/null
  production_apply 1.2.0
  kube --namespace "$namespace" rollout status "deployment/$deployment" --timeout=120s >/dev/null
  expect_runtime 1.2.0
  checks+=("incompatible migration phase: runtime scaled to zero, migrated, scaled back up")

  jq -n \
    --arg status passed \
    --arg cluster "$cluster" \
    --arg trustState verified-local-key \
    --argjson checks "$(printf '%s\n' "${checks[@]}" | jq -R . | jq -s .)" \
    '{status:$status,scenario:"production",scope:"disposable local kind cluster; probe smoke plugin only",cluster:$cluster,trustState:$trustState,checks:$checks}'

  echo "Kind native runtime production path passed (managed-key-no-tlog, two replicas)."
}

"${scenario}_scenario"
