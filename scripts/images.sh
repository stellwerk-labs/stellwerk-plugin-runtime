# shellcheck shell=bash disable=SC2034
# Sourced by the test and signing scripts. Official multi-platform indexes
# (linux/amd64 and linux/arm64), pinned by digest.
oras_image=ghcr.io/oras-project/oras@sha256:f7bc056d54d97baa399414ed5048ecc67c3371b750d4bbce1d871827a5758179     # v1.3.4
cosign_image=ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8 # v3.1.3
registry_image=registry@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8                     # 3.1.2
# kind node image for kind v0.33. KIND_NODE_IMAGE overrides it for other kind versions.
kind_node_image=kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed # Kubernetes v1.36.4

# docker_platform prints the daemon platform as linux/amd64 or linux/arm64.
docker_platform() {
  case "$(docker info --format '{{.OSType}}/{{.Architecture}}')" in
    linux/amd64 | linux/x86_64) echo linux/amd64 ;;
    linux/arm64 | linux/aarch64) echo linux/arm64 ;;
    *) echo "only linux/amd64 and linux/arm64 Docker daemons are supported" >&2; return 1 ;;
  esac
}

# require_image pulls a pinned image for the platform once. Containers that
# use it always run with --pull=never, so no later step reaches a registry.
require_image() {
  local image="$1" platform="$2"
  if [ "$(docker image inspect --platform "$platform" --format '{{.Os}}/{{.Architecture}}' "$image" 2>/dev/null || true)" != "$platform" ]; then
    timeout -k 5s 120s docker pull --quiet --platform "$platform" "$image" >/dev/null
  fi
  docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image" | grep -Fx "$image" >/dev/null
}

# offline_cosign runs the pinned Cosign image without any network. Extra
# docker arguments (mounts) precede "--"; Cosign arguments follow it. A key
# password is read from COSIGN_PASSWORD in the environment, never from argv.
offline_cosign() {
  local docker_args=()
  while [ "$#" -gt 0 ] && [ "$1" != -- ]; do
    docker_args+=("$1")
    shift
  done
  shift
  export COSIGN_PASSWORD="${COSIGN_PASSWORD:-}"
  timeout -k 5s 60s docker run --rm --pull=never --network none --read-only \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m --env HOME=/tmp --env COSIGN_PASSWORD \
    ${docker_args[@]+"${docker_args[@]}"} "$cosign_image" "$@"
}
