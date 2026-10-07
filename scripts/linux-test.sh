#!/usr/bin/env bash
set -euo pipefail

# Run the runtime test suite on Linux inside a throwaway scratch container:
# non-root, read-only root, no network, no capabilities. /tmp, which holds
# every test package, is mounted noexec, so these tests also prove that no
# plugin is ever executed from the package filesystem. LINUX_TEST_PLATFORM
# selects the other architecture where the Docker host can emulate it.
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/images.sh"

platform="${LINUX_TEST_PLATFORM:-$(docker_platform)}"
case "$platform" in
  linux/amd64 | linux/arm64) ;;
  *) echo "LINUX_TEST_PLATFORM must be linux/amd64 or linux/arm64" >&2; exit 1 ;;
esac
workspace="$(mktemp -d "${TMPDIR:-/tmp}/runtime-linux-test.XXXXXX")"
image="stellwerk-plugin-runtime-test:$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
cleanup() {
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf -- "$workspace"
}
trap cleanup EXIT

CGO_ENABLED=0 GOOS=linux GOARCH="${platform#linux/}" GOWORK=off \
  go -C "$root" test -c -trimpath -o "$workspace/runtime.test" ./runtime
printf 'FROM scratch\nCOPY runtime.test /runtime.test\nENTRYPOINT ["/runtime.test"]\n' >"$workspace/Dockerfile"
timeout -k 5s 120s docker build --quiet --network=none --platform "$platform" --tag "$image" "$workspace" >/dev/null
# Under cross-architecture emulation (Rosetta or QEMU) a Go 1.25+ binary
# started from the sealed memfd dies in its container-aware GOMAXPROCS probe,
# while the same binary runs natively on both architectures. Skip only those
# exec tests when emulating; the native CI runner of each platform runs them.
emulation=()
if [ "$platform" != "$(docker_platform)" ]; then
  emulation=(-test.skip 'TestRunExecutesTheSealedVerifiedImage|TestSwapBetweenVerificationAndExecRunsOnlyVerifiedBytes|TestConcurrentSwapsNeverExecuteUnverifiedBytes')
  echo "emulated $platform: sealed-exec tests skipped; native CI runs them" >&2
fi
timeout -k 5s 240s docker run --rm --pull=never --platform "$platform" --network none \
  --user 65532:65532 --read-only --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 512m --tmpfs /tmp:rw,noexec,nosuid,size=256m,mode=1777 \
  "$image" "$@" "${emulation[@]}"
