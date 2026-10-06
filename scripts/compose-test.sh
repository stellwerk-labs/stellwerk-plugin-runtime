#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
architecture="$(docker info --format '{{.Architecture}}')"
case "$architecture" in
  amd64|x86_64) go_arch=amd64 ;;
  arm64|aarch64) go_arch=arm64 ;;
  *) echo "unsupported Docker architecture: $architecture" >&2; exit 1 ;;
esac

workspace="$(mktemp -d "${TMPDIR:-/tmp}/native-plugin-compose.XXXXXX")"
run_id="$(python3 -c 'import secrets; print(secrets.token_hex(6))')"
project="native-plugin-$run_id"
image="stellwerk-native-plugin-runtime:$run_id"

cleanup() {
  NATIVE_PLUGIN_RUNTIME_IMAGE="$image" \
  NATIVE_PLUGIN_VERSION=1.0.0 \
  NATIVE_PLUGIN_MANIFEST_SHA256="${manifest_hash:-unset}" \
  NATIVE_PLUGIN_PACKAGE_DIR="$workspace/package" \
  NATIVE_PLUGIN_STATE_DIR="$workspace/state" \
    docker compose --project-name "$project" --file "$root/compose.yaml" down --volumes --remove-orphans >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf -- "$workspace"
}
trap cleanup EXIT

mkdir -p "$workspace/context" "$workspace/state"
chmod 0777 "$workspace" "$workspace/state"
"$root/scripts/build-fixture.sh" 1.0.0 "$workspace/package" >/dev/null
# Add a one-page UI so the same package also exercises serve-ui.
manifest_hash="$(python3 - "$workspace/package" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
index = b"<!doctype html><title>native probe</title>\n"
(root / "ui").mkdir()
(root / "ui/index.html").write_bytes(index)
catalogue = {
    "schema_version": "1", "plugin_id": "dev.stellwerk.native-probe", "version": "1.0.0",
    "ui": {"sdk_version": "1", "entrypoint": "/embed/", "runtime_config": "/embed/config.js"},
    "files": [{"path": "index.html", "sha256": hashlib.sha256(index).hexdigest(), "size": len(index)}],
}
encoded_catalogue = json.dumps(catalogue, sort_keys=True).encode()
(root / "ui/plugin-ui-manifest.json").write_bytes(encoded_catalogue)
manifest = json.loads((root / "plugin-manifest.json").read_text())
manifest["ui"] = {"path": "ui/plugin-ui-manifest.json", "sha256": hashlib.sha256(encoded_catalogue).hexdigest()}
encoded = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
(root / "plugin-manifest.json").write_bytes(encoded)
print(hashlib.sha256(encoded).hexdigest())
PY
)"
chmod -R a+rX,u+w "$workspace/package"
chmod 0777 "$workspace/package"
# The launcher executes a sealed in-memory copy, never the package file.
chmod a-x "$workspace/package/bin/linux/"*/plugin

CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" GOWORK=off \
  go build -trimpath -o "$workspace/context/runtime-linux-$go_arch" "$root/runtime"
cp "$root/Dockerfile.runtime" "$workspace/context/Dockerfile.runtime"
docker build --network=none --build-arg "TARGETARCH=$go_arch" \
  --file "$workspace/context/Dockerfile.runtime" --tag "$image" "$workspace/context" >/dev/null

export NATIVE_PLUGIN_RUNTIME_IMAGE="$image"
export NATIVE_PLUGIN_VERSION=1.0.0
export NATIVE_PLUGIN_MANIFEST_SHA256="$manifest_hash"
export NATIVE_PLUGIN_PACKAGE_DIR="$workspace/package"
export NATIVE_PLUGIN_STATE_DIR="$workspace/state"
docker compose --project-name "$project" --file "$root/compose.yaml" up --detach >/dev/null

address="$(docker compose --project-name "$project" --file "$root/compose.yaml" port plugin 8080)"
python3 - "$address" <<'PY'
import json
import sys
import time
import urllib.request

address = sys.argv[1]
base = "http://" + address
for _ in range(50):
    try:
        with urllib.request.urlopen(base + "/health", timeout=1):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("probe did not become ready")

request = urllib.request.Request(base + "/v1/note", data=b"retained fixture state", method="POST")
with urllib.request.urlopen(request, timeout=2):
    pass
with urllib.request.urlopen(base + "/v1/info", timeout=2) as response:
    info = json.load(response)
assert info["id"] == "dev.stellwerk.native-probe", info
assert info["version"] == "1.0.0", info
assert info["trust"] == "untrusted-development", info
assert info["uid"] == 65532 and info["pid"] == 1, info
assert info["ambientCanaryPresent"] is False, info
assert info["note"] == "retained fixture state", info
PY

ui_address="$(docker compose --project-name "$project" --file "$root/compose.yaml" port ui 8081)"
python3 - "$ui_address" <<'PY'
import sys
import time
import urllib.request

base = "http://" + sys.argv[1]
for _ in range(50):
    try:
        with urllib.request.urlopen(base + "/health", timeout=1):
            break
    except OSError:
        time.sleep(0.1)
else:
    raise SystemExit("UI server did not become ready")
request = urllib.request.Request(base + "/embed/", headers={"Host": "plugins.example.test"})
with urllib.request.urlopen(request, timeout=2) as response:
    body = response.read().decode()
    policy = response.headers["Content-Security-Policy"]
assert "native probe" in body, body
assert "frame-ancestors https://console.example.test" in policy, policy
assert "connect-src 'none'" in policy, policy
PY

# Both entrypoints run as their container's PID 1 and must exit 0 on SIGTERM.
docker compose --project-name "$project" --file "$root/compose.yaml" stop --timeout 5 plugin ui >/dev/null
for service in plugin ui; do
  exit_code="$(docker inspect --format '{{.State.ExitCode}}' "${project}-${service}-1")"
  if [ "$exit_code" != 0 ]; then
    echo "$service exited with $exit_code after SIGTERM" >&2
    exit 1
  fi
done
echo "Compose native runtime check passed (explicitly untrusted development profile)."
