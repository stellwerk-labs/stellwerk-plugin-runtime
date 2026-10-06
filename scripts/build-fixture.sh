#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:?usage: build-fixture.sh VERSION OUTPUT_DIRECTORY}"
output="${2:?usage: build-fixture.sh VERSION OUTPUT_DIRECTORY}"

semver_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if [[ ! "$version" =~ $semver_pattern ]]; then
  echo "version must be canonical SemVer" >&2
  exit 1
fi

mkdir -p "$output/bin/linux/amd64" "$output/bin/linux/arm64"
for architecture in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" GOWORK=off \
    go build -trimpath -ldflags "-s -w -X main.version=$version" \
    -o "$output/bin/linux/$architecture/plugin" "$root/probe"
done

python3 - "$version" "$output" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

version, output = sys.argv[1], Path(sys.argv[2])
executables = {}
for architecture in ("amd64", "arm64"):
    relative = f"bin/linux/{architecture}/plugin"
    executables[f"linux/{architecture}"] = {
        "path": relative,
        "sha256": hashlib.sha256((output / relative).read_bytes()).hexdigest(),
    }
manifest = {
    "executables": executables,
    "pluginId": "dev.stellwerk.native-probe",
    "pluginVersion": version,
    "protocolVersion": 1,
    "runtimeProfile": "native-static-v1",
    "schemaVersion": 1,
}
encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
(output / "plugin-manifest.json").write_text(encoded)
print(hashlib.sha256(encoded.encode()).hexdigest())
PY
