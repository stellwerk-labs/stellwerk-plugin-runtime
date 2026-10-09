#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/release-tools.sh"
directory="${1:?usage: scan-release-content.sh DIRECTORY [FORBIDDEN_LITERAL ...]}"
shift
test "$(gitleaks version)" = "$gitleaks_version" || { echo "incorrect gitleaks version" >&2; exit 1; }
workspace="$(mktemp -d "${TMPDIR:-/tmp}/runtime-scan.XXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT
# Compressed archives are shipping content, not opaque binary blobs. Extract
# only bounded regular members, never links/devices/traversal or unbounded bombs.
if ! python3 "$root/scripts/release_content.py" unpack "$directory" "$workspace/archives" >/dev/null 2>&1; then
  echo "archive inspection failed (unsafe content or scan limit)" >&2
  exit 1
fi
scan_tree() {
  local tree="$1"
  # Avoid logging finding values, even on scanner failure. No findings report is
  # uploaded. The exact test-only allowlist is source-specific, not artifact-wide.
  if ! (cd "$tree" && gitleaks dir --redact --no-banner --log-level error --config "$root/scripts/gitleaks.toml" . >/dev/null 2>&1); then
    echo "secret scan failed (finding or scanner error); inspect locally with redaction" >&2
    exit 1
  fi
  # Gitleaks intentionally skips binary files. Inspect their printable strings
  # and shipping paths without writing credentials into logs or reports.
  if ! python3 "$root/scripts/release_content.py" strings "$tree" |
    gitleaks stdin --redact --no-banner --log-level error --config "$root/scripts/gitleaks.toml" >/dev/null 2>&1; then
    echo "binary/path secret scan failed (finding or scanner error)" >&2
    exit 1
  fi
  python3 "$root/scripts/release_content.py" scan "$tree" "${forbidden[@]}"
}
forbidden=("$@")
scan_tree "$directory"
scan_tree "$workspace/archives"
