#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/release-tools.sh"
directory="${1:?usage: scan-release-content.sh DIRECTORY [FORBIDDEN_LITERAL ...]}"
shift
test "$(gitleaks version)" = "$gitleaks_version" || { echo "incorrect gitleaks version" >&2; exit 1; }
# Avoid logging finding values, even on scanner failure. No findings report is
# uploaded. The exact test-only allowlist is source-specific, not artifact-wide.
if ! (cd "$directory" && gitleaks dir --redact --no-banner --log-level error --config "$root/scripts/gitleaks.toml" . >/dev/null 2>&1); then
  echo "secret scan failed (finding or scanner error); inspect locally with redaction" >&2
  exit 1
fi
# Gitleaks intentionally skips binary files. Inspect their printable strings as
# a second stream, without writing extracted credentials into logs or reports.
if ! python3 "$root/scripts/release_content.py" strings "$directory" |
  gitleaks stdin --redact --no-banner --log-level error --config "$root/scripts/gitleaks.toml" >/dev/null 2>&1; then
  echo "binary secret scan failed (finding or scanner error)" >&2
  exit 1
fi
python3 "$root/scripts/release_content.py" scan "$directory" "$@"
