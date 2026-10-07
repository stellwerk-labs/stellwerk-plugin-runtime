#!/bin/sh
# import-offline-bundle.sh verifies an offline bundle completely offline and
# imports it into the customer's registry with every digest and referrer
# intact, then prints the chart values and Secrets the installation needs.
#
# The trust bootstrap digest reaches the operator out of band (with the
# licence, which is never part of the bundle). The runtime's verify-bundle
# checks the bundle against it before anything is pushed: the publisher pinned
# for the plugin must have signed bundle.json under managed-key-no-tlog, every
# component and blob must match bundle.json, the package's signature, SBOM and
# provenance must verify as one release set, every image must hold exactly
# linux/amd64 and linux/arm64, and nothing unrecorded may be present. Only
# then does ORAS copy each component, which the registry checks against its
# digest again; the import re-reads the registry to prove the result.
#
# POSIX sh: it also runs in the pinned ORAS image (busybox), which is how
# offline-bundle-test.sh runs it without any network but the registry's.
set -eu

usage='usage: import-offline-bundle.sh BUNDLE_DIRECTORY REGISTRY[/PATH] --trust-bootstrap-digest sha256:HEX --out DIRECTORY
       [--plain-http] [--registry-config FILE] [--ca-file FILE] [--verifier RUNTIME_BINARY]'
bundle="" registry="" trust_digest="" out="" verifier="" plain_http="" registry_config="" ca_file=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --plain-http) plain_http=true; shift ;;
    --trust-bootstrap-digest | --out | --verifier | --registry-config | --ca-file)
      [ "$#" -ge 2 ] || { echo "$usage" >&2; exit 2; }
      case "$1" in
        --trust-bootstrap-digest) trust_digest="$2" ;;
        --out) out="$2" ;;
        --verifier) verifier="$2" ;;
        --registry-config) registry_config="$2" ;;
        --ca-file) ca_file="$2" ;;
      esac
      shift 2
      ;;
    -*) echo "$usage" >&2; exit 2 ;;
    *)
      if [ -z "$bundle" ]; then bundle="$1"
      elif [ -z "$registry" ]; then registry="$1"
      else echo "$usage" >&2; exit 2
      fi
      shift
      ;;
  esac
done
for value in "$bundle" "$registry" "$trust_digest" "$out"; do
  [ -n "$value" ] || { echo "$usage" >&2; exit 2; }
done
case "$bundle" in
  *:* | *@*) echo "the bundle path must not contain ':' or '@' (ORAS reads them as a reference)" >&2; exit 2 ;;
esac
command -v oras >/dev/null || { echo "oras is required" >&2; exit 1; }
mkdir -p "$out"

workspace=""
trap '[ -z "$workspace" ] || rm -rf -- "$workspace"' EXIT
if [ -z "$verifier" ]; then
  # Without a verifier, build the runtime from this checkout: the bundle's
  # own runtime image is what is being verified, so it cannot verify itself.
  command -v go >/dev/null || { echo "go is required, or pass --verifier with a trusted runtime binary" >&2; exit 1; }
  workspace="$(mktemp -d "${TMPDIR:-/tmp}/import-offline-bundle.XXXXXX")"
  root="$(cd "$(dirname "$0")/.." && pwd)"
  (cd "$root" && CGO_ENABLED=0 GOWORK=off go build -trimpath -o "$workspace/runtime" ./runtime)
  verifier="$workspace/runtime"
fi

"$verifier" verify-bundle --bundle "$bundle" --trust-bootstrap-digest "$trust_digest" \
  --registry "$registry" ${plain_http:+--plain-http} --out "$out"

# remote ORAS_COMMAND... runs ORAS against the customer registry.
remote() {
  oras "$@" ${plain_http:+--plain-http} ${registry_config:+--registry-config "$registry_config"} \
    ${ca_file:+--ca-file "$ca_file"}
}

# Push each component under its bundle tag, refusing to move a tag that
# already names another digest.
while read -r kind repository digest tag; do
  [ "$kind" = copy ] || continue
  if current="$(remote resolve "$repository:$tag" 2>/dev/null </dev/null)" && [ "$current" != "$digest" ]; then
    echo "$repository:$tag already names $current; refusing to move it to $digest" >&2
    exit 1
  fi
  oras cp --no-tty -r --from-oci-layout "$bundle/oci@$digest" "$repository:$tag" \
    ${plain_http:+--to-plain-http} ${registry_config:+--to-registry-config "$registry_config"} \
    ${ca_file:+--to-ca-file "$ca_file"} >/dev/null </dev/null
done <"$out/plan"

# Prove the registry now serves exactly the bundle: each tag names the
# component's digest, every platform manifest resolves by digest and the
# package has exactly its recorded referrers.
while read -r kind repository digest rest; do
  case "$kind" in
    copy) actual="$(remote resolve "$repository:$rest" </dev/null)" ;;
    manifest) actual="$(remote resolve "$repository@$digest" </dev/null)" ;;
    referrers)
      actual="$(remote discover --format go-template='{{range .referrers}}{{println .digest}}{{end}}' \
        "$repository@$digest" </dev/null | sort | tr '\n' ',' | sed 's/,$//')"
      digest="$rest"
      ;;
    *) echo "unknown import plan entry $kind" >&2; exit 1 ;;
  esac
  if [ "$actual" != "$digest" ]; then
    echo "the registry does not serve $repository as imported: $kind expected $digest, found $actual" >&2
    exit 1
  fi
done <"$out/plan"

cat "$out/instructions.txt"
