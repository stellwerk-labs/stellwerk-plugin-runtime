# shellcheck shell=bash disable=SC2034
# Sourced by the test and signing scripts. Official multi-platform indexes
# (linux/amd64 and linux/arm64), pinned by digest.
oras_image=ghcr.io/oras-project/oras@sha256:f7bc056d54d97baa399414ed5048ecc67c3371b750d4bbce1d871827a5758179     # v1.3.4
cosign_image=ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8 # v3.1.3
registry_image=registry@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8                     # 3.1.2
# kind node image for kind v0.33. KIND_NODE_IMAGE overrides it for other kind versions.
kind_node_image=kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed # Kubernetes v1.36.4

# Release set attestations: Sigstore bundles attached as OCI referrers of the
# package manifest, following Cosign's bundle referrer convention.
sigstore_bundle_type=application/vnd.dev.sigstore.bundle.v0.3+json
sbom_predicate_type=https://spdx.dev/Document
provenance_predicate_type=https://stellwerk.dev/attestation/source-provenance/v1
# Cosign's predicate type for a message signature bundle kept as a referrer.
signature_predicate_type=https://sigstore.dev/cosign/sign/v1

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

# quiet hides a step's progress chatter but replays it when the step fails.
quiet() {
  local output
  if ! output="$("$@" 2>&1)"; then
    printf '%s\n' "$output" >&2
    return 1
  fi
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

# attach_bundle SUBJECT BUNDLE PREDICATE_TYPE [ORAS_FLAGS...] attaches a
# Sigstore bundle file as an OCI referrer of SUBJECT (an absolute layout path
# or a registry reference, with digest) and prints the referrer manifest
# digest. The layer is titled with the bundle's file name; the content
# annotation names what the bundle holds (message-signature or dsse-envelope).
attach_bundle() {
  local subject="$1" bundle="$2" predicate_type="$3" content
  shift 3
  content="$(jq -er 'if .messageSignature then "message-signature" elif .dsseEnvelope then "dsse-envelope"
    else error("not a Sigstore bundle") end' "$bundle")"
  (
    cd "$(dirname "$bundle")" || exit 1
    timeout -k 5s 60s oras attach "$@" --artifact-type "$sigstore_bundle_type" \
      --annotation "dev.sigstore.bundle.content=$content" \
      --annotation "dev.sigstore.bundle.predicateType=$predicate_type" --format json \
      "$subject" "$(basename "$bundle"):$sigstore_bundle_type" | jq -er '.digest | select(test("^sha256:[0-9a-f]{64}$"))'
  )
}

# sbom_fixture OUTPUT VERSION writes a minimal SPDX 2 document of the probe
# package. It stands in for the publisher's SBOM generator, which is outside
# this repository.
sbom_fixture() {
  jq -n --arg version "$2" --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '{
    spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
    name: ("native-probe-" + $version), documentNamespace: ("https://spdx.example.test/native-probe/" + $version),
    creationInfo: {created: $created, creators: ["Tool: native-probe test fixture"]},
    packages: [{SPDXID: "SPDXRef-Package", name: "native-probe", versionInfo: $version,
                downloadLocation: "NOASSERTION", filesAnalyzed: false}],
    relationships: [{spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: "SPDXRef-Package"}]}' >"$1"
}

# trust_bootstrap OUTPUT POLICY PUBLIC_KEY PLUGIN_ID writes an operator trust
# bootstrap that pins PUBLIC_KEY for PLUGIN_ID under POLICY, valid from one
# day ago to one day ahead.
trust_bootstrap() {
  python3 - "$@" <<'PY'
import base64, datetime, hashlib, json, sys
output, policy, public_key, plugin_id = sys.argv[1:]
pem = open(public_key, encoding="ascii").read()
body = "".join(line for line in pem.splitlines() if not line.startswith("-----"))
now = datetime.datetime.now(datetime.timezone.utc)
stamp = lambda moment: moment.strftime("%Y-%m-%dT%H:%M:%SZ")
key = {"keyId": base64.b64encode(hashlib.sha256(base64.b64decode(body)).digest()).decode(),
       "algorithm": "ecdsa-p256-sha256", "publicKey": pem,
       "validFrom": stamp(now - datetime.timedelta(days=1)), "validUntil": stamp(now + datetime.timedelta(days=1))}
with open(output, "w", encoding="utf-8") as file:
    json.dump({"schemaVersion": 1, "publishers": [{"id": "stellwerk", "policy": policy, "pluginIds": [plugin_id], "keys": [key]}]}, file)
PY
}

# airgap_import NETWORK REGISTRY/PREFIX BUNDLE VERIFIER OUT PIN [probe] runs
# import-offline-bundle.sh in the pinned ORAS image (busybox sh and ORAS
# only), attached to NETWORK alone, which should be an internal network whose
# only peer is the registry. VERIFIER is a Linux runtime binary for the Docker
# platform. With "probe" the container first proves that it reaches the
# registry and nothing else: no route to a public address, no public name.
airgap_import() {
  local network="$1" registry="$2" bundle="$3" verifier="$4" out="$5" pin="$6" probe="${7:-}"
  # shellcheck disable=SC2016 # the container's shell expands the script
  timeout -k 5s 120s docker run --rm --pull=never --network "$network" --read-only \
    --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
    --tmpfs /tmp:rw,nosuid,size=16m --env HOME=/tmp --env "REGISTRY_HOST=${registry%%/*}" --env "PROBE=$probe" \
    --mount "type=bind,src=$bundle,dst=/bundle,readonly" \
    --mount "type=bind,src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd),dst=/scripts,readonly" \
    --mount "type=bind,src=$(dirname "$verifier"),dst=/verifier,readonly" \
    --mount "type=bind,src=$out,dst=/out" \
    --entrypoint /bin/sh "$oras_image" -c '
      if [ -n "$PROBE" ]; then
        wget -q -T 5 -O /dev/null "http://$REGISTRY_HOST/v2/" ||
          { echo "the import container cannot reach $REGISTRY_HOST" >&2; exit 96; }
        for target in http://1.1.1.1/ https://ghcr.io/v2/ https://registry-1.docker.io/v2/; do
          if wget -q -T 5 -O /dev/null "$target" 2>/dev/null; then echo "the import container reached $target" >&2; exit 97; fi
        done
      fi
      exec /bin/sh /scripts/import-offline-bundle.sh "$@"' import-offline-bundle \
    /bundle "$registry" --trust-bootstrap-digest "$pin" --plain-http --verifier "/verifier/$(basename "$verifier")" --out /out
}
