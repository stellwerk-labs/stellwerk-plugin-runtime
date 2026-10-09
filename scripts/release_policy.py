#!/usr/bin/env python3
"""Fail-closed public release policy and producer provenance, without writes."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


REPOSITORY = "stellwerk-labs/stellwerk-plugin-runtime"
ENVIRONMENT = "runtime-release"
IMAGE = "stellwerk-labs/stellwerk-plugin-runtime"
CHART = "stellwerk-labs/charts/native-plugin-runtime"


def inputs(env):
    if (env.get("GITHUB_REPOSITORY") != REPOSITORY or env.get("GITHUB_REF") != "refs/heads/main"
            or env.get("RUNTIME_PUBLIC_RELEASES_ENABLED") != "true"
            or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"):
        raise ValueError("public release is dormant outside its explicitly enabled public main workflow")
    source = env.get("RELEASE_SOURCE_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", source) or source != env.get("GITHUB_SHA"):
        raise ValueError("dispatch and source SHA must be the same immutable commit")
    if not re.fullmatch(r"[0-9a-f]{40}", env.get("RELEASE_TAG_OBJECT_SHA", "")):
        raise ValueError("dispatch must bind an annotated signed tag object")
    if not env.get("RELEASE_FORBIDDEN_LITERAL", "").strip():
        raise ValueError("the private-reference scan literal must be configured as a repository secret")
    if not re.fullmatch(r"0\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?", env.get("RELEASE_VERSION", "")):
        raise ValueError("invalid release version")
    notes = env.get("RELEASE_NOTES", "")
    if not notes.strip() or hashlib.sha256(notes.encode()).hexdigest() != env.get("RELEASE_NOTES_SHA256"):
        raise ValueError("reviewed release notes do not match their immutable checksum")


def identities(env, repository, environment, ref, tag, commit):
    inputs(env)
    if repository.get("full_name") != REPOSITORY or repository.get("private") is not False or repository.get("default_branch") != "main":
        raise ValueError("publication requires the configured public repository with main as default")
    if environment.get("name") != ENVIRONMENT or not any(
        rule.get("type") == "required_reviewers" and rule.get("reviewers")
        for rule in environment.get("protection_rules", [])
    ):
        raise ValueError("reviewer-protected release environment must already exist")
    if (ref.get("object", {}).get("type"), ref.get("object", {}).get("sha")) != ("tag", env["RELEASE_TAG_OBJECT_SHA"]):
        raise ValueError("tag must be the exact preapproved annotated tag object")
    if (tag.get("sha") != env["RELEASE_TAG_OBJECT_SHA"] or tag.get("tag") != "v" + env["RELEASE_VERSION"]
            or tag.get("object", {}).get("type") != "commit"
            or tag.get("object", {}).get("sha") != env["RELEASE_SOURCE_SHA"]
            or tag.get("verification", {}).get("verified") is not True):
        raise ValueError("annotated tag must have a verified signature and name the exact source")
    if commit.get("sha") != env["RELEASE_SOURCE_SHA"] or commit.get("commit", {}).get("verification", {}).get("verified") is not True:
        raise ValueError("source commit signature is not verified")


def request(url, token=None, headers=None, missing=False):
    headers = dict(headers or {})
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        with urlopen(Request(url, headers=headers), timeout=30) as response:
            return response.read()
    except HTTPError as error:
        if missing and error.code == 404:
            return None
        raise ValueError("release destination check failed; absence was not established") from None


def preflight(env):
    inputs(env)  # This runs before any API call or environment declaration.
    token = env.get("GH_TOKEN")
    if not token:
        raise ValueError("authenticated read-only release checks require a token")

    def api(path, missing=False):
        data = request("https://api.github.com/" + path, token,
                       {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}, missing)
        return None if data is None else json.loads(data)

    base = "repos/" + REPOSITORY
    identities(env, api(base), api(base + "/environments/" + ENVIRONMENT),
               api(base + "/git/ref/tags/v" + env["RELEASE_VERSION"]),
               api(base + "/git/tags/" + env["RELEASE_TAG_OBJECT_SHA"]),
               api(base + "/commits/" + env["RELEASE_SOURCE_SHA"]))
    if api(base + "/releases/tags/v" + env["RELEASE_VERSION"], missing=True) is not None:
        raise ValueError("release destination is already occupied; inspect partial publication")
    for package, tag in ((IMAGE, "v" + env["RELEASE_VERSION"]), (CHART, env["RELEASE_VERSION"].replace("+", "_"))):
        # Visibility must be configured separately by the operator. The workflow
        # does not create public repositories or change package visibility.
        metadata = api("orgs/stellwerk-labs/packages/container/" + quote(package.split("/", 1)[1], safe=""))
        if metadata.get("visibility") != "public":
            raise ValueError("public package destination must be configured before publishing")
        credentials = base64.b64encode((env["GITHUB_ACTOR"] + ":" + token).encode()).decode()
        bearer = json.loads(request("https://ghcr.io/token?" + urlencode({"service": "ghcr.io", "scope": "repository:" + package + ":pull"}),
                                    headers={"Authorization": "Basic " + credentials}))["token"]
        if request("https://ghcr.io/v2/" + package + "/manifests/" + tag, bearer,
                   {"Accept": "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json"}, missing=True) is not None:
            raise ValueError("registry destination is already occupied; inspect partial publication")


def provenance(env):
    inputs(env)
    return {
        "buildDefinition": {
            "buildType": "https://stellwerk.dev/build/runtime-release/v1",
            "externalParameters": {"version": env["RELEASE_VERSION"], "releaseNotesSHA256": env["RELEASE_NOTES_SHA256"]},
            "resolvedDependencies": [{"uri": "git+https://github.com/" + REPOSITORY,
                                      "digest": {"gitCommit": env["RELEASE_SOURCE_SHA"], "gitTagObject": env["RELEASE_TAG_OBJECT_SHA"]}}],
        },
        "runDetails": {
            "builder": {"id": "https://github.com/" + REPOSITORY + "/.github/workflows/release.yaml@" + env["GITHUB_SHA"]},
            "metadata": {"invocationId": "https://github.com/" + REPOSITORY + "/actions/runs/" + env["GITHUB_RUN_ID"] + "/attempts/" + env["GITHUB_RUN_ATTEMPT"]},
        },
    }


def statement_matches(statement, digest, predicate_type, predicate):
    subjects = statement.get("subject", [])
    return (statement.get("predicateType") == predicate_type and statement.get("predicate") == predicate
            and len(subjects) == 1 and subjects[0].get("digest") == {"sha256": digest.removeprefix("sha256:")})


def verified_statement(path, digest, predicate_type, predicate_path):
    # Only call after Cosign has cryptographically verified this registry output
    # or bundle with its exact workflow identity, issuer and source SHA.
    raw = Path(path).read_text().strip()
    values = []
    decoder = json.JSONDecoder()
    while raw:
        value, end = decoder.raw_decode(raw)
        values.extend(value if isinstance(value, list) else [value])
        raw = raw[end:].lstrip()
    predicate = json.loads(Path(predicate_path).read_text())
    for record in values:
        payload = record.get("payload") or record.get("Payload") or record.get("dsseEnvelope", {}).get("payload")
        if payload and statement_matches(json.loads(base64.b64decode(payload, validate=True)), digest, predicate_type, predicate):
            return
    raise ValueError("verified attestation does not bind the expected artifact and exact predicate")


if __name__ == "__main__":
    try:
        command, *args = sys.argv[1:]
        if command == "preflight":
            preflight(os.environ)
        elif command == "provenance":
            Path(args[0]).write_text(json.dumps(provenance(os.environ), sort_keys=True, indent=2) + "\n")
        elif command == "statement":
            verified_statement(*args)
        else:
            raise ValueError("unknown release policy command")
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
