import base64
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

import release_policy as policy


class ReleasePolicyTest(unittest.TestCase):
    def setUp(self):
        self.env = {"GITHUB_REPOSITORY": policy.REPOSITORY, "GITHUB_REF": "refs/heads/main",
                    "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNTIME_PUBLIC_RELEASES_ENABLED": "true",
                    "RELEASE_SOURCE_SHA": "a" * 40, "GITHUB_SHA": "a" * 40,
                    "RELEASE_TAG_OBJECT_SHA": "b" * 40, "RELEASE_VERSION": "0.1.0-rc.1",
                    "RELEASE_FORBIDDEN_LITERAL": "private-owner-fixture",
                    "RELEASE_NOTES": "Reviewed notes\n", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
        self.env["RELEASE_NOTES_SHA256"] = hashlib.sha256(self.env["RELEASE_NOTES"].encode()).hexdigest()
        self.repo = {"full_name": policy.REPOSITORY, "private": False, "default_branch": "main"}
        self.environment = {"name": policy.ENVIRONMENT, "protection_rules": [{"type": "required_reviewers", "reviewers": [{"type": "User"}]}]}
        self.ref = {"object": {"type": "tag", "sha": "b" * 40, "url": "https://api.github.com/tag"}}
        self.tag = {"sha": "b" * 40, "tag": "v0.1.0-rc.1", "object": {"type": "commit", "sha": "a" * 40},
                    "verification": {"verified": True}}
        self.commit = {"sha": "a" * 40, "commit": {"verification": {"verified": True}}}

    def check(self):
        policy.identities(self.env, self.repo, self.environment, self.ref, self.tag, self.commit)

    def test_complete_identity_is_accepted(self):
        self.check()
        value = policy.provenance(self.env)
        self.assertEqual(value["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"], "a" * 40)
        self.assertIn("/attempts/1", value["runDetails"]["metadata"]["invocationId"])

    def test_dispatch_cannot_override_dormancy_or_source(self):
        for key, value in (("GITHUB_REPOSITORY", "other/runtime"), ("GITHUB_REF", "refs/heads/other"),
                           ("RUNTIME_PUBLIC_RELEASES_ENABLED", "false"), ("GITHUB_EVENT_NAME", "push"),
                           ("GITHUB_SHA", "c" * 40), ("RELEASE_NOTES", "Changed notes"),
                           ("RELEASE_VERSION", "0.01.0"), ("RELEASE_TAG_OBJECT_SHA", "short"),
                           ("RELEASE_FORBIDDEN_LITERAL", "")):
            with self.subTest(key=key):
                env = dict(self.env, **{key: value})
                with self.assertRaises(ValueError):
                    policy.inputs(env)

    def test_missing_or_unprotected_environment_is_refused(self):
        for rules in ([], [{"type": "required_reviewers", "reviewers": []}], [{"type": "wait_timer", "wait_timer": 30}]):
            with self.subTest(rules=rules):
                self.environment["protection_rules"] = rules
                with self.assertRaises(ValueError):
                    self.check()

    def test_private_destination_unsigned_or_moved_tag_is_refused(self):
        variants = [("repo", "private", True), ("tag", "sha", "c" * 40),
                    ("tag", "verification", {"verified": False}),
                    ("tag", "object", {"type": "commit", "sha": "c" * 40}),
                    ("ref", "object", {"type": "commit", "sha": "a" * 40}),
                    ("commit", "commit", {"verification": {"verified": False}})]
        originals = {name: copy.deepcopy(getattr(self, name)) for name in ("repo", "tag", "ref", "commit")}
        for name, key, value in variants:
            with self.subTest(name=name, key=key):
                for target, original in originals.items():
                    setattr(self, target, copy.deepcopy(original))
                getattr(self, name)[key] = value
                with self.assertRaises(ValueError):
                    self.check()

    def test_statement_requires_exact_subject_type_and_predicate(self):
        predicate = policy.provenance(self.env)
        statement = {"predicateType": "https://slsa.dev/provenance/v1", "predicate": predicate,
                     "subject": [{"digest": {"sha256": "d" * 64}}]}
        self.assertTrue(policy.statement_matches(statement, "sha256:" + "d" * 64, "https://slsa.dev/provenance/v1", predicate))
        self.assertFalse(policy.statement_matches(statement, "sha256:" + "e" * 64, "https://slsa.dev/provenance/v1", predicate))
        changed = copy.deepcopy(predicate)
        changed["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = "e" * 40
        self.assertFalse(policy.statement_matches(statement, "d" * 64, "https://slsa.dev/provenance/v1", changed))

    def test_dormant_cli_exits_before_network_or_any_mutation(self):
        script = Path(__file__).with_name("release_policy.py")
        result = subprocess.run(["python3", str(script), "preflight"], env={**os.environ, "GITHUB_REPOSITORY": "other/runtime"}, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"dormant", result.stderr)

    def test_bundle_statement_inspection_binds_exact_predicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            predicate = policy.provenance(self.env)
            (root / "predicate.json").write_text(json.dumps(predicate))
            statement = {"predicateType": "https://slsa.dev/provenance/v1", "predicate": predicate,
                         "subject": [{"digest": {"sha256": "d" * 64}}]}
            (root / "bundle.json").write_text(json.dumps({"dsseEnvelope": {"payload": base64.b64encode(json.dumps(statement).encode()).decode()}}))
            policy.verified_statement(root / "bundle.json", "d" * 64, "https://slsa.dev/provenance/v1", root / "predicate.json")
            with self.assertRaises(ValueError):
                policy.verified_statement(root / "bundle.json", "e" * 64, "https://slsa.dev/provenance/v1", root / "predicate.json")

    def test_real_http_errors_are_not_treated_as_unused_destinations(self):
        class StatusPeer(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(int(self.path[1:]))
                self.end_headers()
                self.wfile.write(b'{}')

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), StatusPeer)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:" + str(server.server_port)
        self.assertIsNone(policy.request(base + "/404", missing=True))
        self.assertEqual(policy.request(base + "/200", missing=True), b'{}')
        for status in (401, 403, 500):
            with self.subTest(status=status), self.assertRaises(ValueError):
                policy.request(base + "/" + str(status), missing=True)


if __name__ == "__main__":
    unittest.main()
