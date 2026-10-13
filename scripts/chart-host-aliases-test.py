#!/usr/bin/env python3
"""Real Helm Pod-level hostname override contracts, without a cluster."""

import json
from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parent.parent
CHART = ROOT / "charts/native-plugin-runtime"
ALIASES = [{"ip": "192.0.2.10", "hostnames": ["core.example.com", "core-alt.example.com"]},
           {"ip": "2001:db8::10", "hostnames": ["ipv6.example.com"]}]
ALIAS_BLOCK = re.compile(r"^      hostAliases:\n(?:        .*\n)+", re.M)


class HostAliasesTests(unittest.TestCase):
    def render(self, *args):
        return subprocess.run(
            ["helm", "template", "native-probe", str(CHART), "--kube-version=1.35.0",
             "--set=enabled=true", "--set-string=trust.mode=development-untrusted",
             "--set-string=plugin.id=dev.stellwerk.native-probe", "--set-string=plugin.version=1.0.0",
             "--set-string=package.reference=registry.invalid/native-probe@sha256:" + "a" * 64,
             "--set-string=package.manifestSHA256=" + "a" * 64,
             "--set-string=images.runtime=registry.invalid/runtime@sha256:" + "b" * 64,
             "--set-string=images.oras=registry.invalid/oras@sha256:" + "c" * 64,
             "--set-string=migration.profileSecret.name=migration-profile",
             "--set-string=migration.databaseSecret.name=migration-database", *args],
            capture_output=True, text=True, timeout=20)

    def test_default_and_explicit_empty_leave_both_phases_unchanged(self):
        for phase in (False, True):
            with self.subTest(migration=phase):
                args = ["--set=migration.enabled=" + str(phase).lower()]
                default = self.render(*args)
                empty = self.render(*args, "--set-json=hostAliases=[]")
                self.assertEqual(default.returncode, 0, default.stderr)
                self.assertEqual(empty.returncode, 0, empty.stderr)
                self.assertEqual(default.stdout, empty.stdout)
                self.assertNotIn("hostAliases:", default.stdout)

    def test_aliases_only_change_both_pod_specs(self):
        for phase in (False, True):
            with self.subTest(migration=phase):
                args = ["--set=migration.enabled=" + str(phase).lower(), "--set=ui.enabled=true",
                        "--set-string=ui.consoleOrigin=https://console.example.com",
                        '--set-json=networkPolicy.additionalIngress=[{"from":[{"podSelector":{}}],"ports":[{"port":8081}]}]',
                        "--set=workloadIdentity.enabled=true",
                        "--set-string=workloadIdentity.audience=core",
                        "--set-string=installationId=11111111-1111-4111-8111-111111111111",
                        "--set-string=workloadIdentity.gateway.url=https://core.example.com"]
                baseline = self.render(*args)
                result = self.render(*args, "--set-json=hostAliases=" + json.dumps(ALIASES))
                self.assertEqual(baseline.returncode, 0, baseline.stderr)
                self.assertEqual(result.returncode, 0, result.stderr)
                pods = [doc for doc in result.stdout.split("\n---")
                        if re.search(r"^kind: (Deployment|Job)$", doc, re.M)]
                self.assertEqual(len(pods), 2 if phase else 1)
                for pod in pods:
                    blocks = ALIAS_BLOCK.findall(pod)
                    self.assertEqual(len(blocks), 1, pod)
                    self.assertEqual(blocks[0], "      hostAliases:\n"
                                     "        - hostnames:\n"
                                     "          - core.example.com\n"
                                     "          - core-alt.example.com\n"
                                     "          ip: 192.0.2.10\n"
                                     "        - hostnames:\n"
                                     "          - ipv6.example.com\n"
                                     "          ip: 2001:db8::10\n")
                self.assertEqual(ALIAS_BLOCK.sub("", result.stdout), baseline.stdout)

    def test_invalid_top_level_shapes_are_refused(self):
        for value in (None, False, 1, "192.0.2.10", {}, [None], [False], [1], ["core.example.com"]):
            with self.subTest(value=value):
                result = self.render("--set-json=hostAliases=" + json.dumps(value))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("hostAliases", result.stderr)

    def test_invalid_entry_shapes_are_refused(self):
        entries = [{}, {"ip": "192.0.2.10"}, {"hostnames": ["core.example.com"]},
                   {"ip": "192.0.2.10", "hostnames": [], "unknown": True},
                   {"ip": "192.0.2.10", "hostnames": ["core.example.com"], "unknown": True},
                   {"ip": "192.0.2.10", "hostnames": []},
                   {"ip": "192.0.2.10", "hostnames": "core.example.com"},
                   {"ip": "192.0.2.10", "hostnames": None}]
        entries += [{"ip": value, "hostnames": ["core.example.com"]}
                    for value in (None, False, 1, [], {}, "", "999.0.0.1", "192.0.2.10/32",
                                  "192.0.2.10:443", "2001:db8::gg", "fe80::1%eth0", "core.example.com")]
        entries += [{"ip": "192.0.2.10", "hostnames": [value]}
                    for value in (None, False, 1, [], {}, "", "Upper.example", "bad_name", "-bad", "bad-",
                                  "a..b", ".example", "example.", "*.example", "https://core.example.com",
                                  "a" * 254, "line\nbreak")]
        for entry in entries:
            with self.subTest(entry=entry):
                result = self.render("--set-json=hostAliases=" + json.dumps([entry]))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("hostAliases", result.stderr)


if __name__ == "__main__":
    unittest.main()
