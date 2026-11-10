#!/usr/bin/env python3
"""Render the real HTTPS and OCI init chains, including migration isolation."""

from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
CHART = ROOT / "charts/native-plugin-runtime"


def blocks(section):
    return dict(re.findall(r"^        - name: ([a-z-]+)\n((?:(?:          .*)?\n)*)", section, re.M))


class HTTPSChartTests(unittest.TestCase):
    def render(self, *overrides, transport="https"):
        values = {
            "enabled": "true", "plugin.id": "dev.stellwerk.native-probe", "plugin.version": "1.0.0",
            "trust.mode": "managed-key-no-tlog", "trust.bootstrapSecret.name": "publisher-trust",
            "package.transport": transport, "package.manifestSHA256": "a" * 64,
            "package.registryConfigSecret.name": "customer-reader",
            "package.registryCASecret.name": "public-ca",
            "package.attestations.sbom": "sha256:" + "e" * 64,
            "package.attestations.provenance": "sha256:" + "f" * 64,
            "images.runtime": "registry.invalid/runtime@sha256:" + "b" * 64,
            "images.cosign": "registry.invalid/cosign@sha256:" + "c" * 64,
        }
        if transport == "https":
            values.update({"package.https.url": "https://gitlab.example/api/v4/projects/1/packages/generic/plugin/1.0.0/plugin.tar",
                           "package.https.archiveSHA256": "d" * 64,
                           "package.https.digest": "sha256:" + "1" * 64,
                           "package.https.signatureDigest": "sha256:" + "2" * 64,
                           "package.https.redirectHosts[0]": "objects.example"})
        else:
            values.update({"package.reference": "registry.invalid/plugin@sha256:" + "1" * 64,
                           "images.oras": "registry.invalid/oras@sha256:" + "d" * 64,
                           "trust.signatureBundleSecret.name": "operator-signature"})
        args = ["helm", "template", "probe", str(CHART)]
        for key, value in values.items():
            args += ["--set" if key == "enabled" else "--set-string", f"{key}={value}"]
        return subprocess.run(args + list(overrides), capture_output=True, text=True, timeout=20)

    def test_https_retains_all_verification_gates_and_fetch_secret_isolation(self):
        result = self.render("--set=migration.enabled=true", "--set-string=migration.profileSecret.name=migration-profile",
                             "--set-string=migration.databaseSecret.name=migration-database")
        self.assertEqual(result.returncode, 0, result.stderr)
        pods = [doc for doc in result.stdout.split("\n---") if re.search(r"^kind: (Deployment|Job)$", doc, re.M)]
        self.assertEqual(len(pods), 2)
        expected = ["fetch-https-package", "verify-package-publisher", "verify-package-signature",
                    "verify-package-sbom", "verify-package-provenance", "validate-package"]
        for pod in pods:
            init, rest = pod.split("      initContainers:\n", 1)[1].split("      containers:\n", 1)
            self.assertEqual(list(blocks(init)), expected)
            self.assertNotIn("oras", init)
            self.assertIn("--redirect-hosts=objects.example", init)
            self.assertIn("--package-digest=sha256:" + "1" * 64, init)
            for name, body in blocks(init).items():
                for secret in ("registry-config", "registry-ca"):
                    self.assertEqual(f"name: {secret}\n" in body, name == "fetch-https-package")
                if name.startswith("verify-"):
                    self.assertIn("readOnly: true", body)
            main, volumes = rest.split("      volumes:\n", 1)
            for secret in ("registry-config", "registry-ca", "signature-bundle", "publisher-trust"):
                self.assertNotIn(secret, main)
            self.assertIn("sizeLimit: 1280Mi", volumes)
            self.assertIn("secretName: customer-reader", volumes)
            self.assertNotIn("operator-signature", volumes)
            self.assertIn('stellwerk.dev/plugin-package: "sha256:' + "1" * 64, pod)

    def test_original_oci_path_keeps_its_ten_gates(self):
        result = self.render(transport="oci")
        self.assertEqual(result.returncode, 0, result.stderr)
        init = result.stdout.split("      initContainers:\n", 1)[1].split("      containers:\n", 1)[0]
        self.assertEqual(list(blocks(init)), ["fetch-package-envelope", "verify-package-envelope", "fetch-package-sbom",
                                             "fetch-package-provenance", "verify-package-publisher", "verify-package-signature",
                                             "verify-package-sbom", "verify-package-provenance", "pull-package", "validate-package"])
        self.assertIn("secretName: operator-signature", result.stdout)
        self.assertIn("sizeLimit: 16Mi", result.stdout)
        self.assertNotIn("fetch-https", result.stdout)

    def test_transport_must_be_explicit_consistent_and_pinned(self):
        for args in (
            ["--set-string=package.transport=unknown"], ["--set-string=trust.mode=development-untrusted"],
            ["--set-string=package.https.archiveSHA256=bad"], ["--set-string=package.https.signatureDigest=bad"],
            ["--set-string=package.https.digest=bad"], ["--set-string=package.https.url=http://gitlab.example/file"],
            ["--set-string=package.https.url=https://reader:token@gitlab.example/file"],
            ["--set-string=package.https.url=https://gitlab.example/file?token=secret"],
            ["--set-string=package.registryConfigSecret.name="], ["--set-string=package.registryCASecret.name="], ["--set=package.plainHTTP=true"],
            ["--set-string=package.reference=registry.invalid/plugin@sha256:" + "a" * 64],
            ["--set-string=package.https.redirectHosts[0]=*.example"],
            ["--set-string=trust.signatureBundleSecret.name=stale-signature"],
        ):
            with self.subTest(args=args):
                result = self.render(*args)
                self.assertNotEqual(result.returncode, 0, result.stdout)
        for validation in ([], ["--skip-schema-validation"]):
            result = self.render(*validation, "--set-string=package.registryCASecret.name=")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("registryCASecret", result.stderr)
        result = self.render("--skip-schema-validation", "--set-string=trust.mode=development-untrusted")
        self.assertNotEqual(result.returncode, 0)
        result = self.render("--set-string=package.https.url=https://gitlab.example/file", transport="oci")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
