#!/usr/bin/env python3
"""Real Helm contracts and ORAS TLS transport, without a cluster or image build."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parent.parent
CHART = ROOT / "charts/native-plugin-runtime"
FETCHERS = {"fetch-package-envelope", "fetch-package-sbom", "fetch-package-provenance", "pull-package"}


def run(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=20, **kwargs)


def container_blocks(section):
    return dict(re.findall(r"^        - name: ([a-z-]+)\n((?:(?:          .*)?\n)*)", section, re.M))


class ChartTests(unittest.TestCase):
    def render(self, *args):
        return run(["helm", "template", "native-probe", str(CHART), "--kube-version=1.35.0",
                    "--set=enabled=true", "--set-string=trust.mode=managed-key-no-tlog",
                    "--set-string=plugin.id=dev.stellwerk.native-probe", "--set-string=plugin.version=1.0.0",
                    "--set-string=package.reference=registry.invalid/native-probe@sha256:" + "a" * 64,
                    "--set-string=package.manifestSHA256=" + "a" * 64,
                    "--set-string=images.runtime=registry.invalid/runtime@sha256:" + "b" * 64,
                    "--set-string=images.oras=registry.invalid/oras@sha256:" + "c" * 64,
                    "--set-string=images.cosign=registry.invalid/cosign@sha256:" + "d" * 64,
                    "--set-string=trust.bootstrapSecret.name=publisher-trust",
                    "--set-string=trust.signatureBundleSecret.name=publisher-signature",
                    "--set-string=package.attestations.sbom=sha256:" + "e" * 64,
                    "--set-string=package.attestations.provenance=sha256:" + "f" * 64, *args])

    def test_optional_ca_leaves_existing_fetches_unchanged(self):
        for mode in ([], ["--set=package.plainHTTP=true"]):
            with self.subTest(mode=mode):
                result = self.render(*mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("registry-ca", result.stdout)
                self.assertNotIn("--ca-file=/registry/ca.crt", result.stdout)
                self.assertEqual(result.stdout.count("- --plain-http"), 4 if mode else 0)

    def test_ca_only_reaches_every_oras_fetcher_in_both_pods(self):
        result = self.render(
            "--set=migration.enabled=true",
            "--set-string=migration.profileSecret.name=migration-profile",
            "--set-string=migration.databaseSecret.name=migration-database",
            "--set-string=migration.databaseCASecret.name=database-ca",
            "--set-string=package.registryCASecret.name=public-registry-ca",
            "--set-string=package.registryCASecret.key=trust.pem",
            "--set-string=package.registryConfigSecret.name=registry-credentials",
            "--set=workloadIdentity.enabled=true",
            "--set-string=installationId=11111111-1111-4111-8111-111111111111",
            "--set-string=workloadIdentity.audience=core",
            "--set-string=workloadIdentity.gateway.url=https://core.example",
            "--set-string=workloadIdentity.gateway.caSecret.name=core-ca",
            "--set=ui.enabled=true", "--set-string=ui.consoleOrigin=https://console.example",
            '--set-json=networkPolicy.additionalIngress=[{"namespaceSelector":{"namespace":"core"},'
            '"podSelector":{"app":"ui-gateway"},"port":8081}]')
        self.assertEqual(result.returncode, 0, result.stderr)
        pods = [doc for doc in result.stdout.split("\n---") if re.search(r"^kind: (Deployment|Job)$", doc, re.M)]
        self.assertEqual(len(pods), 2)
        for pod in pods:
            init, rest = pod.split("      initContainers:\n", 1)[1].split("      containers:\n", 1)
            main, volumes = rest.split("      volumes:\n", 1)
            blocks = {**container_blocks(init), **container_blocks(main)}
            self.assertTrue(FETCHERS <= blocks.keys())
            for name, body in blocks.items():
                with self.subTest(container=name, kind="Job" if "kind: Job\n" in pod else "Deployment"):
                    self.assertEqual("- --ca-file=/registry/ca.crt" in body, name in FETCHERS)
                    self.assertEqual("name: registry-ca\n" in body, name in FETCHERS)
                    if name in FETCHERS:
                        self.assertRegex(body, r"- name: registry-ca\n\s+mountPath: /registry/ca.crt\n"
                                              r"\s+subPath: ca.crt\n\s+readOnly: true\n")
                        self.assertIn("--registry-config=/registry/config.json", body)
                        self.assertIn("- --plain-http=false", body)
                        self.assertNotIn("- --plain-http\n", body)
            ca = re.search(r"^        - name: registry-ca\n((?:          .*\n)+)", volumes, re.M)
            self.assertIsNotNone(ca)
            self.assertIn("secretName: public-registry-ca", ca.group(1))
            self.assertIn("defaultMode: 0440", ca.group(1))
            self.assertIn('key: "trust.pem"', ca.group(1))
            self.assertIn("path: ca.crt", ca.group(1))
            self.assertNotIn("publisher-trust", ca.group(1))
            self.assertNotIn("registry-credentials", ca.group(1))
            self.assertNotIn("database-ca", ca.group(1))
            self.assertNotIn("core-ca", ca.group(1))
        self.assertIn("name: ui\n", result.stdout)
        self.assertIn("name: core-token\n", result.stdout)
        default_key = self.render("--set-string=package.registryCASecret.name=public-registry-ca")
        self.assertEqual(default_key.returncode, 0, default_key.stderr)
        self.assertIn('key: "ca.crt"', default_key.stdout)

    def test_schema_refuses_invalid_secret_references(self):
        invalid = [("name", value) for value in ("Uppercase", "-ca", "ca-", "a..b", "a/b", "a_b", "a" * 64, "a." * 127 + "b")]
        invalid += [("key", value) for value in ("", "a/b", "a b", ".", "..", "..data", "a" * 254)]
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                result = self.render("--set-string=package.registryCASecret.name=public-registry-ca",
                                     f"--set-string=package.registryCASecret.{key}={value}")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("registryCASecret", result.stderr)
        result = self.render("--set-string=package.registryCASecret.unknown=true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("registryCASecret", result.stderr)

    def test_plain_http_with_ca_refused_by_schema_and_template(self):
        for validation in ([], ["--skip-schema-validation"]):
            with self.subTest(validation=validation):
                result = self.render("--set=package.plainHTTP=true",
                                     "--set-string=package.registryCASecret.name=public-registry-ca", *validation)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("registryCASecret", result.stderr)


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class ORASTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.oras = shutil.which("oras")
        if cls.oras is None:
            raise RuntimeError("ORAS 1.3.4 is required")
        version = run([cls.oras, "version"])
        if version.returncode or not re.search(r"^Version:\s+1\.3\.4$", version.stdout, re.M):
            raise RuntimeError("use the pinned ORAS 1.3.4 release binary")
        cls.scratch = tempfile.TemporaryDirectory(prefix="native-registry-ca-")
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.root = Path(cls.scratch.name)
        cls.env = {key: value for key, value in os.environ.items()
                   if key.upper() not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}}
        cls.env.update(HOME=str(cls.root), DOCKER_CONFIG=str(cls.root), NO_PROXY="localhost,127.0.0.1")
        (cls.root / "registry.json").write_text('{"auths":{}}')
        for name in ("ca", "wrong-ca"):
            result = run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                          "-subj", f"/CN={name}", "-keyout", str(cls.root / f"{name}.key"),
                          "-out", str(cls.root / f"{name}.crt")])
            if result.returncode:
                raise RuntimeError("fixture CA generation failed")
        result = run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                      "-keyout", str(cls.root / "server.key"), "-out", str(cls.root / "server.csr")])
        if result.returncode:
            raise RuntimeError("fixture CSR generation failed")
        (cls.root / "extensions").write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n")
        result = run(["openssl", "x509", "-req", "-days", "1", "-in", str(cls.root / "server.csr"),
                      "-CA", str(cls.root / "ca.crt"), "-CAkey", str(cls.root / "ca.key"), "-CAcreateserial",
                      "-extfile", str(cls.root / "extensions"), "-out", str(cls.root / "server.crt")])
        if result.returncode:
            raise RuntimeError("fixture server certificate generation failed")

        cls.resources = {}
        cls.manifests = {}
        cls.payloads = {}
        config = b"{}"
        cls.resources["/v2/fixture/blobs/" + digest(config)] = ("application/octet-stream", config)
        for name in ("package", "sbom", "provenance"):
            payload = f"public {name} TLS transport fixture\n".encode()
            cls.payloads[name] = payload
            cls.resources["/v2/fixture/blobs/" + digest(payload)] = ("application/octet-stream", payload)
            manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                                   "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": digest(config), "size": len(config)},
                                   "layers": [{"mediaType": "application/octet-stream", "digest": digest(payload), "size": len(payload),
                                               "annotations": {"org.opencontainers.image.title": name + ".txt"}}]}, separators=(",", ":")).encode()
            cls.manifests[name] = manifest
            cls.resources["/v2/fixture/manifests/" + digest(manifest)] = ("application/vnd.oci.image.manifest.v1+json", manifest)
        cls.requests = []

        class Registry(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_HEAD(self):
                self.respond(False)

            def do_GET(self):
                self.respond(True)

            def respond(self, body):
                cls.requests.append(self.path)
                if self.path == "/v2/":
                    content_type, data = "application/json", b"{}"
                elif self.path in cls.resources:
                    content_type, data = cls.resources[self.path]
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Docker-Content-Digest", digest(data))
                self.end_headers()
                if body:
                    self.wfile.write(data)

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Registry)
        cls.addClassCleanup(cls.server.server_close)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cls.root / "server.crt", cls.root / "server.key")
        cls.server.socket = tls.wrap_socket(cls.server.socket, server_side=True)
        thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        thread.start()
        cls.addClassCleanup(thread.join, 5)
        cls.addClassCleanup(cls.server.shutdown)
        cls.port = cls.server.server_port

    def operations(self, host, ca, output):
        reference = f"{host}:{self.port}/fixture@"
        flags = ["--ca-file=" + str(ca), "--plain-http=false", "--registry-config=" + str(self.root / "registry.json")]
        yield ["manifest", "fetch", "--output=" + str(output / "manifest.json"), *flags, reference + digest(self.manifests["package"])]
        for name in ("package", "sbom", "provenance"):
            yield ["pull", "--no-tty", "--output=" + str(output / name), *flags, reference + digest(self.manifests[name])]
        yield ["blob", "fetch", "--output=" + str(output / "blob"), *flags, reference + digest(self.payloads["package"])]

    def test_real_manifest_package_referrer_and_blob_fetches(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            output = Path(directory)
            for args in self.operations("localhost", self.root / "ca.crt", output):
                result = run([self.oras, *args], env=self.env)
                self.assertEqual(result.returncode, 0, "ORAS TLS fetch failed")
            self.assertEqual((output / "manifest.json").read_bytes(), self.manifests["package"])
            for name, payload in self.payloads.items():
                self.assertEqual((output / name / (name + ".txt")).read_bytes(), payload)
            self.assertEqual((output / "blob").read_bytes(), self.payloads["package"])

    def assert_tls_refusal(self, host, ca):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            output = Path(directory)
            for args in self.operations(host, ca, output):
                before = len(self.requests)
                result = run([self.oras, *args], env=self.env)
                self.assertNotEqual(result.returncode, 0, "ORAS accepted invalid registry TLS")
                self.assertEqual(len(self.requests), before, "refusal was not before HTTP")
                self.assertFalse(any(path.is_file() and path.stat().st_size for path in output.rglob("*")))

    def test_real_wrong_ca_refused_before_http(self):
        self.assert_tls_refusal("localhost", self.root / "wrong-ca.crt")

    def test_real_wrong_hostname_refused_before_http(self):
        self.assert_tls_refusal("127.0.0.1", self.root / "ca.crt")


if __name__ == "__main__":
    unittest.main()
