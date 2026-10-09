import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import random
import shutil
import string
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

import release_content as release


class ReleaseContentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("gitleaks"):
            raise RuntimeError("pinned gitleaks is required for release-content tests")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.context = self.root / "context"
        self.context.mkdir()
        for arch in ("amd64", "arm64"):
            (self.context / f"runtime-linux-{arch}").write_bytes(b"executable-" + arch.encode())
        for name in release.REQUIRED_NOTICES:
            path = self.context / "licenses" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("notice for " + name)

    def image(self, malicious=None, deleted_secret=None):
        layout = self.root / "oci"
        blobs = layout / "blobs" / "sha256"
        blobs.mkdir(parents=True)
        (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}')

        def blob(data, media_type):
            if not isinstance(data, bytes):
                data = json.dumps(data, sort_keys=True).encode()
            digest = hashlib.sha256(data).hexdigest()
            (blobs / digest).write_bytes(data)
            return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media_type}

        manifests = []
        for arch in ("amd64", "arm64"):
            files = release.content(self.context, arch)
            if deleted_secret:
                files["licenses/deleted-credential"] = (deleted_secret.encode(), 0o644)
            raw = release.tar_bytes(files)
            if malicious:
                out = io.BytesIO()
                with tarfile.open(fileobj=out, mode="w") as archive:
                    entry = tarfile.TarInfo(malicious)
                    entry.size = 4
                    archive.addfile(entry, io.BytesIO(b"bad!"))
                raw = out.getvalue()
            layers = [blob(gzip.compress(raw, mtime=0), "application/vnd.oci.image.layer.v1.tar+gzip")]
            diff_ids = ["sha256:" + hashlib.sha256(raw).hexdigest()]
            if deleted_secret:
                whiteout = release.tar_bytes({"licenses/.wh.deleted-credential": (b"", 0o644)})
                layers.append(blob(gzip.compress(whiteout, mtime=0), "application/vnd.oci.image.layer.v1.tar+gzip"))
                diff_ids.append("sha256:" + hashlib.sha256(whiteout).hexdigest())
            config = blob({"os": "linux", "architecture": arch,
                           "config": {"User": "65532:65532", "Entrypoint": ["/runtime"]},
                           "rootfs": {"type": "layers", "diff_ids": diff_ids}},
                          "application/vnd.oci.image.config.v1+json")
            manifest = blob({"schemaVersion": 2, "config": config, "layers": layers},
                            "application/vnd.oci.image.manifest.v1+json")
            manifest["platform"] = {"os": "linux", "architecture": arch}
            manifests.append(manifest)
        index = blob({"schemaVersion": 2, "manifests": manifests}, "application/vnd.oci.image.index.v1+json")
        (layout / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [index]}))
        return layout, index["digest"]

    def test_archives_are_identical_after_metadata_changes(self):
        first, second = self.root / "first.gz", self.root / "second.gz"
        release.write_archive(self.context, "arm64", first)
        for path in self.context.rglob("*"):
            os.utime(path, (123456, 123456))
        release.write_archive(self.context, "arm64", second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first) as archive:
            self.assertEqual(archive.getmember("runtime").mode, 0o755)
            self.assertEqual(archive.extractfile("runtime").read(), b"executable-arm64")
            for name in release.REQUIRED_NOTICES:
                self.assertEqual(archive.extractfile("licenses/" + name).read(),
                                 (self.context / "licenses" / name).read_bytes())
            self.assertTrue(all(entry.mtime == 0 and entry.uid == 0 and entry.gid == 0 for entry in archive))

    def test_every_required_notice_is_mandatory(self):
        for name in release.REQUIRED_NOTICES:
            with self.subTest(name=name):
                path = self.context / "licenses" / name
                original = path.read_bytes()
                path.unlink()
                with self.assertRaises(ValueError):
                    release.content(self.context, "amd64")
                path.write_bytes(original)

    def test_chart_repack_is_deterministic_and_preserves_files(self):
        source = self.root / "chart.tgz"
        source.write_bytes(gzip.compress(release.tar_bytes({"chart/Chart.yaml": (b"version: 0.1.0\n", 0o600)})))
        one, two = self.root / "one.tgz", self.root / "two.tgz"
        release.chart(source, one)
        release.chart(source, two)
        self.assertEqual(one.read_bytes(), two.read_bytes())
        with tarfile.open(one) as archive:
            self.assertEqual(archive.extractfile("chart/Chart.yaml").read(), b"version: 0.1.0\n")

    def test_release_version_must_match_the_source_chart_before_building(self):
        output = self.root / "wrong-version"
        script = Path(__file__).with_name("build-runtime-release.sh")
        result = subprocess.run([str(script), "0.2.0", str(output)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must match the source chart", result.stderr)
        self.assertFalse(output.exists())

    def test_symlink_notice_is_refused(self):
        path = self.context / "licenses" / release.REQUIRED_NOTICES[0]
        path.unlink()
        path.symlink_to(self.context / "runtime-linux-amd64")
        with self.assertRaises(ValueError):
            release.content(self.context, "amd64")

    def test_export_verifies_both_platforms_and_notice_bytes(self):
        layout, digest = self.image()
        release.export(layout, digest, self.root / "filesystems")
        for arch in ("amd64", "arm64"):
            extracted = self.root / "filesystems" / arch
            self.assertEqual((extracted / "runtime").read_bytes(), b"executable-" + arch.encode())
            for name in release.REQUIRED_NOTICES:
                self.assertEqual((extracted / "licenses" / name).read_bytes(),
                                 (self.context / "licenses" / name).read_bytes())

    def test_corrupt_blob_is_refused(self):
        layout, digest = self.image()
        (layout / "blobs" / "sha256" / digest[7:]).write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            release.export(layout, digest, self.root / "filesystems")

    def test_parent_traversal_layer_is_refused(self):
        layout, digest = self.image("../escape")
        with self.assertRaises(ValueError):
            release.export(layout, digest, self.root / "filesystems")
        self.assertFalse((self.root / "escape").exists())

    def test_private_reference_scan_rejects_seed_without_echoing_it(self):
        seed = self.root / "seed"
        seed.mkdir()
        for value in ("/" + "Users/engineer/private/project", "W" + "X99", "C" + "01", "private-owner-seed"):
            with self.subTest(kind=value[:1]):
                (seed / "binary").write_bytes(value.encode())
                with self.assertRaisesRegex(ValueError, "prohibited content"):
                    release.scan(seed, ["private-owner-seed"])
        (seed / "binary").write_bytes(b"public content")
        release.scan(seed)

    def test_private_reference_in_shipping_path_is_refused(self):
        forbidden = "private-owner-fixture"
        notice = self.context / "licenses" / forbidden / "NOTICE"
        notice.parent.mkdir()
        notice.write_text("public notice text")
        layout, digest = self.image()
        output = self.root / "filesystems"
        release.export(layout, digest, output)
        with self.assertRaisesRegex(ValueError, "prohibited content"):
            release.scan(output, [forbidden])

    def test_final_metadata_notes_and_archive_paths_are_scanned(self):
        scan = Path(__file__).with_name("scan-release-content.sh")
        seed = self.root / "staged"
        seed.mkdir()
        forbidden = "private-owner-fixture"
        token = "ghp_" + "".join(random.Random(17).sample(string.ascii_letters + string.digits, 36))
        fixtures = {
            "source-provenance.json": json.dumps({"source": forbidden}).encode(),
            "runtime-image.spdx.json": json.dumps({"supplier": forbidden}).encode(),
            "release-notes.md": forbidden.encode(),
            "release.json": json.dumps({"extra": "github_token=" + token}).encode(),
            "chart.tgz": gzip.compress(release.tar_bytes({"chart/" + forbidden + "/values.yaml": (b"public", 0o644)})),
            "runtime.tar.gz": gzip.compress(release.tar_bytes({"licenses/NOTICE": (("github_token=" + token).encode(), 0o644)})),
        }
        for name, data in fixtures.items():
            with self.subTest(asset=name):
                path = seed / name
                path.write_bytes(data)
                result = subprocess.run([str(scan), str(seed), forbidden], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(forbidden, result.stdout + result.stderr)
                self.assertNotIn(token, result.stdout + result.stderr)
                path.unlink()
        (seed / "public.md").write_text("public release content")
        result = subprocess.run([str(scan), str(seed), forbidden], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_archive_scan_refuses_unsafe_paths_links_duplicates_and_limits(self):
        for kind in ("traversal", "link", "duplicate", "members", "bytes"):
            with self.subTest(kind=kind):
                source = self.root / kind
                source.mkdir()
                with tarfile.open(source / "content.tar", "w") as archive:
                    entry = tarfile.TarInfo("../escape" if kind == "traversal" else "notice")
                    if kind == "link":
                        entry.type, entry.linkname = tarfile.SYMTYPE, "../escape"
                        archive.addfile(entry)
                    else:
                        entry.size = 4
                        archive.addfile(entry, io.BytesIO(b"text"))
                        if kind == "duplicate":
                            archive.addfile(entry, io.BytesIO(b"text"))
                diagnostic = {
                    "traversal": "unsafe or duplicate", "link": "unsupported",
                    "duplicate": "unsafe or duplicate", "members": "content exceeds",
                    "bytes": "source exceeds",
                }[kind]
                with self.assertRaisesRegex(ValueError, diagnostic):
                    release.unpack(source, self.root / (kind + "-output"),
                                   max_members=0 if kind == "members" else 20,
                                   max_bytes=1 if kind == "bytes" else 20 * 1024)
                self.assertFalse((self.root / "escape").exists())

    def test_nested_archives_are_scanned_and_depth_is_bounded(self):
        source = self.root / "nested"
        source.mkdir()
        nested = gzip.compress(release.tar_bytes({"private-owner-fixture/NOTICE": (b"public", 0o644)}))
        (source / "outer.tgz").write_bytes(gzip.compress(release.tar_bytes({"inner.tgz": (nested, 0o644)})))
        output = self.root / "nested-output"
        release.unpack(source, output)
        with self.assertRaises(ValueError):
            release.scan(output, ["private-owner-fixture"])
        with self.assertRaisesRegex(ValueError, "nesting"):
            release.unpack(source, self.root / "depth-output", max_depth=1)

    def test_compressed_headers_and_zip_paths_are_bounded(self):
        source = self.root / "compressed-limit"
        source.mkdir()
        (source / "large.tgz").write_bytes(gzip.compress(b"\0" * 2048))
        with self.assertRaisesRegex(ValueError, "decompression"):
            release.unpack(source, self.root / "compressed-output", max_bytes=1024)
        (source / "large.tgz").unlink()
        with zipfile.ZipFile(source / "content.zip", "w") as archive:
            archive.writestr("licenses/private-owner-fixture/NOTICE", "public")
        output = self.root / "zip-output"
        release.unpack(source, output)
        with self.assertRaises(ValueError):
            release.scan(output, ["private-owner-fixture"])
        (source / "content.zip").unlink()
        with zipfile.ZipFile(source / "content.zip", "w") as archive:
            archive.writestr("../escape", "public")
        with self.assertRaises(ValueError):
            release.unpack(source, self.root / "unsafe-zip-output")

    def test_secret_in_filename_is_scanned_without_echoing_it(self):
        scan = Path(__file__).with_name("scan-release-content.sh")
        seed = self.root / "path-seed"
        seed.mkdir()
        token = "ghp_" + "".join(random.Random(17).sample(string.ascii_letters + string.digits, 36))
        (seed / token).write_text("public content")
        result = subprocess.run([str(scan), str(seed)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(token, result.stdout + result.stderr)

    def test_real_scanner_rejects_secret_seed_and_missing_input(self):
        scan = Path(__file__).with_name("scan-release-content.sh")
        seed = self.root / "seed"
        seed.mkdir()
        token = "ghp_" + "".join(random.Random(17).sample(string.ascii_letters + string.digits, 36))
        (seed / "credential").write_text("github_token=" + token)
        result = subprocess.run([str(scan), str(seed)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(token, result.stdout + result.stderr)
        missing = subprocess.run([str(scan), str(self.root / "missing")], capture_output=True)
        self.assertNotEqual(missing.returncode, 0)

    def test_real_scanner_rejects_secret_inside_elf_nul_bytes(self):
        scan = Path(__file__).with_name("scan-release-content.sh")
        seed = self.root / "binary-seed"
        seed.mkdir()
        token = "ghp_" + "".join(random.Random(17).sample(string.ascii_letters + string.digits, 36))
        (seed / "runtime").write_bytes(b"\x7fELF\x02\x01\0\xff\0github_token=" + token.encode() + b"\0\xff\0")
        result = subprocess.run([str(scan), str(seed)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(token, result.stdout + result.stderr)

    def test_shipping_content_cannot_allow_its_own_secret_inline(self):
        scan = Path(__file__).with_name("scan-release-content.sh")
        seed = self.root / "inline-allow"
        seed.mkdir()
        token = "ghp_" + "".join(random.Random(19).sample(string.ascii_letters + string.digits, 36))
        line = ('github_token="' + token + '" # gitleaks:allow\n').encode()
        for kind, content in (("text", line), ("binary", b"\x7fELF\x02\x01\0" + line + b"\0")):
            with self.subTest(kind=kind):
                (seed / "credential").write_bytes(content)
                result = subprocess.run([str(scan), str(seed)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(token, result.stdout + result.stderr)

    def test_bash_scans_archived_binaries_without_forbidden_arguments(self):
        scan = Path(__file__).with_name("scan-release-content.sh")
        seed = self.root / "no-arguments"
        seed.mkdir()
        archive = seed / "runtime.tgz"
        token = "ghp_" + "".join(random.Random(23).sample(string.ascii_letters + string.digits, 36))
        for contains_secret in (False, True):
            with self.subTest(contains_secret=contains_secret):
                content = b"\x7fELF\x02\x01\0public-runtime\0"
                if contains_secret:
                    content += ("github_token=" + token).encode() + b"\0"
                archive.write_bytes(gzip.compress(release.tar_bytes({"runtime": (content, 0o755)})))
                result = subprocess.run(["/bin/bash", str(scan), str(seed)],
                                        capture_output=True, text=True, timeout=30)
                if contains_secret:
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("unbound variable", result.stdout + result.stderr)
                self.assertNotIn(token, result.stdout + result.stderr)

    def test_shipping_content_cannot_supply_ignored_fingerprints(self):
        scan = Path(__file__).with_name("scan-release-content.sh")
        seed = self.root / "fingerprint-allow"
        seed.mkdir()
        token = "ghp_" + "".join(random.Random(19).sample(string.ascii_letters + string.digits, 36))
        (seed / "credential").write_text("github_token=" + token)
        detection = subprocess.run(
            ["gitleaks", "dir", "--redact", "--no-banner", "--log-level", "error",
             "--ignore-gitleaks-allow", "--gitleaks-ignore-path", "/dev/null",
             "--config", str(Path(__file__).with_name("gitleaks.toml")),
             "--report-format", "json", "--report-path", "-", "."],
            cwd=seed, capture_output=True, text=True, timeout=20)
        self.assertEqual(detection.returncode, 1)
        findings = json.loads(detection.stdout)
        self.assertTrue(findings)
        (seed / ".gitleaksignore").write_text(
            "\n".join(finding["Fingerprint"] for finding in findings) + "\n")
        result = subprocess.run([str(scan), str(seed)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(token, result.stdout + result.stderr)

    def test_secret_removed_by_whiteout_is_still_scanned(self):
        token = "ghp_" + "".join(random.Random(17).sample(string.ascii_letters + string.digits, 36))
        layout, digest = self.image(deleted_secret="github_token=" + token)
        output = self.root / "filesystems"
        release.export(layout, digest, output)
        self.assertFalse((output / "amd64/licenses/deleted-credential").exists())
        self.assertTrue((output / "layers/amd64/0/licenses/deleted-credential").exists())
        result = subprocess.run([str(Path(__file__).with_name("scan-release-content.sh")), str(output)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(token, result.stdout + result.stderr)

    def test_allowlist_is_exact_and_source_scoped(self):
        scan = Path(__file__).with_name("scan-release-content.sh")
        seed = self.root / "seed"
        (seed / "runtime").mkdir(parents=True)
        token = "PWT-" + "abc_DEF-123"
        line = 'valid := map[string]any{"access_token": "' + token + '"}\n'
        allowed = seed / "runtime" / "coretoken_test.go"
        allowed.write_text(line)
        result = subprocess.run([str(scan), str(seed)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        allowed.rename(seed / "runtime" / "production.go")
        result = subprocess.run([str(scan), str(seed)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
