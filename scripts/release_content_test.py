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
