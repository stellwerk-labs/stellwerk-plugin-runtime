import base64
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import random
import re
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

    def image(self, malicious=None, deleted_secret=None, json_transform=None, directory=None):
        layout = directory or self.root / "oci"
        blobs = layout / "blobs" / "sha256"
        blobs.mkdir(parents=True)
        def metadata(kind, data):
            return json_transform(kind, data) if json_transform else data
        (layout / "oci-layout").write_bytes(metadata("marker", b'{"imageLayoutVersion":"1.0.0"}'))

        def blob(data, media_type):
            if not isinstance(data, bytes):
                data = json.dumps(data, sort_keys=True).encode()
            kinds = {"application/vnd.oci.image.config.v1+json": "config",
                     "application/vnd.oci.image.manifest.v1+json": "manifest",
                     "application/vnd.oci.image.index.v1+json": "index"}
            if media_type in kinds:
                data = metadata(kinds[media_type], data)
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
        (layout / "index.json").write_bytes(metadata("wrapper", json.dumps({"schemaVersion": 2, "manifests": [index]}).encode()))
        return layout, index["digest"]

    def test_original_metadata_bytes_and_decoded_references_are_scanned(self):
        for kind in ("wrapper", "index", "manifest", "config"):
            for value in (b"private-owner-fixture", b"private-owner-fixtur\\u0065"):
                with self.subTest(kind=kind, escaped=b"\\u" in value), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    originals = []
                    def transform(stage, data):
                        if stage == kind:
                            data = b'{ "audit":"' + value + b'",\n' + data[1:]
                            originals.append(data)
                        return data
                    layout, digest = self.image(json_transform=transform, directory=root / "image")
                    release.export(layout, digest, root / "output")
                    retained = [path.read_bytes() for path in (root / "output/metadata").iterdir()]
                    self.assertTrue(originals)
                    for raw in originals:
                        self.assertIn(raw, retained)
                    with self.assertRaisesRegex(ValueError, "prohibited content"):
                        release.scan(root / "output", ["private-owner-fixture"])

    def artifact_check(self, layout, digest, output):
        result = subprocess.run(["python3", str(Path(__file__).with_name("release_content.py")),
                                 "export", str(layout), digest, str(output)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            return result
        return subprocess.run(["bash", str(Path(__file__).with_name("scan-release-content.sh")), str(output)],
                              capture_output=True, text=True, timeout=30)

    def test_duplicate_metadata_keys_fail_at_both_inspection_boundaries(self):
        for kind in ("marker", "wrapper", "index", "manifest", "config"):
            for prefix in (b'{"audit":"private-owner-fixture","audit":"public",',
                           b'{"nested":{"audit":"private-owner-fixture","aud\\u0069t":"public"},'):
                with self.subTest(kind=kind, nested=b"nested" in prefix), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    def transform(stage, data):
                        return prefix + data[1:] if stage == kind else data
                    layout, digest = self.image(json_transform=transform, directory=root / "image")
                    with self.assertRaisesRegex(ValueError, "duplicate OCI JSON key"):
                        release.export(layout, digest, root / "direct")
                    for boundary in ("producer", "publisher"):
                        result = self.artifact_check(layout, digest, root / boundary)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("duplicate OCI JSON key", result.stderr)
                        self.assertNotIn("private-owner-fixture", result.stdout + result.stderr)

    def test_publication_reinspection_rejects_digest_valid_metadata_tamper(self):
        token = "ghp_" + "".join(random.Random(61).sample(string.ascii_letters + string.digits, 36))
        for kind in ("index", "manifest", "config"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                layout, digest = self.image(directory=root / "image")
                for boundary in ("producer", "publisher-clean"):
                    result = self.artifact_check(layout, digest, root / boundary)
                    self.assertEqual(result.returncode, 0, result.stderr)
                shutil.rmtree(layout)
                def transform(stage, data):
                    return b'{"audit":"' + token.encode() + b' # gitleaks:allow",' + data[1:] if stage == kind else data
                layout, digest = self.image(json_transform=transform, directory=root / "image")
                for boundary in ("producer-tampered", "publisher-tampered"):
                    result = self.artifact_check(layout, digest, root / boundary)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn(token, result.stdout + result.stderr)

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

    def sigstore_bundle(self, hashes):
        return {"mediaType": release.SIGSTORE_BUNDLE_MEDIA_TYPE,
                "verificationMaterial": {"tlogEntries": [
                    {"inclusionProof": {"hashes": hashes}}]}}

    def collision_hash(self):
        tail = base64.b64encode(random.Random(41).randbytes(28)).decode()
        encoded = "+" + "C" + "01/" + tail[:37] + "A="
        decoded = base64.b64decode(encoded, validate=True)
        self.assertEqual(len(decoded), 32)
        self.assertEqual(base64.b64encode(decoded).decode(), encoded)
        return encoded

    def test_sigstore_hash_collision_is_scoped_to_exact_media_type_and_path(self):
        seed = self.root / "bundles"
        seed.mkdir()
        path = seed / "bundle.json"
        encoded = self.collision_hash()
        bundle = self.sigstore_bundle([encoded])
        original = json.dumps(bundle, indent=2).encode()
        path.write_bytes(original)
        release.scan(seed)
        self.assertEqual(path.read_bytes(), original)
        for media_type in ("application/vnd.dev.sigstore.bundle.v0.2+json",
                           release.SIGSTORE_BUNDLE_MEDIA_TYPE + "; charset=utf-8", "other"):
            with self.subTest(media_type=media_type):
                changed = copy.deepcopy(bundle)
                changed["mediaType"] = media_type
                path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, "prohibited content.*planning-identifier/text"):
                    release.scan(seed)
        for location in ("root", "proof", "certificate", "nested"):
            with self.subTest(location=location):
                changed = copy.deepcopy(bundle)
                if location == "root":
                    changed["extra"] = encoded
                elif location == "proof":
                    changed["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["extra"] = encoded
                elif location == "certificate":
                    changed["verificationMaterial"]["certificate"] = {"rawBytes": encoded}
                else:
                    changed["extra"] = bundle
                path.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, "prohibited content"):
                    release.scan(seed)
        path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "prohibited content.*configured-literal/text"):
            release.scan(seed, ["C" + "01"])

    def test_original_public_sigstore_bundle_preserves_and_accepts_collision(self):
        source = Path(__file__).parent / "testdata/release/sigstore-inclusion-proof.json"
        fixture = source.read_bytes()
        self.assertEqual(hashlib.sha256(fixture).hexdigest(),
                         "66ec8fc8fc771950acf65c075ea571a65da891de4283e7387687311c65bec86f")
        self.assertTrue(fixture.endswith(b"\n"))
        original = fixture[:-1]
        self.assertEqual(len(original), 20526)
        self.assertEqual(hashlib.sha256(original).hexdigest(),
                         "f5b6af02e20f4c66aa2c9ccffde9a407487babb6ce8c3833576f506d78c65447")
        bundle = json.loads(original)
        hashes = [encoded for entry in bundle["verificationMaterial"]["tlogEntries"]
                  for encoded in entry["inclusionProof"]["hashes"]]
        old_pattern = rb"\b(?:S1\.[0-9]+|PM[0-9]{2}|MO[0-9]{2}|[QCD][0-9]{2})\b"
        self.assertTrue(any(re.search(old_pattern, encoded.encode()) for encoded in hashes))
        seed = self.root / "original-bundle"
        seed.mkdir()
        path = seed / "bundle.json"
        path.write_bytes(original)
        release.scan(seed)
        self.assertEqual(path.read_bytes(), original)

    def test_sigstore_decoded_hashes_keep_existing_content_policy(self):
        seed = self.root / "decoded-hashes"
        seed.mkdir()
        path = seed / "bundle.json"
        values = [b"C" + b"01 ", b"/" + b"home/engineer/private/",
                  b"https://fixture." + b"internal/", b"private-owner-fixture"]
        for decoded in values:
            with self.subTest(kind=decoded[:1]):
                encoded = base64.b64encode(decoded.ljust(32, b"x")).decode()
                path.write_text(json.dumps(self.sigstore_bundle([encoded])))
                with self.assertRaisesRegex(ValueError, "prohibited content") as caught:
                    release.scan(seed, ["private-owner-fixture"])
                self.assertNotIn(decoded.decode(), str(caught.exception))
                self.assertNotIn(encoded, str(caught.exception))
        for decoded in (b"\0" + b"C" + b"01 ", b"\0/" + b"home/engineer/private/"):
            encoded = base64.b64encode(decoded.ljust(32, b"x")).decode()
            path.write_text(json.dumps(self.sigstore_bundle([encoded])))
            if b"home" in decoded:
                with self.assertRaisesRegex(ValueError, "prohibited content.*private-path/text"):
                    release.scan(seed)
            else:
                release.scan(seed)

    def test_sigstore_malformed_hashes_and_container_types_fail_closed(self):
        seed = self.root / "malformed-bundles"
        seed.mkdir()
        path = seed / "bundle.json"
        canonical = base64.b64encode(bytes(range(32))).decode()
        noncanonical = canonical[:-2] + "9="
        self.assertEqual(base64.b64decode(noncanonical), base64.b64decode(canonical))
        for encoded in (None, 1, {}, [], "not-base64", canonical + "\n", canonical.rstrip("="),
                        noncanonical, base64.b64encode(b"x" * 31).decode(),
                        base64.b64encode(b"x" * 33).decode()):
            with self.subTest(hash_type=type(encoded).__name__):
                path.write_text(json.dumps(self.sigstore_bundle([encoded])))
                with self.assertRaisesRegex(ValueError, "prohibited content.*bundle-structure/text"):
                    release.scan(seed)
        for material in (None, [], {"tlogEntries": None}, {"tlogEntries": {}},
                         {"tlogEntries": [None]}, {"tlogEntries": [{"inclusionProof": None}]},
                         {"tlogEntries": [{"inclusionProof": []}]},
                         {"tlogEntries": [{"inclusionProof": {}}]},
                         {"tlogEntries": [{"inclusionProof": {"hashes": "text"}}]}):
            with self.subTest(material_type=type(material).__name__):
                path.write_text(json.dumps({"mediaType": release.SIGSTORE_BUNDLE_MEDIA_TYPE,
                                            "verificationMaterial": material}))
                with self.assertRaisesRegex(ValueError, "prohibited content.*bundle-structure/text"):
                    release.scan(seed)
        path.write_text(json.dumps({"mediaType": release.SIGSTORE_BUNDLE_MEDIA_TYPE}))
        with self.assertRaisesRegex(ValueError, "prohibited content.*bundle-structure/text"):
            release.scan(seed)
        path.write_text('{"mediaType":' + json.dumps(release.SIGSTORE_BUNDLE_MEDIA_TYPE) + ',')
        with self.assertRaisesRegex(ValueError, "prohibited content.*bundle-structure/text"):
            release.scan(seed)

    def test_sigstore_without_inclusion_hashes_keeps_strict_scanning(self):
        seed = self.root / "no-proof"
        seed.mkdir()
        path = seed / "bundle.json"
        for material in ({}, {"tlogEntries": []}, {"tlogEntries": [{}]},
                         {"tlogEntries": [{"inclusionProof": {"hashes": []}}]}):
            with self.subTest(material=material):
                bundle = {"mediaType": release.SIGSTORE_BUNDLE_MEDIA_TYPE,
                          "verificationMaterial": material,
                          "messageSignature": {"messageDigest": {"algorithm": "SHA2_256",
                                                "digest": base64.b64encode(b"x" * 32).decode()}}}
                path.write_text(json.dumps(bundle))
                release.scan(seed)
                bundle["extra"] = self.collision_hash()
                path.write_text(json.dumps(bundle))
                with self.assertRaisesRegex(ValueError, "prohibited content"):
                    release.scan(seed)

    def test_json_duplicate_keys_and_escaped_private_references_are_rejected(self):
        seed = self.root / "json-controls"
        seed.mkdir()
        path = seed / "metadata.json"
        for raw in (b'{"audit":"public","audit":"also public"}',
                    b'{"nested":{"audit":"public","aud\\u0069t":"also public"}}'):
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "prohibited content.*json-structure/text"):
                release.scan(seed)
        encoded = self.collision_hash()
        bundle = json.dumps(self.sigstore_bundle([encoded])).encode()
        path.write_bytes(bundle[:-1] + b',"verificationMaterial":{}}')
        with self.assertRaisesRegex(ValueError, "prohibited content.*json-structure/text"):
            release.scan(seed)
        for raw in (b'{"note":"private-owner-fixtur\\u0065"}',
                    b'{"private-owner-fixtur\\u0065":"public"}',
                    b'"private-owner-fixtur\\u0065"',
                    b'\xef\xbb\xbf{"note":"private-owner-fixtur\\u0065"}',
                    b'{"note":"\\u0043' + b'01"}',
                    b'{"note":"\\u0000\\u0043' + b'01"}',
                    b'{"\\u0000\\u0043' + b'01":"public"}',
                    b'{"note":"\\/home\\/engineer\\/private"}'):
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "prohibited content"):
                release.scan(seed, ["private-owner-fixture"])
        # A source fragment is not a malformed bundle or a JSON object.
        path.write_text('{"public": shell_variable}\n')
        release.scan(seed)

    def test_binary_like_json_openers_keep_existing_scan_policy(self):
        seed = self.root / "binary-openers"
        seed.mkdir()
        path = seed / "content"
        script = Path(__file__).with_name("scan-release-content.sh")
        for data, rejected in ((b"{\xff\0public", False), (b"[\xff\0public", False),
                               (b'{"note":"\xff"}', False),
                               (b"{\xff\0C" + b"01", False),
                               (b"{\xff C" + b"01", True),
                               (b"{\xff\0/" + b"home/engineer/private/", True)):
            with self.subTest(binary=b"\0" in data, rejected=rejected):
                path.write_bytes(data)
                if rejected:
                    with self.assertRaisesRegex(ValueError, "prohibited content"):
                        release.scan(seed)
                else:
                    release.scan(seed)
                result = subprocess.run([str(script), str(seed)], capture_output=True,
                                        text=True, timeout=30)
                if rejected:
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
        path.write_bytes(b'{"mediaType":' + json.dumps(release.SIGSTORE_BUNDLE_MEDIA_TYPE).encode()
                         + b',"note":"\xff"}')
        with self.assertRaisesRegex(ValueError, "prohibited content.*bundle-structure/text"):
            release.scan(seed)

    def test_scan_diagnostics_only_report_fixed_category_and_location(self):
        seed = self.root / "diagnostics"
        seed.mkdir()
        forbidden = "private-owner-fixture"
        path = seed / "public"
        path.write_text(forbidden)
        with self.assertRaisesRegex(ValueError, "configured-literal/text") as caught:
            release.scan(seed, [forbidden])
        self.assertNotIn(forbidden, str(caught.exception))
        self.assertNotIn(str(path), str(caught.exception))
        path.unlink()
        (seed / forbidden).write_text("public")
        with self.assertRaisesRegex(ValueError, "configured-literal/path") as caught:
            release.scan(seed, [forbidden])
        self.assertNotIn(forbidden, str(caught.exception))
        self.assertNotIn(str(seed), str(caught.exception))

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
