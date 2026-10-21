#!/usr/bin/env python3
"""Deterministic runtime archives and strict inspection of the shipped OCI bytes."""

import base64
import binascii
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import zipfile


REQUIRED_NOTICES = (
    "stellwerk-plugin-runtime/LICENSE",
    "go/LICENSE",
    "go/PATENTS",
    "golang.org/x/sys/unix/LICENSE",
    "golang.org/x/sys/PATENTS",
)


def notices(directory):
    directory = Path(directory)
    for name in REQUIRED_NOTICES:
        path = directory / name
        if not path.is_file() or path.is_symlink() or not path.read_bytes().strip():
            raise ValueError("missing, empty or symlinked required license/patent notice")
    for path in directory.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("license tree must contain regular files and directories")


def content(context, arch):
    context = Path(context)
    notices(context / "licenses")
    executable = context / f"runtime-linux-{arch}"
    if arch not in ("amd64", "arm64") or executable.is_symlink() or not executable.is_file():
        raise ValueError("missing runtime executable or unsupported architecture")
    files = {"runtime": (executable.read_bytes(), 0o755)}
    for path in sorted((context / "licenses").rglob("*")):
        if path.is_file():
            files[path.relative_to(context).as_posix()] = (path.read_bytes(), 0o644)
    return files


def tar_bytes(files):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, (data, mode) in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(data), mode, 0
            archive.addfile(entry, io.BytesIO(data))
    return raw.getvalue()


def write_archive(context, arch, output):
    raw = tar_bytes(content(context, arch))
    with open(output, "xb") as file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=0) as compressed:
            compressed.write(raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def chart(source, output):
    files = {}
    with tarfile.open(source, "r:gz") as archive:
        for entry in archive:
            path = PurePosixPath(entry.name)
            if not entry.isfile() or path.is_absolute() or ".." in path.parts or entry.name in files:
                raise ValueError("unexpected chart entry")
            files[entry.name] = (archive.extractfile(entry).read(), 0o644)
    with open(output, "xb") as file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=0) as compressed:
            compressed.write(tar_bytes(files))


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate OCI JSON key")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique)


def blob(layout, descriptor):
    digest, size = descriptor.get("digest", ""), descriptor.get("size")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or type(size) is not int or size < 0:
        raise ValueError("invalid OCI descriptor")
    path = layout / "blobs" / "sha256" / digest[7:]
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or symlinked OCI blob")
    data = path.read_bytes()
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest[7:]:
        raise ValueError("OCI blob digest or size mismatch")
    return data


def export(layout, digest, output):
    layout, output = Path(layout), Path(output)
    if output.exists() or layout.is_symlink():
        raise ValueError("filesystem output must be new and layout must not be a symlink")
    marker_bytes = (layout / "oci-layout").read_bytes()
    if strict_json(marker_bytes) != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("unsupported OCI layout")
    index_bytes = (layout / "index.json").read_bytes()
    index = strict_json(index_bytes)
    selected = [d for d in index["manifests"] if d["digest"] == digest]
    if len(selected) != 1:
        raise ValueError("OCI index must select the requested digest exactly once")
    image_index_bytes = blob(layout, selected[0])
    image_index = strict_json(image_index_bytes)
    manifests = image_index["manifests"]
    if image_index.get("schemaVersion") != 2 or len(manifests) != 2:
        raise ValueError("runtime index must hold exactly two platforms")
    platforms = {(d["platform"]["os"], d["platform"]["architecture"]) for d in manifests}
    if platforms != {("linux", "amd64"), ("linux", "arm64")}:
        raise ValueError("runtime index has the wrong platform set")
    metadata = output / "metadata"
    metadata.mkdir(parents=True)
    # Retain original bytes as well as decoded values for strict scanning.
    (metadata / "oci-layout.json").write_bytes(marker_bytes)
    (metadata / "layout-index.json").write_bytes(index_bytes)
    (metadata / "index.json").write_bytes(image_index_bytes)
    (metadata / "layout-index-decoded.json").write_text(json.dumps(index, sort_keys=True))
    (metadata / "index-decoded.json").write_text(json.dumps(image_index, sort_keys=True))
    for descriptor in manifests:
        arch = descriptor["platform"]["architecture"]
        manifest_bytes = blob(layout, descriptor)
        manifest = strict_json(manifest_bytes)
        if manifest.get("schemaVersion") != 2 or not manifest["layers"]:
            raise ValueError("runtime manifest must hold layers")
        config_bytes = blob(layout, manifest["config"])
        config = strict_json(config_bytes)
        identity = descriptor["digest"][7:]
        (metadata / (identity + "-manifest.json")).write_bytes(manifest_bytes)
        (metadata / (manifest["config"]["digest"][7:] + "-config.json")).write_bytes(config_bytes)
        (metadata / (identity + ".json")).write_text(json.dumps(
            {"descriptor": descriptor, "manifest": manifest, "config": config}, sort_keys=True))
        if (config.get("os"), config.get("architecture"), config.get("config")) != (
            "linux", arch, {"User": "65532:65532", "Entrypoint": ["/runtime"]}
        ):
            raise ValueError("unexpected runtime image configuration")
        diff_ids = []
        destination = output / arch
        destination.mkdir(parents=True)
        for number, layer in enumerate(manifest["layers"]):
            if layer["mediaType"] != "application/vnd.oci.image.layer.v1.tar+gzip":
                raise ValueError("unexpected runtime layer type")
            raw = gzip.decompress(blob(layout, layer))
            diff_ids.append("sha256:" + hashlib.sha256(raw).hexdigest())
            # Keep every original layer for scanning. A merged filesystem can
            # hide credentials removed by a later whiteout.
            layer_root = output / "layers" / arch / str(number)
            layer_root.mkdir(parents=True)
            seen = set()
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                for entry in archive:
                    path = PurePosixPath(entry.name)
                    if (not entry.isfile() or path.is_absolute() or ".." in path.parts
                            or str(path) != entry.name or entry.name in seen
                            or (entry.name != "runtime" and not entry.name.startswith("licenses/"))):
                        raise ValueError("unsafe or unexpected runtime layer entry")
                    seen.add(entry.name)
                    data = archive.extractfile(entry).read()
                    original = layer_root / entry.name
                    original.parent.mkdir(parents=True, exist_ok=True)
                    original.write_bytes(data)
                    target = destination / entry.name
                    if path.name.startswith(".wh."):
                        if entry.size or path.name == ".wh..wh..opq":
                            raise ValueError("invalid or unsupported whiteout")
                        removed = target.with_name(path.name[4:])
                        if removed.is_dir():
                            shutil.rmtree(removed)
                        elif removed.exists():
                            removed.unlink()
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(data)
        if config.get("rootfs") != {"type": "layers", "diff_ids": diff_ids}:
            raise ValueError("runtime layer diff ID mismatch")
        if not (destination / "runtime").is_file():
            raise ValueError("runtime executable missing from layer")
        notices(destination / "licenses")


SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"


def sigstore_hash_paths(value, inspect):
    """Identify only canonical SHA-256 inclusion-proof hashes in v0.3 bundles."""
    if not isinstance(value, dict) or value.get("mediaType") != SIGSTORE_BUNDLE_MEDIA_TYPE:
        return set()

    def malformed():
        raise ValueError("private reference scan found prohibited content (bundle-structure/text)")

    material = value.get("verificationMaterial")
    if not isinstance(material, dict):
        malformed()
    entries = material.get("tlogEntries", [])
    if not isinstance(entries, list):
        malformed()
    paths = set()
    for entry_index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            malformed()
        if "inclusionProof" not in entry:
            continue
        proof = entry["inclusionProof"]
        if not isinstance(proof, dict) or not isinstance(proof.get("hashes"), list):
            malformed()
        for hash_index, encoded in enumerate(proof["hashes"]):
            if not isinstance(encoded, str):
                malformed()
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                malformed()
            if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != encoded:
                malformed()
            inspect(decoded, "text", b"\0" not in decoded)
            paths.add(("verificationMaterial", "tlogEntries", entry_index,
                       "inclusionProof", "hashes", hash_index))
    return paths


def json_scan_projection(data, inspect):
    """Preserve raw JSON except eligible hash tokens, and inspect decoded strings."""
    if b"\0" in data:
        return data
    stripped = data.lstrip()
    if not stripped.startswith((b"{", b"[", b'"', b"\xef\xbb\xbf")):
        return data
    try:
        value = strict_json(data)
    except (json.JSONDecodeError, UnicodeError):
        # JSON fragments also occur in ordinary source files. A fragment claiming
        # the recognized bundle type must not gain an exemption from bad syntax.
        if not stripped.removeprefix(b"\xef\xbb\xbf").lstrip().startswith((b"{", b"[")):
            return data
        for token in re.finditer(rb'"(?:[^"\\]|\\.)*"', data):
            try:
                recognized = json.loads(token.group()) == SIGSTORE_BUNDLE_MEDIA_TYPE
            except (ValueError, UnicodeError):
                continue
            if recognized:
                raise ValueError("private reference scan found prohibited content (bundle-structure/text)")
        return data
    except ValueError:
        raise ValueError("private reference scan found prohibited content (json-structure/text)") from None
    eligible = sigstore_hash_paths(value, inspect)

    def strings(node, path=()):
        if isinstance(node, dict):
            for key, item in node.items():
                yield path + (key,), True, key
                yield from strings(item, path + (key,))
        elif isinstance(node, list):
            for index, item in enumerate(node):
                yield from strings(item, path + (index,))
        elif isinstance(node, str):
            yield path, False, node

    tokens = iter(re.finditer(rb'"(?:[^"\\]|\\.)*"', data))
    pieces, start = [], 0
    for path, is_key, text in strings(value):
        token = next(tokens)
        if not is_key and path in eligible:
            pieces.extend((data[start:token.start()], b'""'))
            start = token.end()
        else:
            decoded = text.encode("utf-8", errors="surrogatepass")
            inspect(decoded, "text")
    pieces.append(data[start:])
    return b"".join(pieces)


def scan(directory, forbidden=()):
    directory = Path(directory)
    common_patterns = [
        ("private-path", rb"/(?:Users|home)/[A-Za-z0-9_.-]+/"),
        ("private-owner", rb"github\.com/[^\s\"'<>]+-enterprise\b"),
        ("private-url", rb"\bhttps?://[a-z0-9.-]+\.(?:internal|localdomain)\b"),
    ] + [("configured-literal", re.escape(value.encode())) for value in forbidden if value]
    text_patterns = [("planning-identifier", rb"\bWX[0-9]+\b"),
                     ("planning-identifier", rb"\b(?:S1\.[0-9]+|PM[0-9]{2}|MO[0-9]{2}|[QCD][0-9]{2})\b")]

    def inspect(data, location, include_text=True):
        for family, pattern in common_patterns + (text_patterns if include_text else []):
            if re.search(pattern, data):
                # Only fixed categories leave this boundary, never values/paths.
                raise ValueError(f"private reference scan found prohibited content ({family}/{location})")

    for path in directory.rglob("*"):
        if path.name == ".gitleaksignore":
            raise ValueError("shipping content cannot supply scanner exemptions")
        if path.is_symlink():
            raise ValueError("refusing symlinked scan content")
        inspect(path.relative_to(directory).as_posix().encode(), "path")
        if path.is_file():
            data = path.read_bytes()
            # Three-character planning identifiers collide with ELF machine
            # instructions. Apply them to text; binary content still gets the
            # complete secret scan and all concrete path/owner/URL patterns.
            inspect(data, "text", False)
            projection = json_scan_projection(data, inspect)
            inspect(projection, "text", b"\0" not in data)


def binary_strings(directory):
    directory = Path(directory)
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError("refusing symlinked scan content")
        # Filenames ship too, and can contain credentials independently of bytes.
        sys.stdout.buffer.write(path.relative_to(directory).as_posix().encode() + b"\n")
        if path.is_file():
            data = path.read_bytes()
            if b"\0" in data:
                for value in re.findall(rb"[\x20-\x7e]{4,}", data):
                    sys.stdout.buffer.write(value + b"\n")


def unpack(directory, output, max_members=20000, max_bytes=512 * 1024 * 1024, max_depth=3):
    """Expose archive members for scanning without trusting archive paths/types."""
    directory, output = Path(directory), Path(output)
    if not directory.is_dir() or directory.is_symlink() or output.exists():
        raise ValueError("archive scan input must exist and output must be new")
    remaining_members, remaining_bytes = max_members, max_bytes
    output.mkdir()

    def archive_path(path):
        return path.name.endswith((".tar.gz", ".tgz", ".tar", ".zip"))

    def extract(source, destination, depth):
        nonlocal remaining_members, remaining_bytes
        if depth > max_depth:
            raise ValueError("archive nesting exceeds scan limit")
        if source.stat().st_size > max_bytes:
            raise ValueError("archive source exceeds scan limit")
        destination.mkdir(parents=True)
        seen = set()

        def write(name, size, is_directory, stream):
            nonlocal remaining_members, remaining_bytes
            path = PurePosixPath(name.rstrip("/") if is_directory else name)
            if (not name or path.is_absolute() or ".." in path.parts or not path.parts
                    or str(path) != (name.rstrip("/") if is_directory else name)
                    or "\\" in name or any(ord(char) < 32 for char in name) or str(path) in seen):
                raise ValueError("unsafe or duplicate archive scan path")
            seen.add(str(path))
            remaining_members -= 1
            remaining_bytes -= size
            if remaining_members < 0 or remaining_bytes < 0 or size < 0:
                raise ValueError("archive content exceeds scan limit")
            target = destination / str(path)
            if is_directory:
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                data = stream.read(size + 1)
                if len(data) != size:
                    raise ValueError("archive scan member size mismatch")
                target.write_bytes(data)

        if source.name.endswith(".zip"):
            with zipfile.ZipFile(source) as archive:
                for entry in archive.infolist():
                    mode = entry.external_attr >> 16
                    if mode & 0o170000 not in (0, 0o100000, 0o040000) or entry.flag_bits & 1:
                        raise ValueError("unsupported archive scan entry")
                    with archive.open(entry) as stream:
                        write(entry.filename, entry.file_size, entry.is_dir(), stream)
        else:
            # Bound decompression before tarfile parses PAX/GNU headers too.
            # Header sizes are attacker-controlled, not just member sizes.
            opener = gzip.open if source.name.endswith((".tar.gz", ".tgz")) else open
            with opener(source, "rb") as compressed:
                raw = compressed.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise ValueError("archive decompression exceeds scan limit")
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                for entry in archive:
                    if not (entry.isfile() or entry.isdir()):
                        raise ValueError("unsupported archive scan entry")
                    write(entry.name, entry.size, entry.isdir(), archive.extractfile(entry) if entry.isfile() else None)
        for number, nested in enumerate(sorted(destination.rglob("*"))):
            if nested.is_file() and archive_path(nested):
                extract(nested, output / f"nested-{depth}-{remaining_members}-{number}", depth + 1)

    for number, source in enumerate(sorted(directory.rglob("*"))):
        if source.is_symlink():
            raise ValueError("refusing symlinked archive scan input")
        if source.is_file() and archive_path(source):
            extract(source, output / str(number), 1)


def main():
    command, *args = sys.argv[1:]
    if command == "notices":
        notices(*args)
    elif command in ("layer", "archive"):
        print(write_archive(*args))
    elif command == "export":
        export(*args)
    elif command == "chart":
        chart(*args)
    elif command == "scan":
        scan(args[0], args[1:])
    elif command == "strings":
        binary_strings(*args)
    elif command == "unpack":
        unpack(*args)
    else:
        raise ValueError("unknown release content command")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile, EOFError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
