#!/usr/bin/env python3
"""Deterministic runtime archives and strict inspection of the shipped OCI bytes."""

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


def scan(directory, forbidden=()):
    directory = Path(directory)
    common_patterns = [
        rb"/(?:Users|home)/[A-Za-z0-9_.-]+/",
        rb"github\.com/[^\s\"'<>]+-enterprise\b",
        rb"\bhttps?://[a-z0-9.-]+\.(?:internal|localdomain)\b",
    ] + [re.escape(value.encode()) for value in forbidden if value]
    text_patterns = [rb"\bWX[0-9]+\b", rb"\b(?:S1\.[0-9]+|PM[0-9]{2}|MO[0-9]{2}|[QCD][0-9]{2})\b"]
    for path in directory.rglob("*"):
        if path.name == ".gitleaksignore":
            raise ValueError("shipping content cannot supply scanner exemptions")
        if path.is_symlink():
            raise ValueError("refusing symlinked scan content")
        if any(re.search(pattern, path.relative_to(directory).as_posix().encode())
               for pattern in common_patterns + text_patterns):
            raise ValueError("private reference scan found prohibited content")
        if path.is_file():
            data = path.read_bytes()
            # Three-character planning identifiers collide with ELF machine
            # instructions. Apply them to text; binary content still gets the
            # complete secret scan and all concrete path/owner/URL patterns.
            patterns = common_patterns + ([] if b"\0" in data else text_patterns)
            if any(re.search(pattern, data) for pattern in patterns):
                # Do not print the match or path: either can itself hold a secret.
                raise ValueError("private reference scan found prohibited content")


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
