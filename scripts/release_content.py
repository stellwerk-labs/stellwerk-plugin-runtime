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
    if json.loads((layout / "oci-layout").read_text()) != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("unsupported OCI layout")
    index = json.loads((layout / "index.json").read_text())
    selected = [d for d in index["manifests"] if d["digest"] == digest]
    if len(selected) != 1:
        raise ValueError("OCI index must select the requested digest exactly once")
    image_index = json.loads(blob(layout, selected[0]))
    manifests = image_index["manifests"]
    if image_index.get("schemaVersion") != 2 or len(manifests) != 2:
        raise ValueError("runtime index must hold exactly two platforms")
    platforms = {(d["platform"]["os"], d["platform"]["architecture"]) for d in manifests}
    if platforms != {("linux", "amd64"), ("linux", "arm64")}:
        raise ValueError("runtime index has the wrong platform set")
    for descriptor in manifests:
        arch = descriptor["platform"]["architecture"]
        manifest = json.loads(blob(layout, descriptor))
        if manifest.get("schemaVersion") != 2 or not manifest["layers"]:
            raise ValueError("runtime manifest must hold layers")
        config = json.loads(blob(layout, manifest["config"]))
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
    common_patterns = [
        rb"/(?:Users|home)/[A-Za-z0-9_.-]+/",
        rb"github\.com/[^\s\"'<>]+-enterprise\b",
        rb"\bhttps?://[a-z0-9.-]+\.(?:internal|localdomain)\b",
    ] + [re.escape(value.encode()) for value in forbidden if value]
    text_patterns = [rb"\bWX[0-9]+\b", rb"\b(?:S1\.[0-9]+|PM[0-9]{2}|MO[0-9]{2}|[QCD][0-9]{2})\b"]
    for path in Path(directory).rglob("*"):
        if path.is_symlink():
            raise ValueError("refusing symlinked scan content")
        if path.is_file():
            data = path.read_bytes()
            # Three-character planning identifiers collide with ELF machine
            # instructions. Apply them to text; binary content still gets the
            # complete secret scan and all concrete path/owner/URL patterns.
            patterns = common_patterns + ([] if b"\0" in data else text_patterns)
            if any(re.search(pattern, data) for pattern in patterns):
                # Do not print the match or path: either can itself hold a secret.
                raise ValueError("private reference scan found prohibited content")


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
    else:
        raise ValueError("unknown release content command")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, EOFError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
