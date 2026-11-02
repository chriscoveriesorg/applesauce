#!/usr/bin/env python3
"""Read-only candidate inventory for native APFS decompressor registrations.

These are catalogue/IORegistry *hints*. No type-to-codec mapping, kernel
readback or filesystem write is implied by a positive or negative result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import re
import stat
import sys
from pathlib import Path

MAX_COMPONENT_BYTES = 1 << 20
MAX_PLIST_BYTES = 1 << 20
MAX_PLISTS = 256
# Exact XNU resource names, bounded to prevent huge untrusted integer parsing.
RESOURCE = re.compile(
    r"com\.apple\.AppleFSCompression\.(providesType|Type)(0|[1-9][0-9]{0,4})"
)
# Candidate extension paths only. Do not recursively inspect user files.
SYSTEM_ROOTS = (
    Path("/System/Library/Extensions"),
    Path("/System/Library/DriverExtensions"),
    Path("/Library/Apple/System/Library/Extensions"),
)


def read_limited(path: Path, limit: int) -> bytes:
    if path.is_symlink():
        raise ValueError(f"refusing symlink: {path}")
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"input must be a regular file: {path}")
        if metadata.st_size > limit:
            raise ValueError(f"input exceeds {limit} bytes: {path}")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    if len(data) > limit:
        raise ValueError(f"input exceeds {limit} bytes: {path}")
    return data


def markers_in_log(data: bytes) -> list[dict]:
    try:
        contents = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("component log is not UTF-8") from error
    found = set()
    for line in contents.splitlines():
        for match in RESOURCE.finditer(line):
            # Ignore matching prefix embedded in a longer identifier.
            start, end = match.span()
            if start and (line[start - 1].isalnum() or line[start - 1] in "._"):
                continue
            if end < len(line) and (line[end].isalnum() or line[end] in "._"):
                continue
            found.add((int(match.group(2)), match.group(1)))
    return [{"type": number, "resource": kind, "origin": "ioreg_text"}
            for number, kind in sorted(found)]


def iter_plist_strings(node):
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                yield key
            yield from iter_plist_strings(value)
    elif isinstance(node, (list, tuple)):
        for child in node:
            yield from iter_plist_strings(child)
    elif isinstance(node, str):
        yield node


def markers_in_plist(data: bytes, path: Path) -> list[dict]:
    try:
        document = plistlib.loads(data)
    except (ValueError, TypeError, plistlib.InvalidFileException) as error:
        raise ValueError(f"invalid Info.plist: {path}") from error
    if not isinstance(document, dict):
        raise ValueError(f"plist root must be a dictionary: {path}")
    personalities = document.get("IOKitPersonalities", {})
    if not isinstance(personalities, dict):
        raise ValueError(f"IOKitPersonalities must be a dictionary: {path}")
    bundle_id = document.get("CFBundleIdentifier", "")
    if not isinstance(bundle_id, str):
        raise ValueError(f"CFBundleIdentifier must be a string: {path}")
    found = set()
    for candidate in iter_plist_strings(personalities):
        match = RESOURCE.fullmatch(candidate)
        if match:
            found.add((int(match.group(2)), match.group(1)))
    digest = hashlib.sha256(data).hexdigest()
    return [{
        "type": number,
        "resource": kind,
        "origin": "iokit_personality",
        "bundle_id": bundle_id,
        "plist_sha256": digest,
        "bundle": path.parent.parent.name if path.name == "Info.plist" else path.name,
    } for number, kind in sorted(found)]


def system_plists() -> list[Path]:
    candidates = set()
    for root in SYSTEM_ROOTS:
        if root.is_dir():
            for plist in root.glob("*FSCompression*.kext/Contents/Info.plist"):
                candidates.add(plist)
    return sorted(candidates)


def build_report(component_log: Path | None, plists: list[Path]) -> dict:
    if len(plists) > MAX_PLISTS:
        raise ValueError(f"too many plist files ({len(plists)} > {MAX_PLISTS})")
    observations = []
    source = {"component_log_sha256": None, "plists_scanned": len(plists)}
    if component_log is not None:
        data = read_limited(component_log, MAX_COMPONENT_BYTES)
        source["component_log_sha256"] = hashlib.sha256(data).hexdigest()
        observations.extend(markers_in_log(data))
    for path in sorted(plists):
        observations.extend(markers_in_plist(read_limited(path, MAX_PLIST_BYTES), path))
    observations.sort(key=lambda x: (x["type"], x["origin"], x["resource"],
                                     x.get("bundle_id", ""), x.get("plist_sha256", "")))
    return {
        "schema_version": 1,
        "kind": "read-only-decmpfs-catalogue-hints",
        "source": source,
        "candidate_declarations": observations,
        "candidate_types": sorted({v["type"] for v in observations}),
        "kernel_decoder_proven": False,
        "codec_identity_proven": False,
        "native_raven_mesh_writes_permitted": False,
        "interpretation": (
            "Candidate resource declarations are neither registered decoder "
            "proof nor a type-to-codec mapping. Missing declarations are "
            "inconclusive; require independent on-disk framing and kernel "
            "readback on a separately approved disposable test host."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component-log", type=Path)
    parser.add_argument("--info-plist", type=Path, action="append", default=[])
    parser.add_argument("--system", action="store_true",
                        help="read selected AppleFSCompression system bundle plists")
    args = parser.parse_args(argv)
    files = list(args.info_plist)
    if args.system:
        files.extend(system_plists())
    try:
        report = build_report(args.component_log, files)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
