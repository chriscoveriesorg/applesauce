#!/usr/bin/env python3
"""Read-only inventory of Apple-supplied decmpfs headers on system files.

Records actual *stored* type numbers, without guessing codec identity. It only
opens ordinary system files read-only; never creates files, changes xattrs,
or issues a compression request. A type appearing here does not prove that the
kernel can decode an arbitrary crafted file using that type.
"""

import argparse
from collections import Counter
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import stat
import sys
import time

MAGIC = b"fpmc"
XATTR_NAME = b"com.apple.decmpfs"
XATTR_SHOWCOMPRESSION = 0x0020
UF_COMPRESSED = 0x0020
MAX_XATTR_SIZE = 3802
DEFAULT_ROOTS = (
    "/usr/bin",
    "/bin",
    "/sbin",
    "/System/Library/CoreServices",
    "/System/Library/Frameworks",
    "/System/Library/PrivateFrameworks",
)
KNOWN_TYPES = {
    3: "zlib-inline", 4: "zlib-fork",
    7: "lzvn-inline", 8: "lzvn-fork",
    11: "lzfse-inline", 12: "lzfse-fork",
    13: "lzbitmap-inline", 14: "lzbitmap-fork",
}


def parse_header(value):
    if len(value) < 16 or len(value) > MAX_XATTR_SIZE:
        raise ValueError("decmpfs attribute length outside 16..3802 bytes")
    if value[:4] != MAGIC:
        raise ValueError("invalid decmpfs magic")
    return {
        "stored_type": int.from_bytes(value[4:8], "little"),
        "logical_size": int.from_bytes(value[8:16], "little"),
        "attribute_bytes": len(value),
    }


class DarwinAttributeReader:
    """Bounded fgetxattr on a pinned O_NOFOLLOW read-only descriptor."""

    def __init__(self):
        if sys.platform != "darwin":
            raise OSError(errno.ENOTSUP, "Darwin fgetxattr is required")
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        self.get = libc.fgetxattr
        self.get.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p,
                             ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
        self.get.restype = ctypes.c_ssize_t

    def __call__(self, fd):
        # XATTR_SHOWCOMPRESSION is needed because decmpfs is normally hidden.
        size = self.get(fd, XATTR_NAME, None, 0, 0, XATTR_SHOWCOMPRESSION)
        if size < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        if size > MAX_XATTR_SIZE:
            raise ValueError("decmpfs attribute too large")
        if size < 16:
            raise ValueError("decmpfs attribute too short")
        buffer = ctypes.create_string_buffer(size)
        actual = self.get(fd, XATTR_NAME, buffer, size, 0,
                          XATTR_SHOWCOMPRESSION)
        if actual < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        if actual != size:
            raise ValueError("decmpfs attribute changed during bounded read")
        return buffer.raw


def new_report():
    return {
        "schema_version": 1,
        "kind": "existing-system-decmpfs-headers-readonly",
        "source": "pre-existing Apple system files only; no synthetic APFS writes",
        "host": {"os": platform.system(), "release": platform.release(),
                 "version": platform.mac_ver()[0], "machine": platform.machine()},
        "files_seen": 0,
        "compressed_flagged": 0,
        "headers_read": 0,
        "types": {},
        "errors": {},
        "roots_visited": [],
        "timed_out": False,
        "file_limit_reached": False,
        "codec_identity_proven": False,
        "kernel_decoder_proven": False,
        "native_raven_mesh_writes_permitted": False,
        "coverage_note": "Bounded sample. Missing type is not evidence of decoder absence.",
    }


def record_header(report, header, physical_stat):
    name = str(header["stored_type"])
    current = report["types"].setdefault(name, {
        "count": 0,
        "known_format": KNOWN_TYPES.get(header["stored_type"]),
        "size_mismatches": 0,
        "smallest_attribute_bytes": MAX_XATTR_SIZE,
        "largest_attribute_bytes": 0,
    })
    current["count"] += 1
    current["size_mismatches"] += int(header["logical_size"] != physical_stat.st_size)
    current["smallest_attribute_bytes"] = min(
        current["smallest_attribute_bytes"], header["attribute_bytes"]
    )
    current["largest_attribute_bytes"] = max(
        current["largest_attribute_bytes"], header["attribute_bytes"]
    )
    report["headers_read"] += 1


def scan_roots(roots, *, max_files=30000, max_seconds=60, attribute_reader=None,
               clock=time.monotonic):
    if max_files < 1 or max_files > 250000 or max_seconds < 1 or max_seconds > 600:
        raise ValueError("scan bounds out of range")
    reader = attribute_reader if attribute_reader is not None else DarwinAttributeReader()
    report = new_report()
    errors = Counter()
    started = clock()
    # A missing no-follow primitive must never silently turn this into a
    # path-following scan, even on an unexpected Python/macOS environment.
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        raise OSError(errno.ENOTSUP, "O_NOFOLLOW is required for read-only inventory")
    open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    open_flags |= nofollow | getattr(os, "O_NONBLOCK", 0)

    def file_identity(info):
        # Metadata changes during an xattr read invalidate the observation.
        return (info.st_dev, info.st_ino, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns,
                getattr(info, "st_flags", 0))
    for root in roots:
        if clock() - started > max_seconds:
            report["timed_out"] = True
            break
        # Never follow a symlink leading outside the explicitly selected root.
        if os.path.islink(root) or not os.path.isdir(root):
            errors["root-unavailable"] += 1
            continue
        report["roots_visited"].append(str(root))
        for directory, subdirectories, filenames in os.walk(root, followlinks=False):
            subdirectories[:] = sorted(
                name for name in subdirectories
                if not os.path.islink(os.path.join(directory, name))
            )
            for name in sorted(filenames):
                if report["files_seen"] >= max_files:
                    report["file_limit_reached"] = True
                    report["errors"] = dict(sorted(errors.items()))
                    return report
                if clock() - started > max_seconds:
                    report["timed_out"] = True
                    report["errors"] = dict(sorted(errors.items()))
                    return report
                path = os.path.join(directory, name)
                report["files_seen"] += 1
                try:
                    before = os.stat(path, follow_symlinks=False)
                    if not stat.S_ISREG(before.st_mode):
                        continue
                    if not (getattr(before, "st_flags", 0) & UF_COMPRESSED):
                        continue
                    report["compressed_flagged"] += 1
                    fd = os.open(path, open_flags)
                    try:
                        after = os.fstat(fd)
                        if (file_identity(before) != file_identity(after)
                                or not stat.S_ISREG(after.st_mode)
                                or not (getattr(after, "st_flags", 0) & UF_COMPRESSED)):
                            errors["file-changed"] += 1
                            continue
                        raw = reader(fd)
                        header = parse_header(raw)
                        final = os.fstat(fd)
                        if file_identity(after) != file_identity(final):
                            errors["file-changed"] += 1
                            continue
                        record_header(report, header, final)
                    finally:
                        os.close(fd)
                except (OSError, ValueError) as error:
                    errors[type(error).__name__] += 1
    report["errors"] = dict(sorted(errors.items()))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-files", type=int, default=30000)
    parser.add_argument("--max-seconds", type=int, default=60)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.platform != "darwin":
        parser.error("system header inventory only runs on macOS")
    try:
        report = scan_roots(DEFAULT_ROOTS, max_files=args.max_files,
                            max_seconds=args.max_seconds)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    # Store aggregate counts only. Never upload contents or system file paths.
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in
                      ("files_seen", "compressed_flagged", "headers_read",
                       "types", "errors", "timed_out", "file_limit_reached")},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
