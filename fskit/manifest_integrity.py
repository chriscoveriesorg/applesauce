#!/usr/bin/env python3
"""Verify signed FSKit handoff bytes via pinned, no-follow file descriptors.

Python 3.9+ and no third-party dependencies. A manifest digest establishes
transfer integrity; signed installation and real mounts require separate proof.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import unittest


class ManifestError(ValueError):
    pass


MAX_MANIFEST = 65536
MAX_MEMBERS = 128
CHUNK = 1024 * 1024
HEX_LINE = re.compile(r"([0-9a-fA-F]{64})  ([A-Za-z0-9_.+/-]+)\Z")
OPEN_FLAGS = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
              | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
DIR_FLAGS = OPEN_FLAGS | getattr(os, "O_DIRECTORY", 0)


def require(condition, message):
    if not condition:
        raise ManifestError(message)


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def safe_member(root_fd, member):
    """Open every directory without following links; return an owned file FD."""
    components = member.split("/")
    require(all(part not in ("", ".", "..") for part in components),
            "unsafe manifest member")
    dir_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            next_fd = os.open(component, DIR_FLAGS, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
            require(stat.S_ISDIR(os.fstat(dir_fd).st_mode),
                    "manifest path crosses non-directory")
        file_fd = os.open(components[-1], OPEN_FLAGS, dir_fd=dir_fd)
        try:
            require(stat.S_ISREG(os.fstat(file_fd).st_mode),
                    "manifest member is not a regular file")
        except BaseException:
            os.close(file_fd)
            raise
        return file_fd
    finally:
        os.close(dir_fd)


def read_manifest(fd):
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_MANIFEST,
            "manifest is not a bounded regular file")
    raw = bytearray()
    while len(raw) <= MAX_MANIFEST:
        block = os.read(fd, min(4096, MAX_MANIFEST + 1 - len(raw)))
        if not block:
            break
        raw.extend(block)
    require(len(raw) <= MAX_MANIFEST and identity(before) == identity(os.fstat(fd)),
            "manifest changed during validation or exceeds size limit")
    try:
        return bytes(raw).decode("ascii")
    except UnicodeDecodeError as error:
        raise ManifestError("manifest is not ASCII") from error


def verify(root, expected):
    """Authenticate members exactly once without path-following hash reads."""
    require(expected and len(expected) <= MAX_MEMBERS
            and len(expected) == len(set(expected)),
            "required manifest path list is empty, duplicated or oversized")
    for member in expected:
        require(HEX_LINE.fullmatch("0" * 64 + "  " + member) is not None
                and all(part not in ("", ".", "..") for part in member.split("/")),
                "unsafe required manifest member")
    root_fd = os.open(root, DIR_FLAGS)
    try:
        manifest_fd = safe_member(root_fd, "SHA256SUMS")
        try:
            listing = read_manifest(manifest_fd)
        finally:
            os.close(manifest_fd)
        require(listing.endswith("\n") and "\r" not in listing,
                "manifest must be newline-terminated with LF records")
        entries = {}
        for line in listing.splitlines():
            match = HEX_LINE.fullmatch(line)
            require(match is not None, "noncanonical SHA256SUMS record")
            digest, member = match.groups()
            require(member in expected and member not in entries,
                    "unexpected or duplicated manifest member")
            entries[member] = digest.lower()
        require(set(entries) == set(expected), "manifest missing required members")
        for member, expected_sha in entries.items():
            fd = safe_member(root_fd, member)
            try:
                start = os.fstat(fd)
                hasher = hashlib.sha256()
                while True:
                    block = os.read(fd, CHUNK)
                    if not block:
                        break
                    hasher.update(block)
                require(identity(start) == identity(os.fstat(fd)),
                        "manifest member changed during digest: " + member)
                require(hasher.hexdigest() == expected_sha,
                        "manifest member SHA-256 mismatch: " + member)
            finally:
                os.close(fd)
    finally:
        os.close(root_fd)
    return len(entries)


class ManifestTests(unittest.TestCase):
    def test_portable_bundle_gates(self):
        members = ["fskit/signed_acceptance.sh", "NEXT-STEPS.txt",
                   "ASCFHost.app/Contents/MacOS/ASCFHost"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for member in members:
                path = root / member
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(member.encode())
            manifest = root / "SHA256SUMS"

            def populate(lines=None):
                if lines is None:
                    lines = [hashlib.sha256((root / member).read_bytes()).hexdigest()
                             + "  " + member for member in members]
                manifest.write_text("\n".join(lines) + "\n", encoding="ascii")

            populate()
            self.assertEqual(verify(root, members), 3)
            (root / "NEXT-STEPS.txt").write_text("tampered")
            with self.assertRaisesRegex(ManifestError, "SHA-256 mismatch"):
                verify(root, members)
            (root / "NEXT-STEPS.txt").write_text("NEXT-STEPS.txt")
            populate()
            self.assertEqual(verify(root, members), 3)
            entries = manifest.read_text().splitlines()
            populate(entries + [entries[0]])
            with self.assertRaisesRegex(ManifestError, "duplicated"):
                verify(root, members)
            populate()
            target = root / "NEXT-STEPS.txt"
            target.rename(root / "original")
            target.symlink_to(root / "original")
            with self.assertRaises(OSError):
                verify(root, members)
            target.unlink()
            (root / "original").rename(target)
            outside = root / "ASCFHost.app/Contents/MacOS/ASCFHost"
            outside.rename(root / "outside")
            outside.parent.rmdir()
            outside.parent.symlink_to(root / "outside-parent")
            with self.assertRaises(OSError):
                verify(root, members)

    def test_reject_special_files_and_unsafe_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "source.ascf"
            path.write_bytes(b"fixture")
            manifest = root / "SHA256SUMS"
            record = hashlib.sha256(b"fixture").hexdigest() + "  source.ascf\n"
            manifest.write_text(record)
            self.assertEqual(verify(root, ["source.ascf"]), 1)
            for data in (record.rstrip("\n"), record + "\n",
                         record.replace("  ", " *"),
                         record + "0" * 64 + "  ../private\n"):
                manifest.write_text(data)
                with self.assertRaises(ManifestError):
                    verify(root, ["source.ascf"])
            manifest.write_text(record)
            # The manifest itself is opened relative to the pinned bundle
            # directory, with O_NOFOLLOW and O_NONBLOCK. It cannot become a
            # redirected digest list or a blocking named pipe.
            manifest.rename(root / "saved-hashes")
            manifest.symlink_to(root / "saved-hashes")
            with self.assertRaises(OSError):
                verify(root, ["source.ascf"])
            manifest.unlink()
            (root / "saved-hashes").rename(manifest)
            manifest.unlink()
            os.mkfifo(manifest)
            with self.assertRaises(ManifestError):
                verify(root, ["source.ascf"])
            manifest.unlink()
            manifest.write_text(record)
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(ManifestError):
                verify(root, ["source.ascf"])


def main():
    if sys.argv[1:] == ["--self-test"]:
        unittest.main(argv=[sys.argv[0]])
        return
    if len(sys.argv) != 2:
        sys.exit("usage: manifest_integrity.py BUNDLE_ROOT")
    expected = os.environ.get("ASCF_REQUIRED_PATHS", "").splitlines()
    try:
        print("Verified", verify(sys.argv[1], expected),
              "manifest-covered regular files with no-follow SHA-256")
    except (ManifestError, OSError) as error:
        sys.exit("ASCF manifest verification refused: " + str(error))


if __name__ == "__main__":
    main()
