#!/usr/bin/env python3
"""Read-only acceptance check for a separately mounted ASCF FSKit volume.

This never modifies the source, archive or mounted volume. Run against a signed,
enabled FSKit extension on a disposable macOS host, with the original cleartext
used to create the ASCF archive. --self-test runs portable synthetic tests.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

READ_BYTES = 1024 * 1024
DENIED = {errno.EROFS, errno.EACCES, errno.EPERM}


class MountCheckError(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise MountCheckError(message)


def digest(path, nofollow=False):
    total = 0
    checksum = hashlib.sha256()
    if nofollow:
        require(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW unavailable for mounted read")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if nofollow:
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        with os.fdopen(fd, "rb", buffering=0) as source:
            fd = -1
            while True:
                data = source.read(READ_BYTES)
                if not data:
                    break
                total += len(data)
                checksum.update(data)
    finally:
        if fd >= 0:
            os.close(fd)
    return total, checksum.hexdigest()


def sampled_offsets(size):
    # Exercise offset mapping throughout large files, including the first,
    # middle and final independent blocks. The number of reads is bounded:
    # whole-file SHA-256 is the exhaustive data-integrity check.
    require(size >= 0, "invalid negative logical file size")
    values = {0, size, max(0, size - 1), size // 2}
    for block in (4096, 65536, 8 * 1024 * 1024):
        # Initial, central and last block boundaries.
        for boundary in (block, (size // (2 * block)) * block,
                         (size // block) * block):
            for delta in (-1, 0, 1):
                values.add(min(size, max(0, boundary + delta)))
    for index in range(1, 33):
        point = size * index // 33
        for delta in (-1, 0, 1):
            values.add(min(size, max(0, point + delta)))
    return sorted(values)


def verify_mount(mount, original, require_real_mount=True):
    mount = Path(mount).resolve(strict=True)
    original = Path(original).resolve(strict=True)
    require(mount.is_dir(), "mount argument is not a directory")
    if require_real_mount:
        require(os.path.ismount(mount), "path is not a filesystem mount point")
    require(original.is_file(), "original cleartext is not a regular file")
    with os.scandir(mount) as scanner:
        entries = list(scanner)
    require(len(entries) == 1, "ASCF mount must expose exactly one restored file")
    entry = entries[0]
    require(entry.is_file(follow_symlinks=False), "mounted entry is not a regular file")
    mounted = mount / entry.name
    require(not os.path.samefile(original, mounted), "source and mounted file are identical")

    original_size, original_sha = digest(original)
    mounted_size, mounted_sha = digest(mounted, nofollow=True)
    require(original_size == mounted_size, "mounted logical byte length differs")
    require(original_sha == mounted_sha, "full mounted SHA-256 differs from cleartext")

    # Open read-only and compare deterministic independent-block boundary
    # windows. The final zero-byte read must return EOF.
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    source_fd = os.open(original, read_flags)
    try:
        mounted_fd = os.open(mounted, read_flags | os.O_NOFOLLOW)
        try:
            offsets = sampled_offsets(original_size)
            for offset in offsets:
                length = min(READ_BYTES, original_size - offset + 1)
                expected = os.pread(source_fd, length, offset)
                observed = os.pread(mounted_fd, length, offset)
                require(observed == expected, f"random read disagrees at byte {offset}")
            require(os.pread(mounted_fd, 32, original_size) == b"",
                    "mounted read did not return EOF")
            # An offset past EOF must also return an empty result. This catches
            # erroneous offset-to-chunk arithmetic on the FSKit read path.
            require(os.pread(mounted_fd, 32, original_size + 1) == b"",
                    "mounted read beyond EOF returned data")
        finally:
            os.close(mounted_fd)
    finally:
        os.close(source_fd)

    # Both write-only and read-write opens must fail. Never send write(),
    # O_CREAT, unlink(), xattr changes, or renames to a mount.
    for access in (os.O_WRONLY, os.O_RDWR):
        try:
            writable_fd = os.open(mounted, access | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
        except OSError as error:
            require(error.errno in DENIED, f"unexpected write-open error: {error}")
        else:
            os.close(writable_fd)
            raise MountCheckError("mounted file permitted write access")

    return {"result": "pass", "mount": str(mount), "restored_file": entry.name,
            "logical_bytes": original_size, "sha256": original_sha,
            "random_read_offsets": offsets, "readonly_open_denied": True}


class SyntheticAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.mount = base / "mount"
        self.mount.mkdir()
        self.original = base / "original.bin"
        payload = bytes(range(251)) * 530
        self.original.write_bytes(payload)
        self.restored = self.mount / "restored"
        self.restored.write_bytes(payload)

    def readonly_open(self, *args, **kwargs):
        if Path(args[0]).resolve() == self.restored.resolve() and args[1] & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
            raise OSError(errno.EROFS, "read-only filesystem")
        return self.real_open(*args, **kwargs)

    def check(self):
        self.real_open = os.open
        with mock.patch("os.open", side_effect=self.readonly_open):
            return verify_mount(self.mount, self.original, require_real_mount=False)

    def test_clean_random_readback_and_eof(self):
        report = self.check()
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["logical_bytes"], self.original.stat().st_size)
        self.assertIn(65535, report["random_read_offsets"])
        self.assertIn(self.original.stat().st_size, report["random_read_offsets"])

    def test_modified_mounted_payload_fails(self):
        with open(self.restored, "r+b") as altered:
            altered.seek(65536)
            altered.write(b"X")
        with self.assertRaisesRegex(MountCheckError, "SHA-256"):
            self.check()

    def test_mounted_symlink_swap_rejected_before_digest(self):
        # Simulate a mount entry being swapped after scandir() but before
        # the first mounted open. O_NOFOLLOW must reject the replacement.
        real_open = os.open
        swapped = False
        # macOS may report the mount as /private/var/... even when the
        # temporary directory was created under /var/.... Resolve only the
        # *parent*: resolving the leaf would follow the symlink being tested.
        restored_parent = self.restored.parent.resolve(strict=True)

        def targets_restored(path):
            candidate = Path(path)
            return (candidate.name == self.restored.name
                    and candidate.parent.resolve(strict=True) == restored_parent)

        def swap_before_open(path, flags, *args, **kwargs):
            nonlocal swapped
            if targets_restored(path) and not swapped:
                swapped = True
                self.restored.unlink()
                self.restored.symlink_to(self.original)
            if targets_restored(path) and flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
                raise OSError(errno.EROFS, "read-only filesystem")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=swap_before_open):
            with self.assertRaises(OSError) as raised:
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(swapped, "symlink replacement must be exercised")
        self.assertEqual(raised.exception.errno, errno.ELOOP)

    def test_extra_file_refused(self):
        (self.mount / "unexpected").write_bytes(b"")
        with self.assertRaisesRegex(MountCheckError, "exactly one"):
            self.check()

    def test_symlink_refused(self):
        self.restored.unlink()
        self.restored.symlink_to(self.original)
        with self.assertRaisesRegex(MountCheckError, "regular file"):
            self.check()

    def test_writable_mount_refused_without_writing(self):
        original_sha = digest(self.restored)
        with self.assertRaisesRegex(MountCheckError, "permitted write"):
            verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertEqual(original_sha, digest(self.restored))

    def test_readwrite_open_refused_even_if_writeonly_denied(self):
        real_open = os.open

        def selective_open(path, flags, *args, **kwargs):
            if Path(path).resolve() == self.restored.resolve() and flags & os.O_ACCMODE == os.O_WRONLY:
                raise OSError(errno.EROFS, "write-only denied")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=selective_open):
            with self.assertRaisesRegex(MountCheckError, "permitted write"):
                verify_mount(self.mount, self.original, require_real_mount=False)

    def test_write_probes_require_nofollow(self):
        # Require O_NOFOLLOW on both write-open probes, closing a potential
        # symlink swap between verified readback and access checks.
        real_open = os.open
        original_inode = self.original.stat().st_ino
        restored_parent = self.restored.parent.resolve(strict=True)
        probes = []

        def guarded_open(path, flags, *args, **kwargs):
            candidate = Path(path)
            is_restored = (candidate.name == self.restored.name
                           and candidate.parent.resolve(strict=True) == restored_parent)
            if is_restored and flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
                probes.append(flags)
                if not flags & os.O_NOFOLLOW:
                    raise MountCheckError("write probe lacks O_NOFOLLOW")
                raise OSError(errno.EROFS, "read-only filesystem")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=guarded_open):
            report = verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertEqual(report["result"], "pass")
        self.assertEqual(len(probes), 2)
        self.assertEqual(self.original.stat().st_ino, original_inode)

    def test_offsets_cover_distant_blocks_with_bounded_reads(self):
        size = 64 * 1024 * 1024
        offsets = sampled_offsets(size)
        self.assertIn(65535, offsets)
        self.assertIn(8 * 1024 * 1024 - 1, offsets)
        self.assertIn(size // 2, offsets)
        self.assertIn(size - 1, offsets)
        self.assertTrue(any(size * 3 // 4 < point < size - 8 * 1024 * 1024
                            for point in offsets))
        self.assertLess(len(offsets), 160)

    def test_beyond_eof_data_is_rejected(self):
        real_pread = os.pread
        restored_inode = self.restored.stat().st_ino
        eof = self.original.stat().st_size

        def bad_pread(fd, count, offset):
            if os.fstat(fd).st_ino == restored_inode and offset == eof + 1:
                return b"bad"
            return real_pread(fd, count, offset)

        self.real_open = os.open
        with mock.patch("os.open", side_effect=self.readonly_open), mock.patch(
                "os.pread", side_effect=bad_pread):
            with self.assertRaisesRegex(MountCheckError, "beyond EOF"):
                verify_mount(self.mount, self.original, require_real_mount=False)

    def test_nonmount_path_refused_by_default(self):
        with self.assertRaisesRegex(MountCheckError, "mount point"):
            verify_mount(self.mount, self.original)


def main():
    if "--self-test" in sys.argv[1:]:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SyntheticAcceptanceTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mount", required=True, help="FSKit mount point, usually under /Volumes")
    parser.add_argument("--original", required=True, help="uncompressed source test fixture")
    args = parser.parse_args()
    try:
        print(json.dumps(verify_mount(args.mount, args.original), indent=2, sort_keys=True))
    except (MountCheckError, OSError) as error:
        print(f"FSKit readback acceptance FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
