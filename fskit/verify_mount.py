#!/usr/bin/env python3
"""Read-only acceptance check for a separately mounted ASCF FSKit volume.

This never modifies the source, archive or mounted volume. Run against a signed,
enabled FSKit extension on a disposable macOS host, with the original cleartext
used to create the ASCF archive. --self-test runs portable synthetic tests.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
import subprocess
import stat
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

READ_BYTES = 1024 * 1024
DENIED = {errno.EROFS, errno.EACCES, errno.EPERM}


class MountCheckError(RuntimeError):
    pass


class DarwinStatFS(ctypes.Structure):
    """64-bit Darwin struct statfs from XNU bsd/sys/mount.h.

    The type name is at offset 72. Keep the complete structure so statfs(2)
    can safely write its entire result, including both mountpoint buffers.
    """
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def darwin_filesystem_type(mount):
    """Read f_fstypename from statfs(2), not BSD stat(1)'s file-type %T."""
    if ctypes.sizeof(DarwinStatFS) != 2168 or DarwinStatFS.f_fstypename.offset != 72:
        raise MountCheckError("unsupported Darwin statfs ABI layout")
    info = DarwinStatFS()
    libc = ctypes.CDLL(None, use_errno=True)
    # Intel Darwin retains a legacy unsuffixed statfs entry point. The
    # $INODE64 variant matches our 64-bit ABI; arm64 uses unsuffixed statfs.
    symbol = "statfs$INODE64" if os.uname().machine == "x86_64" else "statfs"
    try:
        call = getattr(libc, symbol)
    except AttributeError as error:
        raise MountCheckError(f"Darwin libc lacks {symbol}") from error
    call.argtypes = (ctypes.c_char_p, ctypes.POINTER(DarwinStatFS))
    call.restype = ctypes.c_int
    if call(os.fsencode(mount), ctypes.byref(info)) != 0:
        code = ctypes.get_errno()
        raise MountCheckError(f"statfs failed for ASCF mount: {os.strerror(code)}")
    name = info.f_fstypename.decode("ascii")
    require(bool(name), "statfs returned an empty filesystem type")
    return name


def require(ok, message):
    if not ok:
        raise MountCheckError(message)


def digest(path, nofollow=False, include_identity=False):
    total = 0
    checksum = hashlib.sha256()
    if nofollow:
        require(hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW unavailable for mounted read")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if nofollow:
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        identity = os.fstat(fd)
        require(stat.S_ISREG(identity.st_mode), "digest input is not a regular file")
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
    result = (total, checksum.hexdigest())
    return (*result, (identity.st_dev, identity.st_ino)) if include_identity else result


def signed_mount_identity(mount):
    """Require the actual ASCF FSKit filesystem and record macOS provenance.

    A generic disk image or APFS volume containing one matching file cannot
    satisfy signed FSKit acceptance. FSKit publishes this type through its
    FSStatFSResult(fileSystemTypeName: "ascf") implementation.
    """
    require(sys.platform == "darwin", "signed FSKit acceptance requires macOS")

    def output(*command):
        try:
            result = subprocess.run(command, check=True, text=True,
                                    capture_output=True, timeout=10)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            raise MountCheckError(f"cannot inspect mounted FSKit provenance: {error}") from error
        value = result.stdout.strip()
        require(bool(value), f"empty mount provenance from {command[0]}")
        return value

    kind = darwin_filesystem_type(mount)
    require(kind == "ascf", f"expected ASCF FSKit mount, found filesystem type {kind!r}")
    return {"filesystem_type": kind,
            "macos_version": output("/usr/bin/sw_vers", "-productVersion"),
            "macos_build": output("/usr/bin/sw_vers", "-buildVersion")}


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
    mount_identity = {}
    if require_real_mount:
        require(os.path.ismount(mount), "path is not a filesystem mount point")
        mount_identity = signed_mount_identity(mount)
    require(original.is_file(), "original cleartext is not a regular file")
    with os.scandir(mount) as scanner:
        entries = list(scanner)
    require(len(entries) == 1, "ASCF mount must expose exactly one restored file")
    entry = entries[0]
    require(entry.is_file(follow_symlinks=False), "mounted entry is not a regular file")
    mounted = mount / entry.name
    require(not os.path.samefile(original, mounted), "source and mounted file are identical")

    original_size, original_sha, original_identity = digest(
        original, nofollow=True, include_identity=True)
    mounted_size, mounted_sha, mounted_identity = digest(
        mounted, nofollow=True, include_identity=True)
    require(original_identity != mounted_identity,
            "mounted file aliases original cleartext after digest")
    require(original_size == mounted_size, "mounted logical byte length differs")
    require(original_sha == mounted_sha, "full mounted SHA-256 differs from cleartext")

    # Open read-only and compare deterministic independent-block boundary
    # windows. The final zero-byte read must return EOF.
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    source_fd = os.open(original, read_flags | os.O_NOFOLLOW)
    try:
        source_stat = os.fstat(source_fd)
        require((source_stat.st_dev, source_stat.st_ino) == original_identity,
                "original file changed between digest and random reads")
        mounted_fd = os.open(mounted, read_flags | os.O_NOFOLLOW)
        try:
            mounted_stat = os.fstat(mounted_fd)
            require((mounted_stat.st_dev, mounted_stat.st_ino) == mounted_identity,
                    "mounted file changed between digest and random reads")
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
            "random_read_offsets": offsets, "readonly_open_denied": True,
            **mount_identity}


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

    def test_digest_rejects_nonregular_descriptor(self):
        # A pathname can change after directory enumeration. Do not read a
        # FIFO or device (which may block indefinitely) as archive cleartext.
        with self.assertRaisesRegex(MountCheckError, "not a regular file"):
            digest(self.mount, nofollow=True)

    def test_mounted_file_hardlink_swap_rejected_after_precheck(self):
        # The path-level samefile precheck can race with the digest opens.
        # Never accept a mount that actually exposes the reference inode.
        real_open = os.open
        swapped = False
        restored_parent = self.restored.parent.resolve(strict=True)

        def swap_before_mounted_digest(path, flags, *args, **kwargs):
            nonlocal swapped
            candidate = Path(path)
            if (not swapped and candidate.name == self.restored.name
                    and candidate.parent.resolve(strict=True) == restored_parent
                    and flags & os.O_ACCMODE == os.O_RDONLY):
                swapped = True
                self.restored.unlink()
                os.link(self.original, self.restored)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=swap_before_mounted_digest):
            with self.assertRaisesRegex(MountCheckError, "aliases original"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(swapped, "hardlink replacement must be exercised")

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

    def test_mounted_regular_file_swap_rejected_after_digest(self):
        # A different regular file with matching sampled bytes must not
        # replace the file whose complete SHA-256 was authenticated.
        real_open = os.open
        restored_parent = self.restored.parent.resolve(strict=True)
        opens = 0
        swapped = False

        def swap_after_digest(path, flags, *args, **kwargs):
            nonlocal opens, swapped
            candidate = Path(path)
            if (candidate.name == self.restored.name
                    and candidate.parent.resolve(strict=True) == restored_parent
                    and flags & os.O_ACCMODE == os.O_RDONLY):
                opens += 1
                if opens == 2:
                    replacement = self.mount / "replacement"
                    replacement.write_bytes(self.restored.read_bytes())
                    replacement.replace(self.restored)
                    swapped = True
            if (candidate.name == self.restored.name
                    and flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR)):
                raise OSError(errno.EROFS, "read-only filesystem")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=swap_after_digest):
            with self.assertRaisesRegex(MountCheckError, "changed between digest"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(swapped, "regular-file replacement must be exercised")

    def test_original_symlink_swap_rejected_before_digest(self):
        # A reference pathname replaced after resolve() must never be followed
        # during the original SHA-256 read, even on a disposable test host.
        real_open = os.open
        original_parent = self.original.parent.resolve(strict=True)
        swapped = False

        def swap_reference(path, flags, *args, **kwargs):
            nonlocal swapped
            candidate = Path(path)
            if (not swapped and candidate.name == self.original.name
                    and candidate.parent.resolve(strict=True) == original_parent):
                swapped = True
                replacement = self.original.with_suffix(".saved")
                self.original.replace(replacement)
                self.original.symlink_to(replacement)
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=swap_reference):
            with self.assertRaises(OSError) as raised:
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(swapped, "reference symlink swap must be exercised")
        self.assertEqual(raised.exception.errno, errno.ELOOP)

    def test_original_regular_file_swap_rejected_after_digest(self):
        # The reference pread must use the same file whose digest was checked.
        real_open = os.open
        original_parent = self.original.parent.resolve(strict=True)
        opens = 0
        swapped = False

        def swap_original(path, flags, *args, **kwargs):
            nonlocal opens, swapped
            candidate = Path(path)
            if (candidate.name == self.original.name
                    and candidate.parent.resolve(strict=True) == original_parent
                    and flags & os.O_ACCMODE == os.O_RDONLY):
                opens += 1
                if opens == 2:
                    replacement = self.original.with_suffix(".replacement")
                    replacement.write_bytes(self.original.read_bytes())
                    replacement.replace(self.original)
                    swapped = True
            if (candidate.name == self.restored.name
                    and flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR)):
                raise OSError(errno.EROFS, "read-only filesystem")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=swap_original):
            with self.assertRaisesRegex(MountCheckError, "original file changed"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(swapped, "original-file replacement must be exercised")

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

    def test_corrupted_random_read_is_rejected_after_matching_digest(self):
        # A correct whole-file digest does not excuse a broken random-read
        # implementation. Inject corruption only into the mounted pread path,
        # after the exhaustive sequential digest has already succeeded.
        real_pread = os.pread
        restored_inode = self.restored.stat().st_ino
        corrupted = False

        def bad_pread(fd, count, offset):
            nonlocal corrupted
            data = real_pread(fd, count, offset)
            if (os.fstat(fd).st_ino == restored_inode and offset == 0
                    and data):
                corrupted = True
                return bytes([data[0] ^ 1]) + data[1:]
            return data

        self.real_open = os.open
        with mock.patch("os.open", side_effect=self.readonly_open), mock.patch(
                "os.pread", side_effect=bad_pread):
            with self.assertRaisesRegex(MountCheckError, "random read disagrees"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(corrupted, "random-read corruption must be exercised")

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

    def check_signed_gate(self, filesystem_type):
        # The signed acceptance path must use macOS statfs, rather than
        # accepting an unrelated mounted disk with one matching file.
        self.real_open = os.open
        seen = []

        def command(argv, **kwargs):
            seen.append(tuple(argv))
            if argv == ("/usr/bin/sw_vers", "-productVersion"):
                value = "27.2"
            elif argv == ("/usr/bin/sw_vers", "-buildVersion"):
                value = "26B123"
            else:
                raise AssertionError(f"unexpected provenance command: {argv}")
            return subprocess.CompletedProcess(argv, 0, stdout=value + "\n", stderr="")

        with mock.patch("sys.platform", "darwin"), mock.patch(
            "os.path.ismount", return_value=True
        ), mock.patch.object(
            sys.modules[__name__], "darwin_filesystem_type", return_value=filesystem_type
        ), mock.patch("subprocess.run", side_effect=command), mock.patch(
            "os.open", side_effect=self.readonly_open
        ):
            outcome = verify_mount(self.mount, self.original)
        return outcome, seen

    def test_darwin_statfs_decodes_actual_filesystem_type(self):
        self.assertEqual(DarwinStatFS.f_fstypename.offset, 72)
        self.assertEqual(ctypes.sizeof(DarwinStatFS), 2168)

        def fake_statfs(path, pointer):
            self.assertEqual(path, os.fsencode(self.mount))
            ctypes.cast(pointer, ctypes.POINTER(DarwinStatFS)).contents.f_fstypename = b"ascf"
            return 0

        call = mock.Mock(side_effect=fake_statfs)
        with mock.patch("ctypes.CDLL", return_value=mock.Mock(statfs=call)), mock.patch(
            "os.uname", return_value=mock.Mock(machine="arm64")
        ):
            self.assertEqual(darwin_filesystem_type(self.mount), "ascf")
        call.assert_called_once()

    def test_darwin_intel_uses_inode64_entry_point(self):
        def fake_statfs(path, pointer):
            ctypes.cast(pointer, ctypes.POINTER(DarwinStatFS)).contents.f_fstypename = b"ascf"
            return 0

        libc = mock.Mock()
        legacy = libc.statfs
        inode64 = mock.Mock(side_effect=fake_statfs)
        setattr(libc, "statfs$INODE64", inode64)
        with mock.patch("ctypes.CDLL", return_value=libc), mock.patch(
            "os.uname", return_value=mock.Mock(machine="x86_64")
        ):
            self.assertEqual(darwin_filesystem_type(self.mount), "ascf")
        inode64.assert_called_once()
        legacy.assert_not_called()

    def test_darwin_statfs_failure_is_closed(self):
        call = mock.Mock(return_value=-1)
        with mock.patch("ctypes.CDLL", return_value=mock.Mock(statfs=call)), mock.patch(
            "ctypes.get_errno", return_value=errno.EIO
        ), mock.patch("os.uname", return_value=mock.Mock(machine="arm64")):
            with self.assertRaisesRegex(MountCheckError, "statfs failed"):
                darwin_filesystem_type(self.mount)

    def test_real_mount_gate_records_fskit_identity_and_macos_build(self):
        report, seen = self.check_signed_gate("ascf")
        self.assertEqual(report["filesystem_type"], "ascf")
        self.assertEqual(report["macos_version"], "27.2")
        self.assertEqual(report["macos_build"], "26B123")
        self.assertEqual(len(seen), 2)

    def test_real_mount_gate_rejects_unrelated_apfs_volume(self):
        with self.assertRaisesRegex(MountCheckError, "expected ASCF FSKit mount"):
            self.check_signed_gate("apfs")

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
