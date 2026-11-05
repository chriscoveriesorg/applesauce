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


def darwin_statfs(mount):
    """Read Darwin VFS identity through an open directory, resisting path swaps.

    A path-based statfs can inspect a different mount if a volume is
    detached or replaced between the initial mountpoint check and statfs.
    fstatfs pins the inspection to the descriptor, like the FSKit host.
    """
    if ctypes.sizeof(DarwinStatFS) != 2168 or DarwinStatFS.f_fstypename.offset != 72:
        raise MountCheckError("unsupported Darwin statfs ABI layout")
    require(bool(getattr(os, "O_DIRECTORY", 0)), "O_DIRECTORY unavailable for mounted VFS inspection")
    require(bool(getattr(os, "O_NOFOLLOW", 0)), "O_NOFOLLOW unavailable for mounted VFS inspection")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(mount, flags)
    except OSError as error:
        raise MountCheckError(f"cannot open ASCF mount for VFS inspection: {error}") from error
    try:
        try:
            before = os.fstat(fd)
        except OSError as error:
            raise MountCheckError(f"ASCF mount descriptor unavailable before VFS inspection: {error}") from error
        require(stat.S_ISDIR(before.st_mode), "ASCF mount descriptor is not a directory")
        # A mountpoint can be replaced between path validation and opening.
        # Bind the VFS descriptor to the pathname before inspecting it.
        try:
            path_before = os.stat(mount, follow_symlinks=False)
        except OSError as error:
            raise MountCheckError(f"ASCF mount path unavailable before VFS inspection: {error}") from error
        require(stat.S_ISDIR(path_before.st_mode) and
                (path_before.st_dev, path_before.st_ino) == (before.st_dev, before.st_ino),
                "ASCF mount path changed before VFS inspection")
        info = DarwinStatFS()
        libc = ctypes.CDLL(None, use_errno=True)
        # Darwin x86_64 exports the inode64 ABI separately from legacy
        # fstatfs. arm64 uses the unsuffixed symbol for this structure.
        symbol = "fstatfs$INODE64" if os.uname().machine == "x86_64" else "fstatfs"
        try:
            call = getattr(libc, symbol)
        except AttributeError as error:
            raise MountCheckError(f"Darwin libc lacks {symbol}") from error
        call.argtypes = (ctypes.c_int, ctypes.POINTER(DarwinStatFS))
        call.restype = ctypes.c_int
        if call(fd, ctypes.byref(info)) != 0:
            code = ctypes.get_errno()
            raise MountCheckError(f"fstatfs failed for ASCF mount: {os.strerror(code)}")
        try:
            after = os.fstat(fd)
        except OSError as error:
            raise MountCheckError(f"ASCF mount descriptor unavailable during VFS inspection: {error}") from error
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                "ASCF mount descriptor changed during VFS inspection")
        try:
            path_after = os.stat(mount, follow_symlinks=False)
        except OSError as error:
            raise MountCheckError(f"ASCF mount path unavailable during VFS inspection: {error}") from error
        require(stat.S_ISDIR(path_after.st_mode) and
                (path_after.st_dev, path_after.st_ino) == (before.st_dev, before.st_ino),
                "ASCF mount path changed during VFS inspection")
        return info
    finally:
        # Preserve the original verification refusal if descriptor cleanup
        # also fails; otherwise a close error must fail acceptance itself.
        already_failing = sys.exc_info()[0] is not None
        try:
            os.close(fd)
        except OSError as error:
            if not already_failing:
                raise MountCheckError(f"cannot close ASCF mount VFS descriptor: {error}") from error


def darwin_filesystem_type(mount):
    """Read f_fstypename from statfs(2), not BSD stat(1)'s file-type %T."""
    try:
        name = darwin_statfs(mount).f_fstypename.decode("ascii")
    except UnicodeDecodeError as error:
        raise MountCheckError("invalid non-ASCII filesystem type") from error
    require(bool(name), "statfs returned an empty filesystem type")
    return name


def darwin_mount_flags(mount):
    return int(darwin_statfs(mount).f_flags)


def require(ok, message):
    if not ok:
        raise MountCheckError(message)


def digest(path, nofollow=False, include_identity=False):
    total = 0
    checksum = hashlib.sha256()
    if nofollow:
        require(bool(getattr(os, "O_NOFOLLOW", 0)), "O_NOFOLLOW unavailable for mounted read")
    require(bool(getattr(os, "O_NONBLOCK", 0)), "O_NONBLOCK unavailable for safe descriptor open")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK
    if nofollow:
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP and nofollow:
            # Keep the no-follow security refusal recognizable to both
            # operators and tests. Linux/macOS use different ELOOP numbers.
            raise MountCheckError("digest input symlink refused by O_NOFOLLOW") from error
        raise MountCheckError(f"cannot open digest input: {error}") from error
    try:
        try:
            identity = os.fstat(fd)
        except OSError as error:
            raise MountCheckError(f"cannot inspect digest descriptor: {error}") from error
        require(stat.S_ISREG(identity.st_mode), "digest input is not a regular file")
        with os.fdopen(fd, "rb", buffering=0) as source:
            fd = -1
            while True:
                try:
                    data = source.read(READ_BYTES)
                except OSError as error:
                    raise MountCheckError(f"cannot read digest input: {error}") from error
                if not data:
                    break
                total += len(data)
                checksum.update(data)
            try:
                after = os.fstat(source.fileno())
            except OSError as error:
                raise MountCheckError(f"cannot re-inspect digest descriptor: {error}") from error
            require((identity.st_dev, identity.st_ino, identity.st_size,
                     identity.st_mtime_ns, identity.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns),
                    "digest input changed during hashing")
            require(total == identity.st_size,
                    "digest input length changed during hashing")
    finally:
        if fd >= 0:
            already_failing = sys.exc_info()[0] is not None
            try:
                os.close(fd)
            except OSError as error:
                if not already_failing:
                    raise MountCheckError(f"cannot close digest descriptor: {error}") from error
    result = (total, checksum.hexdigest())
    return (*result, (identity.st_dev, identity.st_ino, identity.st_size,
                      identity.st_mtime_ns, identity.st_ctime_ns)) if include_identity else result


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

    # Read type and flags from one statfs record: separate calls could
    # observe different mounts if the path is remounted between checks.
    filesystem = darwin_statfs(mount)
    try:
        kind = filesystem.f_fstypename.decode("ascii")
    except UnicodeDecodeError as error:
        raise MountCheckError("invalid non-ASCII FSKit filesystem type") from error
    require(kind == "ascf", f"expected ASCF FSKit mount, found filesystem type {kind!r}")
    # VFS must acknowledge a kernel-level read-only mount. Handler-level
    # EROFS responses remain mandatory defense in depth.
    flags = int(filesystem.f_flags)
    require(flags & 0x1, "FSKit mount lacks Darwin MNT_RDONLY (kernel read-only flag)")
    return {"filesystem_type": kind, "mount_flags": flags, "kernel_readonly": True,
            "mount_fsid": [int(filesystem.f_fsid[0]), int(filesystem.f_fsid[1])],
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
    # Resolve parent aliases (including macOS /var), but never silently
    # follow a symlink supplied as the mountpoint itself.
    try:
        mount_leaf = os.lstat(mount)
    except OSError as error:
        raise MountCheckError(f"cannot inspect mount argument: {error}") from error
    require(not stat.S_ISLNK(mount_leaf.st_mode),
            "mount argument must not be a symlink")
    try:
        mount = Path(mount).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise MountCheckError(f"cannot resolve mount argument: {error}") from error
    # Preserve the reference leaf: resolve() would silently follow a symlink
    # before digest() can enforce O_NOFOLLOW on its opened descriptor.
    original = Path(os.path.abspath(original))
    try:
        mount_is_dir = mount.is_dir()
    except OSError as error:
        raise MountCheckError(f"cannot inspect mount directory: {error}") from error
    require(mount_is_dir, "mount argument is not a directory")
    try:
        mount_stat = os.stat(mount, follow_symlinks=False)
    except OSError as error:
        raise MountCheckError(f"cannot inspect resolved mount path: {error}") from error
    require(stat.S_ISDIR(mount_stat.st_mode), "mount path is not a directory")
    mount_identity_pair = (mount_stat.st_dev, mount_stat.st_ino)
    mount_identity = {}
    if require_real_mount:
        require(os.path.ismount(mount), "path is not a filesystem mount point")
        mount_identity = signed_mount_identity(mount)
    try:
        original_is_file = original.is_file()
    except OSError as error:
        raise MountCheckError(f"cannot inspect original cleartext: {error}") from error
    require(original_is_file, "original cleartext is not a regular file")
    try:
        with os.scandir(mount) as scanner:
            entries = list(scanner)
    except OSError as error:
        raise MountCheckError("cannot enumerate ASCF mount entries") from error
    require(len(entries) == 1, "ASCF mount must expose exactly one restored file")
    entry = entries[0]
    try:
        entry_is_file = entry.is_file(follow_symlinks=False)
    except OSError as error:
        raise MountCheckError("cannot inspect mounted directory entry") from error
    require(entry_is_file, "mounted entry is not a regular file")
    mounted = mount / entry.name
    try:
        aliases_original = os.path.samefile(original, mounted)
    except OSError as error:
        raise MountCheckError(f"cannot compare mounted and original file identities: {error}") from error
    require(not aliases_original, "source and mounted file are identical")

    original_size, original_sha, original_identity = digest(
        original, nofollow=True, include_identity=True)
    mounted_size, mounted_sha, mounted_identity = digest(
        mounted, nofollow=True, include_identity=True)
    require(original_identity[:2] != mounted_identity[:2],
            "mounted file aliases original cleartext after digest")
    require(original_size == mounted_size, "mounted logical byte length differs")
    require(original_sha == mounted_sha, "full mounted SHA-256 differs from cleartext")

    # Open read-only and compare deterministic independent-block boundary
    # windows. The final zero-byte read must return EOF.
    require(bool(getattr(os, "O_NONBLOCK", 0)), "O_NONBLOCK unavailable for safe descriptor open")
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK
    try:
        source_fd = os.open(original, read_flags | os.O_NOFOLLOW)
    except OSError as error:
        raise MountCheckError(f"cannot reopen original for random reads: {error}") from error
    try:
        try:
            source_stat = os.fstat(source_fd)
        except OSError as error:
            raise MountCheckError(f"cannot inspect random-read original descriptor: {error}") from error
        require(stat.S_ISREG(source_stat.st_mode), "random-read original is not a regular file")
        require((source_stat.st_dev, source_stat.st_ino, source_stat.st_size,
                 source_stat.st_mtime_ns, source_stat.st_ctime_ns) == original_identity,
                "original file changed between digest and random reads")
        try:
            mounted_fd = os.open(mounted, read_flags | os.O_NOFOLLOW)
        except OSError as error:
            raise MountCheckError(f"cannot reopen mounted file for random reads: {error}") from error
        try:
            try:
                mounted_stat = os.fstat(mounted_fd)
            except OSError as error:
                raise MountCheckError(f"cannot inspect random-read mounted descriptor: {error}") from error
            require(stat.S_ISREG(mounted_stat.st_mode), "random-read mounted input is not a regular file")
            require((mounted_stat.st_dev, mounted_stat.st_ino, mounted_stat.st_size,
                     mounted_stat.st_mtime_ns, mounted_stat.st_ctime_ns) == mounted_identity,
                    "mounted file changed between digest and random reads")
            offsets = sampled_offsets(original_size)
            for offset in offsets:
                length = min(READ_BYTES, original_size - offset + 1)
                try:
                    expected = os.pread(source_fd, length, offset)
                    observed = os.pread(mounted_fd, length, offset)
                except OSError as error:
                    raise MountCheckError(f"random read failed at byte {offset}: {error}") from error
                expected_length = min(length, original_size - offset)
                require(len(expected) == expected_length,
                        f"original random read returned short bytes at byte {offset}")
                require(len(observed) == expected_length,
                        f"mounted random read returned short bytes at byte {offset}")
                require(observed == expected, f"random read disagrees at byte {offset}")
            # EOF and beyond-EOF are independent FSKit calls. Propagate read
            # errors as explicit acceptance failures, never as proof of EOF.
            for eof_offset, label in ((original_size, "at EOF"),
                                      (original_size + 1, "beyond EOF")):
                try:
                    eof_data = os.pread(mounted_fd, 32, eof_offset)
                except OSError as error:
                    raise MountCheckError(
                        f"mounted EOF read failed {label} (byte {eof_offset}): {error}"
                    ) from error
                require(eof_data == b"",
                        f"mounted read {label} returned data")
            # A descriptor can retain its inode while bytes change during
            # random-read acceptance. Reject observable concurrent mutations.
            for fd, before, label in ((source_fd, source_stat, "original"),
                                      (mounted_fd, mounted_stat, "mounted")):
                try:
                    after = os.fstat(fd)
                except OSError as error:
                    raise MountCheckError(
                        f"cannot inspect final random-read {label} descriptor: {error}"
                    ) from error
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                require(all(getattr(before, field) == getattr(after, field)
                            for field in fields),
                        f"{label} changed during random-read verification")
        finally:
            # Cleanup must not replace the original integrity refusal.
            failing = sys.exc_info()[0] is not None
            try:
                os.close(mounted_fd)
            except OSError as error:
                if not failing:
                    raise MountCheckError(f"cannot close mounted random-read descriptor: {error}") from error
    finally:
        failing = sys.exc_info()[0] is not None
        try:
            os.close(source_fd)
        except OSError as error:
            if not failing:
                raise MountCheckError(f"cannot close original random-read descriptor: {error}") from error

    # Both write-only and read-write opens must fail. Never send write(),
    # O_CREAT, unlink(), xattr changes, or renames to a mount.
    for access in (os.O_WRONLY, os.O_RDWR):
        try:
            writable_fd = os.open(mounted, access | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK | os.O_NOFOLLOW)
        except OSError as error:
            require(error.errno in DENIED, f"unexpected write-open error: {error}")
        else:
            # A successful writable open is already a safety failure. Even if
            # closing that descriptor fails, retain the primary refusal.
            try:
                os.close(writable_fd)
            except OSError as error:
                raise MountCheckError(
                    f"mounted file permitted write access (close also failed: {error})"
                ) from error
            raise MountCheckError("mounted file permitted write access")

    # Revalidate pathname bindings after negative write probes: a replacement
    # between authenticated reads and the final report must not be accepted.
    for path, identity, label in ((original, original_identity, "original"),
                                  (mounted, mounted_identity, "mounted")):
        try:
            current = os.stat(path, follow_symlinks=False)
        except OSError as error:
            raise MountCheckError(f"{label} path disappeared after verification: {error}") from error
        require(stat.S_ISREG(current.st_mode) and
                (current.st_dev, current.st_ino, current.st_size,
                 current.st_mtime_ns, current.st_ctime_ns) == identity,
                f"{label} path changed after verification")

    # A second directory entry introduced during write probes invalidates the
    # one-file volume contract, even when the authenticated file is unchanged.
    try:
        with os.scandir(mount) as scanner:
            final_entries = list(scanner)
    except OSError as error:
        raise MountCheckError("cannot enumerate final ASCF mount entries") from error
    require(len(final_entries) == 1 and final_entries[0].name == entry.name,
            "ASCF mount entries changed after verification")
    try:
        final_entry_is_file = final_entries[0].is_file(follow_symlinks=False)
    except OSError as error:
        raise MountCheckError("cannot inspect final mounted directory entry") from error
    require(final_entry_is_file, "ASCF mount entries changed after verification")
    # Directory enumeration can race with replacement of its sole file.
    # Rebind the final pathname to the authenticated digest-time identity.
    try:
        final_file_stat = os.stat(mounted, follow_symlinks=False)
    except OSError as error:
        raise MountCheckError("mounted path unavailable during final verification") from error
    require(stat.S_ISREG(final_file_stat.st_mode) and
            (final_file_stat.st_dev, final_file_stat.st_ino, final_file_stat.st_size,
             final_file_stat.st_mtime_ns, final_file_stat.st_ctime_ns) == mounted_identity,
            "mounted path changed during final directory enumeration")

    # Final directory enumeration is not atomic with the earlier source
    # pathname check. Rebind the source after enumeration as well.
    try:
        final_original_stat = os.stat(original, follow_symlinks=False)
    except OSError as error:
        raise MountCheckError("original path unavailable during final verification") from error
    require(stat.S_ISREG(final_original_stat.st_mode) and
            (final_original_stat.st_dev, final_original_stat.st_ino,
             final_original_stat.st_size, final_original_stat.st_mtime_ns,
             final_original_stat.st_ctime_ns) == original_identity,
            "original path changed during final directory enumeration")

    # The directory itself must still be the one authenticated at entry.
    # Otherwise a same-name replacement mount could inherit the final checks.
    try:
        final_mount_stat = os.stat(mount, follow_symlinks=False)
    except OSError as error:
        raise MountCheckError("mount path unavailable during final verification") from error
    require(stat.S_ISDIR(final_mount_stat.st_mode) and
            (final_mount_stat.st_dev, final_mount_stat.st_ino) == mount_identity_pair,
            "ASCF mount directory changed during verification")
    if require_real_mount:
        require(os.path.ismount(mount), "ASCF mount disappeared during verification")
        final_provenance = signed_mount_identity(mount)
        require(final_provenance == mount_identity,
                "ASCF mount provenance changed during verification")

    return {"result": "pass", "mount": str(mount), "restored_file": entry.name,
            "mount_device": int(mount_identity_pair[0]),
            "mount_inode": int(mount_identity_pair[1]),
            "logical_bytes": original_size, "sha256": original_sha,
            "random_read_offsets": offsets, "readonly_open_denied": True,
            **mount_identity}


class SyntheticAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        # Resolve /var -> /private/var on macOS before injecting path-swap
        # failures. verify_mount() canonicalizes its mount argument, and the
        # mocked os.stat/os.scandir paths must use that same spelling.
        base = Path(self.tmp.name).resolve(strict=True)
        self.mount = base / "mount"
        self.mount.mkdir()
        self.original = base / "original.bin"
        payload = bytes(range(251)) * 530
        self.original.write_bytes(payload)
        self.restored = self.mount / "restored"
        self.restored.write_bytes(payload)

    def test_original_file_probe_io_error_fails_closed(self):
        # An I/O failure while probing the reference must reject acceptance.
        real_is_file = Path.is_file

        def fail_original_probe(path):
            if path == self.original:
                raise OSError(errno.EIO, "synthetic original file probe failure")
            return real_is_file(path)

        with mock.patch.object(Path, "is_file", autospec=True, side_effect=fail_original_probe):
            with self.assertRaisesRegex(MountCheckError, "cannot inspect original cleartext"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertEqual(self.check()["result"], "pass")

    def test_mount_directory_probe_io_error_fails_closed(self):
        # A failed mount directory probe must remain a controlled refusal.
        real_is_dir = Path.is_dir

        def fail_mount_probe(path):
            if path == self.mount:
                raise OSError(errno.EIO, "synthetic mount directory probe failure")
            return real_is_dir(path)

        with mock.patch.object(Path, "is_dir", autospec=True, side_effect=fail_mount_probe):
            with self.assertRaisesRegex(MountCheckError, "cannot inspect mount directory"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertEqual(self.check()["result"], "pass")

    def test_writable_open_close_failure_preserves_refusal(self):
        # Never actually open the mounted fixture writable: inject a harmless
        # read-only descriptor and fail its cleanup after closing it.
        real_open, real_close = os.open, os.close
        injected = set()

        def open_probe(path, flags, *args, **kwargs):
            if Path(path) == self.restored and flags & os.O_ACCMODE:
                fd = real_open(self.original, os.O_RDONLY)
                injected.add(fd)
                return fd
            return real_open(path, flags, *args, **kwargs)

        def close_probe(fd):
            real_close(fd)
            if fd in injected:
                injected.remove(fd)
                raise OSError(errno.EIO, "synthetic close failure")

        with mock.patch.object(os, "open", side_effect=open_probe), \
             mock.patch.object(os, "close", side_effect=close_probe):
            with self.assertRaisesRegex(MountCheckError, "permitted write access"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertFalse(injected)

    def test_random_read_final_fstat_errors_fail_closed(self):
        # A descriptor can fail after all random reads have succeeded.
        real_fstat = os.fstat
        real_pread = os.pread
        for target in (1, 2):
            with self.subTest(target=target):
                sampled = False
                final_calls = 0

                def recording_pread(fd, length, offset):
                    nonlocal sampled
                    sampled = True
                    return real_pread(fd, length, offset)

                def failing_fstat(fd):
                    nonlocal final_calls
                    if sampled:
                        final_calls += 1
                        if final_calls == target:
                            raise OSError(errno.EIO, "synthetic final fstat failure")
                    return real_fstat(fd)

                with mock.patch("os.pread", side_effect=recording_pread):
                    with mock.patch("os.fstat", side_effect=failing_fstat):
                        with self.assertRaisesRegex(
                                MountCheckError, "cannot inspect final random-read"):
                            self.check()
        self.assertEqual(self.check()["result"], "pass")

    def test_random_read_initial_fstat_errors_fail_closed(self):
        # A descriptor can become unavailable after a successful reopen.
        real_fstat = os.fstat
        for target in (1, 2):
            with self.subTest(target=target):
                # digest() performs two fstat calls per file; target only the
                # initial random-read fstat after both digests have completed.
                calls = 0
                def failing_fstat(fd):
                    nonlocal calls
                    calls += 1
                    if calls == 4 + target:
                        raise OSError(errno.EIO, "synthetic random-read fstat failure")
                    return real_fstat(fd)
                with mock.patch("os.fstat", side_effect=failing_fstat):
                    with self.assertRaisesRegex(MountCheckError, "cannot inspect random-read"):
                        self.check()
        self.assertEqual(self.check()["result"], "pass")

    def test_random_read_io_errors_fail_closed(self):
        # A successful full digest does not guarantee subsequent pread works.
        # Exercise both descriptors without requiring a real FSKit mount.
        real_pread = os.pread
        for failing_call in (1, 2):
            with self.subTest(failing_call=failing_call):
                calls = 0
                def failing_pread(fd, length, offset):
                    nonlocal calls
                    calls += 1
                    if calls == failing_call:
                        raise OSError(errno.EIO, "synthetic pread failure")
                    return real_pread(fd, length, offset)
                with mock.patch("os.pread", side_effect=failing_pread):
                    with self.assertRaisesRegex(MountCheckError, "random read failed"):
                        verify_mount(self.mount, self.original, require_real_mount=False)
        # The synthetic file lives on a writable host filesystem. Model only
        # the signed FSKit EROFS write-open rule for the positive control.
        self.assertEqual(self.check()["result"], "pass")

    def test_random_read_short_positive_results_fail_closed(self):
        # POSIX pread can return a positive short count without raising.
        # Requiring complete windows prevents incomplete FSKit readback from
        # masquerading as a successful authenticated random read.
        real_pread = os.pread
        for shortened_call, label in ((1, "original"), (2, "mounted")):
            with self.subTest(shortened_call=shortened_call):
                calls = 0

                def short_pread(fd, length, offset):
                    nonlocal calls
                    calls += 1
                    data = real_pread(fd, length, offset)
                    return data[:-1] if calls == shortened_call else data

                with mock.patch("os.pread", side_effect=short_pread):
                    with self.assertRaisesRegex(
                            MountCheckError, label + " random read returned short bytes"):
                        self.check()
        self.assertEqual(self.check()["result"], "pass")

    def test_eof_read_io_errors_fail_closed(self):
        # The last two read operations check EOF and beyond-EOF separately.
        # An EIO at either point must not be reported as a legitimate EOF.
        real_pread = os.pread
        size = self.original.stat().st_size
        for failed_offset in (size, size + 1):
            with self.subTest(failed_offset=failed_offset):
                def failing_eof(fd, length, offset):
                    if offset == failed_offset and length == 32:
                        raise OSError(errno.EIO, "synthetic EOF I/O failure")
                    return real_pread(fd, length, offset)

                with mock.patch("os.pread", side_effect=failing_eof):
                    with self.assertRaisesRegex(MountCheckError, "mounted EOF read failed"):
                        self.check()
        self.assertEqual(self.check()["result"], "pass")

    def test_digest_cleanup_does_not_mask_primary_error(self):
        # fdopen may fail before assuming ownership of the raw descriptor.
        # A secondary close failure must not mask the primary exception.
        with mock.patch("os.fdopen", side_effect=OSError(errno.EIO, "fdopen failed")):
            with mock.patch("os.close", side_effect=OSError(errno.EBADF, "close failed")):
                with self.assertRaisesRegex(OSError, "fdopen failed"):
                    digest(self.original)
        self.assertEqual(digest(self.original)[0], self.original.stat().st_size)

    def test_digest_read_and_final_fstat_fail_closed(self):
        # A read error or late descriptor inspection error must never pass
        # acceptance, even if the initial fstat succeeded.
        real_fdopen = os.fdopen
        class ReadFailure:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                self.stream.__enter__()
                return self
            def __exit__(self, *args):
                return self.stream.__exit__(*args)
            def read(self, size):
                raise OSError(errno.EIO, "synthetic digest read failure")
            def fileno(self):
                return self.stream.fileno()

        def failing_fdopen(*args, **kwargs):
            return ReadFailure(real_fdopen(*args, **kwargs))

        with mock.patch("os.fdopen", side_effect=failing_fdopen):
            with self.assertRaisesRegex(MountCheckError, "cannot read digest input"):
                digest(self.original)

        real_fstat = os.fstat
        calls = 0
        def failing_final_fstat(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError(errno.EIO, "synthetic late fstat failure")
            return real_fstat(fd)

        with mock.patch("os.fstat", side_effect=failing_final_fstat):
            with self.assertRaisesRegex(MountCheckError, "cannot re-inspect digest descriptor"):
                digest(self.original)
        self.assertEqual(calls, 2)
        self.assertEqual(digest(self.original)[1],
                         hashlib.sha256(self.original.read_bytes()).hexdigest())

    def test_digest_open_and_fstat_fail_closed(self):
        # Synthetic failures must be controlled refusals, not raw OS errors.
        with mock.patch("os.open", side_effect=OSError(errno.EIO, "synthetic open failure")):
            with self.assertRaisesRegex(MountCheckError, "cannot open digest input"):
                digest(self.original)

        real_open = os.open
        with mock.patch("os.fstat", side_effect=OSError(errno.EIO, "synthetic fstat failure")):
            with self.assertRaisesRegex(MountCheckError, "cannot inspect digest descriptor"):
                digest(self.original)
        # The failed descriptor inspection must not leak an open descriptor.
        self.assertEqual(digest(self.original), (self.original.stat().st_size,
                         hashlib.sha256(self.original.read_bytes()).hexdigest()))

    def test_mount_enumeration_disappearance_fails_closed(self):
        # A disappearing mount or unreadable directory must fail through the
        # controlled acceptance error path at either directory scan.
        real_scandir = os.scandir
        for failing_scan, expected in ((1, "cannot enumerate ASCF mount entries"),
                                       (2, "cannot enumerate final ASCF mount entries")):
            with self.subTest(failing_scan=failing_scan):
                scans = 0

                def failing_scandir(path):
                    nonlocal scans
                    if Path(path) == self.mount:
                        scans += 1
                        if scans == failing_scan:
                            raise OSError(errno.EIO, "synthetic directory read failure")
                    return real_scandir(path)

                self.real_open = os.open
                with mock.patch("os.open", side_effect=self.readonly_open), \
                        mock.patch("os.scandir", side_effect=failing_scandir):
                    with self.assertRaisesRegex(MountCheckError, expected):
                        verify_mount(self.mount, self.original, require_real_mount=False)
                self.assertEqual(scans, failing_scan)

    def test_directory_entry_stat_failure_fails_closed(self):
        # DirEntry.is_file() can fail after a successful directory scan.
        real_scandir = os.scandir
        for failing_scan, expected in ((1, "cannot inspect mounted directory entry"),
                                       (2, "cannot inspect final mounted directory entry")):
            with self.subTest(failing_scan=failing_scan):
                scans = 0

                class FailingEntry:
                    def __init__(self, entry):
                        self.name = entry.name

                    def is_file(self, follow_symlinks=True):
                        raise OSError(errno.EIO, "synthetic entry stat failure")

                class WrappedScanner:
                    def __init__(self, scanner, fail):
                        self.scanner = scanner
                        self.fail = fail

                    def __enter__(self):
                        self.scanner.__enter__()
                        return self

                    def __exit__(self, *args):
                        return self.scanner.__exit__(*args)

                    def __iter__(self):
                        for item in self.scanner:
                            yield FailingEntry(item) if self.fail else item

                def failing_scandir(path):
                    nonlocal scans
                    scanner = real_scandir(path)
                    if Path(path) == self.mount:
                        scans += 1
                        return WrappedScanner(scanner, scans == failing_scan)
                    return scanner

                self.real_open = os.open
                with mock.patch("os.open", side_effect=self.readonly_open), \
                        mock.patch("os.scandir", side_effect=failing_scandir):
                    with self.assertRaisesRegex(MountCheckError, expected):
                        verify_mount(self.mount, self.original, require_real_mount=False)
                self.assertEqual(scans, failing_scan)

    def test_mount_parent_disappears_during_resolution_fails_closed(self):
        # lstat can succeed before a parent component disappears or an
        # alias loop is detected by strict canonicalization.
        original_resolve = Path.resolve

        def fail_mount_resolution(path, *args, **kwargs):
            if path == self.mount:
                raise FileNotFoundError(errno.ENOENT, "synthetic parent removal")
            return original_resolve(path, *args, **kwargs)

        with mock.patch.object(Path, "resolve", autospec=True,
                               side_effect=fail_mount_resolution):
            with self.assertRaisesRegex(MountCheckError, "cannot resolve mount argument"):
                verify_mount(self.mount, self.original, require_real_mount=False)

    def test_mount_disappears_after_resolution_fails_closed(self):
        # The mount can vanish between strict resolution and the first stat.
        real_stat = os.stat
        def missing_mount_stat(path, *args, **kwargs):
            if Path(path) == self.mount and kwargs.get("follow_symlinks") is False:
                raise FileNotFoundError(errno.ENOENT, "synthetic mount removal")
            return real_stat(path, *args, **kwargs)

        with mock.patch("os.stat", side_effect=missing_mount_stat):
            with self.assertRaisesRegex(MountCheckError, "cannot inspect resolved mount path"):
                verify_mount(self.mount, self.original, require_real_mount=False)

    def test_mounted_entry_disappears_during_samefile_fails_closed(self):
        # A successful directory scan does not pin the mounted file pathname.
        with mock.patch("os.path.samefile", side_effect=FileNotFoundError(errno.ENOENT, "synthetic entry removal")):
            with self.assertRaisesRegex(MountCheckError, "cannot compare mounted and original file identities"):
                verify_mount(self.mount, self.original, require_real_mount=False)

    def test_missing_mount_leaf_fails_closed(self):
        # Missing mountpoint before canonicalization must be a controlled
        # verification refusal, not an uncaught filesystem exception.
        missing = self.mount.parent / "missing-mount"
        with self.assertRaisesRegex(MountCheckError, "cannot inspect mount argument"):
            verify_mount(missing, self.original, require_real_mount=False)

    def test_mount_path_swap_before_vfs_inspection_rejected(self):
        # The descriptor may still point to the old mount after its pathname
        # is replaced. Refuse provenance from that stale descriptor.
        real_stat = os.stat
        swapped = False

        def swap_before_path_stat(path, *args, **kwargs):
            nonlocal swapped
            if Path(path) == self.mount and not swapped:
                moved = self.mount.parent / "previous_mount"
                os.rename(self.mount, moved)
                os.mkdir(self.mount)
                swapped = True
            return real_stat(path, *args, **kwargs)

        with mock.patch("os.stat", side_effect=swap_before_path_stat):
            with self.assertRaisesRegex(MountCheckError,
                                        "ASCF mount path changed before VFS inspection"):
                darwin_statfs(self.mount)
        self.assertTrue(swapped)

    def test_mount_path_disappearance_during_vfs_inspection_fails_closed(self):
        # An unmount or rename can make the pathname disappear while its
        # already-open descriptor still exists. Return a controlled refusal.
        real_stat = os.stat
        for missing_at in (1, 2):
            with self.subTest(missing_at=missing_at):
                observations = 0

                def disappearing_stat(path, *args, **kwargs):
                    nonlocal observations
                    if Path(path) == self.mount:
                        observations += 1
                        if observations == missing_at:
                            raise FileNotFoundError(errno.ENOENT, "mount disappeared")
                    return real_stat(path, *args, **kwargs)

                with mock.patch("os.stat", side_effect=disappearing_stat), \
                        mock.patch("ctypes.CDLL", return_value=mock.Mock(
                            fstatfs=mock.Mock(return_value=0))), \
                        mock.patch("os.uname", return_value=mock.Mock(machine="arm64")):
                    with self.assertRaisesRegex(MountCheckError,
                                                "ASCF mount path unavailable"):
                        darwin_statfs(self.mount)
                self.assertEqual(observations, missing_at)

    def test_darwin_statfs_close_failure_fails_closed(self):
        # A failed descriptor close must not turn an otherwise successful
        # VFS inspection into a reported acceptance pass.
        real_close = os.close
        closed = False

        def failing_close(fd):
            nonlocal closed
            real_close(fd)
            closed = True
            raise OSError(errno.EIO, "simulated descriptor close failure")

        with mock.patch("ctypes.CDLL", return_value=mock.Mock(
                fstatfs=mock.Mock(return_value=0))), \
                mock.patch("os.uname", return_value=mock.Mock(machine="arm64")), \
                mock.patch("os.close", side_effect=failing_close):
            with self.assertRaisesRegex(
                    MountCheckError, "cannot close ASCF mount VFS descriptor"):
                darwin_statfs(self.mount)
        self.assertTrue(closed)

    def test_darwin_statfs_preserves_primary_failure_when_close_also_fails(self):
        # A cleanup error must not hide the VFS failure that triggered it.
        real_close = os.close
        closed = False

        def failing_close(fd):
            nonlocal closed
            real_close(fd)
            closed = True
            raise OSError(errno.EIO, "simulated descriptor close failure")

        with mock.patch("ctypes.CDLL", return_value=mock.Mock(
                fstatfs=mock.Mock(return_value=-1))), \
                mock.patch("os.uname", return_value=mock.Mock(machine="arm64")), \
                mock.patch("ctypes.get_errno", return_value=errno.EIO), \
                mock.patch("os.close", side_effect=failing_close):
            with self.assertRaisesRegex(MountCheckError, "fstatfs failed for ASCF mount"):
                darwin_statfs(self.mount)
        self.assertTrue(closed)

    def readonly_open(self, *args, **kwargs):
        if Path(args[0]).resolve() == self.restored.resolve() and args[1] & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
            raise OSError(errno.EROFS, "read-only filesystem")
        return self.real_open(*args, **kwargs)

    def check(self):
        self.real_open = os.open
        with mock.patch("os.open", side_effect=self.readonly_open):
            return verify_mount(self.mount, self.original, require_real_mount=False)

    def test_mount_directory_replacement_at_final_identity_check_rejected(self):
        # The final directory listing may still describe the original mount,
        # while its pathname is replaced immediately before the last stat.
        # A byte-identical replacement must not inherit acceptance.
        real_stat = os.stat
        real_scandir = os.scandir
        final_listing_started = False
        swapped = False
        scans = 0

        def track_scandir(path):
            nonlocal scans, final_listing_started
            if Path(path) == self.mount:
                scans += 1
                if scans == 2:
                    final_listing_started = True
            return real_scandir(path)

        def swap_at_final_stat(path, *args, **kwargs):
            nonlocal swapped
            if Path(path) == self.mount and final_listing_started and not swapped:
                old_mount = self.mount.parent / "previous_mount"
                os.rename(self.mount, old_mount)
                self.mount.mkdir()
                (self.mount / self.restored.name).write_bytes(
                    (old_mount / self.restored.name).read_bytes())
                swapped = True
            return real_stat(path, *args, **kwargs)

        self.real_open = os.open
        with mock.patch("os.open", side_effect=self.readonly_open), \
                mock.patch("os.scandir", side_effect=track_scandir), \
                mock.patch("os.stat", side_effect=swap_at_final_stat):
            with self.assertRaisesRegex(
                    MountCheckError, "ASCF mount directory changed during verification"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(swapped)
        self.assertEqual(scans, 2)

    def test_final_path_disappearance_rejected_with_mount_error(self):
        # A path may disappear after the final directory scan. Keep the
        # failure within the verifier's controlled rejection contract.
        for target, message in ((self.restored, "mounted"),
                                (self.original, "original"),
                                (self.mount, "mount")):
            with self.subTest(target=target):
                real_stat = os.stat
                real_scandir = os.scandir
                scans = 0
                triggered = False

                def track_scandir(path):
                    nonlocal scans
                    if Path(path) == self.mount:
                        scans += 1
                    return real_scandir(path)

                def missing_final_path(path, *args, **kwargs):
                    nonlocal triggered
                    if scans == 2 and Path(path) == target and not triggered:
                        triggered = True
                        raise FileNotFoundError(errno.ENOENT, "path disappeared")
                    return real_stat(path, *args, **kwargs)

                self.real_open = os.open
                with mock.patch("os.open", side_effect=self.readonly_open), \
                        mock.patch("os.scandir", side_effect=track_scandir), \
                        mock.patch("os.stat", side_effect=missing_final_path):
                    with self.assertRaisesRegex(MountCheckError,
                                                message + " path unavailable during final verification"):
                        verify_mount(self.mount, self.original, require_real_mount=False)
                self.assertTrue(triggered)
                self.assertEqual(scans, 2)

    def test_file_swap_during_final_directory_scan_rejected(self):
        # The first post-write pathname check can pass before scandir.
        # Replacing the only entry during final enumeration must not pass.
        real_scandir = os.scandir
        scans = 0
        swapped = False

        def swap_on_final_scan(path):
            nonlocal scans, swapped
            if Path(path) == self.mount:
                scans += 1
                if scans == 2:
                    replacement = self.mount / "replacement"
                    replacement.write_bytes(self.restored.read_bytes())
                    replacement.replace(self.restored)
                    swapped = True
            return real_scandir(path)

        self.real_open = os.open
        with mock.patch("os.open", side_effect=self.readonly_open), \
                mock.patch("os.scandir", side_effect=swap_on_final_scan):
            with self.assertRaisesRegex(
                    MountCheckError, "mounted path changed during final directory enumeration"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(swapped)
        self.assertEqual(scans, 2)

    def test_original_swap_during_final_directory_scan_rejected(self):
        # A source replacement after its post-write identity check must not
        # inherit acceptance even when the replacement bytes are identical.
        real_scandir = os.scandir
        scans = 0
        swapped = False

        def swap_source_on_final_scan(path):
            nonlocal scans, swapped
            if Path(path) == self.mount:
                scans += 1
                if scans == 2:
                    replacement = self.original.with_suffix(".replacement")
                    replacement.write_bytes(self.original.read_bytes())
                    replacement.replace(self.original)
                    swapped = True
            return real_scandir(path)

        self.real_open = os.open
        with mock.patch("os.open", side_effect=self.readonly_open), \
                mock.patch("os.scandir", side_effect=swap_source_on_final_scan):
            with self.assertRaisesRegex(
                    MountCheckError, "original path changed during final directory enumeration"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(swapped)
        self.assertEqual(scans, 2)

    def test_random_read_reopen_failures_are_controlled(self):
        # Hashing succeeds first; a later descriptor reopen can still fail.
        real_open = os.open
        for target, label in ((self.original, "original"),
                              (self.restored, "mounted")):
            with self.subTest(target=label):
                attempts = 0
                def fail_second_open(path, flags, *args, **kwargs):
                    nonlocal attempts
                    if os.fspath(path) == os.fspath(target):
                        attempts += 1
                        if attempts == 2:
                            raise OSError(errno.ENOENT, "synthetic reopen race")
                    return real_open(path, flags, *args, **kwargs)
                with mock.patch.object(os, "open", side_effect=fail_second_open):
                    with self.assertRaisesRegex(MountCheckError,
                                                "cannot reopen " + label):
                        verify_mount(self.mount, self.original, require_real_mount=False)

    def test_clean_random_readback_and_eof(self):
        report = self.check()
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["logical_bytes"], self.original.stat().st_size)
        self.assertIn(65535, report["random_read_offsets"])
        self.assertIn(self.original.stat().st_size, report["random_read_offsets"])

    def test_tiny_and_empty_files_preserve_exact_readback(self):
        # Boundary sizes exercise EOF at offset zero and the first byte.
        # The mounted copy must still be independently authenticated.
        for payload in (b"", bytes([0]), bytes([255])):
            with self.subTest(payload=payload):
                self.original.write_bytes(payload)
                self.restored.write_bytes(payload)
                report = self.check()
                self.assertEqual(report["logical_bytes"], len(payload))
                self.assertEqual(report["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertIn(0, report["random_read_offsets"])
                self.assertIn(len(payload), report["random_read_offsets"])

    def test_random_read_rejects_nonregular_reopened_descriptor(self):
        # A path can be replaced after digest authentication. Even if a
        # synthetic descriptor reports the authenticated inode, its type
        # must be checked before any pread is attempted.
        real_fstat = os.fstat
        real_pread = os.pread
        mounted_inode = self.restored.stat().st_ino
        observations = 0
        pread_called = False

        def changed_type(fd):
            nonlocal observations
            value = real_fstat(fd)
            if value.st_ino == mounted_inode and observations >= 2:
                from unittest.mock import Mock
                fake = Mock(wraps=value)
                fake.st_mode = stat.S_IFDIR | 0o555
                return fake
            if value.st_ino == mounted_inode:
                observations += 1
            return value

        def guarded_pread(fd, count, offset):
            nonlocal pread_called
            pread_called = True
            return real_pread(fd, count, offset)

        self.real_open = os.open
        with mock.patch("os.open", side_effect=self.readonly_open), mock.patch(
                "os.fstat", side_effect=changed_type), mock.patch(
                "os.pread", side_effect=guarded_pread):
            with self.assertRaisesRegex(MountCheckError, "random-read mounted input is not a regular file"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertFalse(pread_called, "must reject nonregular descriptor before pread")

    def test_same_inode_mutation_between_digest_and_random_open_rejected(self):
        # A rewrite after SHA-256 but before reopening must not pass merely
        # because the inode remains unchanged. Force a deterministic mtime
        # change without relying on filesystem timestamp resolution.
        real_open = os.open
        mounted_opens = 0
        mutated = False

        def mutate_before_random_open(path, flags, *args, **kwargs):
            nonlocal mounted_opens, mutated
            candidate = Path(path)
            if (candidate.name == self.restored.name
                    and candidate.parent.resolve(strict=True)
                    == self.restored.parent.resolve(strict=True)
                    and flags & os.O_ACCMODE == os.O_RDONLY):
                mounted_opens += 1
                if mounted_opens == 2:
                    with open(self.restored, "r+b") as stream:
                        stream.seek(0)
                        stream.write(b"Z")
                    before = self.restored.stat()
                    os.utime(self.restored, ns=(before.st_atime_ns,
                                               before.st_mtime_ns + 2_000_000_000))
                    mutated = True
            if (candidate.name == self.restored.name
                    and flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR)):
                raise OSError(errno.EROFS, "read-only filesystem")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=mutate_before_random_open):
            with self.assertRaisesRegex(MountCheckError,
                                        "mounted file changed between digest"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(mutated)

    def test_random_reads_reject_concurrent_mounted_mutation(self):
        # Mutate an unsampled byte during pread; metadata must expose the
        # change even when the sampled readback windows still match.
        real_pread = os.pread
        mutated = False
        mounted_inode = self.restored.stat().st_ino

        def mutating_pread(fd, count, offset):
            nonlocal mutated
            result = real_pread(fd, count, offset)
            if (not mutated and os.fstat(fd).st_ino == mounted_inode
                    and offset > self.original.stat().st_size):
                mutated = True
                with open(self.restored, "r+b") as stream:
                    stream.seek(0)
                    value = stream.read(1)
                    stream.seek(0)
                    stream.write(bytes([value[0] ^ 1]))
            return result

        self.real_open = os.open
        with mock.patch("os.open", side_effect=self.readonly_open), mock.patch(
                "os.pread", side_effect=mutating_pread):
            with self.assertRaisesRegex(MountCheckError,
                                        "mounted changed during random-read verification"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(mutated)

    def test_mounted_path_replacement_during_write_probe_rejected(self):
        # Negative write probes can race with pathname replacement. Reject
        # a byte-identical replacement rather than reporting a stale pass.
        real_open = os.open
        replaced = False
        restored_parent = self.restored.parent.resolve(strict=True)

        def replace_on_probe(path, flags, *args, **kwargs):
            nonlocal replaced
            candidate = Path(path)
            if (candidate.name == self.restored.name
                    and candidate.parent.resolve(strict=True) == restored_parent
                    and flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR)):
                if not replaced:
                    replacement = self.mount / "replacement"
                    replacement.write_bytes(self.restored.read_bytes())
                    replacement.replace(self.restored)
                    replaced = True
                raise OSError(errno.EROFS, "read-only filesystem")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=replace_on_probe):
            with self.assertRaisesRegex(MountCheckError,
                                        "mounted path changed after verification"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(replaced)

    def test_extra_mount_entry_during_write_probe_rejected(self):
        # The authenticated inode can remain intact while an unexpected
        # second entry appears; final acceptance must reject that volume.
        real_open = os.open
        injected = False

        def inject_on_write_probe(path, flags, *args, **kwargs):
            nonlocal injected
            candidate = Path(path)
            if (candidate.name == self.restored.name
                    and candidate.parent.resolve(strict=True) == self.mount.resolve(strict=True)
                    and flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR)):
                if not injected:
                    (self.mount / "unexpected").write_bytes(b"unexpected")
                    injected = True
                raise OSError(errno.EROFS, "read-only filesystem")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=inject_on_write_probe):
            with self.assertRaisesRegex(MountCheckError,
                                        "ASCF mount entries changed after verification"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(injected)

    def test_write_open_is_nonblocking_if_mount_entry_becomes_fifo(self):
        # A mounted entry may change between digest and the negative write
        # probes. Never let a swapped FIFO block the acceptance process.
        if not hasattr(os, "O_NONBLOCK"):
            self.skipTest("nonblocking opens unavailable")
        real_open = os.open
        restored_parent = self.restored.parent.resolve(strict=True)
        probed = []

        def deny_writes(path, flags, *args, **kwargs):
            # On macOS tempfile may spell /var as /private/var. Match the
            # canonical parent without following a replaced file leaf.
            candidate = Path(path)
            if (candidate.name == self.restored.name
                    and candidate.parent.resolve(strict=True) == restored_parent
                    and flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR)):
                probed.append(flags & os.O_ACCMODE)
                self.assertTrue(flags & os.O_NONBLOCK,
                                "write probe must not block on a swapped FIFO")
                raise OSError(errno.EROFS, "read-only filesystem")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch("os.open", side_effect=deny_writes):
            result = verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertEqual(result["result"], "pass")
        self.assertEqual(probed, [os.O_WRONLY, os.O_RDWR])

    def test_fifo_swap_does_not_block_digest_open(self):
        # A regular path can become a FIFO after the initial type check.
        # O_NONBLOCK must be present before fstat can reject the descriptor.
        if not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"):
            self.skipTest("FIFO/nonblocking opens unavailable")
        real_open = os.open
        swapped = False
        def replace_with_fifo(path, flags, *args, **kwargs):
            nonlocal swapped
            if Path(path) == self.original and not swapped:
                swapped = True
                self.original.unlink()
                os.mkfifo(self.original)
                self.assertTrue(flags & os.O_NONBLOCK,
                                "digest open must not block on a swapped FIFO")
            return real_open(path, flags, *args, **kwargs)
        with mock.patch("os.open", side_effect=replace_with_fifo):
            with self.assertRaisesRegex(MountCheckError, "not a regular file"):
                digest(self.original, nofollow=True)
        self.assertTrue(swapped)

    def test_missing_nonblocking_flag_fails_closed(self):
        # Never fall back to blocking FIFO opens on unsupported hosts.
        with mock.patch.object(os, "O_NONBLOCK", 0, create=True):
            # A zero-valued flag is not useful protection either.
            with self.assertRaisesRegex(MountCheckError, "O_NONBLOCK unavailable"):
                digest(self.original, nofollow=True)

    def test_missing_nofollow_flag_fails_closed(self):
        # A zero-valued flag must not silently disable symlink protection.
        with mock.patch.object(os, "O_NOFOLLOW", 0, create=True):
            with self.assertRaisesRegex(MountCheckError, "O_NOFOLLOW unavailable"):
                digest(self.original, nofollow=True)

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
            with self.assertRaisesRegex(MountCheckError, "symlink refused by O_NOFOLLOW"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(swapped, "symlink replacement must be exercised")

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

    def test_digest_rejects_concurrent_same_size_mutation(self):
        # A stable inode alone cannot authenticate bytes across a rewrite.
        fixture = self.original
        real_fstat = os.fstat
        observations = 0

        def changing_fstat(fd):
            nonlocal observations
            result = real_fstat(fd)
            reference = fixture.stat()
            if (result.st_dev, result.st_ino) == (reference.st_dev, reference.st_ino):
                observations += 1
                if observations == 2:
                    with open(fixture, "r+b") as stream:
                        first = stream.read(1)
                        stream.seek(0)
                        stream.write(bytes([first[0] ^ 1]))
                    result = real_fstat(fd)
            return result

        with mock.patch("os.fstat", side_effect=changing_fstat):
            with self.assertRaisesRegex(MountCheckError, "changed during hashing"):
                digest(fixture, nofollow=True)
        self.assertEqual(observations, 2)

    def test_original_symlink_is_not_silently_resolved(self):
        # A symlink supplied as the reference path must not bypass the
        # O_NOFOLLOW gate through an earlier Path.resolve() call.
        target = self.original.with_suffix(".saved")
        self.original.replace(target)
        self.original.symlink_to(target)
        with self.assertRaisesRegex(MountCheckError, "symlink refused by O_NOFOLLOW"):
            verify_mount(self.mount, self.original, require_real_mount=False)

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
            with self.assertRaisesRegex(MountCheckError, "symlink refused by O_NOFOLLOW"):
                verify_mount(self.mount, self.original, require_real_mount=False)
        self.assertTrue(swapped, "reference symlink swap must be exercised")

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

    def test_mountpoint_symlink_refused_before_resolution(self):
        # A symlink to a real mount must not substitute a different pathname
        # for the directory the caller explicitly asked us to authenticate.
        alias = self.mount.parent / "mount-alias"
        alias.symlink_to(self.mount, target_is_directory=True)
        with self.assertRaisesRegex(MountCheckError,
                                    "mount argument must not be a symlink"):
            verify_mount(alias, self.original, require_real_mount=False)

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

    def test_random_read_close_failures_are_controlled(self):
        # Simulate close failures only after digest() has completed. Verify
        # both descriptor cleanup paths and preserve a preceding read error.
        real_close = os.close
        self.real_open = os.open
        for target, expected in (("mounted", "mounted random-read descriptor"),
                                 ("original", "original random-read descriptor")):
            opened = []

            def tracking_open(path, flags, *args, **kwargs):
                fd = self.readonly_open(path, flags, *args, **kwargs)
                if flags & os.O_ACCMODE == os.O_RDONLY:
                    opened.append((fd, Path(path)))
                return fd

            def failing_close(fd):
                # os.close is called only for the two random-read descriptors
                # in this path; digest() uses file-object cleanup instead.
                matches = [item for item in opened if item[0] == fd]
                if matches and ((target == "mounted" and matches[-1][1] == self.restored)
                                or (target == "original" and matches[-1][1] == self.original)):
                    real_close(fd)
                    raise OSError(errno.EIO, "synthetic close failure")
                return real_close(fd)

            with self.subTest(target=target), mock.patch("os.open", side_effect=tracking_open), mock.patch(
                    "os.close", side_effect=failing_close):
                with self.assertRaisesRegex(MountCheckError, expected):
                    verify_mount(self.mount, self.original, require_real_mount=False)

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

    def check_signed_gate(self, filesystem_type, mount_flags=1,
                          final_filesystem_type=None, final_mount_flags=None):
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

        filesystem = DarwinStatFS()
        filesystem.f_fstypename = filesystem_type.encode("ascii")
        filesystem.f_flags = mount_flags
        final_filesystem = DarwinStatFS()
        final_filesystem.f_fstypename = (final_filesystem_type or filesystem_type).encode("ascii")
        final_filesystem.f_flags = mount_flags if final_mount_flags is None else final_mount_flags
        with mock.patch("sys.platform", "darwin"), mock.patch(
            "os.path.ismount", return_value=True
        ), mock.patch.object(
            sys.modules[__name__], "darwin_statfs", side_effect=[filesystem, final_filesystem]
        ) as statfs_call, mock.patch(
            "subprocess.run", side_effect=command
        ), mock.patch("os.open", side_effect=self.readonly_open):
            outcome = verify_mount(self.mount, self.original)
        expected_mount = self.mount.resolve(strict=True)
        self.assertEqual(statfs_call.call_args_list,
                         [mock.call(expected_mount), mock.call(expected_mount)])
        return outcome, seen

    def test_darwin_statfs_decodes_actual_filesystem_type(self):
        self.assertEqual(DarwinStatFS.f_fstypename.offset, 72)
        self.assertEqual(ctypes.sizeof(DarwinStatFS), 2168)

        def fake_fstatfs(fd, pointer):
            # The acceptance verifier must bind VFS identity to a live
            # descriptor, not a pathname that could be replaced mid-check.
            opened = os.fstat(fd)
            expected = self.mount.stat()
            self.assertEqual((opened.st_dev, opened.st_ino),
                             (expected.st_dev, expected.st_ino))
            ctypes.cast(pointer, ctypes.POINTER(DarwinStatFS)).contents.f_fstypename = b"ascf"
            return 0

        call = mock.Mock(side_effect=fake_fstatfs)
        with mock.patch("ctypes.CDLL", return_value=mock.Mock(fstatfs=call)), mock.patch(
            "os.uname", return_value=mock.Mock(machine="arm64")
        ):
            self.assertEqual(darwin_filesystem_type(self.mount), "ascf")
        call.assert_called_once()

    def test_darwin_intel_uses_inode64_entry_point(self):
        def fake_fstatfs(fd, pointer):
            self.assertTrue(stat.S_ISDIR(os.fstat(fd).st_mode))
            ctypes.cast(pointer, ctypes.POINTER(DarwinStatFS)).contents.f_fstypename = b"ascf"
            return 0

        libc = mock.Mock()
        legacy = libc.fstatfs
        inode64 = mock.Mock(side_effect=fake_fstatfs)
        setattr(libc, "fstatfs$INODE64", inode64)
        with mock.patch("ctypes.CDLL", return_value=libc), mock.patch(
            "os.uname", return_value=mock.Mock(machine="x86_64")
        ):
            self.assertEqual(darwin_filesystem_type(self.mount), "ascf")
        inode64.assert_called_once()
        legacy.assert_not_called()

    def test_darwin_statfs_descriptor_disappearance_fails_closed(self):
        # Descriptor failures before and after fstatfs must be controlled
        # refusals, even if the mount pathname remains present.
        real_fstat = os.fstat
        for fail_at, expected in ((1, "before VFS inspection"),
                                  (2, "during VFS inspection")):
            calls = 0

            def disappearing_fstat(fd):
                nonlocal calls
                calls += 1
                if calls == fail_at:
                    raise OSError(errno.EBADF, "descriptor disappeared")
                return real_fstat(fd)

            fake_vfs = mock.Mock(return_value=0)
            with self.subTest(fail_at=fail_at), mock.patch(
                    "os.fstat", side_effect=disappearing_fstat), mock.patch(
                    "ctypes.CDLL", return_value=mock.Mock(fstatfs=fake_vfs)), mock.patch(
                    "os.uname", return_value=mock.Mock(machine="arm64")):
                with self.assertRaisesRegex(MountCheckError, expected):
                    darwin_statfs(self.mount)
            self.assertGreaterEqual(calls, fail_at)

    def test_darwin_statfs_failure_is_closed(self):
        call = mock.Mock(return_value=-1)
        with mock.patch("ctypes.CDLL", return_value=mock.Mock(fstatfs=call)), mock.patch(
            "ctypes.get_errno", return_value=errno.EIO
        ), mock.patch("os.uname", return_value=mock.Mock(machine="arm64")):
            with self.assertRaisesRegex(MountCheckError, "fstatfs failed"):
                darwin_filesystem_type(self.mount)

    def test_real_mount_gate_records_fskit_identity_and_macos_build(self):
        report, seen = self.check_signed_gate("ascf")
        self.assertEqual(report["filesystem_type"], "ascf")
        self.assertEqual(report["mount_flags"], 1)
        self.assertTrue(report["kernel_readonly"])
        self.assertEqual(report["macos_version"], "27.2")
        self.assertEqual(report["macos_build"], "26B123")
        self.assertEqual(len(seen), 4)

    def test_real_mount_gate_rejects_changed_provenance_at_completion(self):
        # A mount can change after byte verification. Recheck the VFS identity
        # and refuse a different read-only mount under the same path.
        with self.assertRaisesRegex(MountCheckError, "ASCF mount provenance changed"):
            self.check_signed_gate("ascf", final_mount_flags=0x5)

    def test_real_mount_gate_rejects_nonascii_filesystem_type(self):
        # Malformed kernel VFS identity must produce a controlled refusal.
        filesystem = DarwinStatFS()
        filesystem.f_fstypename = bytes([0xff]) + b"ascf"
        filesystem.f_flags = 1
        with mock.patch("sys.platform", "darwin"), mock.patch.object(
                sys.modules[__name__], "darwin_statfs", return_value=filesystem):
            with self.assertRaisesRegex(MountCheckError, "non-ASCII"):
                signed_mount_identity(self.mount)

    def test_filesystem_type_helper_rejects_nonascii_vfs_bytes(self):
        # The standalone type reader must also fail through MountCheckError,
        # rather than leaking UnicodeDecodeError on malformed kernel data.
        filesystem = DarwinStatFS()
        filesystem.f_fstypename = bytes([0xff])
        with mock.patch(__name__ + ".darwin_statfs", return_value=filesystem):
            with self.assertRaisesRegex(MountCheckError, "non-ASCII"):
                darwin_filesystem_type(self.mount)

    def test_real_mount_gate_rejects_unrelated_apfs_volume(self):
        with self.assertRaisesRegex(MountCheckError, "expected ASCF FSKit mount"):
            self.check_signed_gate("apfs")

    def test_kernel_writable_mount_rejected_even_with_erofs_handlers(self):
        # A writable VFS mount violates the read-only product contract even
        # if individual open/write operations already return EROFS.
        with self.assertRaisesRegex(MountCheckError, "MNT_RDONLY"):
            self.check_signed_gate("ascf", mount_flags=0)

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
