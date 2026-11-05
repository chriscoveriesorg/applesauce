#!/usr/bin/env python3
"""Witness a completed FSKit unmount using Darwin's kernel mount table.

Read-only evidence only. A missing pathname is insufficient: a still-mounted
ASCF volume must not be mistaken for an unmount just because its original
mountpoint disappeared or changed. The owner performs the unmount separately.
"""
import argparse
import ctypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import unittest


class UnmountError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise UnmountError(message)


def read_mount_table():
    """Snapshot all kernel mounts, including FSKit and non-Finder mountpoints."""
    require(sys.platform == "darwin", "kernel mount inspection requires macOS")
    from verify_mount import DarwinStatFS

    info_pointer = ctypes.POINTER(DarwinStatFS)()
    symbol = "getmntinfo$INODE64" if os.uname().machine == "x86_64" else "getmntinfo"
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        call = getattr(libc, symbol)
    except AttributeError as error:
        raise UnmountError(f"Darwin libc lacks {symbol}") from error
    call.argtypes = (ctypes.POINTER(ctypes.POINTER(DarwinStatFS)), ctypes.c_int)
    call.restype = ctypes.c_int
    count = call(ctypes.byref(info_pointer), 2)  # Darwin MNT_NOWAIT
    require(count > 0 and bool(info_pointer), "getmntinfo failed or returned an empty table")
    try:
        return [(info_pointer[i].f_fstypename.decode("ascii"),
                 info_pointer[i].f_mntonname.decode("utf-8"))
                for i in range(count)]
    except UnicodeDecodeError as error:
        raise UnmountError("kernel mount table contains an undecodable entry") from error


def verify(mount, first_readback, *, bundle=None, mounts=None, is_mount=None):
    """Validate the first signed readback and require no surviving ASCF mount."""
    require(isinstance(mount, str), "mount path must be text")
    # Signed host-created mounts live directly below /Volumes. Keep this
    # narrow to avoid mistakenly claiming an unrelated directory was unmounted.
    require(mount.startswith("/Volumes/") and
            Path(mount).parent == Path("/Volumes") and
            Path(mount).name not in ("", ".", "..") and
            os.path.normpath(mount) == mount,
            "unmount witness requires one direct /Volumes mountpoint")
    require(not os.path.islink(mount), "mountpoint became a symlink")
    with open(first_readback, encoding="utf-8") as stream:
        previous = json.load(stream)
    require(previous.get("result") == "pass" and
            previous.get("filesystem_type") == "ascf" and
            previous.get("kernel_readonly") is True and
            isinstance(previous.get("mount_flags"), int) and
            previous["mount_flags"] & 1,
            "previous readback lacks kernel-confirmed read-only ASCF identity")
    require(previous.get("mount") == mount, "unmount path differs from signed readback")
    require(previous.get("unique_ascf_mount_verified") is True
            and type(previous.get("active_ascf_mounts")) is int
            and previous["active_ascf_mounts"] == 1,
            "previous readback lacks unique kernel ASCF mount proof")
    require(previous.get("finder_copy_verified") is True and
            previous.get("finder_copy_sha256") == previous.get("sha256"),
            "previous readback lacks verified Finder copy-out")
    digest = previous.get("sha256")
    require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
            "previous readback has invalid logical SHA-256")
    verification_id = previous.get("verification_id")
    require(isinstance(verification_id, str) and bool(verification_id),
            "previous readback lacks verification ID")
    require(previous.get("macos_build"), "previous readback lacks macOS build")

    if bundle is not None:
        # Bind a Finder-confirmed unmount to the signed bundle's synthetic
        # codec, source SHA-256 and logical length before inspecting VFS.
        name = previous.get("restored_file")
        require(name in ("source.lzraven", "source.lzmesh"),
                "bundle readback must identify a supported ASCF fixture")
        source = Path(bundle) / (name + ".jsonl")
        require(source.is_file() and not source.is_symlink(),
                "bundle cleartext fixture missing or symlinked")
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            hasher = hashlib.sha256()
            size = 0
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(block)
                size += len(block)
            after = os.fstat(stream.fileno())
        keys = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, key) == getattr(after, key) for key in keys)
                and size == before.st_size,
                "bundle fixture changed during unmount provenance verification")
        require(hasher.hexdigest() == digest and
                previous.get("logical_bytes") == size,
                "previous readback differs from signed-bundle logical bytes")

    active = read_mount_table() if mounts is None else mounts
    require(isinstance(active, list) and bool(active),
            "missing complete kernel mount table")
    for item in active:
        require(isinstance(item, (tuple, list)) and len(item) == 2 and
                all(isinstance(value, str) and value for value in item),
                "malformed kernel mount table entry")
    require(not any(path == mount for _, path in active),
            "the original mountpoint remains mounted in the kernel")
    # A relocated or second ASCF volume would make the claimed normal
    # unmount ambiguous. The signed host has a one-volume lifecycle contract.
    ascf_mounts = [path for kind, path in active if kind == "ascf"]
    require(not ascf_mounts, "ASCF volume still mounted: " + ", ".join(ascf_mounts))
    actual_ismount = os.path.ismount(mount) if is_mount is None else is_mount
    require(not actual_ismount, "mount path still reports a live mount")
    return {
        "result": "pass", "mount": mount,
        "previous_sha256": digest,
        "previous_verification_id": verification_id,
        "macos_build": previous["macos_build"],
        "verified_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "unmounted": True,
        "kernel_mount_table_verified": True,
        "remaining_ascf_mounts": 0,
    }


class UnmountTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.report = Path(self.folder.name) / "readback.json"
        self.payload = {
            "result": "pass", "filesystem_type": "ascf",
            "kernel_readonly": True, "mount_flags": 1,
            "unique_ascf_mount_verified": True, "active_ascf_mounts": 1,
            "mount": "/Volumes/Applesauce ASCF", "finder_copy_verified": True,
            "sha256": "a" * 64, "finder_copy_sha256": "a" * 64,
            "verification_id": "first", "macos_build": "27A001"
        }
        self.save()

    def save(self):
        self.report.write_text(json.dumps(self.payload), encoding="utf-8")

    def check(self, mounts=None, is_mount=False):
        if mounts is None:
            mounts = [("apfs", "/"), ("devfs", "/dev")]
        return verify(self.payload["mount"], self.report, mounts=mounts,
                      is_mount=is_mount)

    def bundle_fixture(self):
        source = Path(self.folder.name) / "source.lzraven.jsonl"
        data = b"synthetic ASCF logical cleartext\n" * 64
        source.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        self.payload.update(restored_file="source.lzraven",
                            logical_bytes=len(data), sha256=digest,
                            finder_copy_sha256=digest)
        self.save()
        return source

    def signed_bundle_check(self):
        return verify(self.payload["mount"], self.report, bundle=self.folder.name,
                      mounts=[("apfs", "/")], is_mount=False)

    def test_signed_bundle_valid_source(self):
        self.bundle_fixture()
        self.assertEqual(self.signed_bundle_check()["previous_sha256"],
                         self.payload["sha256"])

    def test_signed_bundle_modified_source_refused(self):
        source = self.bundle_fixture()
        source.write_bytes(b"changed after first readback")
        with self.assertRaisesRegex(UnmountError, "differs from signed-bundle"):
            self.signed_bundle_check()

    def test_signed_bundle_wrong_codec_refused(self):
        self.bundle_fixture()
        self.payload["restored_file"] = "unrelated-file"
        self.save()
        with self.assertRaisesRegex(UnmountError, "supported ASCF fixture"):
            self.signed_bundle_check()

    def test_signed_bundle_symlink_refused(self):
        source = self.bundle_fixture()
        other = source.with_suffix(".target")
        source.rename(other)
        source.symlink_to(other)
        with self.assertRaisesRegex(UnmountError, "symlinked"):
            self.signed_bundle_check()

    def test_signed_bundle_wrong_length_refused(self):
        self.bundle_fixture()
        self.payload["logical_bytes"] += 1
        self.save()
        with self.assertRaisesRegex(UnmountError, "differs from signed-bundle"):
            self.signed_bundle_check()

    def test_unmount_rejects_ambiguous_prior_mount(self):
        self.payload["active_ascf_mounts"] = 2
        self.save()
        with self.assertRaisesRegex(UnmountError, "unique kernel ASCF"):
            self.check()

    def test_normal_unmount(self):
        result = self.check()
        self.assertTrue(result["kernel_mount_table_verified"])
        self.assertEqual(result["macos_build"], "27A001")

    def test_stale_original_mount_refused(self):
        with self.assertRaisesRegex(UnmountError, "original mountpoint"):
            self.check([("apfs", "/"), ("ascf", "/Volumes/Applesauce ASCF")])

    def test_relocated_ascf_mount_refused(self):
        with self.assertRaisesRegex(UnmountError, "ASCF volume still mounted"):
            self.check([("apfs", "/"), ("ascf", "/private/tmp/moved")])

    def test_ambiguous_second_ascf_refused(self):
        with self.assertRaisesRegex(UnmountError, "ASCF volume still mounted"):
            self.check([("apfs", "/"), ("ascf", "/Volumes/Other ASCF")])

    def test_unrelated_filesystem_at_original_path_refused(self):
        with self.assertRaisesRegex(UnmountError, "original mountpoint"):
            self.check([("apfs", "/"), ("apfs", "/Volumes/Applesauce ASCF")])

    def test_ismount_fallback_refused(self):
        with self.assertRaisesRegex(UnmountError, "live mount"):
            self.check(is_mount=True)

    def test_untrusted_first_readback_refused(self):
        self.payload["finder_copy_verified"] = False
        self.save()
        with self.assertRaisesRegex(UnmountError, "Finder"):
            self.check()

    def test_different_path_refused(self):
        with self.assertRaisesRegex(UnmountError, "direct /Volumes"):
            verify("/private/tmp/ascf/mount", self.report, mounts=[("apfs", "/")],
                   is_mount=False)

    def test_empty_mount_table_refused(self):
        with self.assertRaisesRegex(UnmountError, "complete kernel mount table"):
            self.check([])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--mount")
    parser.add_argument("--first")
    parser.add_argument("--bundle", help="manifest-authenticated acceptance bundle")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(UnmountTests)
        return int(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
    if not args.mount or not args.first:
        parser.error("--mount and --first readback.json are required")
    try:
        result = verify(args.mount, args.first, bundle=args.bundle)
    except (UnmountError, OSError, ValueError, TypeError, KeyError) as error:
        print("FSKit unmount acceptance FAILED: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
