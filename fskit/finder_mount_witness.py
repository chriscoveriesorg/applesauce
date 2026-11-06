#!/usr/bin/env python3
"""Bind Finder copy-out to the same signed, read-only FSKit mount.

The pre- and post-Finder reports must each come from verify_mount.py with
require_real_mount=True. This checker only stamps generated evidence JSON.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
import uuid


class WitnessError(ValueError):
    pass


def require(condition, explanation):
    if not condition:
        raise WitnessError(explanation)


def load_report(path, include_identity=False):
    # A substituted FIFO must fail before reading: a blocking open here can
    # indefinitely stall the signed physical acceptance ceremony.
    require(bool(getattr(os, "O_NOFOLLOW", 0)) and
            bool(getattr(os, "O_NONBLOCK", 0)),
            "safe nonblocking no-follow report open is unavailable")
    flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
             getattr(os, "O_CLOEXEC", 0))
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and
                0 <= before.st_size <= 1024 * 1024,
                "readback report must be a bounded regular file")
        raw = stream.read(1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, key) == getattr(after, key) for key in fields)
                and len(raw) == before.st_size,
                "readback report changed or was truncated during inspection")
        report = json.loads(raw)
        identity = (before.st_dev, before.st_ino, before.st_mtime_ns)
        return (report, identity) if include_identity else report


def copy_identity(path):
    require(bool(getattr(os, "O_NOFOLLOW", 0)) and
            bool(getattr(os, "O_NONBLOCK", 0)),
            "safe nonblocking no-follow Finder copy open is unavailable")
    flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
             getattr(os, "O_CLOEXEC", 0))
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), "Finder copy must be a regular file")
        checksum = hashlib.sha256()
        length = 0
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            length += len(block)
            checksum.update(block)
        after = os.fstat(stream.fileno())
        for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"):
            require(getattr(before, name) == getattr(after, name),
                    "Finder copy changed while hashing")
        require(before.st_size == length, "Finder copy truncated during hashing")
        return length, checksum.hexdigest()


def validated_identity(report):
    require(isinstance(report, dict) and report.get("result") == "pass",
            "both mounted readback checks must pass")
    require(report.get("filesystem_type") == "ascf" and
            report.get("kernel_readonly") is True,
            "Finder witness requires real kernel read-only ASCF")
    require(report.get("unique_ascf_mount_verified") is True
            and type(report.get("active_ascf_mounts")) is int
            and report["active_ascf_mounts"] == 1,
            "Finder witness lacks unique kernel ASCF mount proof")
    flags = report.get("mount_flags")
    require(type(flags) is int and flags & 1,
            "missing Darwin MNT_RDONLY evidence")
    for key in ("mount_device", "mount_inode", "logical_bytes"):
        require(type(report.get(key)) is int and report[key] >= 0,
                f"missing mounted file identity: {key}")
    require(report["mount_inode"] > 0, "missing mounted directory inode")
    fsid = report.get("mount_fsid")
    require(isinstance(fsid, list) and len(fsid) == 2 and
            all(type(n) is int for n in fsid), "missing kernel FSID")
    for key in ("mount", "restored_file", "sha256", "macos_version", "macos_build"):
        require(isinstance(report.get(key), str) and bool(report[key]),
                f"missing mounted readback field {key}")
    require(len(report["sha256"]) == 64 and
            all(char in "0123456789abcdef" for char in report["sha256"]),
            "invalid logical SHA-256")
    require(report.get("readonly_open_denied") is True,
            "mounted file did not deny write-open")
    offsets = report.get("random_read_offsets")
    require(isinstance(offsets, list) and bool(offsets) and
            all(type(n) is int and 0 <= n <= report["logical_bytes"] for n in offsets),
            "missing verified random-read offsets")
    return {key: report[key] for key in (
        "mount", "restored_file", "sha256", "logical_bytes", "mount_device",
        "mount_inode", "mount_fsid", "filesystem_type", "kernel_readonly",
        "mount_flags", "unique_ascf_mount_verified", "active_ascf_mounts",
        "macos_version", "macos_build", "readonly_open_denied",
        "random_read_offsets")}


def validate(first, after, copied):
    require("verification_id" not in first and not first.get("finder_copy_verified"),
            "first readback was already stamped")
    identity = validated_identity(first)
    require(validated_identity(after) == identity,
            "ASCF mount, filesystem identity or readback changed during Finder copy")
    copied_length, copied_sha = copy_identity(copied)
    require(copied_length == identity["logical_bytes"] and
            copied_sha == identity["sha256"],
            "Finder copy-out differs from mounted logical file")
    return copied_sha


def stamp(first_path, after_path, copied):
    before, first_identity = load_report(first_path, include_identity=True)
    after, second_identity = load_report(after_path, include_identity=True)
    # The post-Finder report must be a fresh filesystem observation. The
    # first report reused as "after", including through a hard link, cannot
    # establish that the original ASCF mount survived Finder copy-out.
    require(first_identity[:2] != second_identity[:2],
            "pre- and post-Finder reports must be separate regular files")
    require(first_identity[2] < second_identity[2],
            "post-Finder report must be newer than initial mounted readback")
    digest = validate(before, after, copied)
    before["finder_copy_verified"] = True
    before["finder_copy_sha256"] = digest
    before["post_finder_mount_verified"] = True
    before["post_finder_mount_fsid"] = after["mount_fsid"]
    before["verification_id"] = str(uuid.uuid4())
    before["verified_at_utc"] = datetime.datetime.now(
        datetime.timezone.utc).isoformat()
    target = Path(first_path)
    descriptor, staged = tempfile.mkstemp(prefix=".finder-witness-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(before, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, target)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)
    return before


class WitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.copy = self.root / "finder.bin"
        self.copy.write_bytes(b"fixture" * 500)
        checksum = hashlib.sha256(self.copy.read_bytes()).hexdigest()
        self.first = {"result": "pass", "filesystem_type": "ascf",
                      "kernel_readonly": True, "mount_flags": 1,
                      "unique_ascf_mount_verified": True, "active_ascf_mounts": 1,
                      "mount_device": 123, "mount_inode": 45, "mount_fsid": [123, 2],
                      "mount": "/Volumes/Applesauce ASCF", "restored_file": "source.lzraven",
                      "logical_bytes": self.copy.stat().st_size, "sha256": checksum,
                      "macos_version": "27.0.1", "macos_build": "synthetic",
                      "readonly_open_denied": True, "random_read_offsets": [0, 1, 3499, 3500]}
        self.before = self.root / "before.json"
        self.after = self.root / "after.json"
        self.write()

    def write(self):
        self.before.write_text(json.dumps(self.first))
        self.after.write_text(json.dumps(self.first))
        # Stable, distinct file observations avoid filesystem clock-resolution
        # flakes in CI while exercising the same ordering as the operator.
        early, late = 1_700_000_000_000_000_000, 1_700_000_002_000_000_000
        os.utime(self.before, ns=(early, early))
        os.utime(self.after, ns=(late, late))

    def test_stamps_only_complete_unchanged_mount(self):
        result = stamp(self.before, self.after, self.copy)
        self.assertTrue(result["post_finder_mount_verified"])
        self.assertEqual(result["finder_copy_sha256"], self.first["sha256"])
        self.assertTrue(result["verification_id"])
        self.assertEqual(json.loads(self.before.read_text()), result)
        with self.assertRaisesRegex(WitnessError, "already stamped"):
            stamp(self.before, self.after, self.copy)

    def test_rejects_swapped_or_remounted_volume(self):
        for key, value in (("mount_inode", 999), ("mount_device", 777),
                           ("mount_fsid", [123, 3]), ("mount_flags", 0),
                           ("macos_build", "another"), ("restored_file", "other"),
                           ("sha256", "a" * 64), ("kernel_readonly", False)):
            with self.subTest(key=key):
                second = dict(self.first, **{key: value})
                self.after.write_text(json.dumps(second))
                with self.assertRaises(WitnessError):
                    stamp(self.before, self.after, self.copy)
                self.assertNotIn("verification_id", self.before.read_text())

    def test_rejects_second_active_ascf_mount(self):
        self.after.write_text(json.dumps(dict(self.first, active_ascf_mounts=2)))
        with self.assertRaisesRegex(WitnessError, "unique kernel ASCF"):
            stamp(self.before, self.after, self.copy)

    def test_rejects_copy_tamper_and_symlinks(self):
        self.copy.write_bytes(b"changed")
        with self.assertRaisesRegex(WitnessError, "Finder copy-out differs"):
            stamp(self.before, self.after, self.copy)
        self.copy.unlink()
        (self.root / "alias.bin").write_bytes(b"fixture" * 500)
        self.copy.symlink_to(self.root / "alias.bin")
        with self.assertRaises(OSError):
            stamp(self.before, self.after, self.copy)

    def test_requires_actual_mounted_readback_fields(self):
        for key in ("mount_fsid", "mount_inode", "random_read_offsets",
                    "kernel_readonly", "readonly_open_denied",
                     "unique_ascf_mount_verified", "active_ascf_mounts"):
            with self.subTest(key=key):
                altered = dict(self.first)
                altered.pop(key)
                self.after.write_text(json.dumps(altered))
                with self.assertRaises(WitnessError):
                    stamp(self.before, self.after, self.copy)

    def test_same_report_and_hardlink_cannot_fake_post_finder_readback(self):
        with self.assertRaisesRegex(WitnessError, "separate regular files"):
            stamp(self.before, self.before, self.copy)
        self.after.unlink()
        os.link(self.before, self.after)
        with self.assertRaisesRegex(WitnessError, "separate regular files"):
            stamp(self.before, self.after, self.copy)
        self.assertNotIn("verification_id", self.before.read_text())

    def test_stale_or_equal_post_finder_timestamp_is_refused(self):
        initial = self.before.stat().st_mtime_ns
        for timestamp in (initial, initial - 1_000_000_000):
            with self.subTest(timestamp=timestamp):
                os.utime(self.after, ns=(timestamp, timestamp))
                with self.assertRaisesRegex(WitnessError, "newer"):
                    stamp(self.before, self.after, self.copy)
                self.assertNotIn("verification_id", self.before.read_text())

    def test_fifo_reports_and_finder_copy_fail_without_blocking(self):
        # O_NONBLOCK must be present before fstat identifies nonregular files:
        # opening an attacker-substituted FIFO O_RDONLY alone would hang.
        self.after.unlink()
        os.mkfifo(self.after)
        with self.assertRaisesRegex(WitnessError, "bounded regular file"):
            load_report(self.after)
        self.after.unlink()
        self.copy.unlink()
        os.mkfifo(self.copy)
        with self.assertRaisesRegex(WitnessError, "regular file"):
            copy_identity(self.copy)

    def test_readback_files_are_opened_nofollow_and_nonblocking(self):
        real_open = os.open
        seen = []
        watched = {str(self.before), str(self.after), str(self.copy)}
        def inspect_open(path, flags, *args, **kwargs):
            if str(path) in watched:
                seen.append(str(path))
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(path, flags, *args, **kwargs)
        with mock.patch("os.open", side_effect=inspect_open):
            report = stamp(self.before, self.after, self.copy)
        self.assertTrue(report["finder_copy_verified"])
        self.assertEqual(set(seen), watched)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", type=Path)
    parser.add_argument("--after", type=Path)
    parser.add_argument("--copy", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(WitnessTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if not (args.first and args.after and args.copy):
        parser.error("--first, --after and --copy are required")
    try:
        result = stamp(args.first, args.after, args.copy)
    except (OSError, ValueError, KeyError) as error:
        print(f"Finder mounted identity witness refused: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"result": result["result"],
                      "verification_id": result["verification_id"],
                      "post_finder_mount_verified": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
