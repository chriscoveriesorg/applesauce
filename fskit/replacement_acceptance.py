#!/usr/bin/env python3
"""Operator-run ASCF archive-replacement refusal on disposable synthetic copies.

Only a stage created under the current user's private temporary directory may be
replaced. The operator mounts that staged copy through the signed FSKit host;
this tool never installs, mounts, unmounts, writes xattrs or touches the bundle.
"""
import argparse
import datetime
import errno
import hashlib
import json
import os
import re
import secrets
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock


CODECS = ("lzraven", "lzmesh")
EXPECTED_ERRORS = {errno.ESTALE, errno.EIO, errno.ENODEV}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha256(path):
    result = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def stage(bundle, codec):
    require(codec in CODECS, "unsupported codec")
    bundle = Path(bundle).resolve(strict=True)
    archive = bundle / f"source.{codec}.ascf"
    damaged = bundle / f"source.{codec}.corrupt.ascf"
    cleartext = bundle / f"source.{codec}.jsonl"
    for path in (archive, damaged, cleartext):
        require(path.is_file() and not path.is_symlink(), f"missing safe bundle fixture: {path}")
    target = Path(tempfile.mkdtemp(prefix="ascf-replacement-", dir="/tmp"))
    os.chmod(target, 0o700)
    # The only mounted filename is derived from the archive basename.
    # Use a fresh stage-specific basename so a different, byte-identical
    # bundle mount cannot accidentally qualify as this replacement control.
    nonce = secrets.token_hex(8)
    staged_name = f"source.{codec}.{nonce}.ascf"
    good = target / staged_name
    bad = target / "replacement.ascf"
    shutil.copyfile(archive, good)
    shutil.copyfile(damaged, bad)
    metadata = {
        # The signed portable package is the authority for the staged copy.
        # Preserve its canonical location so replacement-check can run the
        # manifest-authenticated helper rather than unrelated checkout code.
        "bundle": str(bundle),
        "codec": codec,
        "stage_nonce": nonce,
        "archive": staged_name,
        "good_sha256": sha256(good),
        "replacement_sha256": sha256(bad),
        "original_sha256": sha256(cleartext),
    }
    require(metadata["good_sha256"] != metadata["replacement_sha256"],
            "replacement fixture is identical to the valid archive")
    (target / "stage.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"stage": str(target), "select_archive_in_signed_host": str(good),
                      "codec": codec, "action": "mount this staged copy, then run check"}, indent=2))
    return target


def validate_stage(directory):
    # /tmp is normally /private/tmp on macOS. Enforce location after resolving
    # aliases and refuse stage symlinks, foreign owners and world access.
    directory = Path(directory)
    require(not directory.is_symlink(), "stage directory is a symlink")
    directory = directory.resolve(strict=True)
    private_tmp = Path("/tmp").resolve(strict=True)
    require(directory.parent == private_tmp and directory.name.startswith("ascf-replacement-"),
            "only a direct synthetic /tmp ASCF stage may be replaced")
    mode = directory.stat()
    require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.geteuid()
            and stat.S_IMODE(mode.st_mode) == 0o700,
            "stage directory must belong to this user and be mode 0700")
    metadata_file = directory / "stage.json"
    require(metadata_file.is_file() and not metadata_file.is_symlink(), "stage metadata missing")
    metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    codec = metadata.get("codec")
    nonce = metadata.get("stage_nonce")
    require(codec in CODECS and isinstance(nonce, str)
            and re.fullmatch(r"[0-9a-f]{16}", nonce) is not None
            and metadata.get("archive") == f"source.{codec}.{nonce}.ascf",
            "stage archive identity invalid")
    bundle_string = metadata.get("bundle")
    require(isinstance(bundle_string, str) and bundle_string.startswith("/"),
            "stage is missing absolute signed bundle provenance")
    bundle = Path(bundle_string)
    require(bundle.is_dir() and not bundle.is_symlink()
            and bundle.resolve(strict=True) == bundle,
            "stage signed bundle path is missing, symlinked or noncanonical")
    good = directory / metadata["archive"]
    bad = directory / "replacement.ascf"
    for name, path, digest in (("valid", good, metadata.get("good_sha256")),
                               ("replacement", bad, metadata.get("replacement_sha256"))):
        require(path.is_file() and not path.is_symlink() and isinstance(digest, str)
                and sha256(path) == digest, f"{name} staged archive changed")
    # A replaced or moved package must not supply apparently signed source
    # bytes after staging. Check the original fixture identities before any
    # destructive stage replacement. Bundled script and SHA256SUMS validation
    # is separately enforced by signed_acceptance.sh.
    for name, expected in ((f"source.{codec}.ascf", metadata["good_sha256"]),
                           (f"source.{codec}.corrupt.ascf", metadata["replacement_sha256"]),
                           (f"source.{codec}.jsonl", metadata["original_sha256"])):
        original = bundle / name
        require(original.is_file() and not original.is_symlink()
                and sha256(original) == expected,
                "signed bundle fixture differs from staged provenance: " + name)
    return metadata, good, bad


def replacement_offsets(logical_size):
    """Probe fresh opens across independent ASCF chunk and VFS boundaries.

    Every listed offset must fail after replacement, including EOF. A single
    failure at offset zero cannot certify the remaining mapped file.
    """
    require(type(logical_size) is int and logical_size >= 0,
            "replacement check needs a nonnegative logical size")
    positions = {0, logical_size, logical_size + 1}
    for boundary in (1, 4096, 65536, 8 * 1024 * 1024,
                     logical_size // 2, logical_size):
        for delta in (-1, 0, 1):
            positions.add(min(logical_size + 1, max(0, boundary + delta)))
    return sorted(positions)


def probe_read(path, offset):
    # Reopen for EVERY sampled offset. A cached successful open or readable
    # region after archive replacement is an acceptance failure.
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        return os.pread(fd, 1, offset)
    finally:
        os.close(fd)


def check(directory, mount, original, verifier=None, read_probe=probe_read):
    metadata, good, bad = validate_stage(directory)
    mount = Path(mount)
    expected = mount / Path(metadata["archive"]).stem
    require(Path(original).is_file(), "original cleartext fixture missing")
    require(sha256(original) == metadata["original_sha256"],
            "cleartext reference differs from staged archive")
    if verifier is None:
        from verify_mount import verify_mount
        verifier = verify_mount
    # Authenticate the mounted filesystem and every logical byte before
    # touching a generated copy. A failed prerequisite leaves it unchanged.
    report = verifier(str(mount), str(original), require_real_mount=True)
    require(report.get("result") == "pass"
            and report.get("filesystem_type") == "ascf"
            and report.get("kernel_readonly") is True
            and report.get("unique_ascf_mount_verified") is True
            and type(report.get("active_ascf_mounts")) is int
            and report["active_ascf_mounts"] == 1
            and report.get("restored_file") == expected.name
            and report.get("mount") == str(mount)
            and report.get("sha256") == metadata["original_sha256"]
            and bool(report.get("macos_build")),
            "mounted ASCF readback prerequisite failed")
    before = good.stat()
    os.replace(bad, good)  # Only generated /tmp archive copy.
    after = good.stat()
    require((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino),
            "archive pathname did not change inode after atomic replacement")
    require(sha256(good) == metadata["replacement_sha256"],
            "staged replacement content mismatch")
    offsets = replacement_offsets(Path(original).stat().st_size)
    denied_errnos = []
    for offset in offsets:
        try:
            data = read_probe(expected, offset)
        except OSError as error:
            require(error.errno in EXPECTED_ERRORS,
                    f"mounted read at byte {offset} failed for an unrelated reason: errno {error.errno}")
            denied_errnos.append(error.errno)
        else:
            raise ValueError(
                f"FSKit served replaced-source bytes at offset {offset} ({len(data)} bytes)"
            )
    outcome = {"result": "pass", "codec": metadata["codec"],
               "stage_nonce": metadata["stage_nonce"],
               "staged_archive_name": metadata["archive"],
               "stage": str(good.parent), "archive": str(good),
               "replacement_sha256": metadata["replacement_sha256"],
               "source_archive_sha256": metadata["good_sha256"],
               "original_sha256": metadata["original_sha256"],
               "before_replacement_sha256": report["sha256"],
               "filesystem_type": report["filesystem_type"],
               "kernel_readonly": report["kernel_readonly"],
               "unique_ascf_mount_verified": True, "active_ascf_mounts": 1,
               "restored_file": report["restored_file"],
               "macos_build": report["macos_build"],
               "mount": str(mount), "denied_errno": denied_errnos[0],
               "denied_offsets": offsets, "denied_errnos": denied_errnos,
               "verified_at_utc": datetime.datetime.now(
                   datetime.timezone.utc).isoformat(),
               "scope": "operator-observed replaced-source refusal at fresh VFS opens; independent signed-host review required"}
    print(json.dumps(outcome, sort_keys=True, indent=2))
    return outcome



class ReplacementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.bundle = Path(self.temp.name)
        for codec in CODECS:
            (self.bundle / f"source.{codec}.jsonl").write_bytes(b"synthetic cleartext")
            (self.bundle / f"source.{codec}.ascf").write_bytes(b"ASCF0001valid")
            (self.bundle / f"source.{codec}.corrupt.ascf").write_bytes(b"ASCF0001bad!!")

    def tearDown(self):
        self.temp.cleanup()
        if hasattr(self, "stage_dir"):
            shutil.rmtree(self.stage_dir)

    def prepare(self, codec="lzmesh"):
        with mock.patch("builtins.print"):
            self.stage_dir = stage(self.bundle, codec)
        return validate_stage(self.stage_dir)

    def test_stages_only_synthetic_copies(self):
        meta, good, bad = self.prepare()
        self.assertEqual(meta["codec"], "lzmesh")
        self.assertRegex(meta["stage_nonce"], r"^[0-9a-f]{16}$")
        self.assertEqual(good.name, f"source.lzmesh.{meta['stage_nonce']}.ascf")
        self.assertNotEqual(sha256(good), sha256(bad))
        self.assertEqual((self.bundle / "source.lzmesh.ascf").read_bytes(), b"ASCF0001valid")

    def test_tamper_blocks_before_replacement(self):
        _, good, _ = self.prepare()
        good.write_bytes(b"tamper")
        with self.assertRaisesRegex(ValueError, "valid staged archive changed"):
            check(self.stage_dir, "/Volumes/ASCF", self.bundle / "source.lzmesh.jsonl")

    def test_bundle_fixture_change_blocks_replacement(self):
        _, good, bad = self.prepare()
        (self.bundle / "source.lzmesh.ascf").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "signed bundle fixture differs"):
            check(self.stage_dir, "/Volumes/ASCF", self.bundle / "source.lzmesh.jsonl")
        self.assertTrue(bad.exists(), "must refuse before replacing the staged good archive")
        self.assertEqual(good.read_bytes(), b"ASCF0001valid")

    def test_stage_bundle_provenance_is_required(self):
        self.prepare()
        metadata_path = self.stage_dir / "stage.json"
        metadata = json.loads(metadata_path.read_text())
        metadata.pop("bundle")
        metadata_path.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, "signed bundle provenance"):
            validate_stage(self.stage_dir)

    def test_stale_archive_name_cannot_certify_another_mount(self):
        meta, good, bad = self.prepare()
        def wrong_mount(*_args, **_kwargs):
            return {"result": "pass", "filesystem_type": "ascf",
                    "kernel_readonly": True, "unique_ascf_mount_verified": True,
                    "active_ascf_mounts": 1, "restored_file": "source.lzmesh",
                    "sha256": meta["original_sha256"], "macos_build": "synthetic",
                    "mount": "/Volumes/ASCF"}
        with self.assertRaisesRegex(ValueError, "mounted ASCF readback prerequisite"):
            check(self.stage_dir, "/Volumes/ASCF",
                  self.bundle / "source.lzmesh.jsonl", wrong_mount)
        self.assertTrue(bad.exists(), "wrong mount must be rejected before replacement")
        self.assertEqual(sha256(good), meta["good_sha256"])

    def test_tampered_stage_nonce_cannot_select_a_different_archive(self):
        self.prepare()
        metadata_path = self.stage_dir / "stage.json"
        metadata = json.loads(metadata_path.read_text())
        metadata["stage_nonce"] = "0" * 16
        metadata_path.write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, "stage archive identity invalid"):
            validate_stage(self.stage_dir)

    def test_replaced_archive_read_must_fail_closed(self):
        meta, good, bad = self.prepare()
        def verified(*_args, **_kwargs):
            return {"result": "pass", "filesystem_type": "ascf", "kernel_readonly": True, "unique_ascf_mount_verified": True, "active_ascf_mounts": 1,
                    "restored_file": f"source.lzmesh.{meta['stage_nonce']}", "sha256": meta["original_sha256"], "macos_build": "synthetic", "mount": "/Volumes/ASCF"}
        def refused(_path, _offset):
            raise OSError(errno.ESTALE, "source identity changed")
        with mock.patch("builtins.print"):
            result = check(self.stage_dir, "/Volumes/ASCF",
                           self.bundle / "source.lzmesh.jsonl", verified, refused)
        self.assertEqual(result["denied_errno"], errno.ESTALE)
        self.assertEqual(result["denied_offsets"], replacement_offsets(len(b"synthetic cleartext")))
        self.assertEqual(result["denied_errnos"], [errno.ESTALE] * len(result["denied_offsets"]))
        self.assertEqual(result["source_archive_sha256"], meta["good_sha256"])
        self.assertEqual(result["before_replacement_sha256"], meta["original_sha256"])
        self.assertFalse(bad.exists())
        self.assertEqual(sha256(good), meta["replacement_sha256"])

    def test_ambiguous_mount_blocks_staged_replacement(self):
        meta, good, bad = self.prepare()
        def ambiguous(*_args, **_kwargs):
            return {"result": "pass", "filesystem_type": "ascf",
                    "kernel_readonly": True, "unique_ascf_mount_verified": True,
                    "active_ascf_mounts": 2, "restored_file": f"source.lzmesh.{meta['stage_nonce']}",
                    "sha256": meta["original_sha256"], "macos_build": "synthetic", "mount": "/Volumes/ASCF"}
        with self.assertRaisesRegex(ValueError, "mounted ASCF readback prerequisite"):
            check(self.stage_dir, "/Volumes/ASCF",
                  self.bundle / "source.lzmesh.jsonl", ambiguous)
        self.assertTrue(bad.exists())
        self.assertEqual(good.read_bytes(), b"ASCF0001valid")

    def test_cached_success_is_rejected(self):
        meta, _, _ = self.prepare("lzraven")
        def verified(*_args, **_kwargs):
            return {"result": "pass", "filesystem_type": "ascf", "kernel_readonly": True, "unique_ascf_mount_verified": True, "active_ascf_mounts": 1,
                    "restored_file": f"source.lzraven.{meta['stage_nonce']}", "sha256": meta["original_sha256"], "macos_build": "synthetic", "mount": "/Volumes/ASCF"}
        with self.assertRaisesRegex(ValueError, "served replaced-source bytes at offset 0"):
            check(self.stage_dir, "/Volumes/ASCF",
                  self.bundle / "source.lzraven.jsonl", verified, lambda _path, _offset: b"x")

    def test_replacement_offsets_cover_independent_chunk_boundaries(self):
        size = 9 * 1024 * 1024 + 17
        offsets = replacement_offsets(size)
        self.assertEqual(offsets, sorted(set(offsets)))
        for location in (0, 4095, 4096, 4097, 65535, 65536, 65537,
                         8 * 1024 * 1024 - 1, 8 * 1024 * 1024,
                         8 * 1024 * 1024 + 1, size - 1, size, size + 1):
            self.assertIn(location, offsets)

    def test_later_cached_read_refuses_acceptance(self):
        meta, _, _ = self.prepare()
        def verified(*_args, **_kwargs):
            return {"result": "pass", "filesystem_type": "ascf",
                    "kernel_readonly": True, "unique_ascf_mount_verified": True, "active_ascf_mounts": 1, "restored_file": f"source.lzmesh.{meta['stage_nonce']}",
                    "sha256": meta["original_sha256"], "macos_build": "synthetic", "mount": "/Volumes/ASCF"}
        visited = []
        def probe(_path, offset):
            visited.append(offset)
            if offset == 1:
                return b"cached"
            raise OSError(errno.ESTALE, "source identity changed")
        with self.assertRaisesRegex(ValueError, "offset 1"):
            check(self.stage_dir, "/Volumes/ASCF",
                  self.bundle / "source.lzmesh.jsonl", verified, probe)
        self.assertEqual(visited[:2], [0, 1])

    def test_unrelated_errno_is_rejected(self):
        meta, _, _ = self.prepare("lzraven")
        def verified(*_args, **_kwargs):
            return {"result": "pass", "filesystem_type": "ascf", "kernel_readonly": True, "unique_ascf_mount_verified": True, "active_ascf_mounts": 1,
                    "restored_file": f"source.lzraven.{meta['stage_nonce']}", "sha256": meta["original_sha256"], "macos_build": "synthetic", "mount": "/Volumes/ASCF"}
        def denied(_path, _offset):
            raise OSError(errno.EACCES, "permissions")
        with self.assertRaisesRegex(ValueError, "unrelated reason"):
            check(self.stage_dir, "/Volumes/ASCF",
                  self.bundle / "source.lzraven.jsonl", verified, denied)


def main():
    if sys.argv[1:] == ["--self-test"]:
        return 0 if unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(ReplacementTests)).wasSuccessful() else 1
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    stage_args = sub.add_parser("stage", help="make disposable archive copies in /tmp")
    stage_args.add_argument("bundle")
    stage_args.add_argument("codec", choices=CODECS)
    check_args = sub.add_parser("check", help="require rejection after swapping only the staged archive")
    check_args.add_argument("stage_dir")
    check_args.add_argument("mount")
    check_args.add_argument("original")
    args = parser.parse_args()
    try:
        if args.mode == "stage":
            stage(args.bundle, args.codec)
        else:
            check(args.stage_dir, args.mount, args.original)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"ASCF source-replacement acceptance failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
