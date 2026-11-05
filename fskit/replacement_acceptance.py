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
    good = target / archive.name
    bad = target / "replacement.ascf"
    shutil.copyfile(archive, good)
    shutil.copyfile(damaged, bad)
    metadata = {
        # The signed portable package is the authority for the staged copy.
        # Preserve its canonical location so replacement-check can run the
        # manifest-authenticated helper rather than unrelated checkout code.
        "bundle": str(bundle),
        "codec": codec,
        "archive": archive.name,
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
    require(codec in CODECS and metadata.get("archive") == f"source.{codec}.ascf",
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


def probe_read(path):
    # Require a NEW open after source replacement. A cached successful open
    # or readable cached page is a refusal failure, even if bytes are valid.
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        return os.pread(fd, 1, 0)
    finally:
        os.close(fd)


def check(directory, mount, original, verifier=None, read_probe=probe_read):
    metadata, good, bad = validate_stage(directory)
    mount = Path(mount)
    expected = mount / f"source.{metadata['codec']}"
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
            and report.get("restored_file") == expected.name
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
    try:
        data = read_probe(expected)
    except OSError as error:
        require(error.errno in EXPECTED_ERRORS,
                f"mounted read failed for an unrelated reason: errno {error.errno}")
        outcome = {"result": "pass", "codec": metadata["codec"],
                   "stage": str(good.parent), "archive": str(good),
                   "replacement_sha256": metadata["replacement_sha256"],
                   "source_archive_sha256": metadata["good_sha256"],
                   "original_sha256": metadata["original_sha256"],
                   "before_replacement_sha256": report["sha256"],
                   "filesystem_type": report["filesystem_type"],
                   "kernel_readonly": report["kernel_readonly"],
                   "restored_file": report["restored_file"],
                   "macos_build": report["macos_build"],
                   "mount": str(mount), "denied_errno": error.errno,
                   "verified_at_utc": datetime.datetime.now(
                       datetime.timezone.utc).isoformat(),
                   "scope": "operator-observed replaced-source refusal; independent signed-host review required"}
        print(json.dumps(outcome, sort_keys=True, indent=2))
        return outcome
    raise ValueError(f"FSKit served a newly opened replaced-source file ({len(data)} bytes)")


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

    def test_replaced_archive_read_must_fail_closed(self):
        meta, good, bad = self.prepare()
        def verified(*_args, **_kwargs):
            return {"result": "pass", "filesystem_type": "ascf", "kernel_readonly": True,
                    "restored_file": "source.lzmesh", "sha256": meta["original_sha256"], "macos_build": "synthetic"}
        def refused(_path):
            raise OSError(errno.ESTALE, "source identity changed")
        with mock.patch("builtins.print"):
            result = check(self.stage_dir, "/Volumes/ASCF",
                           self.bundle / "source.lzmesh.jsonl", verified, refused)
        self.assertEqual(result["denied_errno"], errno.ESTALE)
        self.assertEqual(result["source_archive_sha256"], meta["good_sha256"])
        self.assertEqual(result["before_replacement_sha256"], meta["original_sha256"])
        self.assertFalse(bad.exists())
        self.assertEqual(sha256(good), meta["replacement_sha256"])

    def test_cached_success_is_rejected(self):
        meta, _, _ = self.prepare("lzraven")
        def verified(*_args, **_kwargs):
            return {"result": "pass", "filesystem_type": "ascf", "kernel_readonly": True,
                    "restored_file": "source.lzraven", "sha256": meta["original_sha256"], "macos_build": "synthetic"}
        with self.assertRaisesRegex(ValueError, "served a newly opened"):
            check(self.stage_dir, "/Volumes/ASCF",
                  self.bundle / "source.lzraven.jsonl", verified, lambda _: b"x")

    def test_unrelated_errno_is_rejected(self):
        meta, _, _ = self.prepare("lzraven")
        def verified(*_args, **_kwargs):
            return {"result": "pass", "filesystem_type": "ascf", "kernel_readonly": True,
                    "restored_file": "source.lzraven", "sha256": meta["original_sha256"], "macos_build": "synthetic"}
        def denied(_):
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
