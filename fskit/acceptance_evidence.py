#!/usr/bin/env python3
"""Check a completed two-mount FSKit acceptance evidence chain.

The check binds the first signed mounted readback, a witnessed unmount,
a second mounted readback, and the host's typed corrupt-archive refusal
to the same synthetic source. It validates operator evidence, not a
cryptographic attestation of the physical Mac. Independent review remains
a separate merge requirement.
"""
import argparse
import datetime
import errno
import hashlib
import json
import os
import re
import stat
from pathlib import Path
import sys
import tempfile
import unittest

# Share the executable verifier's deterministic read schedule with the
# evidence validator. A partial/randomly invented offset list must not pass.
from verify_mount import sampled_offsets
from replacement_acceptance import replacement_offsets
from finder_mount_witness import load_report


class EvidenceError(ValueError):
    pass


# Source and archive fixtures are independently manifest-limited to 1 GiB.
# Verification streams digests; operator-supplied text never needs megabytes.
MAX_FIXTURE_BYTES = 1024 * 1024 * 1024
MAX_OPERATOR_BYTES = 64 * 1024
READ_CHUNK = 1024 * 1024


def bounded_regular(path, limit, hash_only=False):
    """Read or hash a stable, bounded regular FD, refusing FIFO and symlinks.

    Nonblocking opens avoid hanging when a named pipe has no writer.
    Source identity is checked after the final byte to reject concurrent edits.
    """
    require(all(getattr(os, flag, 0) for flag in
                ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")),
            "platform lacks safe operator-evidence open flags")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
                "evidence is not a bounded regular file: " + str(path))
        snapshot = (before.st_dev, before.st_ino, before.st_mode,
                    before.st_size, before.st_mtime_ns, before.st_ctime_ns,
                    before.st_nlink)
        hasher = hashlib.sha256()
        data = bytearray() if not hash_only else None
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(READ_CHUNK, remaining))
            require(bool(chunk), "evidence shortened during read: " + str(path))
            hasher.update(chunk)
            if data is not None:
                data.extend(chunk)
            remaining -= len(chunk)
        require(not os.read(fd, 1), "evidence grew during read: " + str(path))
        after = os.fstat(fd)
        require(snapshot == (after.st_dev, after.st_ino, after.st_mode,
                             after.st_size, after.st_mtime_ns, after.st_ctime_ns,
                             after.st_nlink),
                "evidence changed during read: " + str(path))
        return (before.st_size, hasher.hexdigest()) if hash_only else bytes(data)
    finally:
        os.close(fd)


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def load_json(path):
    # Evidence files are operator-supplied. A FIFO must not hang acceptance,
    # a symlink must not redirect it, and duplicate JSON keys must not let
    # independent verifiers interpret contradictory success claims.
    try:
        return load_report(path)
    except (OSError, ValueError) as error:
        raise EvidenceError(f"unsafe signed acceptance evidence: {error}") from error


def signed_source_commit(bundle):
    """Require the exact Git identity recorded by the signed packager.

    Both the repository name and full commit SHA are covered by SHA256SUMS.
    A malformed record must never pass as a claimed provenance identity.
    """
    raw = bounded_regular(Path(bundle) / "source-provenance.txt", MAX_OPERATOR_BYTES).decode("utf-8")
    match = re.fullmatch(
        r"repository=chriscoveriesorg/applesauce\ncommit=([0-9a-f]{40})\n",
        raw,
    )
    require(match is not None,
            "signed source provenance must identify chriscoveriesorg/applesauce and an exact 40-hex commit")
    return match.group(1)


def evidence_time(report, stage):
    """Require an unambiguous UTC event time for a witnessed mount lifecycle."""
    raw = report.get("verified_at_utc")
    require(isinstance(raw, str), stage + ": missing UTC verification timestamp")
    try:
        timestamp = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError(stage + ": invalid verification timestamp") from error
    require(timestamp.tzinfo is not None and
            timestamp.utcoffset() == datetime.timedelta(0),
            stage + ": verification timestamp must be UTC")
    return timestamp


def valid_acceptance_mount(mount):
    """Allow only host-created /Volumes mounts or the cli-mount private stage.

    cli-mount creates /private/tmp/ascf-cli-mount.XXXXXXXX/mount with mktemp,
    then verifies that its VFS type is ascf and its kernel flags are read-only.
    Reject generic /tmp paths, traversal and aliases rather than treating
    every operator-selected directory as a signed FSKit mount.
    """
    if not isinstance(mount, str):
        return False
    return bool(
        re.fullmatch(r"/Volumes/[^/\x00.][^/\x00]*", mount)
        or re.fullmatch(
            r"/private/tmp/ascf-cli-mount\.[A-Za-z0-9]{8}/mount", mount)
    )


def validate(bundle, codec, first, unmounted, remounted, refusal, replacement):
    require(codec in ("lzraven", "lzmesh"), "unsupported codec")
    source = Path(bundle) / ("source." + codec + ".jsonl")
    # lstat tests only existence: is_file() follows symlinks and silently
    # classifies FIFOs as missing before the bounded descriptor gate runs.
    try:
        source.lstat()
    except FileNotFoundError as error:
        raise EvidenceError("missing synthetic reference cleartext") from error
    logical_bytes, digest = bounded_regular(source, MAX_FIXTURE_BYTES, hash_only=True)
    reports = [load_json(first), load_json(remounted)]

    for stage, report in zip(("first mount", "remount"), reports):
        require(report.get("result") == "pass", stage + ": readback failed")
        require(report.get("filesystem_type") == "ascf",
                stage + ": ASCF VFS type missing")
        require(report.get("kernel_readonly") is True
                and isinstance(report.get("mount_flags"), int)
                and report["mount_flags"] & 1,
                stage + ": VFS read-only proof missing")
        require(report.get("unique_ascf_mount_verified") is True
                and type(report.get("active_ascf_mounts")) is int
                and report["active_ascf_mounts"] == 1,
                stage + ": unique kernel ASCF mount proof missing")
        require(report.get("readonly_open_denied") is True,
                stage + ": denied write opens not established")
        # Check the mounted bytes against the reference before checking the
        # independently copied Finder output. A replaced synthetic source must
        # fail at the logical-byte contract, even if the Finder proof is stale.
        require(report.get("logical_bytes") == logical_bytes
                and report.get("sha256") == digest,
                stage + ": original logical bytes do not match bundle")
        require(report.get("restored_file") == "source." + codec,
                stage + ": unexpected archive member")
        require(report.get("finder_copy_verified") is True
                and report.get("finder_copy_sha256") == digest,
                stage + ": Finder copy-out whole-file verification missing")
        require(report.get("post_finder_mount_verified") is True
                and report.get("post_finder_mount_fsid") == report.get("mount_fsid")
                and isinstance(report.get("mount_fsid"), list)
                and len(report["mount_fsid"]) == 2
                and type(report.get("mount_device")) is int
                and type(report.get("mount_inode")) is int
                and report["mount_inode"] > 0,
                stage + ": post-Finder kernel mount identity witness missing")
        mount = report.get("mount")
        require(valid_acceptance_mount(mount),
                stage + ": invalid mount location")
        require(report.get("macos_version") and report.get("macos_build"),
                stage + ": missing host OS provenance")
        offsets = report.get("random_read_offsets")
        require(offsets == sampled_offsets(logical_bytes, digest),
                stage + ": complete deterministic random/EOF read evidence missing")
    require(reports[0]["macos_build"] == reports[1]["macos_build"],
            "first mount and remount have different macOS build provenance")
    first_id, second_id = (report.get("verification_id") for report in reports)
    require(isinstance(first_id, str) and bool(first_id)
            and isinstance(second_id, str) and bool(second_id)
            and first_id != second_id,
            "two independent mounted-readback verification IDs required")

    off = load_json(unmounted)
    require(off.get("result") == "pass" and off.get("unmounted") is True,
            "unmount report did not pass")
    require(off.get("kernel_mount_table_verified") is True
            and off.get("remaining_ascf_mounts") == 0,
            "unmount lacks complete kernel mount-table proof")
    require(off.get("macos_build") == reports[0]["macos_build"],
            "unmount and first readback have different macOS builds")
    require(off.get("mount") == reports[0]["mount"],
            "unmount report is for another mount")
    require(off.get("previous_sha256") == digest,
            "unmount report references a different cleartext")
    require(off.get("previous_verification_id") == first_id,
            "unmount report does not bind the first readback verification")
    first_at = evidence_time(reports[0], "first mount")
    unmount_at = evidence_time(off, "unmount")
    remount_at = evidence_time(reports[1], "remount")
    require(first_at < unmount_at < remount_at,
            "mount/unmount/remount timestamps are out of order")
    # Complete acceptance needs a second, signed FSKit mount where a staged
    # synthetic archive is replaced and fresh kernel reads are refused.
    replaced = load_json(replacement)
    require(replaced.get("result") == "pass" and replaced.get("codec") == codec,
            "codec-specific replaced-source refusal evidence missing")
    require(replaced.get("filesystem_type") == "ascf"
            and replaced.get("kernel_readonly") is True
            and replaced.get("unique_ascf_mount_verified") is True
            and type(replaced.get("active_ascf_mounts")) is int
            and replaced["active_ascf_mounts"] == 1,
            "replaced-source refusal lacks read-only ASCF VFS proof")
    # The replacement stage has its own unpredictable archive basename.
    # The FSKit logical entry must carry that basename, so a mount of the
    # otherwise byte-identical signed bundle fixture cannot count as the
    # independent staged replacement. A plain source.<codec> is insufficient.
    nonce = replaced.get("stage_nonce")
    require(isinstance(nonce, str) and
            re.fullmatch(r"[0-9a-f]{16}", nonce) is not None,
            "replacement evidence lacks a valid stage nonce")
    staged_name = f"source.{codec}.{nonce}.ascf"
    stage_path = replaced.get("stage")
    archive_path = replaced.get("archive")
    require(isinstance(stage_path, str)
            and re.fullmatch(r"/(?:private/)?tmp/ascf-replacement-[A-Za-z0-9_]+",
                             stage_path) is not None
            and isinstance(archive_path, str)
            and archive_path == str(Path(stage_path) / staged_name)
            and replaced.get("staged_archive_name") == staged_name
            and replaced.get("restored_file") == f"source.{codec}.{nonce}"
            and replaced.get("mount") == reports[1]["mount"],
            "replaced-source refusal is not bound to its unique staged archive")
    require(replaced.get("macos_build") == reports[1]["macos_build"],
            "replaced-source refusal has different macOS build")
    require(replaced.get("original_sha256") == digest
            and replaced.get("before_replacement_sha256") == digest,
            "replaced-source refusal differs from original logical digest")
    for field, suffix in (("source_archive_sha256", ".ascf"),
                          ("replacement_sha256", ".corrupt.ascf")):
        archive = Path(bundle) / ("source." + codec + suffix)
        require(archive.is_file(), "required signed-bundle archive fixture missing")
        require(replaced.get(field) == bounded_regular(archive, MAX_FIXTURE_BYTES, hash_only=True)[1],
                "replaced-source refusal has wrong " + field)
    require(replaced.get("denied_errno") in (errno.ESTALE, errno.EIO, errno.ENODEV),
            "replaced-source fresh read did not fail with the permitted errno")
    # Check the entire deterministic source-replacement probe schedule. A
    # single refused offset-zero read cannot attest to cached chunk boundaries,
    # nonzero offsets, EOF or newly opened paths.
    offsets = replacement_offsets(logical_bytes)
    require(replaced.get("denied_offsets") == offsets,
            "replaced-source refusal offset schedule incomplete")
    errnos = replaced.get("denied_errnos")
    require(isinstance(errnos, list) and len(errnos) == len(offsets)
            and all(type(code) is int and code in
                    (errno.ESTALE, errno.EIO, errno.ENODEV) for code in errnos)
            and errnos[0] == replaced["denied_errno"],
            "replaced-source offset errno evidence incomplete")
    require(evidence_time(replaced, "source replacement") > remount_at,
            "source replacement must follow the verified remount")

    # Bind the host's typed negative-control result to the exact
    # manifest-covered damaged fixture. Reject a copied confirmation line
    # embedded in other diagnostics and a same-named unrelated corrupt file.
    corrupt_fixture = Path(bundle) / ("source." + codec + ".corrupt.ascf")
    expected_sha = bounded_regular(corrupt_fixture, MAX_FIXTURE_BYTES, hash_only=True)[1]
    expected_prefix = ("CORRUPT_REFUSAL_CONFIRMED: source." + codec
                       + ".corrupt.ascf: sha256=" + expected_sha
                       + ": signed FSKit probe rejected the recognized ASCF payload: "
                       + "FSKitErrorDomain resourceDamaged code ")
    text = bounded_regular(refusal, MAX_OPERATOR_BYTES).decode("utf-8").strip()
    require(text.startswith(expected_prefix)
            and re.fullmatch(r"[1-9][0-9]*: [^\r\n]+", text[len(expected_prefix):]) is not None,
            "typed codec-specific signed-host corruption refusal is not bound to the bundled fixture SHA-256")

    paths = (first, unmounted, remounted, refusal, replacement)
    evidence_hashes = {
        name: bounded_regular(path, MAX_OPERATOR_BYTES, hash_only=True)[1]
        for name, path in zip(("first", "unmounted", "remounted", "refusal", "replacement"), paths)
    }
    return {
        "result": "pass",
        "scope": "operator-evidence-consistency; independent signed-mount review required",
        "codec": codec,
        "logical_bytes": logical_bytes,
        "sha256": digest,
        "source_commit": signed_source_commit(bundle),
        "first_mount": reports[0]["mount"],
        "remounted": reports[1]["mount"],
        "macos_build": reports[0]["macos_build"],
        "evidence_sha256": evidence_hashes,
    }


def validate_both(bundle, raven_paths, mesh_paths):
    """Require two complete codec-specific lifecycles on the same macOS build.

    This is an operator-evidence consistency gate. It cannot attest that the
    physical Mac was signed, provisioned or mounted: review remains mandatory.
    """
    require(len(raven_paths) == 5 and len(mesh_paths) == 5,
            "five evidence paths per codec are required")
    results = {
        "lzraven": validate(bundle, "lzraven", *raven_paths),
        "lzmesh": validate(bundle, "lzmesh", *mesh_paths),
    }
    raven, mesh = results["lzraven"], results["lzmesh"]
    require(raven["sha256"] == mesh["sha256"]
            and raven["logical_bytes"] == mesh["logical_bytes"],
            "Raven and Mesh did not restore the same synthetic logical bytes")
    require(raven["macos_build"] == mesh["macos_build"],
            "Raven and Mesh evidence comes from different macOS builds")
    require(raven["source_commit"] == mesh["source_commit"],
            "Raven and Mesh evidence refers to different source commits")

    # The operator must provide four independent mounted-readback events.
    # A duplicated verification ID shared across codecs invalidates the
    # combined claim even when individual readback chains each appear valid.
    identifiers = [
        load_json(path).get("verification_id")
        for path in (raven_paths[0], raven_paths[2],
                     mesh_paths[0], mesh_paths[2])
    ]
    require(all(isinstance(value, str) and value for value in identifiers)
            and len(set(identifiers)) == 4,
            "four independent codec-specific mounted-readback IDs required")
    return {
        "result": "pass",
        "scope": "both-codec operator-evidence consistency; independent signed-mount review required",
        "source_commit": raven["source_commit"],
        "macos_build": raven["macos_build"],
        "logical_bytes": raven["logical_bytes"],
        "sha256": raven["sha256"],
        "codecs": results,
    }


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / "source.lzmesh.jsonl").write_bytes(b"test\n" * 20)
        (self.base / "source-provenance.txt").write_text(
            "repository=chriscoveriesorg/applesauce\ncommit=" + "a" * 40 + "\n")
        self.sha = hashlib.sha256((self.base / "source.lzmesh.jsonl").read_bytes()).hexdigest()
        self.items = [
            self.base / "first.json", self.base / "off.json",
            self.base / "remount.json", self.base / "refusal.txt",
            self.base / "replacement.json"
        ]
        report = {
            "result": "pass", "filesystem_type": "ascf",
            "kernel_readonly": True, "mount_flags": 1,
            "unique_ascf_mount_verified": True, "active_ascf_mounts": 1,
            "readonly_open_denied": True, "restored_file": "source.lzmesh",
            "finder_copy_verified": True, "finder_copy_sha256": self.sha,
            "post_finder_mount_verified": True,
            "mount_fsid": [42, 21], "post_finder_mount_fsid": [42, 21],
            "mount_device": 12, "mount_inode": 34,
            "logical_bytes": 100, "sha256": self.sha,
            "mount": "/Volumes/Applesauce ASCF", "macos_version": "27.0",
            "macos_build": "fixture", "random_read_offsets": sampled_offsets(100, self.sha)
        }
        for label, item, instant in zip(
            ("first", "second"), (self.items[0], self.items[2]),
            ("2026-11-04T00:00:00+00:00", "2026-11-04T00:00:10+00:00")
        ):
            item.write_text(json.dumps({**report, "verification_id": label,
                                        "verified_at_utc": instant}))
        self.items[1].write_text(json.dumps({
            "result": "pass", "unmounted": True,
            "mount": report["mount"], "previous_sha256": self.sha,
            "previous_verification_id": "first",
            "macos_build": "fixture",
            "kernel_mount_table_verified": True, "remaining_ascf_mounts": 0,
            "verified_at_utc": "2026-11-04T00:00:05+00:00"
        }))
        valid = b"ASCF0001-clean"
        corrupt = b"ASCF0001-damaged"
        (self.base / "source.lzmesh.ascf").write_bytes(valid)
        (self.base / "source.lzmesh.corrupt.ascf").write_bytes(corrupt)
        self.items[3].write_text(
            "CORRUPT_REFUSAL_CONFIRMED: source.lzmesh.corrupt.ascf: sha256="
            + hashlib.sha256(corrupt).hexdigest()
            + ": signed FSKit probe rejected the recognized ASCF payload: "
            + "FSKitErrorDomain resourceDamaged code 17: fixture damage")
        self.items[4].write_text(json.dumps({
            "result": "pass", "codec": "lzmesh", "filesystem_type": "ascf",
            "kernel_readonly": True,
            "stage_nonce": "0123456789abcdef",
            "staged_archive_name": "source.lzmesh.0123456789abcdef.ascf",
            "stage": "/private/tmp/ascf-replacement-fixture",
            "archive": "/private/tmp/ascf-replacement-fixture/source.lzmesh.0123456789abcdef.ascf",
            "restored_file": "source.lzmesh.0123456789abcdef",
            "unique_ascf_mount_verified": True, "active_ascf_mounts": 1,
            "mount": "/Volumes/Applesauce ASCF", "macos_build": "fixture",
            "original_sha256": self.sha, "before_replacement_sha256": self.sha,
            "source_archive_sha256": hashlib.sha256(valid).hexdigest(),
            "replacement_sha256": hashlib.sha256(corrupt).hexdigest(),
            "denied_errno": errno.ESTALE,
            "denied_offsets": replacement_offsets(100),
            "denied_errnos": [errno.ESTALE] * len(replacement_offsets(100)),
            "verified_at_utc": "2026-11-04T00:00:20+00:00"
        }))
    def check(self):
        return validate(self.base, "lzmesh", *self.items)
    def other_codec(self):
        # Reproduce the packaged same-cleartext/different-codec contract.
        codec = "lzraven"
        (self.base / f"source.{codec}.jsonl").write_bytes(
            (self.base / "source.lzmesh.jsonl").read_bytes())
        valid = b"ASCF0001-raven-clean"
        damaged = b"ASCF0001-raven-damaged"
        (self.base / f"source.{codec}.ascf").write_bytes(valid)
        (self.base / f"source.{codec}.corrupt.ascf").write_bytes(damaged)
        paths = [self.base / f"raven-{name}" for name in (
            "first.json", "off.json", "remount.json",
            "refusal.txt", "replacement.json")]
        for index in (0, 2):
            report = load_json(self.items[index])
            report["restored_file"] = "source.lzraven"
            report["verification_id"] = f"raven-{index}"
            paths[index].write_text(json.dumps(report))
        off = load_json(self.items[1])
        off["previous_verification_id"] = "raven-0"
        paths[1].write_text(json.dumps(off))
        paths[3].write_text(
            "CORRUPT_REFUSAL_CONFIRMED: source.lzraven.corrupt.ascf: sha256="
            + hashlib.sha256(damaged).hexdigest()
            + ": signed FSKit probe rejected the recognized ASCF payload: "
            + "FSKitErrorDomain resourceDamaged code 17: fixture damage")
        replacement = load_json(self.items[4])
        replacement["codec"] = codec
        replacement["restored_file"] = "source.lzraven.0123456789abcdef"
        replacement["staged_archive_name"] = "source.lzraven.0123456789abcdef.ascf"
        replacement["archive"] = "/private/tmp/ascf-replacement-fixture/source.lzraven.0123456789abcdef.ascf"
        replacement["source_archive_sha256"] = hashlib.sha256(valid).hexdigest()
        replacement["replacement_sha256"] = hashlib.sha256(damaged).hexdigest()
        paths[4].write_text(json.dumps(replacement))
        return paths

    def test_rejects_ambiguous_or_nonfinite_signed_evidence(self):
        self.items[0].write_text('{"result":"fail","result":"pass"}')
        with self.assertRaisesRegex(EvidenceError, "duplicate JSON"):
            self.check()
        self.items[0].write_text('{"result":"pass","logical_bytes":Infinity}')
        with self.assertRaisesRegex(EvidenceError, "non-finite"):
            self.check()

    def test_rejects_oversized_and_symlinked_signed_evidence(self):
        self.items[1].write_bytes(b" " * (1024 * 1024 + 1))
        with self.assertRaisesRegex(EvidenceError, "bounded regular file"):
            self.check()
        self.items[1].unlink()
        self.items[1].symlink_to(self.items[0])
        with self.assertRaisesRegex(EvidenceError, "unsafe signed acceptance"):
            self.check()

    def test_operator_refusal_fifo_is_rejected_without_blocking(self):
        # Substituted named pipes previously hung the unbounded read_text().
        refusal = self.items[3]
        refusal.unlink()
        os.mkfifo(refusal)
        with self.assertRaisesRegex(EvidenceError, "bounded regular file"):
            self.check()

    def test_operator_refusal_symlink_and_oversized_text_are_rejected(self):
        refusal = self.items[3]
        refusal.unlink()
        refusal.symlink_to(self.items[0])
        with self.assertRaises(OSError):
            self.check()
        refusal.unlink()
        refusal.write_bytes(b"x" * (MAX_OPERATOR_BYTES + 1))
        with self.assertRaisesRegex(EvidenceError, "bounded regular file"):
            self.check()

    def test_source_fixture_fifo_and_oversized_sparse_file_are_rejected(self):
        source = self.base / "source.lzmesh.jsonl"
        source.unlink()
        os.mkfifo(source)
        with self.assertRaisesRegex(EvidenceError, "bounded regular file"):
            self.check()
        source.unlink()
        with source.open("wb") as stream:
            stream.truncate(MAX_FIXTURE_BYTES + 1)
        with self.assertRaisesRegex(EvidenceError, "bounded regular file"):
            self.check()

    def test_bounded_reader_detects_shortened_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            member = Path(tmp) / "fixture"
            member.write_bytes(b"12345")
            original_read = os.read
            member_inode = member.stat().st_ino

            def short_read(fd, amount):
                if os.fstat(fd).st_ino == member_inode:
                    return b""
                return original_read(fd, amount)

            from unittest import mock
            with mock.patch.object(os, "read", side_effect=short_read):
                with self.assertRaisesRegex(EvidenceError, "shortened during read"):
                    bounded_regular(member, MAX_OPERATOR_BYTES, hash_only=True)

    def test_canonical_manifest_source_commit_is_reported(self):
        self.assertEqual(self.check()["source_commit"], "a" * 40)

    def test_source_commit_rejects_wrong_repository(self):
        (self.base / "source-provenance.txt").write_text(
            "repository=other/applesauce\ncommit=" + "a" * 40 + "\n")
        with self.assertRaisesRegex(EvidenceError, "signed source provenance"):
            self.check()

    def test_source_commit_rejects_abbreviated_or_untrusted_sha(self):
        for commit in ("a" * 7, "G" * 40, "a" * 39 + "z", "a" * 41):
            with self.subTest(commit=commit):
                (self.base / "source-provenance.txt").write_text(
                    "repository=chriscoveriesorg/applesauce\ncommit=" + commit + "\n")
                with self.assertRaisesRegex(EvidenceError, "signed source provenance"):
                    self.check()

    def test_source_commit_rejects_appended_or_duplicate_metadata(self):
        base = "repository=chriscoveriesorg/applesauce\ncommit=" + "a" * 40 + "\n"
        for extra in ("commit=" + "b" * 40 + "\n", "owner=other\n", "\n"):
            with self.subTest(extra=extra):
                (self.base / "source-provenance.txt").write_text(base + extra)
                with self.assertRaisesRegex(EvidenceError, "signed source provenance"):
                    self.check()

    def test_both_codec_lifecycles_pass_together(self):
        other = self.other_codec()
        result = validate_both(self.base, other, self.items)
        self.assertEqual(set(result["codecs"]), {"lzraven", "lzmesh"})
        self.assertEqual(result["result"], "pass")

    def test_both_codec_requires_four_distinct_readbacks(self):
        other = self.other_codec()
        first = load_json(other[0])
        first["verification_id"] = "first"
        other[0].write_text(json.dumps(first))
        off = load_json(other[1])
        off["previous_verification_id"] = "first"
        other[1].write_text(json.dumps(off))
        with self.assertRaisesRegex(EvidenceError, "four independent"):
            validate_both(self.base, other, self.items)

    def test_both_codec_rejects_mixed_macos_builds(self):
        other = self.other_codec()
        for index in (0, 2):
            report = load_json(other[index])
            report["macos_build"] = "another-host-build"
            other[index].write_text(json.dumps(report))
        replacement = load_json(other[4])
        replacement["macos_build"] = "another-host-build"
        other[4].write_text(json.dumps(replacement))
        with self.assertRaisesRegex(EvidenceError, "different macOS builds"):
            validate_both(self.base, other, self.items)

    def test_both_codec_rejects_missing_one_codec(self):
        other = self.other_codec()
        other[4].unlink()
        with self.assertRaisesRegex(EvidenceError, "unsafe signed acceptance evidence"):
            validate_both(self.base, other, self.items)

    def test_valid_chain(self):
        self.assertEqual(self.check()["result"], "pass")

    def test_terminal_cli_mount_acceptance_chain(self):
        # The executable cli-mount command uses a fresh, mode-0700 private
        # /private/tmp stage, so its mounted Finder evidence must remain
        # usable by the signed acceptance checker.
        path = "/private/tmp/ascf-cli-mount.AbC123xY/mount"
        for index in (0, 1, 2, 4):
            report = load_json(self.items[index])
            report["mount"] = path
            self.items[index].write_text(json.dumps(report))
        self.assertEqual(self.check()["result"], "pass")

    def test_private_mount_policy_matches_executable_cli_mount(self):
        # Keep the validator's accepted private location aligned with the
        # actual mount stage produced by the shipped executable handoff.
        script = (Path(__file__).parent / "signed_acceptance.sh").read_text(
            encoding="utf-8")
        self.assertIn('mktemp -d /private/tmp/ascf-cli-mount.XXXXXXXX', script)
        self.assertIn('/bin/mkdir "$out/mount"', script)
        self.assertTrue(valid_acceptance_mount(
            "/private/tmp/ascf-cli-mount.AbC123xY/mount"))
        self.assertTrue(valid_acceptance_mount("/Volumes/Applesauce ASCF"))

    def test_rejects_untrusted_terminal_mount_paths(self):
        cases = [
            "/tmp/ascf-cli-mount.AbC123xY/mount",
            "/private/tmp/ascf-cli-mount.AbC123xY/../mount",
            "/private/tmp/ascf-cli-mount.AbC123xY/other",
            "/private/tmp/ascf-cli-mount.AbC123xY/mount/",
            "/private/tmp/ascf-cli-mount.unsafe/mount",
            "/private/tmp/other.AbC123xY/mount",
            "/Volumes/../Other",
            "/Volumes/Applesauce ASCF/child",
            "/Volumes//Other",
            "/Volumes/./Other",
        ]
        for path in cases:
            with self.subTest(path=path):
                self.assertFalse(valid_acceptance_mount(path), path)

    def test_rejects_false_cli_mount_evidence(self):
        report = load_json(self.items[0])
        report["mount"] = "/tmp/ascf-cli-mount.AbC123xY/mount"
        self.items[0].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "invalid mount location"):
            self.check()
    def test_replacement_from_regular_bundle_mount_is_rejected(self):
        report = load_json(self.items[4])
        report["restored_file"] = "source.lzmesh"
        self.items[4].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "unique staged archive"):
            self.check()

    def test_replacement_stale_stage_nonce_is_rejected(self):
        report = load_json(self.items[4])
        report["stage_nonce"] = "bad"
        self.items[4].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "valid stage nonce"):
            self.check()

    def test_replacement_stage_path_mismatch_is_rejected(self):
        report = load_json(self.items[4])
        report["archive"] = "/private/tmp/another-folder/source.lzmesh.0123456789abcdef.ascf"
        self.items[4].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "unique staged archive"):
            self.check()

    def test_replaced_source_wrong_digest(self):
        report = load_json(self.items[4])
        report["replacement_sha256"] = "0" * 64
        self.items[4].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "wrong replacement_sha256"):
            self.check()

    def test_incomplete_replacement_offsets_refused(self):
        report = load_json(self.items[4])
        report["denied_offsets"] = report["denied_offsets"][:1]
        report["denied_errnos"] = report["denied_errnos"][:1]
        self.items[4].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "offset schedule incomplete"):
            self.check()

    def test_replacement_offset_success_refused(self):
        report = load_json(self.items[4])
        report["denied_errnos"][1] = 0
        self.items[4].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "offset errno evidence incomplete"):
            self.check()

    def test_replacement_offset_mismatch_refused(self):
        report = load_json(self.items[4])
        report["denied_errnos"].pop()
        self.items[4].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "offset errno evidence incomplete"):
            self.check()

    def test_replaced_source_cached_read(self):
        report = load_json(self.items[4])
        report["denied_errno"] = 0
        self.items[4].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "permitted errno"):
            self.check()

    def test_replaced_source_wrong_codec(self):
        report = load_json(self.items[4])
        report["codec"] = "lzraven"
        self.items[4].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "codec-specific"):
            self.check()

    def test_replaced_source_precedes_remount(self):
        report = load_json(self.items[4])
        report["verified_at_utc"] = "2026-11-04T00:00:07+00:00"
        self.items[4].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "follow the verified remount"):
            self.check()

    def test_partial_random_read_report_is_not_complete_acceptance(self):
        # An otherwise valid report can retain 20+ sampled positions, start
        # and EOF, but omit boundary and middle-of-file read coverage.
        report = load_json(self.items[0])
        recorded = report["random_read_offsets"]
        report["random_read_offsets"] = recorded[:20] + [100]
        self.items[0].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "complete deterministic"):
            self.check()

    def test_same_size_large_sources_use_distinct_verified_read_schedules(self):
        # For a tiny 100-byte fixture the fixed boundary probes already
        # cover nearly every byte, so extra sampled positions can coincide.
        # Large real acceptance fixtures need source-specific coverage.
        size = 8 * 1024 * 1024
        first = sampled_offsets(size, self.sha)
        foreign = sampled_offsets(
            size, hashlib.sha256(b"different source, same length").hexdigest())
        self.assertNotEqual(first, foreign)
        self.assertGreater(len(set(first) ^ set(foreign)), 40)
        self.assertEqual(self.check()["result"], "pass")

    def test_random_read_report_rejects_duplicate_or_unsorted_offsets(self):
        report = load_json(self.items[2])
        recorded = report["random_read_offsets"]
        report["random_read_offsets"] = list(reversed(recorded))
        self.items[2].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "complete deterministic"):
            self.check()

    def test_random_read_report_rejects_out_of_bounds_position(self):
        report = load_json(self.items[0])
        report["random_read_offsets"][-1] = 101
        self.items[0].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "complete deterministic"):
            self.check()

    def test_wrong_source(self):
        (self.base / "source.lzmesh.jsonl").write_bytes(b"altered")
        with self.assertRaisesRegex(EvidenceError, "logical bytes"):
            self.check()
    def test_missing_kernel_unmount_witness(self):
        off = load_json(self.items[1])
        off["kernel_mount_table_verified"] = False
        self.items[1].write_text(json.dumps(off))
        with self.assertRaisesRegex(EvidenceError, "kernel mount-table"):
            self.check()

    def test_unmount_with_surviving_ascf_mount(self):
        off = load_json(self.items[1])
        off["remaining_ascf_mounts"] = 1
        self.items[1].write_text(json.dumps(off))
        with self.assertRaisesRegex(EvidenceError, "kernel mount-table"):
            self.check()

    def test_unmount_provenance_from_other_host(self):
        off = load_json(self.items[1])
        off["macos_build"] = "other"
        self.items[1].write_text(json.dumps(off))
        with self.assertRaisesRegex(EvidenceError, "different macOS build"):
            self.check()

    def test_missing_unmount_timestamp(self):
        off = load_json(self.items[1])
        off.pop("verified_at_utc")
        self.items[1].write_text(json.dumps(off))
        with self.assertRaisesRegex(EvidenceError, "missing UTC"):
            self.check()

    def test_unmount_before_first_readback(self):
        off = load_json(self.items[1])
        off["verified_at_utc"] = "2026-11-03T23:59:59+00:00"
        self.items[1].write_text(json.dumps(off))
        with self.assertRaisesRegex(EvidenceError, "out of order"):
            self.check()

    def test_remount_before_unmount(self):
        remount = load_json(self.items[2])
        remount["verified_at_utc"] = "2026-11-04T00:00:03+00:00"
        self.items[2].write_text(json.dumps(remount))
        with self.assertRaisesRegex(EvidenceError, "out of order"):
            self.check()

    def test_reject_timezone_naive_readback(self):
        first = load_json(self.items[0])
        first["verified_at_utc"] = "2026-11-04T00:00:00"
        self.items[0].write_text(json.dumps(first))
        with self.assertRaisesRegex(EvidenceError, "must be UTC"):
            self.check()

    def test_unmount_mismatch(self):
        report = load_json(self.items[1])
        report["mount"] = "/Volumes/Other"
        self.items[1].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "another mount"):
            self.check()
    def test_missing_kernel_proof(self):
        report = load_json(self.items[2])
        report["kernel_readonly"] = False
        self.items[2].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "VFS read-only"):
            self.check()
    def test_ambiguous_mounts_in_readbacks_or_replacement(self):
        for index in (0, 2, 4):
            with self.subTest(index=index):
                report = load_json(self.items[index])
                report["active_ascf_mounts"] = 2
                self.items[index].write_text(json.dumps(report))
                with self.assertRaisesRegex(EvidenceError, "ASCF"):
                    self.check()
                report["active_ascf_mounts"] = 1
                self.items[index].write_text(json.dumps(report))


    def test_corruption_refusal_requires_bundle_fixture_digest(self):
        self.items[3].write_text(
            self.items[3].read_text().replace(
                hashlib.sha256(b"ASCF0001-damaged").hexdigest(), "0" * 64))
        with self.assertRaisesRegex(EvidenceError, "SHA-256"):
            self.check()

    def test_corruption_refusal_rejects_embedded_or_multiline_success(self):
        authentic = self.items[3].read_text()
        for value in ("CORRUPT_REFUSAL_FAIL:\n" + authentic,
                      authentic + "\nCORRUPT_REFUSAL_INCONCLUSIVE",
                      "unrelated " + authentic):
            with self.subTest(value=value[:40]):
                self.items[3].write_text(value)
                with self.assertRaisesRegex(EvidenceError, "SHA-256"):
                    self.check()

    def test_corruption_refusal_requires_fskit_domain(self):
        self.items[3].write_text(
            self.items[3].read_text().replace(
                "FSKitErrorDomain", "NSPOSIXErrorDomain"))
        with self.assertRaisesRegex(EvidenceError, "SHA-256"):
            self.check()

    def test_corruption_refusal_requires_typed_resource_damage(self):
        # A non-damage FSKit error (e.g. no entitlement or disabled
        # extension) must not produce an accepted corruption-control proof.
        self.items[3].write_text(
            self.items[3].read_text().replace(
                "FSKitErrorDomain resourceDamaged code ",
                "FSKitErrorDomain code "))
        with self.assertRaisesRegex(EvidenceError, "corruption refusal"):
            self.check()

    def test_corruption_refusal_rejects_other_named_error(self):
        self.items[3].write_text(
            self.items[3].read_text().replace(
                "resourceDamaged", "operationFailed"))
        with self.assertRaisesRegex(EvidenceError, "corruption refusal"):
            self.check()

    def test_corruption_refusal_rejects_zero_error_code(self):
        self.items[3].write_text(
            self.items[3].read_text().replace(
                "resourceDamaged code 17:", "resourceDamaged code 0:"))
        with self.assertRaisesRegex(EvidenceError, "corruption refusal"):
            self.check()

    def test_signed_host_emits_symbolic_damage_identity(self):
        # Keep the runtime enum check, emitted diagnostic and bundled verifier
        # aligned. Compilation and physical acceptance remain separate gates.
        host = (Path(__file__).parent / "Host" / "HostApp.swift").read_text(
            encoding="utf-8")
        self.assertIn("actualError.code == FSError.Code.resourceDamaged.rawValue", host)
        self.assertIn("FSKitErrorDomain resourceDamaged code \\(actualError.code)", host)

    def test_corruption_refusal_rejects_bundle_mutation(self):
        # Keep the replacement-control evidence internally consistent so
        # this test reaches and isolates the separate signed-host SHA gate.
        modified = b"changed"
        (self.base / "source.lzmesh.corrupt.ascf").write_bytes(modified)
        replacement = load_json(self.items[4])
        replacement["replacement_sha256"] = hashlib.sha256(modified).hexdigest()
        self.items[4].write_text(json.dumps(replacement))
        with self.assertRaisesRegex(EvidenceError, "SHA-256"):
            self.check()

    def test_inconclusive_corruption(self):
        self.items[3].write_text("CORRUPT_REFUSAL_INCONCLUSIVE")
        with self.assertRaisesRegex(EvidenceError, "corruption refusal"):
            self.check()
    def test_wrong_codec_refusal(self):
        self.items[3].write_text(
            "CORRUPT_REFUSAL_CONFIRMED: source.lzraven.corrupt.ascf: "
            "signed FSKit probe rejected the recognized ASCF payload")
        with self.assertRaisesRegex(EvidenceError, "codec-specific"):
            self.check()
    def test_finder_missing(self):
        report = load_json(self.items[2])
        report.pop("finder_copy_verified")
        self.items[2].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "Finder copy-out"):
            self.check()
    def test_finder_mismatched_digest(self):
        report = load_json(self.items[2])
        report["finder_copy_sha256"] = "0" * 64
        self.items[2].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "Finder copy-out"):
            self.check()
    def test_reject_missing_post_finder_witness(self):
        report = load_json(self.items[2])
        report.pop("post_finder_mount_verified")
        self.items[2].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "post-Finder kernel mount"):
            self.check()

    def test_reject_swapped_fsid_after_finder_copy(self):
        report = load_json(self.items[0])
        report["post_finder_mount_fsid"] = [42, 22]
        self.items[0].write_text(json.dumps(report))
        with self.assertRaisesRegex(EvidenceError, "post-Finder kernel mount"):
            self.check()

    def test_direct_readback_stamps_only_after_finder_copy(self):
        # The owner-run direct-readback path used to call stamp_readback
        # before Finder copied a file. That dies on a missing second argv.
        # Keep both handoff paths single-stamp and copy-first.
        script = (Path(__file__).parent / "signed_acceptance.sh").read_text(
            encoding="utf-8")
        for label, section in (
            ("direct", script.split("\n  readback)\n", 1)[1].split(
                "\n  acceptance-check)\n", 1)[0]),
            ("bundle", script.split("\n  bundle-readback)\n", 1)[1].split(
                "\n  readback)\n", 1)[0]),
        ):
            with self.subTest(path=label):
                self.assertEqual(section.count('stamp_readback "$out/readback.json"'),
                                 1, "exactly one Finder-bound verification stamp required")
                self.assertLess(section.index("/usr/bin/cmp -s"),
                                section.index('stamp_readback "$out/readback.json"'),
                                "Finder copy must be compared before stamping")
                self.assertIn("post-finder-readback.json", section)
                self.assertLess(section.index("post-finder-readback.json"),
                                section.index('stamp_readback "$out/readback.json"'),
                                "post-Finder mount recheck must precede stamp")
    def test_reused_mount_report(self):
        self.items[2].write_bytes(self.items[0].read_bytes())
        with self.assertRaisesRegex(EvidenceError, "independent mounted-readback"):
            self.check()
    def test_unmount_report_from_other_verification(self):
        off = load_json(self.items[1])
        off["previous_verification_id"] = "unrelated"
        self.items[1].write_text(json.dumps(off))
        with self.assertRaisesRegex(EvidenceError, "bind the first"):
            self.check()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--both", action="store_true",
                        help="require complete independent Raven and Mesh lifecycles")
    for codec in ("raven", "mesh"):
        for phase in ("first", "unmounted", "remounted", "refusal", "replacement"):
            parser.add_argument("--" + codec + "-" + phase)
    parser.add_argument("--bundle")
    parser.add_argument("--codec", choices=("lzraven", "lzmesh"))
    parser.add_argument("--first")
    parser.add_argument("--unmounted")
    parser.add_argument("--remounted")
    parser.add_argument("--refusal")
    parser.add_argument("--replacement")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if args.both:
        if not args.bundle:
            parser.error("--both requires --bundle")
        evidence = []
        for codec in ("raven", "mesh"):
            paths = [getattr(args, codec + "_" + phase) for phase in (
                "first", "unmounted", "remounted", "refusal", "replacement")]
            if not all(paths):
                parser.error("--both requires five evidence paths for each codec")
            evidence.append(paths)
        try:
            report = validate_both(args.bundle, *evidence)
        except (OSError, ValueError, KeyError, TypeError) as error:
            print("acceptance evidence failed: " + str(error), file=sys.stderr)
            return 1
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0
    if not all((args.bundle, args.codec, args.first, args.unmounted,
                args.remounted, args.refusal, args.replacement)):
        parser.error("bundle, codec, first, unmounted, remounted, refusal and replacement are required")
    try:
        report = validate(args.bundle, args.codec, args.first, args.unmounted,
                          args.remounted, args.refusal, args.replacement)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("acceptance evidence failed: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
