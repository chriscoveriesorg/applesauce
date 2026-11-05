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
import re
from pathlib import Path
import sys
import tempfile
import unittest

# Share the executable verifier's deterministic read schedule with the
# evidence validator. A partial/randomly invented offset list must not pass.
from verify_mount import sampled_offsets
from replacement_acceptance import replacement_offsets


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def load_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


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
        re.fullmatch(r"/Volumes/[^/\\x00.][^/\\x00]*", mount)
        or re.fullmatch(
            r"/private/tmp/ascf-cli-mount\\.[A-Za-z0-9]{8}/mount", mount)
    )


def validate(bundle, codec, first, unmounted, remounted, refusal, replacement):
    require(codec in ("lzraven", "lzmesh"), "unsupported codec")
    source = Path(bundle) / ("source." + codec + ".jsonl")
    require(source.is_file(), "missing synthetic reference cleartext")
    reference = source.read_bytes()
    digest = hashlib.sha256(reference).hexdigest()
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
        require(report.get("logical_bytes") == len(reference)
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
        require(offsets == sampled_offsets(len(reference)),
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
    require(replaced.get("restored_file") == "source." + codec
            and replaced.get("mount") == reports[1]["mount"],
            "replaced-source refusal refers to a different mounted file")
    require(replaced.get("macos_build") == reports[1]["macos_build"],
            "replaced-source refusal has different macOS build")
    require(replaced.get("original_sha256") == digest
            and replaced.get("before_replacement_sha256") == digest,
            "replaced-source refusal differs from original logical digest")
    for field, suffix in (("source_archive_sha256", ".ascf"),
                          ("replacement_sha256", ".corrupt.ascf")):
        archive = Path(bundle) / ("source." + codec + suffix)
        require(archive.is_file(), "required signed-bundle archive fixture missing")
        require(replaced.get(field) == hashlib.sha256(archive.read_bytes()).hexdigest(),
                "replaced-source refusal has wrong " + field)
    require(replaced.get("denied_errno") in (errno.ESTALE, errno.EIO, errno.ENODEV),
            "replaced-source fresh read did not fail with the permitted errno")
    # Check the entire deterministic source-replacement probe schedule. A
    # single refused offset-zero read cannot attest to cached chunk boundaries,
    # nonzero offsets, EOF or newly opened paths.
    offsets = replacement_offsets(len(reference))
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
    expected_sha = hashlib.sha256(corrupt_fixture.read_bytes()).hexdigest()
    expected_prefix = ("CORRUPT_REFUSAL_CONFIRMED: source." + codec
                       + ".corrupt.ascf: sha256=" + expected_sha
                       + ": signed FSKit probe rejected the recognized ASCF payload: "
                       + "FSKitErrorDomain resourceDamaged code ")
    text = Path(refusal).read_text(encoding="utf-8").strip()
    require(text.startswith(expected_prefix)
            and re.fullmatch(r"[1-9][0-9]*: [^\r\n]+", text[len(expected_prefix):]) is not None,
            "typed codec-specific signed-host corruption refusal is not bound to the bundled fixture SHA-256")

    paths = (first, unmounted, remounted, refusal, replacement)
    evidence_hashes = {
        name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
        for name, path in zip(("first", "unmounted", "remounted", "refusal", "replacement"), paths)
    }
    return {
        "result": "pass",
        "scope": "operator-evidence-consistency; independent signed-mount review required",
        "codec": codec,
        "logical_bytes": len(reference),
        "sha256": digest,
        "source_commit": (Path(bundle) / "source-provenance.txt").read_text(
            encoding="utf-8").strip(),
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
        (self.base / "source-provenance.txt").write_text("commit=example\n")
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
            "macos_build": "fixture", "random_read_offsets": sampled_offsets(100)
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
            "kernel_readonly": True, "restored_file": "source.lzmesh",
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
        replacement["restored_file"] = "source.lzraven"
        replacement["source_archive_sha256"] = hashlib.sha256(valid).hexdigest()
        replacement["replacement_sha256"] = hashlib.sha256(damaged).hexdigest()
        paths[4].write_text(json.dumps(replacement))
        return paths

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
        with self.assertRaises(OSError):
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
