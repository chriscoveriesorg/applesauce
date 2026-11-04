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
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


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


def validate(bundle, codec, first, unmounted, remounted, refusal):
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
        mount = report.get("mount")
        require(isinstance(mount, str) and mount.startswith("/Volumes/")
                and "/../" not in mount and "/./" not in mount,
                stage + ": invalid mount location")
        require(report.get("macos_version") and report.get("macos_build"),
                stage + ": missing host OS provenance")
        offsets = report.get("random_read_offsets")
        require(isinstance(offsets, list)
                and len(offsets) >= 20 and 0 in offsets
                and len(reference) in offsets,
                stage + ": random/EOF read evidence missing")
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
    text = Path(refusal).read_text(encoding="utf-8")
    require("CORRUPT_REFUSAL_CONFIRMED:" in text
            and "source." + codec + ".corrupt.ascf" in text
            and "signed FSKit probe rejected the recognized ASCF payload" in text,
            "typed codec-specific signed-host corruption refusal evidence missing")

    paths = (first, unmounted, remounted, refusal)
    evidence_hashes = {
        name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
        for name, path in zip(("first", "unmounted", "remounted", "refusal"), paths)
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
            self.base / "remount.json", self.base / "refusal.txt"
        ]
        report = {
            "result": "pass", "filesystem_type": "ascf",
            "kernel_readonly": True, "mount_flags": 1,
            "readonly_open_denied": True, "restored_file": "source.lzmesh",
            "finder_copy_verified": True, "finder_copy_sha256": self.sha,
            "logical_bytes": 100, "sha256": self.sha,
            "mount": "/Volumes/Applesauce ASCF", "macos_version": "27.0",
            "macos_build": "fixture", "random_read_offsets": list(range(20)) + [100]
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
            "verified_at_utc": "2026-11-04T00:00:05+00:00"
        }))
        self.items[3].write_text(
            "CORRUPT_REFUSAL_CONFIRMED: source.lzmesh.corrupt.ascf: signed FSKit probe rejected the recognized ASCF payload")
    def check(self):
        return validate(self.base, "lzmesh", *self.items)
    def test_valid_chain(self):
        self.assertEqual(self.check()["result"], "pass")
    def test_wrong_source(self):
        (self.base / "source.lzmesh.jsonl").write_bytes(b"altered")
        with self.assertRaisesRegex(EvidenceError, "logical bytes"):
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
    parser.add_argument("--bundle")
    parser.add_argument("--codec", choices=("lzraven", "lzmesh"))
    parser.add_argument("--first")
    parser.add_argument("--unmounted")
    parser.add_argument("--remounted")
    parser.add_argument("--refusal")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if not all((args.bundle, args.codec, args.first, args.unmounted,
                args.remounted, args.refusal)):
        parser.error("bundle, codec, first, unmounted, remounted and refusal are required")
    try:
        report = validate(args.bundle, args.codec, args.first, args.unmounted,
                          args.remounted, args.refusal)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("acceptance evidence failed: " + str(error), file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
