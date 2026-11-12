#!/usr/bin/env python3
"""Portable negative controls for the read-only decmpfs evidence crosscheck."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("summarize-decmpfs-evidence.py")
SPEC = importlib.util.spec_from_file_location("decmpfs_crosscheck", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixtures():
    binary = {
        "schema_version": 1,
        "kind": "read-only-decmpfs-binary-evidence",
        "inputs": [{"path": "/kernelcache", "status": "inspected",
                    "sha256": "a" * 64,
                    "images": [{"image": "AppleFSCompressionTypeZlib",
                                "uuid": "generated-test-image",
                                "registration_calls": [{
                                    "call_address": "0x1000",
                                    "target_address": "0x2000",
                                    "window_sha256": "c" * 64,
                                }]}]}],
        "kernel_decoder_proven": False,
        "codec_identity_proven": False,
        "native_raven_mesh_writes_permitted": False,
    }
    table = {
        "schema_version": 1,
        "kind": "read-only-decmpfs-registration-table-evidence",
        "inputs": [{"path": "/kernelcache", "status": "inspected",
                    "sha256": "a" * 64,
                    "tables": [{"image": "AppleFSCompressionTypeZlib",
                                "uuid": "generated-test-image",
                                "callsite": {
                                    "call_address": "0x1000",
                                    "target_address": "0x2000",
                                    "window_sha256": "c" * 64,
                                },
                                "table": {
                        "count": 2, "entries": [
                            {"type": 3, "pointer_resolution": {"status": "chain-verified"}},
                            {"type": 13, "pointer_resolution": {"status": "unresolved"}},
                        ]}}]}],
        "kernel_decoder_proven": False,
        "codec_identity_proven": False,
        "on_disk_framing_proven": False,
        "native_raven_mesh_writes_permitted": False,
    }
    catalogue = {
        "schema_version": 1,
        "kind": "read-only-decmpfs-catalogue-hints",
        "source": {"component_log_sha256": None, "plists_scanned": 0},
        "candidate_declarations": [
            {"type": 3, "resource": "Type", "origin": "ioreg_text"},
            {"type": 5, "resource": "providesType", "origin": "ioreg_text"},
        ],
        "candidate_types": [3, 5],
        "kernel_decoder_proven": False,
        "codec_identity_proven": False,
        "native_raven_mesh_writes_permitted": False,
    }
    inventory = {
        "schema_version": 1,
        "kind": "existing-system-decmpfs-headers-readonly",
        "types": {"8": {"count": 2}, "9": {"count": 1}},
        "headers_read": 3, "files_seen": 200,
        "compressed_flagged": 3, "timed_out": True,
        "file_limit_reached": False,
        "kernel_decoder_proven": False,
        "codec_identity_proven": False,
        "native_raven_mesh_writes_permitted": False,
    }
    return [binary, table, catalogue, inventory]


def summarize(*reports):
    return MODULE.summarize(*reports, {key: "b" * 64 for key in MODULE.EXPECTED})


class CrosscheckTest(unittest.TestCase):
    def test_valid_join_stays_inconclusive(self):
        result = summarize(*fixtures())
        self.assertEqual(result["static_registration_type_candidates"], [3, 13])
        self.assertEqual(result["registration_candidates_without_catalogue_hint"], [13])
        self.assertEqual(result["catalogue_hints_without_static_registration_candidate"], [5])
        self.assertEqual(result["observed_stored_type_counts"], {"8": 2, "9": 1})
        self.assertEqual(result["unresolved_static_registration_pointers"], 1)
        self.assertEqual(result["matched_binary_sources"], 1)
        self.assertEqual(result["matched_static_registration_callsites"], 1)
        self.assertEqual(result["observed_binary_registration_callsites"], 1)
        self.assertEqual(result["unavailable_binary_sources"], [])
        self.assertTrue(result["inventory_bounded"])
        self.assertEqual(result["result"], "inconclusive_kernel_codec_mapping")
        for key in ("kernel_decoder_proven", "codec_identity_proven",
                    "on_disk_framing_proven", "cold_remount_readback_proven",
                    "native_raven_mesh_writes_permitted"):
            self.assertIs(result[key], False)

    def test_reject_registration_table_callsite_not_seen_in_binary(self):
        reports = fixtures()
        reports[1]["inputs"][0]["tables"][0]["callsite"]["window_sha256"] = "d" * 64
        with self.assertRaisesRegex(MODULE.EvidenceError, "callsite disagrees"):
            summarize(*reports)

    def test_reject_registration_from_another_image_or_uuid(self):
        for key, value in (("image", "OtherFSCompression"), ("uuid", "wrong-uuid")):
            with self.subTest(key=key):
                reports = fixtures()
                reports[1]["inputs"][0]["tables"][0][key] = value
                with self.assertRaisesRegex(MODULE.EvidenceError, "callsite disagrees"):
                    summarize(*reports)

    def test_reject_missing_binary_callsite_or_image_inventory(self):
        reports = fixtures()
        reports[0]["inputs"][0]["images"][0]["registration_calls"] = []
        with self.assertRaisesRegex(MODULE.EvidenceError, "callsite disagrees"):
            summarize(*reports)
        reports = fixtures()
        reports[0]["inputs"][0].pop("images")
        with self.assertRaisesRegex(MODULE.EvidenceError, "binary image evidence"):
            summarize(*reports)

    def test_reject_duplicate_registration_callsite_attribution(self):
        reports = fixtures()
        duplicate = copy.deepcopy(reports[1]["inputs"][0]["tables"][0])
        duplicate["table"]["entries"] = [{"type": 12, "pointer_resolution": {"status": "unresolved"}}]
        duplicate["table"]["count"] = 1
        reports[1]["inputs"][0]["tables"].append(duplicate)
        with self.assertRaisesRegex(MODULE.EvidenceError, "duplicate registration callsite"):
            summarize(*reports)

    def test_reject_duplicate_binary_registration_callsites(self):
        reports = fixtures()
        calls = reports[0]["inputs"][0]["images"][0]["registration_calls"]
        calls.append(copy.deepcopy(calls[0]))
        with self.assertRaisesRegex(MODULE.EvidenceError,
                                    "duplicate binary registration callsite"):
            summarize(*reports)

    def test_reject_malformed_binary_callsites(self):
        for malformed in (None, ["not-a-callsite"], [{"target_address": "0x100"}] * 2049):
            with self.subTest(malformed_type=type(malformed).__name__):
                reports = fixtures()
                reports[0]["inputs"][0]["images"][0]["registration_calls"] = malformed
                with self.assertRaisesRegex(MODULE.EvidenceError, "malformed binary registration"):
                    summarize(*reports)

    def test_reject_mismatched_source(self):
        reports = fixtures()
        reports[1]["inputs"][0]["sha256"] = "b" * 64
        with self.assertRaisesRegex(MODULE.EvidenceError, "identical source"):
            summarize(*reports)

    def test_reject_missing_source_inspection(self):
        reports = fixtures()
        reports[0]["inputs"][0]["status"] = "unavailable"
        reports[0]["inputs"][0].pop("sha256")
        with self.assertRaisesRegex(MODULE.EvidenceError, "identical source"):
            summarize(*reports)

    def test_reject_unreviewed_positive_gate(self):
        for report in range(4):
            with self.subTest(report=report):
                reports = fixtures()
                reports[report]["native_raven_mesh_writes_permitted"] = True
                with self.assertRaisesRegex(MODULE.EvidenceError, "permits native writes"):
                    summarize(*reports)
        reports = fixtures()
        reports[1]["codec_identity_proven"] = True
        with self.assertRaisesRegex(MODULE.EvidenceError, "unreviewed positive"):
            summarize(*reports)

    def test_reject_schema_and_type_mismatch(self):
        reports = fixtures()
        reports[2]["schema_version"] = 2
        with self.assertRaisesRegex(MODULE.EvidenceError, "schema"):
            summarize(*reports)
        reports = fixtures()
        reports[3]["kind"] = reports[2]["kind"]
        with self.assertRaisesRegex(MODULE.EvidenceError, "kind"):
            summarize(*reports)

    def test_reject_duplicate_registration_type(self):
        reports = fixtures()
        reports[1]["inputs"][0]["tables"][0]["table"]["entries"][1]["type"] = 3
        with self.assertRaisesRegex(MODULE.EvidenceError, "duplicate type"):
            summarize(*reports)

    def test_reject_inaccurate_registration_length(self):
        reports = fixtures()
        reports[1]["inputs"][0]["tables"][0]["table"]["count"] = 3
        with self.assertRaisesRegex(MODULE.EvidenceError, "length mismatch"):
            summarize(*reports)

    def test_reject_unsigned_bool_and_duplicate_catalogue(self):
        reports = fixtures()
        reports[1]["inputs"][0]["tables"][0]["table"]["entries"][0]["type"] = True
        with self.assertRaisesRegex(MODULE.EvidenceError, "registration type"):
            summarize(*reports)
        reports = fixtures()
        reports[2]["candidate_types"] = [3, 3]
        with self.assertRaisesRegex(MODULE.EvidenceError, "differ from captured"):
            summarize(*reports)

    def test_reject_bad_inventory(self):
        reports = fixtures()
        reports[3]["headers_read"] = 2
        with self.assertRaisesRegex(MODULE.EvidenceError, "header count"):
            summarize(*reports)
        reports = fixtures()
        reports[3]["types"] = {"08": {"count": 3}}
        with self.assertRaisesRegex(MODULE.EvidenceError, "type key"):
            summarize(*reports)
        reports = fixtures()
        reports[3]["file_limit_reached"] = "false"
        with self.assertRaisesRegex(MODULE.EvidenceError, "completion flags"):
            summarize(*reports)


    def test_reject_forged_catalogue_and_provenance(self):
        reports = fixtures()
        reports[2]["candidate_types"] = [3, 5, 13]
        with self.assertRaisesRegex(MODULE.EvidenceError, "differ from captured"):
            summarize(*reports)
        reports = fixtures()
        reports[2]["candidate_declarations"].append(
            {"type": 13, "resource": "unsupported", "origin": "ioreg_text"})
        with self.assertRaisesRegex(MODULE.EvidenceError, "declaration resource"):
            summarize(*reports)
        reports = fixtures()
        reports[2]["candidate_declarations"][0]["type"] = True
        with self.assertRaisesRegex(MODULE.EvidenceError, "declaration type"):
            summarize(*reports)
        reports = fixtures()
        reports[2]["candidate_declarations"][0]["origin"] = "iokit_personality"
        with self.assertRaisesRegex(MODULE.EvidenceError, "plist SHA-256"):
            summarize(*reports)
        reports = fixtures()
        reports[2]["source"]["component_log_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(MODULE.EvidenceError, "component-log SHA-256"):
            summarize(*reports)
        reports = fixtures()
        reports[2]["source"]["plists_scanned"] = -1
        with self.assertRaisesRegex(MODULE.EvidenceError, "plist count"):
            summarize(*reports)

    def test_missing_sources_are_explicit_and_matched(self):
        reports = fixtures()
        unavailable = {"path": "/secondary", "status": "unavailable",
                       "error": "not found"}
        for report in reports[:2]:
            report["inputs"].append(copy.deepcopy(unavailable))
        result = summarize(*reports)
        self.assertEqual(result["matched_binary_sources"], 1)
        self.assertEqual(result["unavailable_binary_sources"], ["/secondary"])
        reports[0]["inputs"].pop()
        with self.assertRaisesRegex(MODULE.EvidenceError, "identical source"):
            summarize(*reports)
        reports = fixtures()
        reports[0]["inputs"].append(copy.deepcopy(unavailable))
        reports[0]["inputs"].append(copy.deepcopy(unavailable))
        with self.assertRaisesRegex(MODULE.EvidenceError, "duplicate/empty"):
            summarize(*reports)

    def test_reject_unavailable_source_with_claimed_digest(self):
        reports = fixtures()
        unavailable = {"path": "/missing-kernelcache", "status": "unavailable",
                       "sha256": "c" * 64}
        for report in reports[:2]:
            report["inputs"].append(copy.deepcopy(unavailable))
        with self.assertRaisesRegex(MODULE.EvidenceError, "unavailable binary source has SHA-256"):
            summarize(*reports)
        # Even matching contradictory claims on both sides cannot be evidence.
        reports[0]["inputs"][-1].pop("sha256")
        with self.assertRaisesRegex(MODULE.EvidenceError, "unavailable table source has SHA-256"):
            summarize(*reports)

    def test_reject_all_unavailable_sources(self):
        reports = fixtures()
        for report in reports[:2]:
            report["inputs"][0]["status"] = "unavailable"
            report["inputs"][0].pop("sha256")
        with self.assertRaisesRegex(MODULE.EvidenceError, "must inspect identical"):
            summarize(*reports)

    def test_reject_positive_remount_claim(self):
        reports = fixtures()
        reports[3]["cold_remount_readback_proven"] = True
        with self.assertRaisesRegex(MODULE.EvidenceError, "unreviewed positive"):
            summarize(*reports)

    def test_reject_malformed_registration_tables(self):
        reports = fixtures()
        reports[1]["inputs"][0]["tables"][0]["table"]["entries"][0] = "bad"
        with self.assertRaisesRegex(MODULE.EvidenceError, "registration record"):
            summarize(*reports)
        reports = fixtures()
        reports[1]["inputs"][0]["tables"][0]["table"]["entries"][0][
            "pointer_resolution"] = None
        with self.assertRaisesRegex(MODULE.EvidenceError, "pointer resolution"):
            summarize(*reports)
        reports = fixtures()
        reports[1]["inputs"][0]["tables"][0]["table"]["count"] = True
        with self.assertRaisesRegex(MODULE.EvidenceError, "length mismatch"):
            summarize(*reports)

    def test_read_rejects_symlink_and_nonregular_file(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            valid = root / "valid.json"
            valid.write_text("{}")
            linked = root / "linked.json"
            linked.symlink_to(valid)
            with self.assertRaises(OSError):
                MODULE.read_evidence(linked)
            if hasattr(os, "mkfifo"):
                fifo = root / "fifo"
                os.mkfifo(fifo)
                with self.assertRaisesRegex(MODULE.EvidenceError, "regular file"):
                    MODULE.read_evidence(fifo)

    def test_read_rejects_duplicate_json_fields_and_empty(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "evidence.json"
            path.write_text('{"a":1,"a":2}')
            with self.assertRaisesRegex(MODULE.EvidenceError, "duplicate JSON"):
                MODULE.read_evidence(path)
            path.write_bytes(b"")
            with self.assertRaisesRegex(MODULE.EvidenceError, "nonempty"):
                MODULE.read_evidence(path)

    def test_cli_complete_file_provenance_and_alias_rejection(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            reports = fixtures()
            paths = []
            for key, data in zip(MODULE.EXPECTED, reports):
                p = root / f"{key}.json"
                p.write_text(json.dumps(data))
                paths.append(p)
            completed = subprocess.run(
                [sys.executable, MODULE_PATH, *paths],
                text=True, capture_output=True, check=True,
            )
            result = json.loads(completed.stdout)
            self.assertEqual(sorted(result["source_document_sha256"]), sorted(MODULE.EXPECTED))
            self.assertFalse(result["native_raven_mesh_writes_permitted"])
            paths[1].unlink()
            os.link(paths[0], paths[1])
            completed = subprocess.run(
                [sys.executable, MODULE_PATH, *paths],
                text=True, capture_output=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("alias the same file", completed.stderr)


if __name__ == "__main__":
    unittest.main()
