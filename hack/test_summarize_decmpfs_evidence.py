#!/usr/bin/env python3
"""Portable negative controls for the read-only decmpfs evidence crosscheck."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest

MODULE_PATH = Path(__file__).with_name("summarize-decmpfs-evidence.py")
SPEC = importlib.util.spec_from_file_location("decmpfs_crosscheck", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixtures():
    raw_table = (struct.pack("<IIQ", 3, 0, 0x5000)
                 + struct.pack("<IIQ", 13, 0, 0x6000))
    # ARM64 BL at 0x1000 branches to 0x2000, with four bytes of trailing code.
    code = struct.pack("<8I", *([0xD503201F] * 8))
    code += struct.pack("<II", 0x94000400, 0xD503201F)
    callsite = {
        "call_address": "0x1000", "target_address": "0x2000",
        "target_symbol": "_register_decmpfs_decompressor",
        "section": "__text", "file_offset": 4096,
        "window_address": "0xfe0", "instruction_window_hex": code.hex(),
        "window_sha256": hashlib.sha256(code).hexdigest(),
        "type_constant_candidate": None, "registration_pointer_candidate": None,
        "registration_record_candidate": None,
    }
    binary = {
        "schema_version": 1,
        "kind": "read-only-decmpfs-binary-evidence",
        "inputs": [{"path": "/kernelcache", "status": "inspected",
                    "sha256": "a" * 64,
                    "images": [{"image": "AppleFSCompressionTypeZlib",
                                "uuid": "generated-test-image",
                                "registration_calls": [copy.deepcopy(callsite)]}]}],
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
                                "callsite": copy.deepcopy(callsite),
                                "table": {
                        "address": "0x3000", "file_offset": 0,
                        "stride": 16, "count": 2,
                        "bytes_hex": raw_table.hex(),
                        "sha256": hashlib.sha256(raw_table).hexdigest(),
                        "loop_window_sha256": callsite["window_sha256"],
                        "entries": [
                            {"type": 3, "raw_registration_pointer": "0x5000",
                             "pointer_resolution": {"status": "chain-verified",
                                                    "address": "0x3008"}},
                            {"type": 13, "raw_registration_pointer": "0x6000",
                             "pointer_resolution": {"status": "unresolved",
                                                    "address": "0x3018"}},
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

    def test_unavailable_source_rejects_claimed_observations(self):
        for kind, field in ((0, "images"), (1, "tables")):
            with self.subTest(kind=kind, field=field):
                reports = fixtures()
                source = reports[kind]["inputs"][0]
                source["status"] = "unavailable"
                source.pop("sha256")
                # A matching unavailable peer must not make stale observations valid.
                peer = reports[1 - kind]["inputs"][0]
                peer["status"] = "unavailable"
                peer.pop("sha256")
                peer.pop("images" if kind == 1 else "tables")
                with self.assertRaisesRegex(MODULE.EvidenceError,
                                            "unavailable .* source has " + field):
                    summarize(*reports)

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

    def test_reject_conflicting_records_at_same_callsite_address(self):
        reports = fixtures()
        calls = reports[0]["inputs"][0]["images"][0]["registration_calls"]
        duplicate = copy.deepcopy(calls[0])
        # A different section label makes the JSON signatures distinct, but
        # the pinned image still has only one instruction at this address.
        duplicate["section"] = "__alternate_text"
        calls.append(duplicate)
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

    def test_reject_corrupted_callsite_attestation_in_both_probes(self):
        # A matching copy of a forged callsite in both probe reports must fail.
        variants = (
            "stale_digest", "forged_digest", "branch_target", "not_a_bl",
            "missing_instruction", "oversized_instruction", "misaligned_call",
            "wrong_window", "bad_file_offset", "boolean_file_offset",
            "missing_symbol", "noncanonical_target", "bad_type", "bad_pointer",
        )
        for variant in variants:
            with self.subTest(variant=variant):
                reports = fixtures()
                call = reports[0]["inputs"][0]["images"][0]["registration_calls"][0]
                if variant == "stale_digest":
                    call["instruction_window_hex"] = "00" + call["instruction_window_hex"][2:]
                elif variant == "forged_digest":
                    call["window_sha256"] = "f" * 64
                elif variant in ("branch_target", "not_a_bl"):
                    raw = bytearray.fromhex(call["instruction_window_hex"])
                    struct.pack_into("<I", raw, 32, 0x94000401 if variant == "branch_target"
                                     else 0xD503201F)
                    call["instruction_window_hex"] = raw.hex()
                    call["window_sha256"] = hashlib.sha256(raw).hexdigest()
                elif variant == "missing_instruction":
                    call.pop("instruction_window_hex")
                elif variant == "oversized_instruction":
                    call["instruction_window_hex"] = "00" * 100
                elif variant == "misaligned_call":
                    call["call_address"] = "0x1001"
                elif variant == "wrong_window":
                    call["window_address"] = "0xeff"
                elif variant == "bad_file_offset":
                    call["file_offset"] = -1
                elif variant == "boolean_file_offset":
                    call["file_offset"] = True
                elif variant == "missing_symbol":
                    call["target_symbol"] = ""
                elif variant == "noncanonical_target":
                    call["target_address"] = "0X2000"
                elif variant == "bad_type":
                    call["type_constant_candidate"] = True
                elif variant == "bad_pointer":
                    call["registration_pointer_candidate"] = "0x" + "f" * 5000
                reports[1]["inputs"][0]["tables"][0]["callsite"] = copy.deepcopy(call)
                reports[1]["inputs"][0]["tables"][0]["table"]["loop_window_sha256"] = call["window_sha256"]
                with self.assertRaises(MODULE.EvidenceError):
                    summarize(*reports)

    def test_reject_unaligned_arm64_callsite_even_when_branch_matches(self):
        # Moving the entire instruction window and branch by one byte keeps
        # the encoded displacement and cross-probe signatures consistent, but
        # cannot represent an aligned AArch64 instruction.
        for field in ("call_address", "target_address", "window_address"):
            with self.subTest(field=field):
                reports = fixtures()
                call = reports[0]["inputs"][0]["images"][0]["registration_calls"][0]
                if field == "target_address":
                    # A lone target shift also violates instruction alignment.
                    call[field] = hex(int(call[field], 16) + 1)
                else:
                    for key in ("call_address", "target_address", "window_address"):
                        call[key] = hex(int(call[key], 16) + 1)
                reports[1]["inputs"][0]["tables"][0]["callsite"] = copy.deepcopy(call)
                with self.assertRaisesRegex(MODULE.EvidenceError, "unaligned ARM64"):
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

    def test_reject_oversized_inventory_type_key(self):
        # JSON object keys are strings. A multi-thousand-digit decimal key
        # must be rejected as evidence, not crash Python's int parser.
        reports = fixtures()
        reports[3]["types"] = {"9" * 5000: {"count": 3}}
        with self.assertRaisesRegex(MODULE.EvidenceError, "invalid inventory type key"):
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

    def test_reject_registration_table_byte_and_pointer_forgery(self):
        for mutation, expected in (
            ("missing-bytes", "raw bytes"),
            ("wrong-stride", "stride"),
            ("altered-bytes", "digest mismatch"),
            ("missing-digest", "digest mismatch"),
            ("forged-record-type", "differs from raw bytes"),
            ("forged-record-pointer", "pointer differs"),
            ("forged-resolution-address", "resolution address"),
            ("changed-loop-window", "window digest"),
            ("wrong-raw-type", "differs from raw bytes"),
            ("nonzero-padding", "differs from raw bytes"),
            ("wrong-raw-pointer", "pointer differs"),
        ):
            with self.subTest(mutation=mutation):
                reports = fixtures()
                entry = reports[1]["inputs"][0]["tables"][0]
                rows = entry["table"]
                if mutation == "missing-bytes":
                    rows.pop("bytes_hex")
                elif mutation == "wrong-stride":
                    rows["stride"] = 8
                elif mutation == "altered-bytes":
                    rows["bytes_hex"] = "7" + rows["bytes_hex"][1:]
                elif mutation == "missing-digest":
                    rows.pop("sha256")
                elif mutation == "forged-record-type":
                    rows["entries"][0]["type"] = 7
                elif mutation == "forged-record-pointer":
                    rows["entries"][0]["raw_registration_pointer"] = "0x7000"
                elif mutation == "forged-resolution-address":
                    rows["entries"][0]["pointer_resolution"]["address"] = "0x3018"
                elif mutation == "changed-loop-window":
                    rows["loop_window_sha256"] = "d" * 64
                else:
                    raw = bytearray.fromhex(rows["bytes_hex"])
                    if mutation == "wrong-raw-type":
                        struct.pack_into("<I", raw, 0, 7)
                    elif mutation == "nonzero-padding":
                        struct.pack_into("<I", raw, 4, 1)
                    else:
                        struct.pack_into("<Q", raw, 8, 0x7000)
                    rows["bytes_hex"] = raw.hex()
                    rows["sha256"] = hashlib.sha256(raw).hexdigest()
                with self.assertRaisesRegex(MODULE.EvidenceError, expected):
                    summarize(*reports)

    def test_reject_boolean_schema_version(self):
        reports = fixtures()
        reports[0]["schema_version"] = True
        with self.assertRaisesRegex(MODULE.EvidenceError, "kind/schema"):
            summarize(*reports)

    def test_raw_table_accepts_valid_pointer_and_unresolved_entries(self):
        reports = fixtures()
        result = summarize(*reports)
        self.assertEqual(result["static_registration_type_candidates"], [3, 13])
        self.assertEqual(result["unresolved_static_registration_pointers"], 1)

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

    def test_read_preserves_invalid_json_when_close_fails(self):
        # The evidence parser's rejection must not be replaced by a cleanup
        # error; the descriptor must still receive a close attempt.
        from unittest import mock
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "evidence.json"
            path.write_text('{"a":1,"a":2}')
            actual_close = os.close
            closed = []

            def close_then_fail(fd):
                closed.append(fd)
                actual_close(fd)
                raise OSError("injected close failure")

            with mock.patch.object(MODULE.os, "close", side_effect=close_then_fail):
                with self.assertRaisesRegex(MODULE.EvidenceError, "duplicate JSON"):
                    MODULE.read_evidence(path)
            self.assertEqual(len(closed), 1)

    def test_read_reports_close_failure_after_success(self):
        from unittest import mock
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "evidence.json"
            path.write_text("{}")
            actual_close = os.close
            closed = []

            def close_then_fail(fd):
                closed.append(fd)
                actual_close(fd)
                raise OSError("injected close failure")

            with mock.patch.object(MODULE.os, "close", side_effect=close_then_fail):
                with self.assertRaisesRegex(OSError, "injected close failure"):
                    MODULE.read_evidence(path)
            self.assertEqual(len(closed), 1)

    def test_read_rejects_excessively_nested_json(self):
        # The bounded input size alone does not bound parser recursion depth.
        # A hostile report must produce a controlled evidence rejection.
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "nested.json"
            path.write_text("[" * 2000 + "0" + "]" * 2000)
            with self.assertRaisesRegex(MODULE.EvidenceError, "invalid JSON evidence"):
                MODULE.read_evidence(path)

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
