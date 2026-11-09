"""Offline correctness and fail-closed tests for Criterion confidence export."""
import csv
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).with_name("criterion-confidence.py")
SPEC = importlib.util.spec_from_file_location("criterion_confidence", MODULE)
assert SPEC and SPEC.loader
confidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(confidence)


class ConfidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.summary = self.root / "summary.csv"
        self.criterion = self.root / "criterion"
        self.output = self.root / "confidence.csv"
        self.row = dict.fromkeys(confidence.SUMMARY_COLUMNS, "")
        self.row.update({
            "schema_version": "1",
            "fixture_version": "1",
            "suite": "smoke",
            "workload": "mixed-jsonl",
            "input_bytes": "65536",
            "input_sha256": "a" * 64,
            "layout": "whole",
            "chunk_bytes": "65536",
            "codec": "lzraven",
            "scratch_mode": "reused-scratch",
            "encode_scratch_bytes": "0",
            "decode_scratch_bytes": "0",
            "encoded_bytes": "8192",
            "encoded_over_input_ratio": "0.125",
            "verified_roundtrip": "true",
            "encode_median_ns": "1500000.00000",
            "encode_mib_per_s": "41.6667",
            "decode_median_ns": "1000000.00000",
            "decode_mib_per_s": "62.5000",
        })
        self.rewrite_summary()
        self.make_estimate("encode", 1_000_000, 1_500_000, 2_000_000)
        self.make_estimate("decode", 500_000, 1_000_000, 1_500_000)

    def rewrite_summary(self, rows=None):
        with self.summary.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=confidence.SUMMARY_COLUMNS)
            writer.writeheader()
            writer.writerows([self.row] if rows is None else rows)

    def estimate_path(self, operation):
        return (self.criterion /
                "apple-buffer_smoke_65536_mixed-jsonl_whole" /
                "lzraven-reused-scratch" / operation / "new" /
                "estimates.json")

    def make_estimate(self, operation, lower, median, upper, level=0.95):
        path = self.estimate_path(operation)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "median": {
                "point_estimate": median,
                "confidence_interval": {
                    "confidence_level": level,
                    "lower_bound": lower,
                    "upper_bound": upper,
                },
            },
        }), encoding="utf-8")

    def complete_smoke(self):
        """Build the full smoke matrix with independent fixture hashes."""
        matrix = confidence._matrix
        source_rows = []
        summary_rows = []
        for suite, workload, size, layout, codec, mode in sorted(
            matrix.expected_cases("smoke")
        ):
            row = dict(self.row)
            row.update(
                suite=suite, workload=workload, input_bytes=str(size),
                input_sha256=matrix.GOLDEN_SHA256[size][workload],
                layout=layout, codec=codec, scratch_mode=mode,
                encode_scratch_bytes="n/a" if mode == "api-managed" else "0",
                decode_scratch_bytes="n/a" if mode == "api-managed" else "0",
            )
            source_rows.append({
                field: row[field] for field in confidence._summary.FIELDS
            })
            summary_rows.append(row)
            group = self.criterion / (
                f"apple-buffer_{suite}_{size}_{workload}_{layout}"
            ) / f"{codec}-{mode}"
            for operation, low, center, high in (
                ("encode", 1_000_000, 1_500_000, 2_000_000),
                ("decode", 500_000, 1_000_000, 1_500_000),
            ):
                estimate = group / operation / "new" / "estimates.json"
                estimate.parent.mkdir(parents=True, exist_ok=True)
                estimate.write_text(json.dumps({"median": {
                    "point_estimate": center,
                    "confidence_interval": {
                        "confidence_level": 0.95,
                        "lower_bound": low,
                        "upper_bound": high,
                    },
                }}), encoding="utf-8")
        manifest = self.root / "manifest.csv"
        with manifest.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=confidence._summary.FIELDS
            )
            writer.writeheader()
            writer.writerows(source_rows)
        self.rewrite_summary(summary_rows)
        return manifest, summary_rows

    def test_cli_success_and_failure_remove_stale_evidence(self):
        # Run the actual CLI, not only the in-process math functions.
        # A self-hosted macOS runner may retain previous benchmark outputs,
        # and the workflow uploads its artifact directory even on failure.
        manifest, rows = self.complete_smoke()
        command = [
            sys.executable, str(MODULE), str(manifest), str(self.summary),
            str(self.criterion), str(self.output), "smoke",
        ]
        success = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertIn(f"for {len(rows)} codec cases", success.stdout)
        with self.output.open(newline="", encoding="utf-8") as stream:
            output_rows = list(csv.DictReader(stream))
        self.assertEqual(len(output_rows), len(rows))

        # Deliberately invalidate the manifest after a successful export.
        # The subsequent command must remove the previously valid artifact.
        with manifest.open(newline="", encoding="utf-8") as stream:
            source = list(csv.DictReader(stream))
        source[0]["input_sha256"] = "a" * 64
        with manifest.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=confidence._summary.FIELDS
            )
            writer.writeheader()
            writer.writerows(source)
        failure = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(failure.returncode, 1)
        self.assertIn("invalid or incomplete", failure.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".confidence.csv.*.tmp")), [])

    def test_invalid_utf8_estimates_fail_closed_without_traceback(self):
        manifest, _ = self.complete_smoke()
        # The smoke suite includes chat-jsonl and entropy. The single-row
        # mixed-jsonl fixture from setUp is not among the exported cases.
        estimate = (
            self.criterion / "apple-buffer_smoke_65536_chat-jsonl_whole"
            / "lzraven-reused-scratch" / "encode" / "new" / "estimates.json"
        )
        self.assertTrue(estimate.is_file())
        estimate.write_bytes(b"\xff\xfe\x80")
        self.output.write_text("stale evidence", encoding="utf-8")
        command = [
            sys.executable, str(MODULE), str(manifest), str(self.summary),
            str(self.criterion), str(self.output), "smoke",
        ]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=10
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("invalid or incomplete Criterion confidence evidence:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(self.output.exists())

    def test_estimates_require_utf8_and_unambiguous_json_keys(self):
        path = self.estimate_path("encode")
        original = path.read_text(encoding="utf-8")
        for encoding in ("utf-16", "utf-32"):
            with self.subTest(encoding=encoding):
                path.write_bytes(original.encode(encoding))
                with self.assertRaises(UnicodeDecodeError):
                    confidence.confidence_rows(self.summary, self.criterion)

        # JSON permits duplicate object keys in many parsers; silently taking
        # the last estimate can make audit evidence mean different things to
        # different readers.
        median = json.loads(original)["median"]
        path.write_text(
            '{"median":' + json.dumps(median)
            + ',"median":' + json.dumps(median) + '}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ValueError, "duplicate Criterion estimate JSON key: median"
        ):
            confidence.confidence_rows(self.summary, self.criterion)

    def test_partial_csv_write_never_publishes_evidence(self):
        manifest, _ = self.complete_smoke()
        # Simulate a disk-full/error after the header has been written.
        self.output.write_text("previous run", encoding="utf-8")
        with patch.object(
            confidence.csv.DictWriter, "writerows",
            side_effect=OSError("simulated interrupted output"),
        ):
            with self.assertRaisesRegex(OSError, "simulated interrupted"):
                confidence.write_confidence(
                    self.summary, self.criterion, self.output, manifest, "smoke"
                )
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".confidence.csv.*.tmp")), [])

    def test_export_refuses_output_aliases_without_deleting_inputs(self):
        manifest, _ = self.complete_smoke()
        for source in (manifest, self.summary):
            with self.subTest(source=source.name):
                original = source.read_bytes()
                with self.assertRaisesRegex(ValueError, "aliases"):
                    confidence.write_confidence(
                        self.summary, self.criterion, source, manifest, "smoke"
                    )
                self.assertEqual(source.read_bytes(), original)

        hardlink = self.root / "hardlink-to-summary.csv"
        os.link(self.summary, hardlink)
        before = self.summary.read_bytes()
        with self.assertRaisesRegex(ValueError, "aliases"):
            confidence.write_confidence(
                self.summary, self.criterion, hardlink, manifest, "smoke"
            )
        self.assertEqual(self.summary.read_bytes(), before)
        self.assertTrue(hardlink.exists())

        symlink = self.root / "link-to-manifest.csv"
        symlink.symlink_to(manifest)
        original = manifest.read_bytes()
        with self.assertRaisesRegex(ValueError, "aliases"):
            confidence.write_confidence(
                self.summary, self.criterion, symlink, manifest, "smoke"
            )
        self.assertEqual(manifest.read_bytes(), original)
        self.assertTrue(symlink.is_symlink())

    def test_confidence_output_never_deletes_raw_criterion_measurements(self):
        manifest, _ = self.complete_smoke()
        estimate = self.estimate_path("encode")
        original = estimate.read_bytes()
        with self.assertRaisesRegex(ValueError, "raw Criterion"):
            confidence.write_confidence(
                self.summary, self.criterion, estimate, manifest, "smoke"
            )
        self.assertEqual(estimate.read_bytes(), original)

        # A symlinked parent can redirect an apparently separate output into
        # the Criterion tree. Reject it before unlinking anything.
        alias = self.root / "criterion-alias"
        alias.symlink_to(self.criterion, target_is_directory=True)
        destination = (
            alias / "apple-buffer_smoke_65536_mixed-jsonl_whole"
            / "lzraven-reused-scratch" / "encode" / "new" / "estimates.json"
        )
        with self.assertRaisesRegex(ValueError, "raw Criterion"):
            confidence.write_confidence(
                self.summary, self.criterion, destination, manifest, "smoke"
            )
        self.assertEqual(estimate.read_bytes(), original)

        # Also refuse creating a fresh CSV inside a previously untouched
        # Criterion case directory.
        new_output = estimate.parent / "confidence.csv"
        with self.assertRaisesRegex(ValueError, "raw Criterion"):
            confidence.write_confidence(
                self.summary, self.criterion, new_output, manifest, "smoke"
            )
        self.assertFalse(new_output.exists())

    def test_estimates_refuse_fifo_symlink_and_oversized_files(self):
        path = self.estimate_path("encode")
        path.write_bytes(b"x" * (confidence.MAX_ESTIMATE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "oversized"):
            confidence.confidence_rows(self.summary, self.criterion)

        path.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "empty"):
            confidence.confidence_rows(self.summary, self.criterion)

        path.unlink()
        path.symlink_to(self.estimate_path("decode"))
        with self.assertRaises(OSError):
            confidence.confidence_rows(self.summary, self.criterion)

        path.unlink()
        os.mkfifo(path)
        # Reading a FIFO with no writer would otherwise block indefinitely.
        with self.assertRaisesRegex(ValueError, "regular file"):
            confidence.confidence_rows(self.summary, self.criterion)


    def test_full_matrix_provenance_gate(self):
        manifest, rows = self.complete_smoke()
        expected = len(confidence._matrix.expected_cases("smoke"))
        self.assertEqual(confidence.write_confidence(
            self.summary, self.criterion, self.output, manifest, "smoke"
        ), expected)
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), expected)
        self.rewrite_summary(rows[:-1])
        with self.assertRaisesRegex(ValueError, "missing benchmark cases"):
            confidence.write_confidence(
                self.summary, self.criterion, self.output, manifest, "smoke"
            )
        self.rewrite_summary(rows)
        modified = [dict(row) for row in rows]
        modified[0]["encode_scratch_bytes"] = "2048"
        self.rewrite_summary(modified)
        with self.assertRaisesRegex(ValueError, "differs from verified source"):
            confidence.write_confidence(
                self.summary, self.criterion, self.output, manifest, "smoke"
            )
        self.rewrite_summary(rows)
        with self.assertRaisesRegex(ValueError, "incomplete|unexpected"):
            confidence.write_confidence(
                self.summary, self.criterion, self.output, manifest, "standard"
            )
        with self.assertRaises(TypeError):
            confidence.write_confidence(
                self.summary, self.criterion, self.output, manifest=manifest
            )
        # Tampering with manifest hashes must fail the independent golden check.
        with manifest.open(newline="", encoding="utf-8") as stream:
            source = list(csv.DictReader(stream))
        source[0]["input_sha256"] = "a" * 64
        with manifest.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=confidence._summary.FIELDS
            )
            writer.writeheader()
            writer.writerows(source)
        with self.assertRaisesRegex(ValueError, "golden"):
            confidence.write_confidence(
                self.summary, self.criterion, self.output, manifest, "smoke"
            )

    def test_inverts_time_intervals_for_throughput_and_preserves_schema(self):
        rows = confidence.confidence_rows(self.summary, self.criterion)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(tuple(row), confidence.COLUMNS)
        self.assertEqual(row["encode_ci95_lower_ns"], "1000000.00000")
        self.assertEqual(row["encode_ci95_upper_ns"], "2000000.00000")
        self.assertEqual(row["encode_median_mib_per_s"], "41.6667")
        self.assertEqual(row["encode_ci95_lower_mib_per_s"], "31.2500")
        self.assertEqual(row["encode_ci95_upper_mib_per_s"], "62.5000")
        self.assertEqual(row["decode_ci95_lower_mib_per_s"], "41.6667")
        self.assertEqual(row["decode_ci95_upper_mib_per_s"], "125.0000")
        self.assertEqual(row["input_sha256"], "a" * 64)

    def test_parses_recorded_macos_criterion_shape(self):
        # Use checked-in read-only macOS 27.2 Criterion evidence, not just
        # hand-constructed JSON, to catch changes to group paths and estimates.
        source = (
            Path(__file__).parent / "benchmarks" /
            "2026-11-06-m1max-macos27.2" / "criterion"
        )
        group = (
            source / "apple-buffer_standard_1048576_mixed-jsonl_whole" /
            "lzraven-reused-scratch"
        )
        row = dict(self.row)
        row.update(suite="standard", input_bytes="1048576",
                   chunk_bytes="1048576", encoded_bytes="131072")
        for operation in ("encode", "decode"):
            estimate = json.loads(
                (group / operation / "new" / "estimates.json").read_text(
                    encoding="utf-8"
                )
            )["median"]
            nanoseconds = estimate["point_estimate"]
            row[f"{operation}_median_ns"] = f"{nanoseconds:.5f}"
            row[f"{operation}_mib_per_s"] = f"{1e9 / nanoseconds:.4f}"
        self.rewrite_summary([row])
        actual = confidence.confidence_rows(self.summary, source)
        self.assertEqual(len(actual), 1)
        for operation in ("encode", "decode"):
            self.assertLessEqual(
                float(actual[0][f"{operation}_ci95_lower_ns"]),
                float(actual[0][f"{operation}_median_ns"]),
            )
            self.assertLessEqual(
                float(actual[0][f"{operation}_median_ns"]),
                float(actual[0][f"{operation}_ci95_upper_ns"]),
            )

    def test_requires_exact_95_percent_finite_ordered_intervals(self):
        for lower, median, upper, level in (
            (1_000_000, 1_500_000, 2_000_000, 0.9),
            (1_000_000, 1_500_000, 2_000_000, "0.95"),
            (0, 1_500_000, 2_000_000, 0.95),
            (2_000_000, 1_500_000, 1_000_000, 0.95),
            (1_600_000, 1_500_000, 2_000_000, 0.95),
            (1_000_000, 1_500_000, float("nan"), 0.95),
            (1_000_000, True, 2_000_000, 0.95),
        ):
            with self.subTest(bounds=(lower, median, upper, level)):
                self.make_estimate("encode", lower, median, upper, level)
                with self.assertRaises(ValueError):
                    confidence.confidence_rows(self.summary, self.criterion)

    def test_missing_or_truncated_estimate_is_fatal(self):
        self.estimate_path("decode").unlink()
        with self.assertRaises(FileNotFoundError):
            confidence.confidence_rows(self.summary, self.criterion)
        self.estimate_path("decode").write_text("{not json", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            confidence.confidence_rows(self.summary, self.criterion)

    def test_refuses_mismatched_summary_median_and_speed(self):
        for field, new in (
            ("encode_median_ns", "1500001.00000"),
            ("decode_mib_per_s", "999.0000"),
        ):
            with self.subTest(field=field):
                old = self.row[field]
                self.row[field] = new
                self.rewrite_summary()
                with self.assertRaisesRegex(ValueError, "disagree"):
                    confidence.confidence_rows(self.summary, self.criterion)
                self.row[field] = old
        self.rewrite_summary()

    def test_rejects_unverified_or_inconsistent_source_rows(self):
        for field, bad in (
            ("verified_roundtrip", "false"),
            ("schema_version", "2"),
            ("fixture_version", "2"),
            ("chunk_bytes", "4096"),
            ("encoded_bytes", "0"),
            ("encoded_bytes", "9999999"),
            ("encoded_over_input_ratio", "0.5"),
            ("encoded_over_input_ratio", "nan"),
        ):
            with self.subTest(field=field, bad=bad):
                original = self.row[field]
                self.row[field] = bad
                self.rewrite_summary()
                with self.assertRaisesRegex(ValueError, "unverified|wrong|invalid"):
                    confidence.confidence_rows(self.summary, self.criterion)
                self.row[field] = original
        self.rewrite_summary()

    def test_rejects_duplicates_traversal_invalid_hash_and_schema(self):
        self.rewrite_summary([self.row, self.row])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            confidence.confidence_rows(self.summary, self.criterion)
        for field, bad in (
            ("workload", "../mixed-jsonl"),
            ("codec", "../lzraven"),
            ("scratch_mode", "../../etc"),
            ("input_sha256", "INVALID"),
            ("input_bytes", "065536"),
        ):
            with self.subTest(field=field):
                old = self.row[field]
                self.row[field] = bad
                self.rewrite_summary()
                with self.assertRaisesRegex(ValueError, "invalid|unsupported"):
                    confidence.confidence_rows(self.summary, self.criterion)
                self.row[field] = old
        self.rewrite_summary()
        # The existing published summary.csv contract must be recognizable.
        with self.summary.open("w", encoding="utf-8") as stream:
            stream.write("codec,encode_median_ns\nlzraven,1500000\n")
        with self.assertRaisesRegex(ValueError, "schema"):
            confidence.confidence_rows(self.summary, self.criterion)


if __name__ == "__main__":
    unittest.main()
