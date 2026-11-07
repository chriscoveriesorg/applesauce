"""Offline correctness and fail-closed tests for Criterion confidence export."""
import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

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

    def test_inverts_time_intervals_for_throughput_and_preserves_schema(self):
        self.assertEqual(confidence.write_confidence(
            self.summary, self.criterion, self.output), 1)
        with self.output.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(tuple(reader.fieldnames), confidence.COLUMNS)
            row = next(reader)
            self.assertEqual(len(list(reader)), 0)
        self.assertEqual(row["encode_ci95_lower_ns"], "1000000.00000")
        self.assertEqual(row["encode_ci95_upper_ns"], "2000000.00000")
        self.assertEqual(row["encode_median_mib_per_s"], "41.6667")
        self.assertEqual(row["encode_ci95_lower_mib_per_s"], "31.2500")
        self.assertEqual(row["encode_ci95_upper_mib_per_s"], "62.5000")
        self.assertEqual(row["decode_ci95_lower_mib_per_s"], "41.6667")
        self.assertEqual(row["decode_ci95_upper_mib_per_s"], "125.0000")
        self.assertEqual(row["input_sha256"], "a" * 64)

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
