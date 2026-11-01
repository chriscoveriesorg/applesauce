"""Fail-closed coverage tests for the versioned macOS benchmark standard."""

import csv
import importlib.util
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "applesauce_benchmark_matrix", Path(__file__).with_name("validate-benchmark-matrix.py")
)
assert SPEC and SPEC.loader
matrix = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix)


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manifest = Path(self.temp.name) / "manifest.csv"
        self.rows = []
        for suite, workload, size, layout, codec, mode in sorted(matrix.expected_cases("smoke")):
            encoded_bytes = size // 2
            self.rows.append(dict(
                schema_version="1",
                fixture_version="1",
                suite=suite,
                workload=workload,
                input_bytes=str(size),
                input_sha256=matrix.GOLDEN_64K[workload],
                layout=layout,
                chunk_bytes=str(size),
                codec=codec,
                scratch_mode=mode,
                encode_scratch_bytes="n/a" if mode == "api-managed" else "0",
                decode_scratch_bytes="n/a" if mode == "api-managed" else "0",
                encoded_bytes=str(encoded_bytes),
                encoded_over_input_ratio="0.500000000",
                verified_roundtrip="true",
            ))

    def write(self):
        with self.manifest.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=matrix.FIELDS)
            writer.writeheader()
            writer.writerows(self.rows)

    def test_expected_v1_case_counts(self):
        self.assertEqual(len(matrix.expected_cases("smoke")), 20)
        self.assertEqual(len(matrix.expected_cases("standard")), 120)
        self.assertEqual(len(matrix.expected_cases("extended")), 300)
        with self.assertRaisesRegex(ValueError, "unknown suite"):
            matrix.expected_cases("unexpected")

    def test_complete_smoke_and_missing_raven_are_detected(self):
        self.write()
        self.assertEqual(matrix.validate(self.manifest, "smoke"), 20)
        self.rows = [row for row in self.rows if row["codec"] != "lzraven"]
        self.write()
        with self.assertRaisesRegex(ValueError, "incomplete smoke suite"):
            matrix.validate(self.manifest, "smoke")

    def test_rejects_duplicate_forged_mismatched_or_malformed_cases(self):
        for field, bad, message in (
            ("codec", "lzvn", "unexpected benchmark case"),
            ("input_sha256", "f" * 64, "differs from v1 golden"),
            ("input_sha256", "bad-hash", "invalid fixture SHA-256"),
            ("encoded_over_input_ratio", "0.1", "invalid encoded size or ratio"),
            ("encoded_over_input_ratio", "nan", "invalid encoded size or ratio"),
            ("verified_roundtrip", "false", "round trip not verified"),
            ("chunk_bytes", "123", "incorrect chunk size"),
            ("encode_scratch_bytes", "n/a" if self.rows[0]["scratch_mode"] == "reused-scratch" else "2", "scratch"),
        ):
            with self.subTest(field=field, bad=bad):
                original = self.rows[0][field]
                self.rows[0][field] = bad
                self.write()
                with self.assertRaisesRegex(ValueError, message):
                    matrix.validate(self.manifest, "smoke")
                self.rows[0][field] = original
        self.rows.append(self.rows[0].copy())
        self.write()
        with self.assertRaisesRegex(ValueError, "duplicate benchmark case"):
            matrix.validate(self.manifest, "smoke")


if __name__ == "__main__":
    unittest.main()
