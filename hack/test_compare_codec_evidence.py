"""Regression tests for matched Raven/Mesh Criterion comparisons."""
import csv
import importlib.util
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("compare-codec-evidence.py")
SPEC = importlib.util.spec_from_file_location("applesauce_codec_compare", SCRIPT)
assert SPEC and SPEC.loader
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)


class CodecCompareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "confidence.csv"
        self.output = self.root / "raven-mesh-comparison.csv"
        self.rows = self.make_rows("smoke")
        self.save()

    def make_rows(self, suite):
        rows = []
        for identity in sorted(compare.matrix.expected_cases(suite)):
            name, workload, size, layout, codec, mode = identity
            row = dict.fromkeys(compare.confidence.COLUMNS, "")
            row.update(
                suite=name, workload=workload, input_bytes=str(size),
                input_sha256=compare.matrix.GOLDEN_SHA256[size][workload],
                layout=layout, codec=codec, scratch_mode=mode,
                encoded_over_input_ratio=(
                    "0.25" if codec == "lzraven" else
                    "0.5" if codec == "lzmesh" else "0.8"
                ),
            )
            for op in ("encode", "decode"):
                center = (
                    (9_000_000 if codec == "lzraven" else
                     1_000_000 if codec == "lzmesh" else 2_000_000)
                    if op == "encode" else
                    (1_000_000 if codec == "lzraven" else
                     1_100_000 if codec == "lzmesh" else 2_000_000)
                )
                low, high = center * 0.9, center * 1.1
                mibs = size * 1e9 / 1048576
                row[f"{op}_median_ns"] = str(center)
                row[f"{op}_ci95_lower_ns"] = str(low)
                row[f"{op}_ci95_upper_ns"] = str(high)
                row[f"{op}_median_mib_per_s"] = str(mibs / center)
                row[f"{op}_ci95_lower_mib_per_s"] = str(mibs / high)
                row[f"{op}_ci95_upper_mib_per_s"] = str(mibs / low)
            rows.append(row)
        return rows

    def save(self, rows=None, columns=None):
        with self.input.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=columns or compare.confidence.COLUMNS, extrasaction="ignore"
            )
            writer.writeheader()
            writer.writerows(self.rows if rows is None else rows)

    def test_full_smoke_matrix_comparison_and_bounds(self):
        rows = compare.compare(self.input, "smoke")
        self.assertEqual(len(rows), 4)  # Two workloads x two modes.
        self.assertEqual(tuple(rows[0]), compare.OUT_FIELDS)
        for result in rows:
            self.assertEqual(result["encode_mesh_speedup_x"], "9.000")
            self.assertEqual(result["encode_bound_low_x"], "7.364")
            self.assertEqual(result["encode_bound_high_x"], "11.000")
            self.assertEqual(result["encode_separation"], "mesh-faster")
            self.assertEqual(result["decode_separation"], "overlap")
            self.assertEqual(result["raven_savings_vs_mesh_pct"], "50.00")
        self.assertIn("not 95% confidence", compare.markdown(rows))

    def test_cli_writes_complete_artifact(self):
        cmd = [sys.executable, str(SCRIPT), str(self.input), "smoke", str(self.output)]
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        self.assertEqual(done.returncode, 0, done.stderr)
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), 4)
        self.assertIn("same-fixture", done.stdout)
        self.assertEqual(
            subprocess.run([sys.executable, str(SCRIPT), str(self.input),
                            "smoke", str(self.input)],
                           capture_output=True, text=True, timeout=5).returncode, 1
        )

    def test_output_hardlink_to_confidence_is_refused(self):
        original = self.input.read_bytes()
        os.link(self.input, self.output)
        command = [sys.executable, str(SCRIPT), str(self.input), "smoke",
                   str(self.output)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("must differ", result.stderr)
        self.assertEqual(self.input.read_bytes(), original)
        self.assertEqual(self.output.read_bytes(), original)

    def test_output_symlink_to_confidence_is_refused(self):
        # A symlink output must not replace or remove the input evidence.
        original = self.input.read_bytes()
        self.output.symlink_to(self.input)
        command = [sys.executable, str(SCRIPT), str(self.input), "smoke",
                   str(self.output)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("must differ", result.stderr)
        self.assertEqual(self.input.read_bytes(), original)
        self.assertTrue(self.output.is_symlink())

    def test_output_symlink_to_unrelated_file_does_not_modify_target(self):
        # Atomic publication must replace the output link, not follow it
        # into an unrelated file when generating valid comparison evidence.
        target = self.root / "unrelated.txt"
        original = b"unrelated data must remain unchanged\\n"
        target.write_bytes(original)
        self.output.symlink_to(target)
        command = [sys.executable, str(SCRIPT), str(self.input), "smoke",
                   str(self.output)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_bytes(), original)
        self.assertFalse(self.output.is_symlink())
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), 4)

    def test_output_hardlink_to_unrelated_file_does_not_modify_target(self):
        # Publishing through an existing hardlink must not overwrite the
        # other name's inode or change its exact bytes.
        target = self.root / "unrelated-hardlink.txt"
        original = b"independent evidence must remain unchanged\n"
        target.write_bytes(original)
        os.link(target, self.output)
        command = [sys.executable, str(SCRIPT), str(self.input), "smoke",
                   str(self.output)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_bytes(), original)
        self.assertNotEqual(os.stat(target).st_ino, os.stat(self.output).st_ino)
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(len(list(csv.DictReader(stream))), 4)

    def test_failed_rerun_does_not_retain_stale_comparison(self):
        self.output.write_text("stale prior-run evidence", encoding="utf-8")
        self.save(self.rows[:-1])
        command = [sys.executable, str(SCRIPT), str(self.input), "smoke",
                   str(self.output)]
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=5
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("incomplete", result.stderr)
        self.assertFalse(self.output.exists())
        self.assertTrue(self.input.exists())

    def test_incomplete_duplicate_and_forged_fixtures_fail(self):
        self.save(self.rows[:-1])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            compare.compare(self.input, "smoke")
        self.save(self.rows + [self.rows[0]])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            compare.compare(self.input, "smoke")
        changed = [dict(row) for row in self.rows]
        changed[0]["input_sha256"] = "a" * 64
        self.save(changed)
        with self.assertRaisesRegex(ValueError, "golden"):
            compare.compare(self.input, "smoke")

    def test_time_or_throughput_tamper_fails(self):
        for field, bad in (
            ("encode_ci95_lower_ns", "1000000000"),
            ("encode_ci95_upper_ns", "NaN"),
            ("encode_median_mib_per_s", "12345"),
            ("encode_ci95_lower_mib_per_s", "12345"),
            ("decode_ci95_upper_mib_per_s", "NaN"),
        ):
            with self.subTest(field=field):
                rows = [dict(row) for row in self.rows]
                raven = next(row for row in rows if row["codec"] == "lzraven")
                raven[field] = bad
                self.save(rows)
                with self.assertRaisesRegex(ValueError, "invalid|disagrees|reversed"):
                    compare.compare(self.input, "smoke")

    def test_throughput_tamper_beyond_export_rounding_is_rejected(self):
        # The confidence exporter rounds throughput to four decimals.
        # A 0.00015 modification exceeds its maximum 0.00005 error,
        # but the previous 0.0002 absolute tolerance accepted it.
        rows = [dict(row) for row in self.rows]
        raven = next(row for row in rows if row["codec"] == "lzraven")
        field = "encode_ci95_lower_mib_per_s"
        raven[field] = str(float(raven[field]) + 0.00015)
        self.save(rows)
        with self.assertRaisesRegex(ValueError, "throughput disagrees"):
            compare.compare(self.input, "smoke")

    def test_high_throughput_tamper_cannot_hide_in_relative_tolerance(self):
        # The exporter writes four decimals, so permitted absolute error
        # must not grow with throughput. Old 1e-5 relative tolerance
        # accepted a 0.01 MiB/s alteration at sufficiently high rates.
        rows = [dict(row) for row in self.rows]
        raven = next(row for row in rows if row["codec"] == "lzraven")
        size = int(raven["input_bytes"])
        elapsed = 1.0
        expected = size * 1e9 / 1048576 / elapsed
        raven["encode_median_ns"] = str(elapsed)
        raven["encode_ci95_lower_ns"] = str(elapsed)
        raven["encode_ci95_upper_ns"] = str(elapsed)
        for field in ("median", "ci95_lower", "ci95_upper"):
            raven[f"encode_{field}_mib_per_s"] = f"{expected:.4f}"
        self.save(rows)
        self.assertEqual(len(compare.compare(self.input, "smoke")), 4)
        raven["encode_median_mib_per_s"] = f"{expected + 0.01:.4f}"
        self.save(rows)
        with self.assertRaisesRegex(ValueError, "throughput disagrees"):
            compare.compare(self.input, "smoke")

    def test_tiny_positive_payload_ratios_remain_nonzero_in_csv(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            if row["codec"] == "lzraven":
                row["encoded_over_input_ratio"] = "1e-12"
            elif row["codec"] == "lzmesh":
                row["encoded_over_input_ratio"] = "2e-12"
        self.save(rows)
        result = compare.compare(self.input, "smoke")
        self.assertEqual(len(result), 4)
        for pair in result:
            self.assertEqual(float(pair["raven_payload_ratio"]), 1e-12)
            self.assertEqual(float(pair["mesh_payload_ratio"]), 2e-12)
            self.assertEqual(pair["raven_savings_vs_mesh_pct"], "50.00")

    def test_adjacent_payload_ratios_preserve_relative_difference(self):
        # Dividing first loses precision in the relative difference for
        # adjacent large floats, even though both inputs are finite.
        mesh_ratio = 1e300
        raven_ratio = math.nextafter(mesh_ratio, math.inf)
        rows = [dict(row) for row in self.rows]
        for row in rows:
            if row["codec"] == "lzraven":
                row["encoded_over_input_ratio"] = repr(raven_ratio)
            elif row["codec"] == "lzmesh":
                row["encoded_over_input_ratio"] = repr(mesh_ratio)
        self.save(rows)
        expected = 100 * ((mesh_ratio - raven_ratio) / mesh_ratio)
        for pair in compare.compare(self.input, "smoke"):
            self.assertEqual(float(pair["raven_payload_ratio"]), raven_ratio)
            self.assertEqual(float(pair["mesh_payload_ratio"]), mesh_ratio)
            self.assertEqual(float(pair["raven_savings_vs_mesh_pct"]), expected)
            self.assertLess(expected, 0)

    def test_tiny_nonzero_payload_savings_remains_visible(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            if row["codec"] == "lzraven":
                row["encoded_over_input_ratio"] = "0.99999999"
            elif row["codec"] == "lzmesh":
                row["encoded_over_input_ratio"] = "1.0"
        self.save(rows)
        for pair in compare.compare(self.input, "smoke"):
            self.assertGreater(float(pair["raven_savings_vs_mesh_pct"]), 0)
        for row in rows:
            if row["codec"] == "lzraven":
                row["encoded_over_input_ratio"] = "1.00000001"
        self.save(rows)
        for pair in compare.compare(self.input, "smoke"):
            self.assertLess(float(pair["raven_savings_vs_mesh_pct"]), 0)

    def test_small_nonzero_savings_are_not_materially_rounded(self):
        # Two-decimal rounding inflates a genuine 0.006% saving to 0.01%.
        rows = [dict(row) for row in self.rows]
        for row in rows:
            if row["codec"] == "lzraven":
                row["encoded_over_input_ratio"] = "0.99994"
            elif row["codec"] == "lzmesh":
                row["encoded_over_input_ratio"] = "1.0"
        self.save(rows)
        for pair in compare.compare(self.input, "smoke"):
            saving = float(pair["raven_savings_vs_mesh_pct"])
            expected = 100 * (1.0 - 0.99994)
            self.assertLessEqual(abs(saving - expected) / expected, 0.01)
        # Normal-size savings keep their established two-decimal rendering.
        for row in rows:
            if row["codec"] == "lzraven":
                row["encoded_over_input_ratio"] = "0.5"
        self.save(rows)
        for pair in compare.compare(self.input, "smoke"):
            self.assertEqual(pair["raven_savings_vs_mesh_pct"], "50.00")

    def test_near_unity_speedups_preserve_direction(self):
        # A reported 1.000x must not contradict a faster/slower verdict.
        self.assertEqual(compare.format_speedup(1.0), "1.000")
        self.assertGreater(float(compare.format_speedup(1.0001)), 1.0)
        self.assertLess(float(compare.format_speedup(0.9999)), 1.0)
        # Eight significant digits previously rounded these back to 1.0.
        self.assertGreater(float(compare.format_speedup(1.0 + 1e-9)), 1.0)
        self.assertLess(float(compare.format_speedup(1.0 - 1e-9)), 1.0)
        self.assertEqual(compare.format_speedup(9.0), "9.000")

    def test_small_speedups_are_not_materially_rounded(self):
        # Fixed three-decimal rounding doubles a valid 0.0005 ratio.
        for value in (0.0005, 0.00051, 0.00449, 0.0149):
            with self.subTest(value=value):
                reported = float(compare.format_speedup(value))
                self.assertLessEqual(abs(reported - value) / value, 0.01)
        # Keep the established normal-range CSV representation.
        self.assertEqual(compare.format_speedup(9.0), "9.000")
        self.assertEqual(compare.format_speedup(0.0 + 0.0000001), repr(0.0000001))

    def test_tiny_positive_speedup_bounds_remain_nonzero(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            if row["codec"] != "lzraven":
                continue
            size = int(row["input_bytes"])
            center = 1e-6
            low, high = center * 0.9, center * 1.1
            mibs = size * 1e9 / 1048576
            row["encode_median_ns"] = str(center)
            row["encode_ci95_lower_ns"] = str(low)
            row["encode_ci95_upper_ns"] = str(high)
            row["encode_median_mib_per_s"] = str(mibs / center)
            row["encode_ci95_lower_mib_per_s"] = str(mibs / high)
            row["encode_ci95_upper_mib_per_s"] = str(mibs / low)
        self.save(rows)
        for result in compare.compare(self.input, "smoke"):
            for field in ("encode_mesh_speedup_x", "encode_bound_low_x",
                          "encode_bound_high_x"):
                self.assertGreater(float(result[field]), 0, field)
            self.assertEqual(result["encode_separation"], "raven-faster")

    def test_overflowing_payload_savings_is_rejected(self):
        rows = [dict(row) for row in self.rows]
        for row in rows:
            if row["codec"] == "lzraven":
                row["encoded_over_input_ratio"] = "1e300"
            elif row["codec"] == "lzmesh":
                row["encoded_over_input_ratio"] = "1e-300"
        self.save(rows)
        with self.assertRaisesRegex(ValueError, "nonfinite.*savings"):
            compare.compare(self.input, "smoke")

    def test_unsafe_confidence_inputs_fail_without_hanging(self):
        self.input.unlink()
        self.input.symlink_to(self.output)
        with self.assertRaises(OSError):
            compare.compare(self.input, "smoke")
        self.input.unlink()
        self.input.write_bytes(b"x" * (compare.MAX_CONFIDENCE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "oversized"):
            compare.compare(self.input, "smoke")
        self.input.unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.input)
            with self.assertRaisesRegex(ValueError, "regular file"):
                compare.compare(self.input, "smoke")

    def test_unknown_schema_or_suite_is_refused(self):
        self.save(columns=compare.confidence.COLUMNS[:-1])
        with self.assertRaisesRegex(ValueError, "schema"):
            compare.compare(self.input, "smoke")
        self.save()
        with self.assertRaisesRegex(ValueError, "unknown suite"):
            compare.compare(self.input, "not-a-suite")


if __name__ == "__main__":
    unittest.main()
