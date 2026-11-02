"""Offline tests for the Criterion-to-CSV summary contract."""

import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("summarize-benchmarks.py")
SPEC = importlib.util.spec_from_file_location("applesauce_benchmark_summary", SCRIPT)
assert SPEC and SPEC.loader
summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(summary)


class BenchmarkSummaryTests(unittest.TestCase):
    def test_median_throughput_and_missing_result_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = root / "manifest.csv"
            criterion = root / "criterion"
            output = root / "summary.csv"
            row = dict.fromkeys(summary.FIELDS, "")
            row.update(
                schema_version="1",
                fixture_version="1",
                suite="smoke",
                workload="chat-jsonl",
                input_bytes="65536",
                input_sha256="0" * 64,
                layout="whole",
                chunk_bytes="65536",
                codec="lzraven",
                scratch_mode="reused-scratch",
                encode_scratch_bytes="0",
                decode_scratch_bytes="0",
                encoded_bytes="8192",
                encoded_over_input_ratio="0.125",
                verified_roundtrip="true",
            )
            with manifest.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=summary.FIELDS)
                writer.writeheader()
                writer.writerow(row)
            for operation, nanoseconds in (("encode", 1_000_000), ("decode", 500_000)):
                path = (
                    criterion
                    / "apple-buffer_smoke_65536_chat-jsonl_whole/lzraven-reused-scratch"
                    / operation
                    / "new/estimates.json"
                )
                path.parent.mkdir(parents=True)
                path.write_text(
                    json.dumps({"median": {"point_estimate": nanoseconds}}),
                    encoding="utf-8",
                )
            rows = summary.summarize(manifest, criterion, output)
            self.assertEqual(rows[0]["encode_mib_per_s"], "62.5000")
            self.assertEqual(rows[0]["decode_mib_per_s"], "125.0000")
            self.assertIn("lzraven", summary.markdown(rows))
            with output.open(encoding="utf-8") as result:
                self.assertEqual(len(list(csv.DictReader(result))), 1)
            estimate = (
                criterion
                / "apple-buffer_smoke_65536_chat-jsonl_whole/lzraven-reused-scratch"
                / "encode/new/estimates.json"
            )
            # JSON permits nonstandard NaN/Infinity tokens in Python; the old
            # <= 0 check accepted them and emitted fabricated throughput.
            invalid_values = (
                0, -1, float("nan"), float("inf"), -float("inf"),
                None, True, "2.5", [], {}, 10 ** 400,
                # Positive finite medians must not print as 0.00000 ns;
                # subnormal values could otherwise produce infinite MiB/s.
                1e-320, 1e-6,
            )
            for invalid in invalid_values:
                with self.subTest(invalid=repr(invalid)):
                    estimate.write_text(
                        json.dumps({"median": {"point_estimate": invalid}}),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ValueError, "invalid encode median"):
                        summary.summarize(manifest, criterion, output)
            estimate.write_text(
                json.dumps({"median": {"point_estimate": 1_000_000}}),
                encoding="utf-8",
            )

            decode = (
                criterion
                / "apple-buffer_smoke_65536_chat-jsonl_whole/lzraven-reused-scratch"
                / "decode/new/estimates.json"
            )
            decode.unlink()
            with self.assertRaises(FileNotFoundError):
                summary.summarize(manifest, criterion, output)
            decode.write_text(
                json.dumps({"median": {"point_estimate": 500_000}}),
                encoding="utf-8",
            )

            with manifest.open("a", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=summary.FIELDS)
                writer.writerow(row)
            with self.assertRaisesRegex(ValueError, "duplicate benchmark case"):
                summary.summarize(manifest, criterion, output)

            # The standalone summarizer must not interpret arbitrary
            # manifest identifiers as filesystem paths into Criterion output.
            for field, invalid in (
                ("suite", "../smoke"),
                ("suite", "unknown"),
                ("workload", "../chat-jsonl"),
                ("codec", "../../lzfse"),
                ("codec", "lzvn"),
                ("scratch_mode", "../reused-scratch"),
            ):
                with self.subTest(field=field, invalid=invalid):
                    original = row[field]
                    row[field] = invalid
                    with manifest.open("w", newline="", encoding="utf-8") as handle:
                        writer = csv.DictWriter(handle, fieldnames=summary.FIELDS)
                        writer.writeheader()
                        writer.writerow(row)
                    with self.assertRaisesRegex(ValueError, "unsupported benchmark identity"):
                        summary.summarize(manifest, criterion, output)
                    row[field] = original

            for invalid_size in ("0", "-1", "8192", "065536"):
                row["input_bytes"] = invalid_size
                with manifest.open("w", newline="", encoding="utf-8") as handle:
                    writer = csv.DictWriter(handle, fieldnames=summary.FIELDS)
                    writer.writeheader()
                    writer.writerow(row)
                with self.assertRaisesRegex(ValueError, "invalid benchmark input size"):
                    summary.summarize(manifest, criterion, output)

            row["input_bytes"] = "65536"
            row["chunk_bytes"] = "1"
            with manifest.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=summary.FIELDS)
                writer.writeheader()
                writer.writerow(row)
            with self.assertRaisesRegex(ValueError, "invalid benchmark chunk size"):
                summary.summarize(manifest, criterion, output)
            row["chunk_bytes"] = "65536"

            for encoded_bytes, ratio in (
                ("0", "0"),
                ("8192", "nan"),
                ("8192", "inf"),
                ("8192", "0.500"),
                ("1" + "0" * 400, "0.125"),
                # Mathematically consistent but larger than the encoder's
                # 2 * input + 64 KiB output buffer.
                ("196609", str(196609 / 65536)),
            ):
                with self.subTest(encoded_bytes=encoded_bytes, ratio=ratio):
                    row["encoded_bytes"] = encoded_bytes
                    row["encoded_over_input_ratio"] = ratio
                    with manifest.open("w", newline="", encoding="utf-8") as handle:
                        writer = csv.DictWriter(handle, fieldnames=summary.FIELDS)
                        writer.writeheader()
                        writer.writerow(row)
                    with self.assertRaisesRegex(ValueError, "invalid encoded size or ratio"):
                        summary.summarize(manifest, criterion, output)

            row["encoded_bytes"] = "8192"
            row["encoded_over_input_ratio"] = "0.125"
            with manifest.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=summary.FIELDS)
                writer.writeheader()
                writer.writerow(row)
            valid_lines = manifest.read_text(encoding="utf-8").splitlines()
            for malformed_row in (
                valid_lines[1] + ",unexpected",
                valid_lines[1].rsplit(",", 1)[0],
            ):
                with self.subTest(malformed_row=malformed_row):
                    manifest.write_text(
                        "\n".join((valid_lines[0], malformed_row)) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ValueError, "malformed benchmark manifest row"):
                        summary.summarize(manifest, criterion, output)


if __name__ == "__main__":
    unittest.main()
