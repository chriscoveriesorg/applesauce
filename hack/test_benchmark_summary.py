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
            (criterion / "apple-buffer_smoke_65536_chat-jsonl_whole/lzraven-reused-scratch/decode/new/estimates.json").unlink()
            with self.assertRaises(FileNotFoundError):
                summary.summarize(manifest, criterion, output)


if __name__ == "__main__":
    unittest.main()
