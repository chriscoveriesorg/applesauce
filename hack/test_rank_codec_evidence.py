"""Verify five-codec rankings from complete, same-host synthetic Criterion rows."""
import csv
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("rank-codec-evidence.py")
SPEC = importlib.util.spec_from_file_location("applesauce_rank_codecs", SCRIPT)
assert SPEC and SPEC.loader
ranker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ranker)


class RankCodecEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "confidence.csv"
        self.output = self.root / "all-codecs-ranking.csv"
        self.rows = self.fixture_rows()
        self.write()

    def fixture_rows(self):
        rows = []
        # Raven wins payload and decode; Mesh wins encode, providing a
        # cross-metric ranking with no implicit single 'best' codec.
        metrics = {
            "zlib": (5, 5, 0.70),
            "lzfse": (4, 4, 0.60),
            "lzbitmap": (3, 3, 0.50),
            "lzmesh": (1, 2, 0.40),
            "lzraven": (9, 1, 0.20),
        }
        for suite, workload, size, layout, codec, mode in sorted(
            ranker.compare.matrix.expected_cases("smoke")
        ):
            encode, decode, ratio = metrics[codec]
            row = dict.fromkeys(ranker.compare.confidence.COLUMNS, "")
            row.update(
                suite=suite, workload=workload, input_bytes=str(size),
                input_sha256=ranker.compare.matrix.GOLDEN_SHA256[size][workload],
                layout=layout, codec=codec, scratch_mode=mode,
                encoded_over_input_ratio=str(ratio),
            )
            for op, median in (("encode", encode * 1_000_000),
                               ("decode", decode * 1_000_000)):
                row[f"{op}_median_ns"] = str(median)
                row[f"{op}_ci95_lower_ns"] = str(median * 0.9)
                row[f"{op}_ci95_upper_ns"] = str(median * 1.1)
                speed_unit = size * 1e9 / 1048576
                row[f"{op}_median_mib_per_s"] = str(speed_unit / median)
                row[f"{op}_ci95_lower_mib_per_s"] = str(speed_unit / (median * 1.1))
                row[f"{op}_ci95_upper_mib_per_s"] = str(speed_unit / (median * 0.9))
            rows.append(row)
        return rows

    def write(self, rows=None):
        with self.source.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=ranker.compare.confidence.COLUMNS)
            writer.writeheader()
            writer.writerows(self.rows if rows is None else rows)

    def test_complete_five_codec_rankings_and_markdown(self):
        result = ranker.rank_cases(self.source, "smoke")
        self.assertEqual(len(result), len(self.rows))
        self.assertEqual(len(result), 20)  # Two workloads, two scratch modes, five codecs.
        for codec, payload, encode, decode in (
            ("lzraven", 1, 5, 1),
            ("lzmesh", 2, 1, 2),
            ("zlib", 5, 4, 5),
        ):
            cases = [r for r in result if r["codec"] == codec]
            self.assertEqual(len(cases), 4)
            for r in cases:
                self.assertEqual((r["payload_rank"], r["encode_rank"],
                                  r["decode_rank"]), (payload, encode, decode))
        self.assertIn("not statistically significant", ranker.markdown(result))

    def test_cli_publishes_complete_csv(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.source), "smoke",
             str(self.output)], capture_output=True, text=True, timeout=6,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.output.open(newline="", encoding="utf-8") as stream:
            recorded = list(csv.DictReader(stream))
        self.assertEqual(len(recorded), 20)
        self.assertEqual(tuple(recorded[0]), ranker.FIELDS)

    def test_missing_duplicate_forged_source_refused(self):
        self.write(self.rows[:-1])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            ranker.rank_cases(self.source, "smoke")
        self.write(self.rows + [self.rows[0]])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ranker.rank_cases(self.source, "smoke")
        changed = [dict(row) for row in self.rows]
        changed[0]["input_sha256"] = "0" * 64
        self.write(changed)
        with self.assertRaisesRegex(ValueError, "golden"):
            ranker.rank_cases(self.source, "smoke")

    def test_non_raven_codec_timing_and_ratio_corruption_refused(self):
        cases = (
            ("decode_ci95_upper_ns", "NaN", "invalid"),
            ("encode_median_mib_per_s", "1000000", "disagrees"),
            ("encoded_over_input_ratio", "-0.5", "invalid"),
        )
        for field, corrupt, message in cases:
            with self.subTest(field=field):
                changed = [dict(row) for row in self.rows]
                target = next(r for r in changed if r["codec"] == "zlib")
                target[field] = corrupt
                self.write(changed)
                with self.assertRaisesRegex(ValueError, message):
                    ranker.rank_cases(self.source, "smoke")

    def test_unsafe_confidence_inputs_are_bounded_and_nonblocking(self):
        original = self.source.read_bytes()
        backup = self.root / "untouched-fixture.csv"
        backup.write_bytes(original)
        command = [sys.executable, str(SCRIPT), str(self.source),
                   "smoke", str(self.output)]

        self.source.unlink()
        self.source.write_bytes(b"x" * (ranker.compare.MAX_CONFIDENCE_BYTES + 1))
        oversized = subprocess.run(
            command, capture_output=True, text=True, timeout=5
        )
        self.assertEqual(oversized.returncode, 1, oversized.stderr)
        self.assertIn("oversized", oversized.stderr)
        self.assertFalse(self.output.exists())

        self.source.unlink()
        self.source.symlink_to(backup)
        symlink = subprocess.run(
            command, capture_output=True, text=True, timeout=5
        )
        self.assertEqual(symlink.returncode, 1, symlink.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual(backup.read_bytes(), original)

        self.source.unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.source)
            fifo = subprocess.run(
                command, capture_output=True, text=True, timeout=5
            )
            self.assertEqual(fifo.returncode, 1, fifo.stderr)
            self.assertIn("regular file", fifo.stderr)
            self.assertFalse(self.output.exists())

    def test_output_hardlink_to_evidence_is_refused(self):
        original = self.source.read_bytes()
        os.link(self.source, self.output)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.source), "smoke",
             str(self.output)], capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("differ from source", result.stderr)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(self.output.read_bytes(), original)

    def test_failed_rerun_drops_stale_output_without_erasing_input(self):
        self.output.write_text("old measurements", encoding="utf-8")
        self.write(self.rows[:-1])
        result = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.source), "smoke",
             str(self.output)], capture_output=True, text=True, timeout=6,
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.output.exists())
        self.assertTrue(self.source.exists())
        self.assertIn("incomplete", result.stderr)


if __name__ == "__main__":
    unittest.main()
