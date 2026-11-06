#!/usr/bin/env python3
"""Synthetic harness regression: a failed archive verify must invalidate the run."""
import csv
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import bench2


class ArchiveVerifyFailureTest(unittest.TestCase):
    def test_verify_failure_is_not_reported_as_ok_even_if_extract_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "source.bin"
            src.write_bytes(b"synthetic benchmark input")
            work = Path(tmp) / "work"
            work.mkdir()
            out = io.StringIO()
            writer = csv.DictWriter(out, fieldnames=bench2.FIELDS)
            writer.writeheader()

            def fake_timed(cmd, stdout_to=None):
                if cmd[1:3] == ["archive", "create"]:
                    Path(cmd[4]).write_bytes(b"fake archive")
                elif cmd[1:3] == ["archive", "extract"]:
                    Path(cmd[4]).write_bytes(src.read_bytes())
                return dict(real=1.0, user=0.5, sys_=0.1, rc=1 if cmd[2] == "verify" else 0,
                            rss=None, instr=None, cycles=None, peak=None, err="injected verify error")

            # metrics() expects 'sys', not 'sys_'.
            def timed(cmd, stdout_to=None):
                result = fake_timed(cmd, stdout_to)
                result["sys"] = result.pop("sys_")
                return result

            with patch.object(bench2, "WORK", str(work)), patch.object(
                bench2, "run_timed", side_effect=timed
            ):
                bench2.bench_file("test", "synthetic", str(src),
                                 [("lzraven", "archive")], {"*": 1}, writer, out)

            row = list(csv.DictReader(io.StringIO(out.getvalue())))[0]
            self.assertEqual(row["status"], "error")
            self.assertEqual(row["sha_ok"], "True")
            self.assertIn("verify rc=1", row["note"])


class NativeSizeInspectionTests(unittest.TestCase):
    def inspect(self, stdout, returncode=0, stderr=""):
        from subprocess import CompletedProcess
        result = CompletedProcess(["applesauce", "info", "/tmp/copy"], returncode,
                                  stdout=stdout, stderr=stderr)
        with patch.object(bench2.subprocess, "run", return_value=result):
            return bench2.decmpfs_size("/tmp/copy")

    def test_valid_native_size(self):
        self.assertEqual(self.inspect("Compressed size: 512\\n"), (512, True, ""))

    def test_explicit_uncompressed_skip(self):
        self.assertEqual(self.inspect("File is not compressed\\n"),
                         (None, False, "not-compressed"))

    def test_nonzero_info_exit_refused_even_with_plausible_size(self):
        with self.assertRaisesRegex(RuntimeError, "rc=2"):
            self.inspect("Compressed size: 512\\n", returncode=2,
                         stderr="permission denied")

    def test_missing_or_zero_native_size_refused(self):
        for output in ("unrecognised info format\\n", "Compressed size: 0\\n"):
            with self.subTest(output=output):
                with self.assertRaisesRegex(RuntimeError, "no valid compressed byte count"):
                    self.inspect(output)

    def test_native_ratio_skip_detects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "source.bin"
            src.write_bytes(b"original synthetic bytes")
            work = Path(tmp) / "work"
            work.mkdir()
            out = io.StringIO()
            writer = csv.DictWriter(out, fieldnames=bench2.FIELDS)
            writer.writeheader()

            def corrupting_compress(cmd, stdout_to=None):
                # Simulate an unexpected mutation even though the codec
                # reports that compression was skipped for ratio reasons.
                Path(cmd[-1]).write_bytes(b"changed synthetic bytes")
                return dict(real=1.0, user=0.2, sys=0.1, rc=0,
                            rss=None, instr=None, cycles=None, peak=None, err="")

            with patch.object(bench2, "WORK", str(work)), patch.object(
                bench2, "run_timed", side_effect=corrupting_compress
            ), patch.object(bench2, "decmpfs_size",
                            return_value=(None, False, "not-compressed")):
                bench2.bench_file("test", "synthetic", str(src),
                                 [("lzfse", "decmpfs")], {"*": 1}, writer, out)
            row = list(csv.DictReader(io.StringIO(out.getvalue())))[0]
            self.assertEqual(row["status"], "SHA-MISMATCH")
            self.assertEqual(row["sha_ok"], "False")

    def test_native_row_cannot_report_ok_if_info_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "source.bin"
            src.write_bytes(b"native benchmark fixture")
            work = Path(tmp) / "work"
            work.mkdir()
            out = io.StringIO()
            writer = csv.DictWriter(out, fieldnames=bench2.FIELDS)
            writer.writeheader()

            def successful_compress(cmd, stdout_to=None):
                return dict(real=1.0, user=0.2, sys=0.1, rc=0,
                            rss=None, instr=None, cycles=None, peak=None, err="")

            with patch.object(bench2, "WORK", str(work)), patch.object(
                bench2, "run_timed", side_effect=successful_compress
            ), patch.object(bench2, "decmpfs_size",
                            side_effect=RuntimeError("applesauce info failed")):
                bench2.bench_file("test", "synthetic", str(src),
                                 [("lzfse", "decmpfs")], {"*": 1}, writer, out)
            row = list(csv.DictReader(io.StringIO(out.getvalue())))[0]
            self.assertEqual(row["status"], "harness-error")
            self.assertEqual(row["sha_ok"], "")
            self.assertIn("info failed", row["note"])



class FreshOutputRootTests(unittest.TestCase):
    def test_unknown_batch_fails_before_creating_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "output"
            with patch.object(bench2, "WORK", str(root / "work")), patch.object(
                bench2, "CSV_PATH", str(root / "results" / "runs2.csv")
            ), patch.object(bench2.sys, "argv", ["bench2.py", "typo"]):
                with self.assertRaisesRegex(ValueError, "unknown benchmark batch"):
                    bench2.main()
            self.assertFalse((root / "results" / "runs2.csv").exists())

    def test_main_creates_results_directory_for_fresh_output_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "fresh-benchmark-output"
            csv_path = root / "results" / "runs2.csv"
            with patch.object(bench2, "WORK", str(root / "work")), patch.object(
                bench2, "CSV_PATH", str(csv_path)
            ), patch.object(bench2.sys, "argv", ["bench2.py", "main"]), patch.object(
                bench2, "files_in", return_value=[]
            ), patch.object(bench2, "batch_header"):
                bench2.main()
            self.assertTrue((root / "work").is_dir())
            with csv_path.open(newline="") as handle:
                self.assertEqual(next(csv.reader(handle)), bench2.FIELDS)


if __name__ == "__main__":
    unittest.main()
