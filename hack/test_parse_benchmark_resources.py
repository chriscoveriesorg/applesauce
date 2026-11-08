#!/usr/bin/env python3
"""Portable negative controls for macOS benchmark resource evidence."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("parse-benchmark-resources.py")
SPEC = importlib.util.spec_from_file_location("bench_resource_parser", SCRIPT)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
TRAILER = """Benchmarking some generated test
   4.50 real
   2.25 user
   0.25 sys
  184549376 maximum resident set size
     20 page reclaims
     0 page faults
"""


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "criterion.log"
        self.output = self.root / "resources.json"
        self.source.write_text(TRAILER)

    def cli(self):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.source),
                               str(self.output)], timeout=5, text=True,
                              capture_output=True)

    def test_works_and_is_bound_to_log_digest(self):
        self.assertEqual(self.cli().returncode, 0)
        result = json.loads(self.output.read_text())
        self.assertEqual(result["maximum_resident_bytes"], 184549376)
        self.assertEqual(result["wall_seconds"], 4.5)
        self.assertEqual(result["system_cpu_seconds"], 0.25)
        self.assertEqual(len(result["criterion_log_sha256"]), 64)
        self.assertIn("not per-codec", result["rss_scope"])

    def test_single_line_darwin_time_format(self):
        self.source.write_text("Benchmarking codec\n 4.50 real 2.25 user 0.25 sys\n"
                               "184549376 maximum resident set size\n")
        self.assertEqual(module.parse(self.source.read_bytes())["wall_seconds"], 4.5)

    def test_reverse_order_time_format(self):
        self.source.write_text("real 4.50\nuser 2.25\nsys 0.25\n"
                               "184549376 maximum resident set size\n")
        self.assertEqual(module.parse(self.source.read_bytes())["wall_seconds"], 4.5)

    def test_missing_or_duplicate_report_refused(self):
        for damaged in [TRAILER.replace("0.25 sys\n", ""),
                        TRAILER + "\n0.12 user\n",
                        TRAILER.replace("184549376 maximum resident set size\n", ""),
                        TRAILER + "\n7 maximum resident set size\n"]:
            self.source.write_text(damaged)
            self.assertEqual(self.cli().returncode, 1)
            self.assertFalse(self.output.exists())

    def test_stale_output_removed_on_failed_run(self):
        self.output.write_text("OLD DATA")
        self.source.write_text("benchmark failed before time trailer\n")
        self.assertEqual(self.cli().returncode, 1)
        self.assertFalse(self.output.exists())

    def test_samefile_and_hardlink_refused_without_deletion(self):
        self.output.hardlink_to(self.source)
        original = self.source.read_bytes()
        self.assertEqual(self.cli().returncode, 1)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(self.output.read_bytes(), original)
        self.output.unlink()
        self.assertRaises(ValueError, module.export, self.source, self.source)
        self.assertEqual(self.source.read_bytes(), original)

    def test_fifo_symlink_and_large_log_refused(self):
        symlink = self.root / "linked.log"
        symlink.symlink_to(self.source)
        self.assertRaises(OSError, module.read_log, symlink)
        fifo = self.root / "pipe.log"
        os.mkfifo(fifo)
        self.assertRaises(ValueError, module.read_log, fifo)
        big = self.root / "big.log"
        with big.open("wb") as stream:
            stream.truncate(module.MAX_LOG_BYTES + 1)
        self.assertRaises(ValueError, module.read_log, big)

    def test_floats_and_negative_resources_rejected(self):
        for damaged in [TRAILER.replace("4.50 real", "nan real"),
                        TRAILER.replace("4.50 real", "-1.0 real"),
                        TRAILER.replace("184549376", "0"),
                        TRAILER.replace("2.25 user", "1e999 user")]:
            self.source.write_text(damaged)
            self.assertEqual(self.cli().returncode, 1)


if __name__ == "__main__":
    unittest.main()
