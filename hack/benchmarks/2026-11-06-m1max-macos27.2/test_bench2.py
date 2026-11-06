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


if __name__ == "__main__":
    unittest.main()
