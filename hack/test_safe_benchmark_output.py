"""Adversarial filesystem tests for derived benchmark CSV publication."""
import csv
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from safe_benchmark_output import SafeCsvOutput


class SafeOutputTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.input = self.root / "confidence.csv"
        self.input.write_text("source evidence", encoding="utf-8")
        self.output = self.evidence / "comparison.csv"
        self.rows = [{"codec": "lzraven", "value": "123"}]

    def test_atomic_csv_replaces_stale_evidence(self):
        self.output.write_text("OLD", encoding="utf-8")
        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            self.assertFalse(self.output.exists())
            publisher.write_rows(self.rows, ("codec", "value"))
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])

    def test_invalid_evidence_removes_stale_output_before_validation(self):
        self.output.write_text("STALE", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid benchmark evidence"):
            with SafeCsvOutput(self.output, (self.input,)):
                raise ValueError("invalid benchmark evidence")
        self.assertFalse(self.output.exists())

    def test_existing_hardlink_and_symlink_alias_leave_input_untouched(self):
        os.link(self.input, self.output)
        with self.assertRaisesRegex(ValueError, "differ from source"):
            with SafeCsvOutput(self.output, (self.input,)):
                pass
        self.assertEqual(self.input.read_text(), "source evidence")
        self.assertEqual(self.output.read_text(), "source evidence")
        self.output.unlink()
        self.output.symlink_to(self.input)
        with self.assertRaisesRegex(ValueError, "differ from source"):
            with SafeCsvOutput(self.output, (self.input,)):
                pass
        self.assertEqual(self.input.read_text(), "source evidence")
        self.assertTrue(self.output.is_symlink())

    def test_symlinked_parent_refuses_stale_cleanup(self):
        linked = self.root / "linked-evidence"
        linked.symlink_to(self.evidence, target_is_directory=True)
        self.output.write_text("prior", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "must not be a symlink"):
            with SafeCsvOutput(linked / self.output.name, (self.input,)):
                pass
        self.assertEqual(self.output.read_text(), "prior")

    def test_directory_swap_after_cleanup_cannot_redirect_publication(self):
        moved = self.root / "evidence-moved"
        protected = self.root / "protected"
        protected.mkdir()
        protected_output = protected / self.output.name
        protected_output.write_text("never overwrite", encoding="utf-8")
        self.output.write_text("stale", encoding="utf-8")
        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            self.assertFalse(self.output.exists())
            self.evidence.rename(moved)
            self.evidence.symlink_to(protected, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "changed during publication"):
                publisher.write_rows(self.rows, ("codec", "value"))
        self.assertEqual(protected_output.read_text(), "never overwrite")
        with (moved / self.output.name).open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)
        self.assertEqual(list(moved.glob(".comparison.csv.*.tmp")), [])

    def test_directory_swap_before_open_cannot_redirect_cleanup(self):
        moved = self.root / "evidence-moved"
        protected = self.root / "protected"
        protected.mkdir()
        protected_output = protected / self.output.name
        protected_output.write_text("never delete", encoding="utf-8")
        self.output.write_text("stale", encoding="utf-8")
        original_open = os.open
        swapped = False

        def switch(path, flags, *args, **kwargs):
            nonlocal swapped
            if not swapped and Path(path) == self.evidence:
                swapped = True
                self.evidence.rename(moved)
                self.evidence.symlink_to(protected, target_is_directory=True)
            return original_open(path, flags, *args, **kwargs)

        with patch("safe_benchmark_output.os.open", side_effect=switch):
            with self.assertRaises(OSError):
                with SafeCsvOutput(self.output, (self.input,)):
                    pass
        self.assertTrue(swapped)
        self.assertEqual(protected_output.read_text(), "never delete")
        self.assertEqual((moved / self.output.name).read_text(), "stale")


if __name__ == "__main__":
    unittest.main()
