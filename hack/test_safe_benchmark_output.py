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
        # A failed publication must not leave a plausible CSV in the
        # displaced directory, even though the protected path is untouched.
        self.assertFalse((moved / self.output.name).exists())
        self.assertEqual(list(moved.glob(".comparison.csv.*.tmp")), [])

    def test_missing_directory_after_publication_cleans_anchored_csv(self):
        moved = self.root / "evidence-moved"
        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            self.evidence.rename(moved)
            with self.assertRaises(FileNotFoundError):
                publisher.write_rows(self.rows, ("codec", "value"))
        self.assertFalse((moved / self.output.name).exists())
        self.assertEqual(list(moved.glob(".comparison.csv.*.tmp")), [])
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_replaced_entry_survives_failed_publication_cleanup(self):
        # A concurrent writer can substitute the entry just before cleanup.
        # The cleanup must not knowingly unlink the replacement.
        replacement = self.root / "unrelated.csv"
        replacement.write_text("independent evidence", encoding="utf-8")
        real_fsync = os.fsync
        triggered = False

        def fail_after_rename(fd):
            nonlocal triggered
            if not triggered and self.output.exists():
                triggered = True
                os.replace(replacement, self.output)
                raise OSError("injected post-rename sync failure")
            return real_fsync(fd)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fsync", side_effect=fail_after_rename):
                with self.assertRaisesRegex(OSError, "injected post-rename"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(triggered)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "independent evidence")
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_real_directory_swap_during_open_is_rejected(self):
        moved = self.root / "evidence-moved"
        incoming = self.root / "replacement-directory"
        incoming.mkdir()
        preserved = incoming / self.output.name
        preserved.write_text("do not remove", encoding="utf-8")
        self.output.write_text("old derived evidence", encoding="utf-8")
        original_open = os.open
        swapped = False

        def switch(path, flags, *args, **kwargs):
            nonlocal swapped
            if not swapped and Path(path) == self.evidence:
                swapped = True
                self.evidence.rename(moved)
                incoming.rename(self.evidence)
            return original_open(path, flags, *args, **kwargs)

        with patch("safe_benchmark_output.os.open", side_effect=switch):
            with self.assertRaisesRegex(ValueError, "changed during open"):
                with SafeCsvOutput(self.output, (self.input,)):
                    pass
        self.assertTrue(swapped)
        self.assertEqual((self.evidence / self.output.name).read_text(), "do not remove")
        self.assertEqual((moved / self.output.name).read_text(), "old derived evidence")

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
