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

    def test_shared_writable_directory_refuses_stale_cleanup(self):
        # Other users could substitute an entry between inode check/unlink.
        # Refuse publication rather than delete evidence in shared storage.
        self.output.write_text("old derived evidence", encoding="utf-8")
        original_mode = self.evidence.stat().st_mode & 0o777
        try:
            for unsafe_mode in (0o770, 0o777):
                self.evidence.chmod(unsafe_mode)
                with self.assertRaisesRegex(ValueError, "group/world writable"):
                    with SafeCsvOutput(self.output, (self.input,)):
                        pass
                self.assertEqual(
                    self.output.read_text(encoding="utf-8"), "old derived evidence"
                )
        finally:
            self.evidence.chmod(original_mode)
        self.assertEqual(self.input.read_text(), "source evidence")

    def test_foreign_owned_directory_refuses_stale_cleanup(self):
        # Simulate an ACL-accessible directory owned by another user. Even
        # mode 0700 would not establish exclusive control for this process.
        self.output.write_text("old derived evidence", encoding="utf-8")
        real_fstat = os.fstat

        def foreign_owner(fd):
            result = real_fstat(fd)
            class ForeignStat:
                st_dev = result.st_dev
                st_ino = result.st_ino
                st_mode = result.st_mode
                st_uid = os.geteuid() + 1
            return ForeignStat()

        with patch("safe_benchmark_output.os.fstat", side_effect=foreign_owner):
            with self.assertRaisesRegex(ValueError, "owned by current user"):
                with SafeCsvOutput(self.output, (self.input,)):
                    pass
        self.assertEqual(self.output.read_text(), "old derived evidence")
        self.assertEqual(self.input.read_text(), "source evidence")

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
        self.assertEqual((moved / self.output.name).stat().st_size, 0)
        self.assertEqual(list(moved.glob(".comparison.csv.*.tmp")), [])

    def test_missing_directory_after_publication_cleans_anchored_csv(self):
        moved = self.root / "evidence-moved"
        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            self.evidence.rename(moved)
            with self.assertRaises(FileNotFoundError):
                publisher.write_rows(self.rows, ("codec", "value"))
        self.assertEqual((moved / self.output.name).stat().st_size, 0)
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

    def test_same_uid_replacement_between_cleanup_stat_and_unlink_survives(self):
        # A concurrent pathname substitution must survive failed-publication
        # invalidation, which operates on an already-open inode.
        replacement = self.root / "independent.csv"
        replacement.write_text("independent evidence", encoding="utf-8")
        real_fsync = os.fsync
        real_stat = os.stat
        triggered = False
        swapped = False

        def fail_directory_sync(fd):
            nonlocal triggered
            if not triggered and self.output.exists():
                triggered = True
                raise OSError("injected directory sync failure")
            return real_fsync(fd)

        def swap_after_identity_check(path, *args, **kwargs):
            nonlocal swapped
            result = real_stat(path, *args, **kwargs)
            if (
                triggered and not swapped and path == self.output.name
                and kwargs.get("dir_fd") is not None
                and kwargs.get("follow_symlinks") is False
            ):
                swapped = True
                os.replace(replacement, self.output)
            return result

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fsync", side_effect=fail_directory_sync):
                with patch("safe_benchmark_output.os.stat", side_effect=swap_after_identity_check):
                    with self.assertRaisesRegex(OSError, "directory sync failure"):
                        publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(triggered)
        self.assertTrue(swapped)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "independent evidence")
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_failed_atomic_replace_cleans_temporary_without_publishing(self):
        # A rename refusal must not leave a plausible upload artifact or
        # abandon a partially completed temporary CSV.
        real_replace = os.replace
        attempted = False

        def refuse_publication(src, dst, *args, **kwargs):
            nonlocal attempted
            if (
                dst == self.output.name
                and kwargs.get("src_dir_fd") is not None
                and kwargs.get("dst_dir_fd") is not None
            ):
                attempted = True
                raise PermissionError("injected atomic replace refusal")
            return real_replace(src, dst, *args, **kwargs)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.replace", side_effect=refuse_publication):
                with self.assertRaisesRegex(PermissionError, "atomic replace refusal"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(attempted)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_temporary_file_sync_failure_never_publishes(self):
        # A failed file durability barrier must not publish an unverified
        # CSV, even if its rows have already been written successfully.
        real_fsync = os.fsync
        failed = False

        def refuse_file_sync(fd):
            nonlocal failed
            if not failed and os.fstat(fd).st_mode & 0o170000 == 0o100000:
                failed = True
                raise OSError("injected temporary CSV sync failure")
            return real_fsync(fd)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fsync", side_effect=refuse_file_sync):
                with self.assertRaisesRegex(OSError, "temporary CSV sync failure"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(failed)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_directory_sync_failure_removes_published_csv(self):
        # A successful rename is not durable until the parent directory
        # sync succeeds. Refuse to leave a plausible upload artifact.
        real_fsync = os.fsync
        failed = False

        def refuse_directory_sync(fd):
            nonlocal failed
            if (
                not failed
                and self.output.exists()
                and os.fstat(fd).st_mode & 0o170000 == 0o040000
            ):
                failed = True
                raise OSError("injected directory durability failure")
            return real_fsync(fd)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fsync", side_effect=refuse_directory_sync):
                with self.assertRaisesRegex(OSError, "directory durability failure"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(failed)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_cleanup_unlink_failure_preserves_original_sync_error(self):
        # Cleanup is best-effort: a second filesystem failure must not hide
        # the publication durability error or affect original evidence.
        real_fsync = os.fsync
        real_unlink = os.unlink
        triggered = False
        cleanup_attempted = False

        def fail_publication_sync(fd):
            nonlocal triggered
            if not triggered and self.output.exists():
                triggered = True
                raise OSError("injected publication sync failure")
            return real_fsync(fd)

        def fail_cleanup_unlink(path, *args, **kwargs):
            nonlocal cleanup_attempted
            if path == self.output.name and kwargs.get("dir_fd") is not None:
                cleanup_attempted = True
                raise PermissionError("injected cleanup refusal")
            return real_unlink(path, *args, **kwargs)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fsync", side_effect=fail_publication_sync):
                with patch("safe_benchmark_output.os.unlink", side_effect=fail_cleanup_unlink):
                    with self.assertRaisesRegex(OSError, "injected publication sync failure"):
                        publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(triggered)
        self.assertTrue(cleanup_attempted)
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])

    def test_temporary_unlink_failure_preserves_original_write_error(self):
        # A failed write must remain the reported failure even if cleanup of
        # the partially written disposable temporary CSV is also refused.
        real_unlink = os.unlink
        cleanup_attempted = False

        def refuse_temp_cleanup(path, *args, **kwargs):
            nonlocal cleanup_attempted
            if (
                isinstance(path, str)
                and path.startswith(".comparison.csv.")
                and path.endswith(".tmp")
                and kwargs.get("dir_fd") is not None
            ):
                cleanup_attempted = True
                raise PermissionError("injected temporary cleanup refusal")
            return real_unlink(path, *args, **kwargs)

        def invalid_rows():
            raise ValueError("injected invalid benchmark row")
            yield {}  # Keep this a generator for DictWriter.writerows.

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.unlink", side_effect=refuse_temp_cleanup):
                with self.assertRaisesRegex(ValueError, "injected invalid benchmark row"):
                    publisher.write_rows(invalid_rows(), ("codec", "value"))
        self.assertTrue(cleanup_attempted)
        self.assertFalse(self.output.exists())
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

    def test_directory_swap_after_fstat_refuses_stale_cleanup(self):
        # The opened descriptor is still valid when the pathname is moved.
        # A second identity check must refuse stale cleanup on that inode.
        moved = self.root / "evidence-moved"
        replacement = self.root / "replacement-directory"
        replacement.mkdir()
        self.output.write_text("old derived evidence", encoding="utf-8")
        protected = replacement / self.output.name
        protected.write_text("independent evidence", encoding="utf-8")
        original_fstat = os.fstat
        swapped = False

        def swap_after_fstat(fd):
            nonlocal swapped
            result = original_fstat(fd)
            if not swapped:
                swapped = True
                self.evidence.rename(moved)
                replacement.rename(self.evidence)
            return result

        with patch("safe_benchmark_output.os.fstat", side_effect=swap_after_fstat):
            with self.assertRaisesRegex(ValueError, "changed during open"):
                with SafeCsvOutput(self.output, (self.input,)):
                    pass
        self.assertTrue(swapped)
        self.assertEqual((moved / self.output.name).read_text(), "old derived evidence")
        self.assertEqual((self.evidence / self.output.name).read_text(), "independent evidence")
        self.assertEqual(self.input.read_text(), "source evidence")

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
