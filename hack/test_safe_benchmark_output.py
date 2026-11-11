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

    def test_exclusive_csv_publish_and_stale_refusal(self):
        self.output.write_text("OLD", encoding="utf-8")
        with self.assertRaisesRegex(FileExistsError, "already exists"):
            with SafeCsvOutput(self.output, (self.input,)):
                pass
        self.assertEqual(self.output.read_text(), "OLD")
        self.output.unlink()
        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            publisher.write_rows(self.rows, ("codec", "value"))
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])

    def test_invalid_evidence_retains_existing_output_without_cleanup(self):
        self.output.write_text("STALE", encoding="utf-8")
        with self.assertRaisesRegex(FileExistsError, "already exists"):
            with SafeCsvOutput(self.output, (self.input,)):
                raise ValueError("invalid benchmark evidence")
        self.assertEqual(self.output.read_text(), "STALE")

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

    def test_directory_swap_after_open_cannot_redirect_publication(self):
        moved = self.root / "evidence-moved"
        protected = self.root / "protected"
        protected.mkdir()
        protected_output = protected / self.output.name
        protected_output.write_text("never overwrite", encoding="utf-8")
        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            self.evidence.rename(moved)
            self.evidence.symlink_to(protected, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "changed during publication"):
                publisher.write_rows(self.rows, ("codec", "value"))
        self.assertEqual(protected_output.read_text(), "never overwrite")
        # The failed job uploads raw diagnostics only; do not mutate any
        # published inode because another same-UID process can hardlink it.
        with (moved / self.output.name).open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)
        self.assertEqual(list(moved.glob(".comparison.csv.*.tmp")), [])

    def test_missing_directory_after_publication_preserves_inodes(self):
        moved = self.root / "evidence-moved"
        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            self.evidence.rename(moved)
            with self.assertRaises(FileNotFoundError):
                publisher.write_rows(self.rows, ("codec", "value"))
        with (moved / self.output.name).open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)
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

    def test_same_uid_replacement_during_failed_publication_is_preserved(self):
        replacement = self.root / "independent.csv"
        replacement.write_text("independent evidence", encoding="utf-8")
        real_fsync = os.fsync
        swapped = False

        def swap_then_fail(fd):
            nonlocal swapped
            if not swapped and self.output.exists():
                swapped = True
                os.replace(replacement, self.output)
                raise OSError("injected directory sync failure")
            return real_fsync(fd)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fsync", side_effect=swap_then_fail):
                with self.assertRaisesRegex(OSError, "directory sync failure"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(swapped)
        self.assertEqual(self.output.read_text(), "independent evidence")
        self.assertEqual(self.input.read_text(), "source evidence")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_substituted_fifo_does_not_block_failed_publication_cleanup(self):
        # Opening a substituted FIFO O_WRONLY without O_NONBLOCK would hang
        # waiting for a reader. Preserve the independent FIFO and error.
        replacement = self.root / "unrelated.fifo"
        os.mkfifo(replacement)
        real_fsync = os.fsync
        substituted = False

        def replace_then_fail(fd):
            nonlocal substituted
            if not substituted and self.output.exists():
                substituted = True
                os.replace(replacement, self.output)
                raise OSError("injected directory sync failure")
            return real_fsync(fd)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fsync", side_effect=replace_then_fail):
                with self.assertRaisesRegex(OSError, "directory sync failure"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(substituted)
        self.assertTrue(self.output.is_fifo())
        self.assertEqual(self.input.read_text(), "source evidence")

    def test_post_publication_hardlink_preserves_independent_alias(self):
        # A same-UID process may link the published inode before a failing
        # durability barrier. Cleanup must not truncate the other pathname.
        alias = self.root / "independent-alias.csv"
        real_fsync = os.fsync
        injected = False

        def link_then_fail(fd):
            nonlocal injected
            if not injected and self.output.exists():
                injected = True
                os.link(self.output, alias)
                raise OSError("injected directory sync failure")
            return real_fsync(fd)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fsync", side_effect=link_then_fail):
                with self.assertRaisesRegex(OSError, "directory sync failure"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(injected)
        with alias.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)
        self.assertEqual(self.input.read_text(), "source evidence")

    def test_late_hardlink_preserved_after_directory_sync_failure(self):
        # Previously expectedFailure: failure cleanup truncated an inode
        # that a same-UID process hardlinked after its st_nlink check.
        alias = self.root / "late-hardlink.csv"
        real_fsync = os.fsync
        linked = False

        def link_then_fail(fd):
            nonlocal linked
            if not linked and self.output.exists():
                linked = True
                os.link(self.output, alias)
                raise OSError("injected directory sync failure")
            return real_fsync(fd)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fsync", side_effect=link_then_fail):
                with self.assertRaisesRegex(OSError, "directory sync failure"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(linked)
        with alias.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)

    def test_exclusive_link_publication_refuses_concurrent_entry(self):
        # Another writer introduces an entry after our preflight; exclusive
        # linking must preserve it and remove only our random staging file.
        real_link = os.link
        raced = False

        def introduce_competing_output(src, dst, *args, **kwargs):
            nonlocal raced
            if dst == self.output.name and kwargs.get("dst_dir_fd") is not None:
                raced = True
                self.output.write_text("independent evidence", encoding="utf-8")
            return real_link(src, dst, *args, **kwargs)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.link", side_effect=introduce_competing_output):
                with self.assertRaises(FileExistsError):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(raced)
        self.assertEqual(self.output.read_text(), "independent evidence")
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])
        self.assertEqual(self.input.read_text(), "source evidence")

    def test_two_preflighted_publishers_cannot_overwrite_each_other(self):
        # Both publishers observe an absent destination. The second writer
        # must still fail at the atomic exclusive-link operation, preserving
        # the first writer's complete CSV and cleaning its own staging file.
        competing_rows = [{"codec": "lzmesh", "value": "456"}]
        with SafeCsvOutput(self.output, (self.input,)) as first:
            with SafeCsvOutput(self.output, (self.input,)) as second:
                first.write_rows(self.rows, ("codec", "value"))
                with self.assertRaises(FileExistsError):
                    second.write_rows(competing_rows, ("codec", "value"))
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_exclusive_publish_refuses_concurrent_symlink_to_source(self):
        # A same-UID writer can install a symlink after the preflight.
        # Exclusive publication must neither follow nor overwrite it.
        real_link = os.link
        injected = False

        def install_symlink_before_publish(src, dst, *args, **kwargs):
            nonlocal injected
            if dst == self.output.name and kwargs.get("dst_dir_fd") is not None:
                injected = True
                self.output.symlink_to(self.input)
            return real_link(src, dst, *args, **kwargs)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.link", side_effect=install_symlink_before_publish):
                with self.assertRaises(FileExistsError):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(injected)
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(self.output.resolve(), self.input.resolve())
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])

    def test_exclusive_publish_refuses_concurrent_hardlink_to_source(self):
        # A same-UID writer can hardlink protected source evidence into the
        # destination after preflight. The exclusive link must fail without
        # deleting the competing entry or changing either inode's bytes.
        real_link = os.link
        injected = False

        def install_hardlink_before_publish(src, dst, *args, **kwargs):
            nonlocal injected
            if dst == self.output.name and kwargs.get("dst_dir_fd") is not None:
                injected = True
                real_link(self.input, self.output)
            return real_link(src, dst, *args, **kwargs)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.link", side_effect=install_hardlink_before_publish):
                with self.assertRaises(FileExistsError):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(injected)
        self.assertTrue(os.path.samefile(self.output, self.input))
        self.assertEqual(self.output.read_text(encoding="utf-8"), "source evidence")
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])

    def test_failed_exclusive_link_cleans_temporary_without_publishing(self):
        real_link = os.link
        attempted = False

        def refuse_publication(src, dst, *args, **kwargs):
            nonlocal attempted
            if dst == self.output.name and kwargs.get("dst_dir_fd") is not None:
                attempted = True
                raise PermissionError("injected exclusive link refusal")
            return real_link(src, dst, *args, **kwargs)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.link", side_effect=refuse_publication):
                with self.assertRaisesRegex(PermissionError, "exclusive link refusal"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(attempted)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])
        self.assertEqual(self.input.read_text(), "source evidence")

    def test_predictable_temporary_name_collision_preserves_existing_evidence(self):
        # Even if a staging filename is guessed or reused, O_EXCL must
        # reject it before opening the file for writing or publishing.
        occupied = self.evidence / (".comparison.csv." + "ab" * 16 + ".tmp")
        occupied.write_text("independent temporary evidence", encoding="utf-8")
        with patch("safe_benchmark_output.secrets.token_hex", return_value="ab" * 16):
            with SafeCsvOutput(self.output, (self.input,)) as publisher:
                with self.assertRaises(FileExistsError):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertEqual(occupied.read_text(encoding="utf-8"), "independent temporary evidence")
        self.assertFalse(self.output.exists())
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_post_publish_temporary_unlink_failure_preserves_csv(self):
        # Once the exclusive link succeeds, failing to remove our staging
        # name must not delete or truncate the already-published inode.
        # The failed job quarantines derived CSV uploads.
        real_unlink = os.unlink
        refused = False

        def fail_staging_unlink(path, *args, **kwargs):
            nonlocal refused
            if (
                not refused
                and path.startswith(".comparison.csv.")
                and path.endswith(".tmp")
                and kwargs.get("dir_fd") is not None
                and self.output.exists()
            ):
                refused = True
                raise PermissionError("injected staging unlink failure")
            return real_unlink(path, *args, **kwargs)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.unlink", side_effect=fail_staging_unlink):
                with self.assertRaisesRegex(PermissionError, "staging unlink failure"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(refused)
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_fdopen_failure_closes_staging_descriptor(self):
        # fdopen can fail before adopting the raw descriptor. Ensure the
        # staging inode and descriptor are both released on this path.
        captured = []

        def reject_fdopen(fd, *args, **kwargs):
            captured.append(fd)
            raise OSError("injected fdopen failure")

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fdopen", side_effect=reject_fdopen):
                with self.assertRaisesRegex(OSError, "injected fdopen failure"):
                    publisher.write_rows(self.rows, ("codec", "value"))
        self.assertEqual(len(captured), 1)
        with self.assertRaises(OSError):
            os.fstat(captured[0])
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_fdopen_and_descriptor_close_failures_preserve_original_error(self):
        # A secondary close failure must not hide the original fdopen error.
        # The temporary pathname is still removed by write_rows cleanup.
        real_close = os.close
        captured = []

        def reject_fdopen(fd, *args, **kwargs):
            captured.append(fd)
            raise ValueError("injected fdopen failure")

        def reject_close(fd):
            if fd in captured:
                real_close(fd)
                raise OSError("injected descriptor close failure")
            return real_close(fd)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fdopen", side_effect=reject_fdopen):
                with patch("safe_benchmark_output.os.close", side_effect=reject_close):
                    with self.assertRaisesRegex(ValueError, "injected fdopen failure"):
                        publisher.write_rows(self.rows, ("codec", "value"))
        self.assertEqual(len(captured), 1)
        with self.assertRaises(OSError):
            os.fstat(captured[0])
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

    def test_directory_sync_failure_is_unqualified_and_keeps_published_inode(self):
        # Publication can be visible before a failing durability barrier.
        # Workflow failure must quarantine derived CSVs; the library leaves
        # published inodes unmodified to protect concurrent hardlink owners.
        real_fsync = os.fsync
        failed = False

        def refuse_directory_sync(fd):
            nonlocal failed
            if (
                not failed and self.output.exists()
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
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)
        self.assertEqual(list(self.evidence.glob(".comparison.csv.*.tmp")), [])
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_failed_publication_does_not_truncate_published_inode(self):
        real_fsync = os.fsync
        triggered = False

        def fail_publication_sync(fd):
            nonlocal triggered
            if not triggered and self.output.exists():
                triggered = True
                raise OSError("injected publication sync failure")
            return real_fsync(fd)

        with SafeCsvOutput(self.output, (self.input,)) as publisher:
            with patch("safe_benchmark_output.os.fsync", side_effect=fail_publication_sync):
                with patch("safe_benchmark_output.os.ftruncate", side_effect=AssertionError("unsafe truncation")):
                    with self.assertRaisesRegex(OSError, "injected publication sync failure"):
                        publisher.write_rows(self.rows, ("codec", "value"))
        self.assertTrue(triggered)
        with self.output.open(newline="", encoding="utf-8") as stream:
            self.assertEqual(list(csv.DictReader(stream)), self.rows)
        self.assertEqual(self.input.read_text(encoding="utf-8"), "source evidence")

    def test_failed_upload_excludes_derived_csvs(self):
        workflow = (
            Path(__file__).resolve().parent.parent / ".github/workflows/benchmark-codecs.yml"
        ).read_text(encoding="utf-8")
        qualified = workflow.split("- name: Retain fully qualified benchmark evidence", 1)[1]
        self.assertIn("if: success()", qualified.split("- name:", 1)[0])
        unqualified = workflow.split("- name: Retain unqualified raw diagnostics after failure", 1)[1]
        self.assertIn("if: failure()", unqualified)
        self.assertIn("target/criterion/**", unqualified)
        for derived in ("confidence.csv", "summary.csv", "raven-mesh-comparison.csv",
                        "all-codecs-ranking.csv"):
            self.assertNotIn(derived, unqualified)

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
