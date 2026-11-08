#!/usr/bin/env python3
"""Run the authenticated Finder copy-out AppleScript with a finite deadline.

Finder may wait indefinitely on Apple Events consent, an unresponsive GUI, or
an incomplete FSKit read. Acceptance must fail and retain diagnostics rather
than leaving an unattended operator command blocked forever. The production
entry point always invokes Apple's /usr/bin/osascript; synthetic self-tests
exercise the same process and timeout path without contacting Finder.
"""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

FINDER_TIMEOUT_SECONDS = 180


def run_finder(interpreter, script, mount, name, size, destination, evidence, timeout):
    """Return an exit status; preserve bounded-stage stdout/stderr log files."""
    stdout_path = evidence / "finder-readback.txt"
    stderr_path = evidence / "finder-error.txt"
    # The caller's mktemp-created private evidence directory is the sole
    # destination. Exclusive opens refuse accidental reuse of old evidence.
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            process = subprocess.Popen(
                [str(interpreter), str(script), mount, name, size, str(destination)],
                stdout=stdout, stderr=stderr, start_new_session=True,
            )
        except OSError as error:
            print("Finder automation could not start: " + str(error), file=sys.stderr)
            return 127
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            # A script can spawn its own children; kill the separate process
            # group so a hung osascript cannot continue acceptance in the
            # background after the operator has received a failure.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            message = "Finder automation timed out after {} seconds; inspect {} and {}".format(
                timeout, stdout_path, stderr_path)
            stderr.write((message + "\n").encode("utf-8"))
            stderr.flush()
            print(message, file=sys.stderr)
            return 124


class FinderRunnerTests(unittest.TestCase):
    def test_success_and_preserved_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "ok.py"
            script.write_text("import sys\nprint('finder copied')\n"
                              "print('metadata', file=sys.stderr)\n")
            evidence = root / "evidence"
            evidence.mkdir()
            self.assertEqual(run_finder(sys.executable, script, "/Volumes/Test",
                                        "source.lzmesh", "33", root, evidence, 3), 0)
            self.assertEqual((evidence / "finder-readback.txt").read_text(),
                             "finder copied\n")
            self.assertEqual((evidence / "finder-error.txt").read_text(), "metadata\n")

    def test_nonzero_exit_fails_with_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "error.py"
            script.write_text("import sys\nprint('permission denied', file=sys.stderr)\n"
                              "sys.exit(23)\n")
            evidence = root / "evidence"
            evidence.mkdir()
            self.assertEqual(run_finder(sys.executable, script, "/Volumes/Test",
                                        "source.lzraven", "9", root, evidence, 3), 23)
            self.assertIn("permission denied",
                          (evidence / "finder-error.txt").read_text())

    def test_hung_automation_is_killed_and_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "hang.py"
            script.write_text("import time\ntime.sleep(30)\n")
            evidence = root / "evidence"
            evidence.mkdir()
            self.assertEqual(run_finder(sys.executable, script, "/Volumes/Test",
                                        "source.lzraven", "9", root, evidence, 0.05), 124)
            self.assertIn("Finder automation timed out",
                          (evidence / "finder-error.txt").read_text())

    def test_existing_evidence_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "finder-readback.txt").write_text("prior proof")
            with self.assertRaises(FileExistsError):
                run_finder(sys.executable, root / "anything.py", "/Volumes/Test",
                           "source.lzmesh", "10", root, root, 1)
            self.assertEqual((root / "finder-readback.txt").read_text(), "prior proof")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--script", type=Path)
    parser.add_argument("--mount")
    parser.add_argument("--name")
    parser.add_argument("--size")
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(FinderRunnerTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if not all((args.script, args.mount, args.name, args.size,
                args.destination, args.evidence)):
        parser.error("Finder run requires script, mount, name, size, destination and evidence")
    if not args.size.isascii() or not args.size.isdecimal():
        parser.error("expected logical size must be decimal bytes")
    try:
        return run_finder("/usr/bin/osascript", args.script, args.mount, args.name,
                          args.size, args.destination, args.evidence,
                          FINDER_TIMEOUT_SECONDS)
    except (OSError, ValueError) as error:
        print("Finder evidence runner refused unsafe output: " + str(error),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
