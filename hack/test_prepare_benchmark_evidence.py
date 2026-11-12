"""Regression tests for isolated, fail-closed Criterion evidence reset."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

MODULE = Path(__file__).with_name("prepare_benchmark_evidence.py")
SPEC = importlib.util.spec_from_file_location("prepare_benchmark_evidence", MODULE)
assert SPEC and SPEC.loader
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class PrepareEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.target = self.checkout / "target"
        self.target.mkdir()

    def invoke(self, workspace=None):
        env = dict(os.environ, GITHUB_WORKSPACE=str(workspace or self.checkout))
        return subprocess.run(
            [sys.executable, str(MODULE)], env=env, capture_output=True,
            text=True, timeout=5,
        )

    def test_reset_clears_only_generated_evidence_and_retains_cargo_cache(self):
        (self.target / "debug").mkdir()
        (self.target / "debug" / "compiled").write_bytes(b"keep")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "sentinel").write_bytes(b"untouched")
        for name in ("criterion", "applesauce-bench"):
            folder = self.target / name
            folder.mkdir()
            (folder / "stale-result").write_bytes(b"old run")
            (folder / "external").symlink_to(outside, target_is_directory=True)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("criterion", "applesauce-bench"):
            self.assertEqual(list((self.target / name).iterdir()), [])
        self.assertEqual((self.target / "debug" / "compiled").read_bytes(), b"keep")
        self.assertEqual((outside / "sentinel").read_bytes(), b"untouched")
        self.assertEqual(self.invoke().returncode, 0)  # idempotent retry

    def test_symlinked_output_refused_before_other_output_is_removed(self):
        criterion = self.target / "criterion"
        criterion.mkdir()
        (criterion / "previous").write_text("preserved")
        outside = self.root / "external"
        outside.mkdir()
        (outside / "sentinel").write_text("safe")
        (self.target / "applesauce-bench").symlink_to(outside, target_is_directory=True)
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("symlinked evidence path", result.stderr)
        self.assertEqual((criterion / "previous").read_text(), "preserved")
        self.assertEqual((outside / "sentinel").read_text(), "safe")

    def test_symlinked_cargo_target_refused(self):
        self.target.rmdir()
        outside = self.root / "external"
        outside.mkdir()
        (outside / "keep").write_text("safe")
        self.target.symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.invoke().returncode, 1)
        self.assertEqual((outside / "keep").read_text(), "safe")

    def test_regular_file_at_evidence_path_refused_without_partial_delete(self):
        stale = self.target / "criterion" / "old"
        stale.parent.mkdir()
        stale.write_text("preserved")
        (self.target / "applesauce-bench").write_text("not a directory")
        self.assertEqual(self.invoke().returncode, 1)
        self.assertEqual(stale.read_text(), "preserved")

    def test_missing_workspace_refused(self):
        env = dict(os.environ)
        env.pop("GITHUB_WORKSPACE", None)
        result = subprocess.run([sys.executable, str(MODULE)], env=env,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn("GITHUB_WORKSPACE is required", result.stderr)


if __name__ == "__main__":
    unittest.main()
