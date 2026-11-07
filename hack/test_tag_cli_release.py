"""Owner tag helper tests, using only generated local Git repositories."""

from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
SCRIPT = ROOT / "tag-cli-release.sh"


class TagCliReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        remote = base / "chriscoveriesorg" / "applesauce.git"
        remote.parent.mkdir()
        self.repo = base / "working"
        self.repo.mkdir()
        self.git("init", "--bare", str(remote), cwd=base)
        self.git("init", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        cargo = self.repo / "crates/applesauce-cli/Cargo.toml"
        cargo.parent.mkdir(parents=True)
        cargo.write_text('[package]\nname = "applesauce-cli"\nversion = "0.5.32"\n')
        self.git("add", ".")
        self.git("commit", "-m", "generated source")
        self.sha = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("remote", "add", "origin", str(remote))
        self.git("push", "-u", "origin", "main")
        bindir = base / "bin"
        bindir.mkdir()
        curl = bindir / "curl"
        curl.write_text('#!/bin/sh\nprintf "%s\\n" "$MOCK_CI"\n')
        curl.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
        self.set_green(True)

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd or self.repo,
                              capture_output=True, text=True, check=True)

    def set_green(self, enabled):
        runs = []
        if enabled:
            runs.append({"head_sha": self.sha, "head_branch": "main",
                         "event": "push", "conclusion": "success"})
        self.env["MOCK_CI"] = json.dumps({"workflow_runs": runs})

    def run_helper(self, *args):
        return subprocess.run(["bash", str(SCRIPT), *args],
                              cwd=self.repo, env=self.env,
                              capture_output=True, text=True)

    def test_check_verifies_exact_commit_without_creating_tag(self):
        result = self.run_helper("0.5.32", self.sha)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(self.sha, result.stdout)
        self.assertEqual(self.git("tag", "--list").stdout.strip(), "")

    def test_push_creates_exact_tag_and_refuses_repeat(self):
        result = self.run_helper("0.5.32", self.sha, "--push")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git("rev-parse", "applesauce-cli/v0.5.32").stdout.strip(), self.sha)
        self.assertNotEqual(self.run_helper("0.5.32", self.sha, "--push").returncode, 0)

    def test_rejects_unqualified_source_or_version(self):
        for version, sha in [("0.5.31", self.sha), ("0.5.32", "f" * 40),
                             ("0.5.33", self.sha), ("../bad", self.sha)]:
            self.assertNotEqual(self.run_helper(version, sha).returncode, 0)
        self.assertEqual(self.git("tag", "--list").stdout.strip(), "")

    def test_requires_green_main_ci_and_refuses_divergent_commit(self):
        self.set_green(False)
        self.assertNotEqual(self.run_helper("0.5.32", self.sha).returncode, 0)
        self.set_green(True)
        self.git("checkout", "-b", "unmerged")
        (self.repo / "scratch").write_text("unmerged")
        self.git("add", "scratch")
        self.git("commit", "-m", "unmerged")
        unmerged = self.git("rev-parse", "HEAD").stdout.strip()
        self.assertNotEqual(self.run_helper("0.5.32", unmerged).returncode, 0)


if __name__ == "__main__":
    unittest.main()
