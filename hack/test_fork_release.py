"""Portable, read-only invariants for the fork's GitHub binary releases."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ForkReleaseSafetyTests(unittest.TestCase):
    def test_dist_never_targets_upstream_homebrew(self):
        config = (ROOT / "dist-workspace.toml").read_text(encoding="utf-8")
        self.assertIn('installers = ["shell"]', config)
        self.assertIn('publish-jobs = []', config)
        self.assertNotIn('tap = "Dr-Emann/homebrew-tap"', config)

    def test_git_release_requires_exact_version_and_green_main(self):
        workflow = (
            ROOT / ".github/workflows/applesauce-cli-release.yml"
        ).read_text(encoding="utf-8")
        for phrase in (
            '"actions": "read"',
            '"contents": "write"',
            "github.repository == 'chriscoveriesorg/applesauce'",
            'cargo metadata --no-deps --format-version 1',
            'applesauce-cli/v$version',
            'git merge-base --is-ancestor "$GITHUB_SHA" origin/main',
            'actions/workflows/cargo.yml/runs?head_sha=${GITHUB_SHA}',
            '.conclusion == "success"',
            "github.repository == 'Dr-Emann/applesauce'",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, workflow)
        self.assertIn("on:\n  pull_request:\n  push:\n    tags:", workflow)

    def test_upstream_crate_publish_stays_disabled(self):
        workflow = (
            ROOT / ".github/workflows/release-plz.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("if: github.repository == 'Dr-Emann/applesauce'", workflow)


if __name__ == "__main__":
    unittest.main()
