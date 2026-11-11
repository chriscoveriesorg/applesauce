"""Portable, read-only invariants for the fork's GitHub binary releases."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ForkReleaseSafetyTests(unittest.TestCase):
    def test_dist_never_targets_upstream_homebrew(self):
        config = (ROOT / "dist-workspace.toml").read_text(encoding="utf-8")
        self.assertIn('installers = ["shell"]', config)
        self.assertNotIn('tap = "Dr-Emann/homebrew-tap"', config)
        self.assertNotIn('publish-jobs = ["homebrew"]', config)
        self.assertIn('github-build-setup = "../fork-release-build-setup.yml"', config)

    def test_git_release_requires_exact_version_and_green_main(self):
        workflow = (
            ROOT / ".github/workflows/applesauce-cli-release.yml"
        ).read_text(encoding="utf-8")
        step = (ROOT / ".github/fork-release-build-setup.yml").read_text(encoding="utf-8")
        gate = (ROOT / "hack/verify-fork-release.sh").read_text(encoding="utf-8")
        for phrase in (
            '"contents": "write"',
            "github.repository == 'chriscoveriesorg/applesauce'",
            'cargo metadata --no-deps --format-version 1',
            'applesauce-cli/v$version',
            'compare/${GITHUB_SHA}...main',
            'actions/workflows/cargo.yml/runs?head_sha=${GITHUB_SHA}',
            '.conclusion == "success"',
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, workflow + step + gate)
        self.assertIn("bash hack/verify-fork-release.sh", workflow)
        self.assertNotIn("publish-homebrew-formula:", workflow)
        self.assertNotIn('repository: "Dr-Emann/homebrew-tap"', workflow)
        self.assertIn("on:\n  pull_request:\n  push:\n    tags:", workflow)

    def test_fork_metadata_links_and_guard_changes_trigger_ci(self):
        for package in ("applesauce-cli", "applesauce-core", "applesauce", "resource-fork"):
            with self.subTest(package=package):
                manifest = (ROOT / "crates" / package / "Cargo.toml").read_text(encoding="utf-8")
                self.assertIn('repository = "https://github.com/chriscoveriesorg/applesauce"', manifest)
        ci = (ROOT / ".github/workflows/fork-release-safety.yml").read_text(encoding="utf-8")
        self.assertEqual(ci.count("'hack/verify-fork-release.sh'"), 2)
        self.assertEqual(ci.count("'.github/fork-release-build-setup.yml'"), 2)
        self.assertEqual(ci.count("'crates/**/Cargo.toml'"), 2)

    def _run_gate(self, *, tag="applesauce-cli/v0.5.30", relation="identical",
                  green=True, sha=None, version="0.5.30"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cargo = root / "cargo"
            cargo.write_text(
                '#!/bin/sh\nprintf \'{"packages":[{"name":"applesauce-cli","version":"0.5.30"}]}\\n\'\n',
                encoding="utf-8",
            )
            cargo.write_text(cargo.read_text(encoding="utf-8").replace(
                '"version":"0.5.30"', f'"version":"{version}"'
            ), encoding="utf-8")
            cargo.chmod(0o755)
            curl = root / "curl"
            curl.write_text(
                "#!/bin/sh\n"
                'case "$*" in\n'
                '  *"/compare/"*) printf \'{"status":"%s"}\\n\' "$MOCK_RELATION" ;;\n'
                '  *"/actions/workflows/"*) printf \'{"workflow_runs":[%s]}\\n\' "$MOCK_RUN" ;;\n'
                '  *) exit 2 ;;\n'
                'esac\n',
                encoding="utf-8",
            )
            curl.chmod(0o755)
            sha = sha or "a" * 40
            passed = (
                f'{{"head_sha":"{sha}","head_branch":"main",'
                '"event":"push","conclusion":"success"}'
            )
            env = os.environ.copy()
            env.update(
                PATH=f"{tmp}:{os.environ['PATH']}",
                GITHUB_REPOSITORY="chriscoveriesorg/applesauce",
                GITHUB_SHA=sha,
                GITHUB_REF=f"refs/tags/{tag}",
                GITHUB_REF_NAME=tag,
                MOCK_RELATION=relation,
                MOCK_RUN=passed if green else "",
            )
            return subprocess.run(
                ["bash", str(ROOT / "hack/verify-fork-release.sh")],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )

    def test_release_gate_accepts_green_main_tag(self):
        self.assertEqual(self._run_gate().returncode, 0)

    def test_v0531_release_gate_refuses_same_version_on_wrong_main_commit(self):
        tag = "applesauce-cli/v0.5.31"
        wrong = self._run_gate(tag=tag, version="0.5.31")
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn("qualified exact commit", wrong.stderr)
        qualified = self._run_gate(
            tag=tag, version="0.5.31",
            sha="1585dceb6c745cebf822588526ee5005255818c9",
        )
        self.assertEqual(qualified.returncode, 0, qualified.stderr)

    def test_release_gate_rejects_wrong_version(self):
        self.assertNotEqual(self._run_gate(tag="applesauce-cli/v99.0").returncode, 0)

    def test_release_gate_rejects_diverged_history(self):
        self.assertNotEqual(self._run_gate(relation="diverged").returncode, 0)

    def test_release_gate_rejects_no_green_ci(self):
        self.assertNotEqual(self._run_gate(green=False).returncode, 0)

    def test_upstream_crate_publish_stays_disabled(self):
        workflow = (
            ROOT / ".github/workflows/release-plz.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("if: github.repository == 'Dr-Emann/applesauce'", workflow)


if __name__ == "__main__":
    unittest.main()
