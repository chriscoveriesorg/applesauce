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
        # The real origin is canonical. A test-only Git shim routes transport
        # to a disposable bare repo, without rewriting the Git configuration.
        self.remote = remote
        self.git("remote", "add", "origin", "https://github.com/chriscoveriesorg/applesauce.git")
        self.git("push", str(remote), "main")
        bindir = base / "bin"
        bindir.mkdir()
        curl = bindir / "curl"
        curl.write_text('#!/bin/sh\nprintf "%s\\n" "$MOCK_CI"\n')
        curl.chmod(0o755)
        # All network-shaped Git operations are intercepted. Unexpected
        # transport calls fail closed instead of accessing GitHub.
        gitbin = bindir / "git"
        realgit = subprocess.check_output(["which", "git"], text=True).strip()
        gitbin.write_text(
            '#!/bin/sh\n'
            'if [ "$1" = fetch ] && [ "$2" = --no-tags ] && [ "$3" = origin ]; then\n'
            '  if [ "${FETCH_HEAD_ONLY:-}" = 1 ]; then\n'
            f'    exec "{realgit}" fetch --no-tags "$TEST_REMOTE" refs/heads/main\n'
            '  fi\n'
            f'  exec "{realgit}" fetch --no-tags "$TEST_REMOTE" "main:refs/remotes/origin/main"\n'
            'fi\n'
            'if [ "$1" = ls-remote ] && [ "$4" = origin ]; then\n'
            '  if [ "${FAIL_TAG_LOOKUP:-}" = 1 ]; then\n'
            '    echo "simulated remote tag lookup failure" >&2; exit 128\n'
            '  fi\n'
            f'  exec "{realgit}" ls-remote "$2" "$3" "$TEST_REMOTE" "$5"\n'
            'fi\n'
            'if [ "$1" = push ] && [ "$2" = origin ]; then\n'
            '  if [ "${FAIL_TAG_PUSH:-}" = 1 ]; then\n'
            '    echo "simulated tag push failure" >&2; exit 128\n'
            '  fi\n'
            f'  exec "{realgit}" push "$TEST_REMOTE" "$3"\n'
            'fi\n'
            'case "$1" in fetch|ls-remote|push) echo "unmocked Git transport" >&2; exit 125 ;; esac\n'
            f'exec "{realgit}" "$@"\n'
        )
        gitbin.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}",
                        TEST_REMOTE=str(remote))
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
        self.assertIn(self.sha, self.git("ls-remote", str(self.remote), "refs/tags/applesauce-cli/v0.5.32").stdout)

    def test_failed_tag_push_cleans_only_its_local_ref_and_allows_retry(self):
        self.env["FAIL_TAG_PUSH"] = "1"
        result = self.run_helper("0.5.32", self.sha, "--push")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("removed the local tag", result.stderr)
        self.assertEqual(self.git("tag", "--list").stdout.strip(), "")
        self.assertEqual(self.git("ls-remote", "--tags", str(self.remote),
                                  "refs/tags/applesauce-cli/v0.5.32").stdout.strip(), "")
        del self.env["FAIL_TAG_PUSH"]
        result = self.run_helper("0.5.32", self.sha, "--push")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.git("rev-parse", "applesauce-cli/v0.5.32").stdout.strip(),
                         self.sha)

    def test_refuses_existing_remote_tag_even_if_not_present_locally(self):
        self.git("tag", "applesauce-cli/v0.5.32", self.sha)
        self.git("push", str(self.remote), "refs/tags/applesauce-cli/v0.5.32")
        self.git("tag", "-d", "applesauce-cli/v0.5.32")
        self.assertNotEqual(self.run_helper("0.5.32", self.sha, "--push").returncode, 0)

    def test_remote_main_replacement_cannot_use_stale_tracking_ref(self):
        # An offline test with two disconnected histories. The approved SHA
        # stays in the local remote-tracking cache, while the actual remote
        # main ref is moved to a different root commit. A fresh FETCH_HEAD
        # must govern ancestry even if green CI evidence for the old SHA exists.
        self.git("update-ref", "refs/remotes/origin/main", self.sha)
        self.git("checkout", "--orphan", "disconnected")
        self.git("rm", "-r", "--cached", ".")
        (self.repo / "different-root").write_text("unrelated source")
        self.git("add", "different-root")
        self.git("commit", "-m", "generated unrelated main")
        unrelated = self.git("rev-parse", "HEAD").stdout.strip()
        # Transfer the detached history using a new test-only branch, then
        # move main inside the disposable bare repo without a force push.
        self.git("push", str(self.remote), "HEAD:refs/heads/disconnected")
        self.git("--git-dir", str(self.remote), "update-ref",
                 "refs/heads/main", unrelated)
        self.env["FETCH_HEAD_ONLY"] = "1"
        result = self.run_helper("0.5.32", self.sha, "--push")
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("freshly fetched origin main", result.stderr)
        self.assertEqual(
            self.git("rev-parse", "refs/remotes/origin/main").stdout.strip(),
            self.sha)
        self.assertEqual(self.git("tag", "--list").stdout.strip(), "")
        self.assertEqual(
            self.git("ls-remote", "--tags", str(self.remote),
                     "refs/tags/applesauce-cli/v0.5.32").stdout.strip(), "")

    def test_rejects_wrong_origin(self):
        self.git("remote", "set-url", "origin", "https://example.invalid/other/repo.git")
        result = self.run_helper("0.5.32", self.sha)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("origin must point", result.stderr)

    def test_rejects_lookalike_origin_host(self):
        for origin in ("https://attacker.invalid/chriscoveriesorg/applesauce.git",
                       "https://github.com.attacker.invalid/chriscoveriesorg/applesauce.git",
                       "ssh://git@attacker.invalid/chriscoveriesorg/applesauce.git"):
            self.git("remote", "set-url", "origin", origin)
            result = self.run_helper("0.5.32", self.sha, "--push")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("origin must point", result.stderr)
            self.assertEqual(self.git("tag", "--list").stdout.strip(), "")

    def test_rejects_instead_of_rewrite_before_tag_creation(self):
        self.git("config", f"url.file://{self.remote}.insteadOf",
                 "https://github.com/chriscoveriesorg/applesauce.git")
        result = self.run_helper("0.5.32", self.sha, "--push")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Git URL rewrites", result.stderr)
        self.assertEqual(self.git("tag", "--list").stdout.strip(), "")

    def test_rejects_push_instead_of_rewrite_before_tag_creation(self):
        self.git("config", f"url.file://{self.remote}.pushInsteadOf",
                 "https://github.com/chriscoveriesorg/applesauce.git")
        result = self.run_helper("0.5.32", self.sha, "--push")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Git URL rewrites", result.stderr)
        self.assertEqual(self.git("tag", "--list").stdout.strip(), "")

    def test_rejects_explicit_origin_pushurl_before_tag_creation(self):
        self.git("config", "remote.origin.pushurl", str(self.remote))
        result = self.run_helper("0.5.32", self.sha, "--push")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pushurl overrides", result.stderr)
        self.assertEqual(self.git("tag", "--list").stdout.strip(), "")

    def test_rejects_multiple_origin_urls(self):
        self.git("config", "--add", "remote.origin.url", str(self.remote))
        result = self.run_helper("0.5.32", self.sha, "--push")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("origin must point", result.stderr)
        self.assertEqual(self.git("tag", "--list").stdout.strip(), "")

    def test_fails_closed_when_remote_tag_lookup_fails(self):
        self.env["FAIL_TAG_LOOKUP"] = "1"
        result = self.run_helper("0.5.32", self.sha, "--push")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unable to verify remote tag absence", result.stderr)
        self.assertEqual(self.git("tag", "--list").stdout.strip(), "")

    def test_rejects_unqualified_source_or_version(self):
        for version, sha in [("0.5.31", self.sha), ("0.5.32", "f" * 40),
                             ("0.5.33", self.sha), ("../bad", self.sha)]:
            self.assertNotEqual(self.run_helper(version, sha).returncode, 0)
        self.assertEqual(self.git("tag", "--list").stdout.strip(), "")

    def test_ci_attestation_requires_matching_sha_branch_event_and_success(self):
        valid = {"head_sha": self.sha, "head_branch": "main",
                 "event": "push", "conclusion": "success"}
        for field, wrong in (("head_sha", "f" * 40),
                             ("head_branch", "feature"),
                             ("event", "pull_request"),
                             ("conclusion", "failure")):
            invalid = dict(valid, **{field: wrong})
            self.env["MOCK_CI"] = json.dumps({"workflow_runs": [invalid]})
            result = self.run_helper("0.5.32", self.sha, "--push")
            self.assertNotEqual(result.returncode, 0, (field, result.stdout))
            self.assertEqual(self.git("tag", "--list").stdout.strip(), "")
        self.env["MOCK_CI"] = json.dumps({"workflow_runs": [invalid, valid]})
        result = self.run_helper("0.5.32", self.sha)
        self.assertEqual(result.returncode, 0, result.stderr)
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
