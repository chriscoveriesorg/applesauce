#!/usr/bin/env python3
"""Pin a signed FSKit acceptance package to an immutable, clean Git source tree.

This only inspects the checkout. Generated project and build products must be
ignored by Git; all other untracked source files refuse provenance.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


class SourceProvenanceError(ValueError):
    pass


def git(root, *args):
    result = subprocess.run(["git", *args], cwd=root, capture_output=True,
                            text=True, check=False)
    if result.returncode:
        raise SourceProvenanceError(
            f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def source_commit(root, expected=None):
    """Reject modified/staged/untracked sources and an unexpected HEAD."""
    root = Path(root).resolve()
    top = Path(git(root, "rev-parse", "--show-toplevel")).resolve()
    if top != root:
        raise SourceProvenanceError("source root is not the checkout top level")
    head = git(root, "rev-parse", "--verify", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise SourceProvenanceError("checkout has no valid 40-character source commit")
    if expected is not None and head != expected:
        raise SourceProvenanceError(
            f"source commit changed during signing: expected {expected}, found {head}")
    # Git status deliberately omits tracked files marked assume-unchanged or
    # skip-worktree, even when their on-disk bytes differ from HEAD. Neither
    # index shortcut is safe when attesting a signed package's source tree.
    # Use NUL records so unusual file names cannot hide a flagged entry.
    indexed = git(root, "ls-files", "-v", "-z")
    for record in indexed.split("\0"):
        if record and (len(record) < 3 or record[1] != " " or record[0] != "H"):
            raise SourceProvenanceError(
                "tracked source has an untrusted index flag (assume-unchanged, "
                "skip-worktree or unmerged): " + repr(record[:160]))
    # Git records symlinks by their link text, not the bytes of their targets.
    # A tracked link to external Swift source can therefore change what Xcode
    # builds while both git status and ls-files -v report a clean checkout.
    # Reject gitlinks and unresolved index stages for the same provenance reason.
    staged = git(root, "ls-files", "--stage", "-z")
    for record in staged.split("\0"):
        if not record:
            continue
        metadata, separator, filename = record.partition("\t")
        parts = metadata.split(" ")
        if (not separator or not filename or len(parts) != 3
                or parts[0] not in ("100644", "100755")
                or not re.fullmatch(r"[0-9a-f]{40}", parts[1])
                or parts[2] != "0"):
            raise SourceProvenanceError(
                "tracked source is not a normal stage-0 regular file "
                "(symlink, gitlink or unmerged index): " + repr(record[:160]))
    # XcodeGen walks Host/extension inputs, while Cargo reads crates/ and
    # repository-local .cargo/config* (including compiler and linker overrides).
    # Rustup also reads root rust-toolchain* selection files. Git excludes can
    # hide any of these inputs from status, even though they affect the binary
    # signed under HEAD. Reject them unless tracked by the pinned commit.
    # Finder metadata is the only harmless ignored exception.
    ignored_sources = git(root, "ls-files", "--others", "--ignored",
                          "--exclude-standard", "-z", "--",
                          "fskit/Host", "fskit/ASCFExtension", "crates",
                          ".cargo", "rust-toolchain", "rust-toolchain.toml")
    for name in ignored_sources.split("\0"):
        if name and Path(name).name != ".DS_Store":
            raise SourceProvenanceError(
                "ignored build input may be compiled outside HEAD: "
                + repr(name[:160]))
    # --porcelain includes staged, unstaged, copied and untracked inputs.
    # Excluding ignored generated products is Git's responsibility.
    dirty = git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if dirty:
        raise SourceProvenanceError(
            "source checkout changed or contains untracked inputs: "
            + dirty.splitlines()[0])
    return head


class SourceProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        # Fixture repos must not inherit the developer's Git config: a global
        # excludes file can hide every fixture file (seen on a Mac whose
        # ~/.gitignore_global ignores new files), and signing or hooks can
        # block the fixture commit.
        env = mock.patch.dict(os.environ, {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "core.excludesFile",
            "GIT_CONFIG_VALUE_0": os.devnull,
            "GIT_CONFIG_KEY_1": "commit.gpgSign",
            "GIT_CONFIG_VALUE_1": "false",
        })
        env.start()
        self.addCleanup(env.stop)
        self.gitcmd("init", "-q")
        (self.root / ".gitignore").write_text("/target/\n.DS_Store\nfskit/ApplesauceASCF.xcodeproj/\n")
        (self.root / "source.swift").write_text("original\n")
        self.gitcmd("add", ".")
        self.gitcmd("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-qm", "initial")
        self.original = source_commit(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def gitcmd(self, *args):
        return git(self.root, *args)

    def test_clean_tree_and_ignored_build_products(self):
        target = self.root / "target"
        target.mkdir()
        (target / "cache").write_text("generated")
        generated = self.root / "fskit" / "ApplesauceASCF.xcodeproj"
        generated.mkdir(parents=True)
        (generated / "project.pbxproj").write_text("generated")
        self.assertEqual(source_commit(self.root, self.original), self.original)

    def test_untracked_source_refused(self):
        (self.root / "new_file.swift").write_text("untracked")
        with self.assertRaisesRegex(SourceProvenanceError, "untracked"):
            source_commit(self.root)

    def test_staged_or_modified_source_refused(self):
        (self.root / "source.swift").write_text("modified")
        with self.assertRaisesRegex(SourceProvenanceError, "changed"):
            source_commit(self.root)
        self.gitcmd("add", "source.swift")
        with self.assertRaisesRegex(SourceProvenanceError, "changed"):
            source_commit(self.root)

    def test_assume_unchanged_cannot_hide_modified_source(self):
        self.gitcmd("update-index", "--assume-unchanged", "source.swift")
        (self.root / "source.swift").write_text("untracked mutation\n")
        # Git status suppresses exactly this dangerous tracked-file change.
        self.assertEqual(self.gitcmd("status", "--porcelain=v1"), "")
        with self.assertRaisesRegex(SourceProvenanceError, "untrusted index flag"):
            source_commit(self.root, self.original)

    def test_skip_worktree_cannot_hide_modified_source(self):
        self.gitcmd("update-index", "--skip-worktree", "source.swift")
        (self.root / "source.swift").write_text("untracked mutation\n")
        self.assertEqual(self.gitcmd("status", "--porcelain=v1"), "")
        with self.assertRaisesRegex(SourceProvenanceError, "untrusted index flag"):
            source_commit(self.root, self.original)

    def test_unusual_tracked_filename_is_not_misparsed(self):
        name = "name with space and\nnewline.swift"
        (self.root / name).write_text("fixture")
        self.gitcmd("add", name)
        self.gitcmd("-c", "user.name=Fixture", "-c",
                    "user.email=fixture@example.invalid", "commit", "-qm", "unusual")
        self.assertEqual(source_commit(self.root),
                         self.gitcmd("rev-parse", "--verify", "HEAD"))

    def test_tracked_symlink_to_mutable_external_source_refused(self):
        external = Path(self.temp.name).parent / (Path(self.temp.name).name + "-external.swift")
        try:
            external.write_text("initial\n")
            link = self.root / "fskit" / "Host" / "Injected.swift"
            link.parent.mkdir(parents=True)
            link.symlink_to(external)
            self.gitcmd("add", "fskit/Host/Injected.swift")
            self.gitcmd("-c", "user.name=Fixture", "-c",
                        "user.email=fixture@example.invalid", "commit", "-qm", "tracked symlink")
            external.write_text("changed source outside checkout\n")
            self.assertEqual(self.gitcmd("status", "--porcelain=v1"), "")
            with self.assertRaisesRegex(SourceProvenanceError, "symlink"):
                source_commit(self.root)
        finally:
            external.unlink(missing_ok=True)

    def test_git_ignored_swift_compiled_by_xcodegen_refused(self):
        source_dir = self.root / "fskit" / "Host"
        source_dir.mkdir(parents=True)
        (self.root / ".git" / "info" / "exclude").write_text(
            "fskit/Host/Injected.swift\n")
        (source_dir / "Injected.swift").write_text("print(\"mutable ignored code\")\n")
        self.assertEqual(self.gitcmd("status", "--porcelain=v1"), "")
        with self.assertRaisesRegex(SourceProvenanceError, "ignored build input"):
            source_commit(self.root, self.original)

    def test_git_ignored_extension_source_refused(self):
        source_dir = self.root / "fskit" / "ASCFExtension"
        source_dir.mkdir(parents=True)
        (self.root / ".git" / "info" / "exclude").write_text(
            "fskit/ASCFExtension/Injected.swift\n")
        (source_dir / "Injected.swift").write_text("// replacement code\n")
        self.assertEqual(self.gitcmd("status", "--porcelain=v1"), "")
        with self.assertRaisesRegex(SourceProvenanceError, "ignored build input"):
            source_commit(self.root)

    def test_git_ignored_rust_crate_source_refused(self):
        source_dir = self.root / "crates" / "applesauce-fskit-bridge" / "src"
        source_dir.mkdir(parents=True)
        (self.root / ".git" / "info" / "exclude").write_text(
            "crates/applesauce-fskit-bridge/src/Injected.rs\n")
        (source_dir / "Injected.rs").write_text("// mutable Rust code\n")
        self.assertEqual(self.gitcmd("status", "--porcelain=v1"), "")
        with self.assertRaisesRegex(SourceProvenanceError, "ignored build input"):
            source_commit(self.root)

    def test_git_ignored_cargo_config_refused(self):
        # Repo-local Cargo config can change the compiler/linker or inject a
        # rustc wrapper while Git continues to report a clean source HEAD.
        cargo = self.root / ".cargo"
        cargo.mkdir()
        (self.root / ".git" / "info" / "exclude").write_text(
            ".cargo/config.toml\\n")
        (cargo / "config.toml").write_text(
            '[build]\\nrustflags = ["--cfg", "unreviewed_code"]\\n')
        self.assertEqual(self.gitcmd("status", "--porcelain=v1"), "")
        with self.assertRaisesRegex(SourceProvenanceError, "ignored build input"):
            source_commit(self.root, self.original)

    def test_git_ignored_rustup_toolchain_refused(self):
        # An ignored rust-toolchain.toml can silently change the compiler
        # used for an otherwise identical source SHA.
        (self.root / ".git" / "info" / "exclude").write_text(
            "rust-toolchain.toml\\n")
        (self.root / "rust-toolchain.toml").write_text(
            '[toolchain]\\nchannel = "nightly"\\n')
        self.assertEqual(self.gitcmd("status", "--porcelain=v1"), "")
        with self.assertRaisesRegex(SourceProvenanceError, "ignored build input"):
            source_commit(self.root, self.original)

    def test_finder_metadata_ignored_without_weakening_source_gate(self):
        for directory in ("fskit/Host", "fskit/ASCFExtension", "crates"):
            path = self.root / directory
            path.mkdir(parents=True, exist_ok=True)
            (path / ".DS_Store").write_bytes(b"Finder view metadata")
        self.assertEqual(source_commit(self.root, self.original), self.original)

    def test_head_change_refused_even_when_tree_clean(self):
        self.gitcmd("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "commit", "-q", "--allow-empty", "-m", "next")
        self.assertNotEqual(source_commit(self.root), self.original)
        with self.assertRaisesRegex(SourceProvenanceError, "commit changed"):
            source_commit(self.root, self.original)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--check", metavar="ROOT")
    parser.add_argument("--expected-sha")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(SourceProvenanceTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if not args.check:
        parser.error("--check ROOT is required unless --self-test")
    try:
        print(source_commit(args.check, args.expected_sha))
    except SourceProvenanceError as error:
        print(f"ASCF source provenance invalid: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
