#!/usr/bin/env python3
"""Capture exact build executables and compiler-affecting environment.

This is a provenance witness for a disposable signed FSKit build. Values of
inherited build flags are hashed so portable bundles do not expose local paths.
"""
import argparse
import hashlib
import io
import json
import os
import shlex
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

TOOLS = ("cargo", "rustc", "xcodegen", "xcodebuild", "xcrun", "git", "python3")
EXACT_ENV = frozenset((
    "PATH", "HOME", "DEVELOPER_DIR", "SDKROOT", "TOOLCHAINS",
    "RUSTUP_TOOLCHAIN", "RUSTUP_HOME", "CARGO_HOME", "CARGO_TARGET_DIR",
    "RUSTC_BOOTSTRAP",
    "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTDOCFLAGS",
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET", "SWIFTFLAGS", "OTHER_SWIFT_FLAGS",
    "CC", "CXX", "CFLAGS", "CXXFLAGS", "LDFLAGS",
    "MACOSX_DEPLOYMENT_TARGET", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH", "LIBRARY_PATH", "DYLD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES", "PKG_CONFIG_PATH",
))
ENV_PREFIXES = ("CARGO_TARGET_", "CARGO_PROFILE_", "CARGO_ENCODED_",
                "CARGO_BUILD_", "RUSTFLAGS_")
# The environment's hash alone does not pin executable bytes. Compiler,
# linker and Cargo wrapper overrides must also be inspected individually.
EXECUTABLE_OVERRIDES = frozenset((
    "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTDOC",
    "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_RUSTDOC",
    "CC", "CXX", "LD", "AR", "PKG_CONFIG", "SWIFT_EXEC",
))


class ToolchainError(ValueError):
    pass


def executable_fingerprint(path):
    """Hash a resolved regular executable and detect changes during reading."""
    try:
        target = Path(path).resolve(strict=True)
        if not os.access(target, os.X_OK):
            raise ToolchainError("build tool is not executable")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(target, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ToolchainError("build tool is not a regular file")
            digest = hashlib.sha256()
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(fd)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if identity(before) != identity(after) or identity(os.stat(target)) != identity(before):
                raise ToolchainError("build tool changed during fingerprint")
            return digest.hexdigest()
        finally:
            os.close(fd)
    except (OSError, RuntimeError) as error:
        raise ToolchainError("cannot fingerprint required build tool") from error


def fingerprint_optional_regular_file(path):
    """Pin optional Cargo configuration without disclosing its contents/path.

    A missing config is a distinct witness: adding one during a signed build
    must change the post-build record. Refuse symlinks and nonregular inputs.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return "absent"
    except OSError as error:
        raise ToolchainError("cannot inspect Cargo home configuration") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ToolchainError("Cargo home configuration is not a regular file")
        # On platforms without O_NOFOLLOW, reject a final-component symlink.
        if Path(path).is_symlink():
            raise ToolchainError("symlinked Cargo home configuration")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        observed = os.stat(path, follow_symlinks=False)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if identity(before) != identity(after) or identity(before) != identity(observed):
            raise ToolchainError("Cargo home configuration changed during fingerprint")
        return digest.hexdigest()
    except OSError as error:
        raise ToolchainError("cannot fingerprint Cargo home configuration") from error
    finally:
        os.close(fd)


def cargo_home_config_fingerprints(environ=None):
    """Capture Cargo's legacy and TOML home configuration as signing inputs."""
    environ = os.environ if environ is None else environ
    home = Path(environ.get("CARGO_HOME") or Path(environ.get("HOME") or str(Path.home())) / ".cargo")
    if not home.is_absolute():
        raise ToolchainError("CARGO_HOME must be absolute for signed builds")
    return {
        "cargo-home:" + name: fingerprint_optional_regular_file(home / name)
        for name in ("config", "config.toml")
    }


def cargo_directory_config_fingerprints(cwd=None):
    """Pin Cargo config search paths from checkout up through its ancestors.

    Cargo can read .cargo/config[.toml] from parent directories outside Git.
    Record absence as well as bytes so a configuration appearing mid-build
    invalidates the signed artifact's source/toolchain witness.
    """
    directory = Path.cwd() if cwd is None else Path(cwd)
    if not directory.is_absolute():
        raise ToolchainError("Cargo build directory must be absolute")
    hashes = {}
    for depth, ancestor in enumerate((directory, *directory.parents)):
        for name in ("config", "config.toml"):
            hashes[f"cargo-parent:{depth}:{name}"] = fingerprint_optional_regular_file(
                ancestor / ".cargo" / name)
    return hashes


def capture_environment(environ=None):
    environ = os.environ if environ is None else environ
    selected = {key: value for key, value in environ.items()
                if key in EXACT_ENV or key in EXECUTABLE_OVERRIDES
                or key.startswith(ENV_PREFIXES)}
    serialized = json.dumps(selected, sort_keys=True, ensure_ascii=True,
                            separators=(",", ":")).encode("utf-8")
    return sorted(selected), hashlib.sha256(serialized).hexdigest()



def fingerprint_executable_overrides(environ=None, finder=shutil.which):
    """Pin the programs selected by inherited build-tool overrides.

    A shell command with arguments or redirection is ambiguous in a
    signed build. Reject it instead of attesting only the unchanging
    environment string while an arbitrary wrapper binary changes.
    """
    environ = os.environ if environ is None else environ
    hashes = {}
    for key, value in sorted(environ.items()):
        if not (key in EXECUTABLE_OVERRIDES
                or (key.startswith("CARGO_TARGET_")
                    and key.endswith(("_LINKER", "_AR")))):
            continue
        if not value.strip():
            continue
        try:
            tokens = shlex.split(value)
        except ValueError as error:
            raise ToolchainError("invalid executable override: " + key) from error
        if len(tokens) != 1:
            raise ToolchainError("ambiguous executable override: " + key)
        command = tokens[0]
        resolved = command if "/" in command else finder(command)
        if not resolved:
            raise ToolchainError("unresolved executable override: " + key)
        hashes["override:" + key] = executable_fingerprint(resolved)
    return hashes

def record(tool_names=TOOLS, finder=shutil.which, xcrun=None,
           rust_binary=None, environ=None):
    """Pin executable bytes, including actual SDK compilers, and relevant flags."""
    tool_hashes = {}
    for name in tool_names:
        resolved = finder(name)
        if not resolved:
            raise ToolchainError("required build tool missing: " + name)
        tool_hashes[name] = executable_fingerprint(resolved)
    if xcrun is not None:
        for name in ("swiftc", "clang"):
            try:
                resolved = xcrun(name)
            except (subprocess.CalledProcessError, OSError) as error:
                raise ToolchainError("cannot resolve SDK compiler: " + name) from error
            if not resolved or "\n" in resolved:
                raise ToolchainError("untrusted SDK compiler path: " + name)
            tool_hashes["xcrun:" + name] = executable_fingerprint(resolved)
    if rust_binary is not None:
        for name in ("rustc", "cargo"):
            tool_hashes["rust-toolchain:" + name] = executable_fingerprint(rust_binary(name))
    tool_hashes.update(fingerprint_executable_overrides(environ, finder))
    env_keys, env_sha = capture_environment(environ)
    return {
        "schema": "ascf-build-toolchain-v1",
        "executables_sha256": dict(sorted(tool_hashes.items())),
        "cargo_home_config_sha256": cargo_home_config_fingerprints(environ),
        "cargo_directory_config_sha256": cargo_directory_config_fingerprints(),
        "build_environment_keys": env_keys,
        "build_environment_sha256": env_sha,
    }


def rust_toolchain_binary(name):
    try:
        root = subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ToolchainError("cannot locate actual Rust compiler") from error
    if not root or "\n" in root:
        raise ToolchainError("invalid Rust sysroot")
    return Path(root) / "bin" / name


def sdk_compiler(name):
    return subprocess.check_output(["xcrun", "--find", name], text=True).strip()


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.binary = Path(self.temporary.name) / "fake-tool"
        self.binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o700)

    def test_executable_byte_changes_affect_record(self):
        first = executable_fingerprint(self.binary)
        self.binary.write_bytes(b"#!/bin/sh\nexit 1\n")
        self.assertNotEqual(first, executable_fingerprint(self.binary))

    def test_untrusted_nonregular_executable_fails_closed(self):
        with self.assertRaises(ToolchainError):
            executable_fingerprint(self.temporary.name)

    def test_environment_flags_change_witness(self):
        a = {"PATH": "/bin", "RUSTFLAGS": "-C opt-level=2"}
        b = {"PATH": "/bin", "RUSTFLAGS": "-C opt-level=3"}
        self.assertNotEqual(capture_environment(a)[1], capture_environment(b)[1])

    def test_env_order_has_no_effect_and_extra_build_overrides_are_captured(self):
        a = {"CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER": "linker-A",
             "PATH": "/bin", "UNRELATED_SECRET": "secret"}
        b = {"UNRELATED_SECRET": "other", "PATH": "/bin",
             "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER": "linker-A"}
        self.assertEqual(capture_environment(a), capture_environment(b))
        self.assertNotIn("UNRELATED_SECRET", capture_environment(a)[0])

    def test_finder_and_sdk_compiler_are_fingerprinted(self):
        report = record(("cargo",), lambda name: str(self.binary),
                        lambda name: str(self.binary), lambda name: str(self.binary),
                        {"PATH": "/bin"})
        self.assertEqual(set(report["executables_sha256"]),
                         {"cargo", "xcrun:swiftc", "xcrun:clang",
                          "rust-toolchain:rustc", "rust-toolchain:cargo"})
        self.assertEqual(report["build_environment_keys"], ["PATH"])
        self.assertNotIn("/bin", json.dumps(report))

    def test_wrapper_executable_changes_are_recorded(self):
        wrapper = Path(self.temporary.name) / "wrapper"
        wrapper.write_bytes(b"#!/bin/sh\nexit 0\n")
        wrapper.chmod(0o700)
        env = {"RUSTC_WRAPPER": str(wrapper)}
        original = record(("cargo",), lambda name: str(self.binary),
                          environ=env)
        self.assertIn("override:RUSTC_WRAPPER", original["executables_sha256"])
        wrapper.write_bytes(b"#!/bin/sh\nexit 1\n")
        changed = record(("cargo",), lambda name: str(self.binary),
                         environ=env)
        self.assertEqual(original["executables_sha256"]["cargo"],
                         changed["executables_sha256"]["cargo"])
        self.assertEqual(original["build_environment_sha256"],
                         changed["build_environment_sha256"])
        self.assertNotEqual(original["executables_sha256"]["override:RUSTC_WRAPPER"],
                            changed["executables_sha256"]["override:RUSTC_WRAPPER"])

    def test_cargo_workspace_wrapper_and_rustdoc_binary_changes_are_pinned(self):
        # Cargo accepts build.* environment aliases independently of RUSTC_*.
        # A wrapper can be replaced in place without changing env or Git HEAD.
        key = "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER"
        rustdoc_key = "CARGO_BUILD_RUSTDOC"
        wrapper = Path(self.temporary.name) / "workspace-wrapper"
        wrapper.write_bytes(b"#!/bin/sh\nexit 0\n")
        wrapper.chmod(0o700)
        env = {key: str(wrapper), rustdoc_key: str(self.binary)}
        before = record(("cargo",), lambda name: str(self.binary), environ=env)
        self.assertIn("override:" + key, before["executables_sha256"])
        self.assertIn("override:" + rustdoc_key, before["executables_sha256"])
        wrapper.write_bytes(b"#!/bin/sh\nexit 1\n")
        after = record(("cargo",), lambda name: str(self.binary), environ=env)
        self.assertEqual(before["build_environment_sha256"],
                         after["build_environment_sha256"])
        self.assertNotEqual(before["executables_sha256"]["override:" + key],
                            after["executables_sha256"]["override:" + key])
        with self.assertRaisesRegex(ToolchainError, "ambiguous executable override"):
            record(("cargo",), lambda name: str(self.binary),
                   environ={rustdoc_key: "python3 dynamic-rustdoc.py"})

    def test_cargo_build_flags_and_rustc_bootstrap_change_environment_witness(self):
        # Cargo's build.* overrides and rustc bootstrap can affect artifacts.
        base = {"PATH": "/bin", "CARGO_BUILD_RUSTFLAGS": "-C opt-level=2"}
        changed = dict(base, CARGO_BUILD_RUSTFLAGS="-C opt-level=3")
        self.assertNotEqual(capture_environment(base)[1],
                            capture_environment(changed)[1])
        self.assertNotEqual(capture_environment(base)[1],
                            capture_environment(dict(base, RUSTC_BOOTSTRAP="1"))[1])
        self.assertIn("RUSTC_BOOTSTRAP",
                      capture_environment({"RUSTC_BOOTSTRAP": "1"})[0])
        self.assertIn("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
                      capture_environment({"CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER": "tool"})[0])

    def test_target_linker_is_pinned_and_ambiguous_commands_rejected(self):
        key = "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER"
        witness = record(("cargo",), lambda name: str(self.binary),
                         environ={key: str(self.binary)})
        self.assertIn("override:" + key, witness["executables_sha256"])
        with self.assertRaisesRegex(ToolchainError, "ambiguous executable override"):
            record(("cargo",), lambda name: str(self.binary),
                   environ={"RUSTC_WRAPPER": "ccache rustc"})
        # The required Cargo binary must resolve first. Otherwise this test
        # fails on the Cargo preflight and never exercises the override gate.
        with self.assertRaisesRegex(ToolchainError, "unresolved executable override: RUSTC_WRAPPER"):
            record(("cargo",),
                   lambda name: str(self.binary) if name == "cargo" else None,
                   environ={"RUSTC_WRAPPER": "missing-wrapper"})

    def test_missing_tool_fails(self):
        with self.assertRaises(ToolchainError):
            record(("cargo",), lambda name: None, environ={})

    def test_cargo_home_config_mutation_is_visible_to_signed_build(self):
        cargo_home = Path(self.temporary.name) / "cargo-home"
        cargo_home.mkdir()
        env = {"CARGO_HOME": str(cargo_home), "HOME": self.temporary.name}
        first = record(("cargo",), lambda name: str(self.binary), environ=env)
        self.assertEqual(first["cargo_home_config_sha256"],
                         {"cargo-home:config": "absent",
                          "cargo-home:config.toml": "absent"})
        config = cargo_home / "config.toml"
        config.write_text('[build]\nrustflags = ["--cfg", "trusted"]\n')
        changed = record(("cargo",), lambda name: str(self.binary), environ=env)
        self.assertNotEqual(first["cargo_home_config_sha256"],
                            changed["cargo_home_config_sha256"])
        self.assertEqual(first["build_environment_sha256"],
                         changed["build_environment_sha256"])
        config.write_text('[build]\nrustflags = ["--cfg", "modified"]\n')
        changed_again = record(("cargo",), lambda name: str(self.binary), environ=env)
        self.assertNotEqual(changed["cargo_home_config_sha256"],
                            changed_again["cargo_home_config_sha256"])
        config.unlink()
        self.assertEqual(first["cargo_home_config_sha256"],
                         cargo_home_config_fingerprints(env))

    def test_parent_cargo_configuration_is_fingerprinted_even_outside_git(self):
        outer = Path(self.temporary.name) / "outside-checkout"
        current = outer / "project" / "source"
        current.mkdir(parents=True)
        before = cargo_directory_config_fingerprints(current)
        self.assertEqual(before["cargo-parent:2:config.toml"], "absent")
        cargo_dir = outer / ".cargo"
        cargo_dir.mkdir()
        config = cargo_dir / "config.toml"
        config.write_text('[build]\nrustflags = ["--cfg", "outside"]\n')
        after = cargo_directory_config_fingerprints(current)
        self.assertNotEqual(before["cargo-parent:2:config.toml"],
                            after["cargo-parent:2:config.toml"])
        config.write_text('[build]\nrustflags = ["--cfg", "changed"]\n')
        again = cargo_directory_config_fingerprints(current)
        self.assertNotEqual(after["cargo-parent:2:config.toml"],
                            again["cargo-parent:2:config.toml"])
        with self.assertRaisesRegex(ToolchainError, "must be absolute"):
            cargo_directory_config_fingerprints(Path("relative-checkout"))

    def test_cargo_home_symlink_and_nonregular_config_rejected(self):
        cargo_home = Path(self.temporary.name) / "cargo-home"
        cargo_home.mkdir()
        config = cargo_home / "config"
        config.symlink_to(self.binary)
        with self.assertRaises(ToolchainError):
            cargo_home_config_fingerprints({"CARGO_HOME": str(cargo_home)})
        config.unlink()
        config.mkdir()
        with self.assertRaises(ToolchainError):
            cargo_home_config_fingerprints({"CARGO_HOME": str(cargo_home)})
        with self.assertRaisesRegex(ToolchainError, "must be absolute"):
            cargo_home_config_fingerprints({"CARGO_HOME": "./relative"})

    def test_self_test_runner_propagates_failures_and_errors(self):
        # A formerly used unittest.main(exit=False) discarded the failure
        # status and let GitHub Actions report a broken signing check as green.
        class Successful(unittest.TestCase):
            def test_pass(self):
                self.assertTrue(True)

        class Failing(unittest.TestCase):
            def test_failure(self):
                self.fail("intentional fixture failure")

        class Crashing(unittest.TestCase):
            def test_error(self):
                raise RuntimeError("intentional fixture error")

        for test_case, expected in ((Successful, 0), (Failing, 1), (Crashing, 1)):
            with self.subTest(test_case=test_case.__name__):
                self.assertEqual(run_self_tests(test_case, stream=io.StringIO()), expected)


def run_self_tests(test_case=ToolchainTests, stream=None):
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(test_case)
    outcome = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    return 0 if outcome.wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return run_self_tests()
    if args.record:
        try:
            print(json.dumps(record(xcrun=sdk_compiler, rust_binary=rust_toolchain_binary),
                             sort_keys=True, indent=2))
        except ToolchainError as error:
            print(str(error), file=sys.stderr)
            return 1
        return 0
    parser.error("specify --record or --self-test")


if __name__ == "__main__":
    sys.exit(main())
