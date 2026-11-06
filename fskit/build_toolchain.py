#!/usr/bin/env python3
"""Capture exact build executables and compiler-affecting environment.

This is a provenance witness for a disposable signed FSKit build. Values of
inherited build flags are hashed so portable bundles do not expose local paths.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

TOOLS = ("cargo", "rustc", "xcodegen", "xcodebuild", "xcrun", "git", "python3")
EXACT_ENV = frozenset((
    "PATH", "DEVELOPER_DIR", "SDKROOT", "TOOLCHAINS",
    "RUSTUP_TOOLCHAIN", "RUSTUP_HOME", "CARGO_HOME", "CARGO_TARGET_DIR",
    "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTDOCFLAGS",
    "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET", "SWIFTFLAGS", "OTHER_SWIFT_FLAGS",
    "CC", "CXX", "CFLAGS", "CXXFLAGS", "LDFLAGS",
    "MACOSX_DEPLOYMENT_TARGET", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH", "LIBRARY_PATH", "DYLD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES", "PKG_CONFIG_PATH",
))
ENV_PREFIXES = ("CARGO_TARGET_", "CARGO_PROFILE_", "CARGO_ENCODED_", "RUSTFLAGS_")


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


def capture_environment(environ=None):
    environ = os.environ if environ is None else environ
    selected = {key: value for key, value in environ.items()
                if key in EXACT_ENV or key.startswith(ENV_PREFIXES)}
    serialized = json.dumps(selected, sort_keys=True, ensure_ascii=True,
                            separators=(",", ":")).encode("utf-8")
    return sorted(selected), hashlib.sha256(serialized).hexdigest()


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
    env_keys, env_sha = capture_environment(environ)
    return {
        "schema": "ascf-build-toolchain-v1",
        "executables_sha256": dict(sorted(tool_hashes.items())),
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

    def test_missing_tool_fails(self):
        with self.assertRaises(ToolchainError):
            record(("cargo",), lambda name: None, environ={})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[sys.argv[0]], exit=False)
    elif args.record:
        try:
            print(json.dumps(record(xcrun=sdk_compiler, rust_binary=rust_toolchain_binary), sort_keys=True, indent=2))
        except ToolchainError as error:
            sys.exit(str(error))
    else:
        parser.error("specify --record or --self-test")


if __name__ == "__main__":
    main()
