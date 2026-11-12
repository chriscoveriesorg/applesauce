#!/usr/bin/env python3
"""Portable regressions for the generated-only macOS signed-bundle probe."""
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("bundle-codesign-probe.py")
SPEC = importlib.util.spec_from_file_location("bundle_codesign_probe", SCRIPT)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def completed(output):
    return subprocess.CompletedProcess(["/usr/bin/xattr"], 0, stdout=output)


class SignedBundleProbeTests(unittest.TestCase):
    def test_xattr_snapshot_decodes_binary_hex(self):
        responses = [
            completed(b"com.apple.test\\ncom.apple.second\\n".replace(b"\\n", b"\n")),
            completed(b"00 ff 81\n"),
            completed(b"4142\n"),
        ]
        with patch.object(probe.subprocess, "run", side_effect=responses) as called:
            attrs = probe.xattrs(Path("/tmp/generated-fixture"))
        self.assertEqual(
            attrs, {"com.apple.test": b"\x00\xff\x81", "com.apple.second": b"AB"}
        )
        self.assertEqual(called.call_count, 3)
        self.assertEqual(
            called.call_args_list[1].args[0],
            ["/usr/bin/xattr", "-px", "com.apple.test", "/tmp/generated-fixture"],
        )
        self.assertTrue(all(call.kwargs["check"] for call in called.call_args_list))

    def test_unreadable_attribute_is_an_error(self):
        responses = [
            completed(b"com.apple.protected\n"),
            subprocess.CalledProcessError(1, ["/usr/bin/xattr", "-px"]),
        ]
        with patch.object(probe.subprocess, "run", side_effect=responses):
            with self.assertRaises(subprocess.CalledProcessError):
                probe.xattrs(Path("/tmp/generated-fixture"))

    def test_malformed_hex_is_an_error(self):
        with patch.object(
            probe.subprocess, "run",
            side_effect=[completed(b"com.apple.test\n"), completed(b"not-hex")],
        ):
            with self.assertRaises(ValueError):
                probe.xattrs(Path("/tmp/generated-fixture"))

    def test_duplicate_metadata_name_is_an_error(self):
        with patch.object(
            probe.subprocess, "run",
            side_effect=[
                completed(b"com.apple.same\ncom.apple.same\n"),
                completed(b"00"),
            ],
        ):
            with self.assertRaises(AssertionError):
                probe.xattrs(Path("/tmp/generated-fixture"))

    def test_mmap_digest_matches_original_bytes(self):
        payload = (b"\x00\xffABCD" * 16000) + b"end"
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "resource.dat"
            path.write_bytes(payload)
            self.assertEqual(probe.mmap_digest(path), hashlib.sha256(payload).hexdigest())
            path.write_bytes(payload + b"more")
            self.assertNotEqual(probe.mmap_digest(path), hashlib.sha256(payload).hexdigest())


    def test_readback_rejects_changed_kernel_and_mmap_contents(self):
        original = b"same-byte-proof" * 500
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "resource.bin"
            path.write_bytes(original)
            probe.verify_readback(path, original)
            path.write_bytes(original + b"corrupt")
            with self.assertRaisesRegex(AssertionError, "kernel readback changed"):
                probe.verify_readback(path, original)
            path.write_bytes(original)
            with patch.object(probe, "mmap_digest", return_value="0" * 64):
                with self.assertRaisesRegex(AssertionError, "mmap readback changed"):
                    probe.verify_readback(path, original)

    def test_sealed_path_mutation_fails_closed(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "CodeResources"
            path.write_bytes(b"sealed")
            with patch.object(probe, "xattrs", return_value={}):
                baseline = {path: (probe.digest(path), path.stat().st_mtime_ns, {})}
                probe.assert_sealed_paths_unchanged((path,), baseline)
                path.write_bytes(b"changed")
                with self.assertRaisesRegex(AssertionError, "seal changed"):
                    probe.assert_sealed_paths_unchanged((path,), baseline)

    def test_storage_report_requires_real_single_decmpfs_row(self):
        path = Path("/tmp/disposable.app/Contents/Resources/test.bin")
        def row(storage):
            return {
                "path": {"display": str(path)}, "entry_type": "file",
                "error": None, "source": "decmpfs", "codec": "zlib",
                "storage": storage, "decmpfs_type": 3 if storage == "inline_xattr" else 4,
                "decmpfs_xattr_bytes": 128 if storage == "inline_xattr" else 16,
                "resource_fork_bytes": 0 if storage == "inline_xattr" else 4096,
                "raw_compressed_bytes": 2048, "logical_size_bytes": 8192,
            }
        for storage in ("inline_xattr", "resource_fork"):
            with self.subTest(storage=storage):
                good_row = row(storage)
                report = {
                    "schema_version": 1, "report_kind": "actual_storage",
                    "complete": True, "paths": [good_row],
                }
                with patch.object(probe, "run", return_value=json.dumps(report)):
                    probe.require_report("/tmp/applesauce", path, "zlib", storage, 8192)
                bad_rows = [
                    {**good_row, "entry_type": "directory"},
                    {**good_row, "error": {"kind": "io_error"}},
                    {**good_row, "source": "none"},
                    {**good_row, "codec": "lzvn"},
                    {**good_row, "storage": "none"},
                    {**good_row, "decmpfs_type": 99},
                    {**good_row, "decmpfs_type": True},
                    {**good_row, "logical_size_bytes": 8191},
                    {**good_row, "decmpfs_xattr_bytes": 0},
                    {**good_row, "decmpfs_xattr_bytes": 15},
                    {**good_row, "resource_fork_bytes": -1},
                    {**good_row, "raw_compressed_bytes": 0},
                    {**good_row, "raw_compressed_bytes": None},
                    {**good_row, "path": {"display": "/wrong/path"}},
                ]
                if storage == "inline_xattr":
                    bad_rows.extend([
                        {**good_row, "decmpfs_xattr_bytes": 16},
                        {**good_row, "resource_fork_bytes": 1},
                    ])
                else:
                    bad_rows.extend([
                        {**good_row, "decmpfs_xattr_bytes": 20},
                        {**good_row, "resource_fork_bytes": 0},
                    ])
                invalid = [
                    {**report, "complete": False},
                    {**report, "schema_version": 2},
                    {**report, "report_kind": "projection"},
                    {**report, "paths": []},
                    {**report, "paths": [good_row, good_row]},
                    {**report, "paths": [good_row, row(storage)]},
                    *({**report, "paths": [bad]} for bad in bad_rows),
                ]
                for malformed in invalid:
                    with self.subTest(storage=storage, malformed=malformed):
                        with patch.object(probe, "run", return_value=json.dumps(malformed)):
                            with self.assertRaises(AssertionError):
                                probe.require_report(
                                    "/tmp/applesauce", path, "zlib", storage, 8192
                                )


    def test_restoration_requires_absent_decmpfs_metadata(self):
        path = Path("/tmp/Fixture.app/Contents/Resources/original.dat")
        clean = {
            "path": {"display": str(path)}, "entry_type": "file",
            "error": None, "source": "none", "codec": "none",
            "storage": None, "decmpfs_type": None,
            "decmpfs_xattr_bytes": 0, "resource_fork_bytes": 0,
            "logical_size_bytes": 4096,
        }
        report = {
            "schema_version": 1, "complete": True,
            "report_kind": "actual_storage", "paths": [clean],
        }
        with patch.object(probe, "run", return_value=json.dumps(report)):
            probe.require_restored_report("/tmp/applesauce", path, 4096)

        # A successful decompression exit code and matching logical bytes
        # must not conceal a residual decmpfs header or resource fork.
        bad_rows = [
            {**clean, "source": "decmpfs"},
            {**clean, "codec": "zlib"},
            {**clean, "storage": "resource_fork"},
            {**clean, "decmpfs_type": 4},
            {**clean, "decmpfs_xattr_bytes": 16},
            {**clean, "resource_fork_bytes": 128},
            {**clean, "logical_size_bytes": 4095},
            {**clean, "entry_type": "symlink"},
            {**clean, "error": {"kind": "io_error"}},
            {**clean, "path": {"display": "/tmp/other-app"}},
            {**clean, "decmpfs_xattr_bytes": False},
            {**clean, "resource_fork_bytes": False},
            {**clean, "logical_size_bytes": True},
            {**clean, "decmpfs_xattr_bytes": "0"},
            {**clean, "resource_fork_bytes": -1},
        ]
        bad_reports = [
            {**report, "complete": False},
            {**report, "schema_version": 2},
            {**report, "schema_version": True},
            {**report, "report_kind": "projection"},
            {**report, "paths": []},
            {**report, "paths": {}},
            {**report, "paths": [clean, clean]},
            {**report, "paths": [clean, {**clean, "path": {"display": "/tmp/another"}}]},
            *({**report, "paths": [bad]} for bad in bad_rows),
        ]
        for invalid in bad_reports:
            with self.subTest(invalid=invalid):
                with patch.object(probe, "run", return_value=json.dumps(invalid)):
                    with self.assertRaises(AssertionError):
                        probe.require_restored_report(
                            "/tmp/applesauce", path, 4096
                        )

    def test_signed_bundle_audit_prunes_executable_and_seal(self):
        app = Path("/tmp/Fixture.app")
        files = (
            app / "Contents" / "Resources" / "small.txt",
            app / "Contents" / "Resources" / "events.jsonl",
        )
        excluded = (
            app / "Contents" / "Info.plist",
            app / "Contents" / "MacOS",
            app / "Contents" / "_CodeSignature",
        )

        def row(path, selected, reason):
            return {
                "path": {"display": str(path)},
                "would_compress": selected, "reason": reason,
            }

        good = {
            "complete": True, "profile": "bundles", "full_encoding": True,
            "paths": [row(p, True, "compress") for p in files]
            + [row(p, False, "bundle_non_resource") for p in excluded],
        }
        probe.require_bundle_audit(good, app, files)
        invalid = [
            {**good, "complete": False},
            {**good, "profile": "caches"},
            {**good, "full_encoding": False},
            {**good, "paths": good["paths"][:-1]},
            {**good, "paths": good["paths"] + [good["paths"][0]]},
            {**good, "paths": good["paths"] + [
                row(app / "Contents" / "Frameworks" / "nested", True, "compress")
            ]},
            {**good, "paths": good["paths"] + [
                row(app.parent / "outside-file", True, "compress")
            ]},
            {**good, "paths": good["paths"] + [
                row(app / "Contents" / "Resources" / "extra.txt", 1, "compress")
            ]},
            {**good, "paths": good["paths"] + [
                {"path": {"display": None}, "would_compress": False}
            ]},
            {**good, "paths": good["paths"] + [
                row(excluded[1] / "applesauce-probe", False, "bundle_non_resource")
            ]},
            {**good, "paths": good["paths"] + [
                row(excluded[2] / "CodeResources", False, "bundle_non_resource")
            ]},
            {**good, "paths": good["paths"][:2]
                + [row(excluded[0], True, "compress")] + good["paths"][3:]},
        ]
        for malformed in invalid:
            with self.subTest(malformed=malformed):
                with self.assertRaises(AssertionError):
                    probe.require_bundle_audit(malformed, app, files)

    def test_executable_consumes_both_signed_resources_via_mmap(self):
        """The launch gate must detect same-length corruption in either resource."""
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler is required for portable executable acceptance")
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            app = root / "Fixture.app" / "Contents"
            binary = app / "MacOS" / "probe"
            resources = app / "Resources"
            binary.parent.mkdir(parents=True)
            resources.mkdir()
            small = resources / "small.txt"
            large = resources / "events.jsonl"
            small.write_bytes(b"A" * 2048)
            large.write_bytes(b'{"key":"value"}\n' * 5000)
            source = root / "probe.c"
            source.write_text(
                probe.resource_reader_source(small.read_bytes(), large.read_bytes())
            )
            subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                 "-o", str(binary), str(source)],
                check=True, capture_output=True, text=True,
            )
            passed = subprocess.run(
                [binary], capture_output=True, text=True, check=False,
            )
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertEqual(passed.stdout.strip(), "APPLESauce signed bundle fixture")
            for path in (small, large):
                with self.subTest(path=path.name):
                    original = path.read_bytes()
                    path.write_bytes(b"Z" + original[1:])
                    failed = subprocess.run(
                        [binary], capture_output=True, text=True, check=False,
                    )
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertIn("resource readback mismatch", failed.stderr)
                    path.write_bytes(original)
                    self.assertEqual(subprocess.run([binary]).returncode, 0)
            large.unlink()
            absent = subprocess.run(
                [binary], capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(absent.returncode, 0)
            self.assertIn("open resource", absent.stderr)


if __name__ == "__main__":
    unittest.main()
