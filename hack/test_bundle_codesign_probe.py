#!/usr/bin/env python3
"""Portable regressions for the generated-only macOS signed-bundle probe."""
import hashlib
import importlib.util
import json
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
        good_row = {
            "path": {"display": str(path)}, "codec": "zlib",
            "storage": "resource_fork", "source": "decmpfs",
        }
        report = {"complete": True, "paths": [good_row]}
        with patch.object(probe, "run", return_value=json.dumps(report)):
            probe.require_report("/tmp/applesauce", path, "zlib", "resource_fork")
        failures = [
            {"complete": False, "paths": [good_row]},
            {"complete": True, "paths": []},
            {"complete": True, "paths": [good_row, good_row]},
            {"complete": True, "paths": [{**good_row, "source": "none"}]},
            {"complete": True, "paths": [{**good_row, "codec": "lzvn"}]},
            {"complete": True, "paths": [{**good_row, "storage": "inline_xattr"}]},
        ]
        for invalid in failures:
            with self.subTest(invalid=invalid):
                with patch.object(probe, "run", return_value=json.dumps(invalid)):
                    with self.assertRaises(AssertionError):
                        probe.require_report(
                            "/tmp/applesauce", path, "zlib", "resource_fork"
                        )


if __name__ == "__main__":
    unittest.main()
