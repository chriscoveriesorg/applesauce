#!/usr/bin/env python3
"""Portable regressions for the generated-only macOS signed-bundle probe."""
import hashlib
import importlib.util
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


if __name__ == "__main__":
    unittest.main()
