"""Synthetic LZRAVEN ASCF proof-harness tests, not codec conformance.

Genuine LZRAVEN proof is the independent macOS 27 CI job using liblzraven.
"""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from verify_independent_lzmesh import InvalidArchive, verify


class IndependentRavenProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "fixture.ascf"
        self.original = self.root / "fixture.bin"
        self.decoder = self.root / "mock_raven_decoder"
        self.clear = b"generated synthetic plaintext for ASCF parser tests" * 7
        self.set_decoder(
            "import pathlib,sys\n"
            "assert sys.argv[1] == '--cap'\n"
            "assert int(sys.argv[2]) > 0\n"
            "pathlib.Path(sys.argv[4]).write_bytes(pathlib.Path(sys.argv[3]).read_bytes())\n"
        )
        self.write_archive(self.clear)

    def set_decoder(self, code):
        self.decoder.write_text("#!/usr/bin/env python3\n" + code, encoding="utf-8")
        self.decoder.chmod(0o700)

    def write_archive(self, clear):
        self.original.write_bytes(clear)
        header = bytearray(64)
        header[:8] = b"ASCF0001"
        struct.pack_into("<IIQI", header, 8, 0xD05, 65536, len(clear), 1)
        header[32:64] = hashlib.sha256(clear).digest()
        entry = (
            struct.pack("<QII", 112, len(clear), len(clear))
            + hashlib.sha256(clear).digest()
        )
        self.archive.write_bytes(header + entry + clear)

    def proof(self):
        return verify(self.archive, self.original, self.decoder, codec="lzraven")

    def test_accepts_raven_fixture_and_report(self):
        report = self.proof()
        self.assertEqual(report["codec"], "lzraven")
        self.assertEqual(report["codec_id"], "0xD05")
        self.assertEqual(report["status"], "independent_lzraven_buffer_decode_verified")
        self.assertEqual(report["original_sha256"], hashlib.sha256(self.clear).hexdigest())

    def test_rejects_wrong_codec_and_unknown_name(self):
        with self.assertRaisesRegex(InvalidArchive, "only accepts LZMESH"):
            verify(self.archive, self.original, self.decoder)
        with self.assertRaisesRegex(InvalidArchive, "unsupported independent codec"):
            verify(self.archive, self.original, self.decoder, codec="other")

    def test_rejects_changed_payload(self):
        data = bytearray(self.archive.read_bytes())
        data[-1] ^= 0x20
        self.archive.write_bytes(data)
        with self.assertRaisesRegex(InvalidArchive, "incorrect bytes/length"):
            self.proof()

    def test_rejects_wrong_output_length(self):
        self.set_decoder(
            "import pathlib,sys\n"
            "p=pathlib.Path(sys.argv[3]).read_bytes()\n"
            "pathlib.Path(sys.argv[4]).write_bytes(p[:-1])\n"
        )
        with self.assertRaisesRegex(InvalidArchive, "incorrect bytes/length"):
            self.proof()

    def test_rejects_excess_output_before_comparison(self):
        self.set_decoder(
            "import pathlib,sys\n"
            "pathlib.Path(sys.argv[4]).write_bytes(b'A' * (1024 * 1024))\n"
        )
        with self.assertRaisesRegex(InvalidArchive, "independent decoder failed"):
            self.proof()

    def test_rejects_missing_output_file(self):
        self.set_decoder("import sys\nsys.exit(0)\n")
        with self.assertRaisesRegex(InvalidArchive, "omitted chunk"):
            self.proof()

    def test_rejects_mutated_original_during_decode(self):
        self.set_decoder(
            "import os,pathlib,sys\n"
            f"p=pathlib.Path({str(self.original)!r})\n"
            "info=p.stat()\n"
            "with p.open('r+b') as f: f.write(b'!')\n"
            "os.utime(p, ns=(info.st_atime_ns, info.st_mtime_ns))\n"
            "pathlib.Path(sys.argv[4]).write_bytes(pathlib.Path(sys.argv[3]).read_bytes())\n"
        )
        with self.assertRaisesRegex(InvalidArchive, "proof input changed"):
            self.proof()


if __name__ == "__main__":
    unittest.main()
