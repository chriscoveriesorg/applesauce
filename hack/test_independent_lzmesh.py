"""Portable synthetic ASCF parser/provenance tests.

Identity decoder mocks only parser behavior; it is not LZMESH conformance.
Real acceptance requires an independently compiled decoder on macOS 27+.
"""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from verify_independent_lzmesh import InvalidArchive, verify


class IndependentMeshProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "fixture.ascf"
        self.original = self.root / "fixture.bin"
        self.decoder = self.root / "mock_identity_decoder"
        self.decoder.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if sys.argv[1:] != ['dec', 'e05']: sys.exit(19)\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        self.decoder.chmod(0o700)
        self.plaintext = b"synthetic chunk bytes for index and hash testing"
        self.write_archive(self.plaintext)

    def write_archive(self, clear):
        self.original.write_bytes(clear)
        header = bytearray(64)
        header[:8] = b"ASCF0001"
        struct.pack_into("<IIQI", header, 8, 0xE05, 65536, len(clear), 1)
        header[32:64] = hashlib.sha256(clear).digest()
        entry = struct.pack("<QII", 112, len(clear), len(clear)) + hashlib.sha256(clear).digest()
        self.archive.write_bytes(header + entry + clear)

    def test_accepts_synthetic_index_and_original_hash(self):
        report = verify(self.archive, self.original, self.decoder)
        self.assertEqual(report["chunk_count"], 1)
        self.assertEqual(report["codec_id"], "0xE05")
        self.assertEqual(report["original_sha256"], hashlib.sha256(self.plaintext).hexdigest())

    def test_rejects_corrupted_payload(self):
        data = bytearray(self.archive.read_bytes())
        data[-1] ^= 0x80
        self.archive.write_bytes(data)
        with self.assertRaisesRegex(InvalidArchive, "incorrect bytes/length"):
            verify(self.archive, self.original, self.decoder)

    def test_rejects_trailing_bytes_and_changed_offsets(self):
        self.archive.write_bytes(self.archive.read_bytes() + b"extra")
        with self.assertRaisesRegex(InvalidArchive, "trailing"):
            verify(self.archive, self.original, self.decoder)
        self.write_archive(self.plaintext)
        data = bytearray(self.archive.read_bytes())
        struct.pack_into("<Q", data, 64, 113)
        self.archive.write_bytes(data)
        with self.assertRaisesRegex(InvalidArchive, "geometry"):
            verify(self.archive, self.original, self.decoder)

    def test_rejects_wrong_codec_and_short_header(self):
        data = bytearray(self.archive.read_bytes())
        struct.pack_into("<I", data, 8, 0xD05)
        self.archive.write_bytes(data)
        with self.assertRaisesRegex(InvalidArchive, "only accepts LZMESH"):
            verify(self.archive, self.original, self.decoder)
        self.archive.write_bytes(b"ASCF0001")
        with self.assertRaisesRegex(InvalidArchive, "truncated"):
            verify(self.archive, self.original, self.decoder)

    def test_rejects_mutated_original_and_short_decode(self):
        self.original.write_bytes(b"modified" + self.plaintext[8:])
        with self.assertRaisesRegex(InvalidArchive, "original chunk"):
            verify(self.archive, self.original, self.decoder)
        self.original.write_bytes(self.plaintext)
        self.decoder.write_text(
            "#!/usr/bin/env python3\nimport sys\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read()[:-1])\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(InvalidArchive, "incorrect bytes/length"):
            verify(self.archive, self.original, self.decoder)

    def test_rejects_fixture_over_budget(self):
        with self.assertRaisesRegex(InvalidArchive, "bounded fixture budget"):
            verify(self.archive, self.original, self.decoder, max_logical_bytes=10)


if __name__ == "__main__":
    unittest.main()
