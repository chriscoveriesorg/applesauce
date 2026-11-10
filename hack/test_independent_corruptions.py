"""Portable checks for the genuine-payload negative proof harness.

Mock identity decoders are only used here to prove the test harness fails
closed. The macOS workflows use pinned independent C11 decoders instead.
"""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from prove_independent_corruptions import check_corruptions


class NegativeProofTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.original = self.root / "source.bin"
        self.archive = self.root / "fixture.ascf"
        self.decoder = self.root / "mock_decoder"
        self.clear = b"independent negative proof fixture, generated only" * 20

    def make_fixture(self, codec):
        self.original.write_bytes(self.clear)
        header = bytearray(64)
        header[:8] = b"ASCF0001"
        code = {"lzmesh": 0xE05, "lzraven": 0xD05}[codec]
        struct.pack_into("<IIQI", header, 8, code, 65536, len(self.clear), 1)
        header[32:64] = hashlib.sha256(self.clear).digest()
        chunk = (
            struct.pack("<QII", 112, len(self.clear), len(self.clear))
            + hashlib.sha256(self.clear).digest()
        )
        self.archive.write_bytes(header + chunk + self.clear)
        if codec == "lzmesh":
            self.set_decoder(
                "import sys\n"
                "assert sys.argv[1:] == ['dec', 'e05']\n"
                "sys.stdout.buffer.write(sys.stdin.buffer.read())\n"
            )
        else:
            self.set_decoder(
                "from pathlib import Path\nimport sys\n"
                "assert sys.argv[1] == '--cap'\n"
                "assert int(sys.argv[2]) >= 1\n"
                "Path(sys.argv[4]).write_bytes(Path(sys.argv[3]).read_bytes())\n"
            )

    def set_decoder(self, code):
        self.decoder.write_text(
            "#!/usr/bin/env python3\n" + code, encoding="utf-8"
        )
        self.decoder.chmod(0o700)

    def test_mesh_detects_all_five_corruptions(self):
        self.make_fixture("lzmesh")
        result = check_corruptions(
            self.archive, self.original, self.decoder, codec="lzmesh"
        )
        self.assertEqual(result["case_count"], 5)
        self.assertEqual(
            {case["case"] for case in result["cases"]},
            {"payload_one_third", "payload_middle", "index_digest",
             "truncated_payload", "appended_payload"},
        )
        self.assertEqual(result["baseline_original_sha256"],
                         hashlib.sha256(self.clear).hexdigest())
        self.assertEqual(self.archive.read_bytes()[112:], self.clear)

    def test_raven_detects_all_five_corruptions(self):
        self.make_fixture("lzraven")
        result = check_corruptions(
            self.archive, self.original, self.decoder, codec="lzraven"
        )
        self.assertEqual(result["case_count"], 5)
        self.assertEqual(result["codec"], "lzraven")

    def test_never_passes_a_decoder_that_ignores_corrupted_payload(self):
        self.make_fixture("lzmesh")
        # This decoder always emits the good plaintext. Its baseline passes,
        # but altered payload bytes cannot be considered verified.
        self.set_decoder(
            "import sys\n"
            f"sys.stdout.buffer.write({self.clear!r})\n"
        )
        with self.assertRaisesRegex(AssertionError, "ACCEPTED corrupted"):
            check_corruptions(
                self.archive, self.original, self.decoder, codec="lzmesh"
            )

    def test_invalid_baseline_cannot_pass_corruption_suite(self):
        self.make_fixture("lzmesh")
        self.set_decoder("import sys\nsys.exit(17)\n")
        from verify_independent_lzmesh import InvalidArchive
        with self.assertRaisesRegex(InvalidArchive, "independent decoder failed"):
            check_corruptions(
                self.archive, self.original, self.decoder, codec="lzmesh"
            )


if __name__ == "__main__":
    unittest.main()
