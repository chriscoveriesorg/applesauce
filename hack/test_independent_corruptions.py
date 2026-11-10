"""Portable checks for the genuine-payload negative proof harness.

Mock identity decoders are only used here to prove the test harness fails
closed. The macOS workflows use pinned independent C11 decoders instead.
"""

import hashlib
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from prove_independent_corruptions import check_corruptions
from verify_independent_lzmesh import InvalidArchive


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


    def test_rejects_archive_replaced_after_successful_baseline(self):
        # A byte-identical replacement cannot inherit the original proof.
        self.make_fixture("lzmesh")
        replacement = self.root / "replacement.ascf"
        replacement.write_bytes(self.archive.read_bytes())
        from prove_independent_corruptions import verify as real_verify

        def replace_after_baseline(*args, **kwargs):
            result = real_verify(*args, **kwargs)
            os.replace(replacement, self.archive)
            return result

        with mock.patch("prove_independent_corruptions.verify",
                        side_effect=replace_after_baseline):
            with self.assertRaisesRegex(
                InvalidArchive, "proof input changed during decode"
            ):
                check_corruptions(
                    self.archive, self.original, self.decoder, codec="lzmesh"
                )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_rejects_fifo_swapped_into_archive_after_baseline(self):
        # The previous read_bytes() path could hang indefinitely here.
        self.make_fixture("lzmesh")
        from prove_independent_corruptions import verify as real_verify

        def replace_after_baseline(*args, **kwargs):
            result = real_verify(*args, **kwargs)
            self.archive.unlink()
            os.mkfifo(self.archive)
            return result

        with mock.patch("prove_independent_corruptions.verify",
                        side_effect=replace_after_baseline):
            with self.assertRaisesRegex(
                InvalidArchive, "proof input changed during decode"
            ):
                check_corruptions(
                    self.archive, self.original, self.decoder, codec="lzmesh"
                )

    def test_rejects_oversize_archive_before_baseline(self):
        self.make_fixture("lzmesh")
        with mock.patch("prove_independent_corruptions.MAX_ARCHIVE_BYTES",
                        self.archive.stat().st_size - 1):
            with self.assertRaisesRegex(
                InvalidArchive, "archive exceeds fixture budget"
            ):
                check_corruptions(
                    self.archive, self.original, self.decoder, codec="lzmesh"
                )

    def test_rejects_archive_growth_during_baseline(self):
        self.make_fixture("lzmesh")
        initial_size = self.archive.stat().st_size
        from prove_independent_corruptions import verify as real_verify

        def grow_after_baseline(*args, **kwargs):
            result = real_verify(*args, **kwargs)
            with self.archive.open("ab") as source:
                source.write(b"!" * 64)
            return result

        with mock.patch("prove_independent_corruptions.MAX_ARCHIVE_BYTES",
                        initial_size + 16):
            with mock.patch("prove_independent_corruptions.verify",
                            side_effect=grow_after_baseline):
                with self.assertRaisesRegex(
                    InvalidArchive, "grew beyond fixture budget"
                ):
                    check_corruptions(
                        self.archive, self.original, self.decoder, codec="lzmesh"
                    )


if __name__ == "__main__":
    unittest.main()
