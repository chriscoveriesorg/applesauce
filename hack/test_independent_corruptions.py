"""Portable checks for the genuine-payload negative proof harness.

Mock identity decoders are only used here to prove the test harness fails
closed. The macOS workflows use pinned independent C11 decoders instead.
"""

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
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

    def make_fixture(self, codec, *, multi_chunk=False):
        if multi_chunk:
            # A genuine three-chunk ASCF geometry including a short tail.
            self.clear = (self.clear * (131103 // len(self.clear) + 1))[:131103]
        self.original.write_bytes(self.clear)
        header = bytearray(64)
        header[:8] = b"ASCF0001"
        code = {"lzmesh": 0xE05, "lzraven": 0xD05}[codec]
        parts = [self.clear[i:i + 65536] for i in range(0, len(self.clear), 65536)]
        struct.pack_into("<IIQI", header, 8, code, 65536, len(self.clear), len(parts))
        header[32:64] = hashlib.sha256(self.clear).digest()
        offset = 64 + 48 * len(parts)
        entries = []
        for part in parts:
            entries.append(
                struct.pack("<QII", offset, len(part), len(part))
                + hashlib.sha256(part).digest()
            )
            offset += len(part)
        self.archive.write_bytes(header + b"".join(entries) + self.clear)
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

    def test_mesh_rejects_corruption_in_final_chunk(self):
        self.make_fixture("lzmesh", multi_chunk=True)
        result = check_corruptions(
            self.archive, self.original, self.decoder, codec="lzmesh"
        )
        self.assertEqual(result["case_count"], 7)
        self.assertEqual(
            {case["case"] for case in result["cases"]},
            {"payload_one_third", "payload_middle", "index_digest",
             "truncated_payload", "appended_payload",
             "payload_final_chunk", "final_index_digest"},
        )
        self.assertEqual(self.archive.read_bytes()[208:], self.clear)

    def test_raven_rejects_corruption_in_final_chunk(self):
        self.make_fixture("lzraven", multi_chunk=True)
        result = check_corruptions(
            self.archive, self.original, self.decoder, codec="lzraven"
        )
        self.assertEqual(result["case_count"], 7)
        self.assertEqual(result["codec"], "lzraven")

    def test_final_payload_corruption_rejects_wrong_chunk_error(self):
        self.make_fixture("lzmesh", multi_chunk=True)
        from prove_independent_corruptions import verify as real_verify

        calls = 0

        def fail_wrong_chunk(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 7:
                raise InvalidArchive("independent decoder failed on chunk 0 (exit 1)")
            return real_verify(*args, **kwargs)

        with mock.patch("prove_independent_corruptions.verify",
                        side_effect=fail_wrong_chunk):
            with self.assertRaisesRegex(
                AssertionError, "payload_final_chunk failed outside decoder result gate"
            ):
                check_corruptions(
                    self.archive, self.original, self.decoder, codec="lzmesh"
                )
        self.assertEqual(calls, 7)

    def test_final_digest_corruption_rejects_wrong_parser_gate(self):
        self.make_fixture("lzmesh", multi_chunk=True)
        from prove_independent_corruptions import verify as real_verify

        calls = 0

        def fail_wrong_gate(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 8:
                raise InvalidArchive("original chunk 0 differs from ASCF chunk digest")
            return real_verify(*args, **kwargs)

        with mock.patch("prove_independent_corruptions.verify",
                        side_effect=fail_wrong_gate):
            with self.assertRaisesRegex(
                AssertionError, "final_index_digest failed outside expected parser gate"
            ):
                check_corruptions(
                    self.archive, self.original, self.decoder, codec="lzmesh"
                )
        self.assertEqual(calls, 8)

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


    def test_rejects_invalid_negative_suite_budget(self):
        self.make_fixture("lzmesh")
        for invalid in (0, -1, float("nan"), 3601):
            with self.subTest(value=invalid):
                with self.assertRaisesRegex(InvalidArchive, "negative suite time budget"):
                    check_corruptions(
                        self.archive, self.original, self.decoder,
                        codec="lzmesh", total_timeout_seconds=invalid,
                    )

    def test_decoder_timeout_never_qualifies_as_corruption_rejection(self):
        self.make_fixture("lzmesh")
        from prove_independent_corruptions import verify as real_verify

        calls = 0

        def timeout_on_corruption(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_verify(*args, **kwargs)
            raise InvalidArchive("independent decoder timed out on chunk 0")

        with mock.patch("prove_independent_corruptions.verify",
                        side_effect=timeout_on_corruption):
            with self.assertRaisesRegex(
                InvalidArchive, "decoder timeout cannot qualify"
            ):
                check_corruptions(
                    self.archive, self.original, self.decoder, codec="lzmesh"
                )
        self.assertEqual(calls, 2)

    def test_negative_suite_passes_only_remaining_decoder_budget(self):
        self.make_fixture("lzmesh")
        from prove_independent_corruptions import verify as real_verify

        now = [100.0]
        seen = []

        def paced_verify(*args, **kwargs):
            seen.append(kwargs["total_timeout_seconds"])
            result = real_verify(*args, **kwargs)
            if len(seen) == 1:
                now[0] = 115.0
            return result

        clock = SimpleNamespace(monotonic=lambda: now[0])
        with mock.patch("prove_independent_corruptions.time", clock):
            with mock.patch("prove_independent_corruptions.verify",
                            side_effect=paced_verify):
                result = check_corruptions(
                    self.archive, self.original, self.decoder,
                    codec="lzmesh", total_timeout_seconds=20,
                )
        self.assertEqual(result["case_count"], 5)
        self.assertEqual(result["suite_timeout_seconds"], 20)
        self.assertEqual(len(seen), 6)
        self.assertEqual(seen[0], 20)
        self.assertTrue(all(value == 5 for value in seen[1:]))

    def test_deadline_exhaustion_during_last_negative_check_fails_suite(self):
        self.make_fixture("lzmesh")
        from prove_independent_corruptions import verify as real_verify

        now = [100.0]
        calls = 0

        def expire_on_last_check(*args, **kwargs):
            nonlocal calls
            calls += 1
            try:
                return real_verify(*args, **kwargs)
            finally:
                if calls == 6:
                    now[0] = 300.0

        clock = SimpleNamespace(monotonic=lambda: now[0])
        with mock.patch("prove_independent_corruptions.time", clock):
            with mock.patch("prove_independent_corruptions.verify",
                            side_effect=expire_on_last_check):
                with self.assertRaisesRegex(
                    InvalidArchive, "negative proof suite exceeded total time budget"
                ):
                    check_corruptions(
                        self.archive, self.original, self.decoder,
                        codec="lzmesh", total_timeout_seconds=180,
                    )
        self.assertEqual(calls, 6)

    def test_parser_corruption_must_fail_its_intended_gate(self):
        self.make_fixture("lzmesh")
        from prove_independent_corruptions import verify as real_verify

        calls = 0

        def fail_wrong_gate(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 4:  # Baseline, two payload flips, index digest.
                raise InvalidArchive("unrelated failure")
            return real_verify(*args, **kwargs)

        with mock.patch("prove_independent_corruptions.verify",
                        side_effect=fail_wrong_gate):
            with self.assertRaisesRegex(
                AssertionError, "index_digest failed outside expected parser gate"
            ):
                check_corruptions(
                    self.archive, self.original, self.decoder, codec="lzmesh"
                )
        self.assertEqual(calls, 4)


    def test_payload_case_rejects_unrelated_decoder_provenance_failure(self):
        self.make_fixture("lzmesh")
        from prove_independent_corruptions import verify as real_verify

        calls = 0

        def unrelated_failure(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_verify(*args, **kwargs)
            raise InvalidArchive("independent decoder binary changed during proof")

        with mock.patch("prove_independent_corruptions.verify",
                        side_effect=unrelated_failure):
            with self.assertRaisesRegex(
                AssertionError, "payload_one_third failed outside decoder result gate"
            ):
                check_corruptions(
                    self.archive, self.original, self.decoder, codec="lzmesh"
                )
        self.assertEqual(calls, 2)

    def test_decoder_rewrite_after_negative_cases_invalidates_proof(self):
        self.make_fixture("lzmesh")
        from prove_independent_corruptions import verify as real_verify

        calls = 0

        def change_decoder_on_final_case(*args, **kwargs):
            nonlocal calls
            calls += 1
            try:
                return real_verify(*args, **kwargs)
            finally:
                if calls == 6:
                    with self.decoder.open("a", encoding="utf-8") as stream:
                        stream.write("\n# decoder changed after baseline\n")

        with mock.patch("prove_independent_corruptions.verify",
                        side_effect=change_decoder_on_final_case):
            with self.assertRaisesRegex(InvalidArchive, "proof input changed"):
                check_corruptions(
                    self.archive, self.original, self.decoder, codec="lzmesh"
                )
        self.assertEqual(calls, 6)

    def test_original_rewrite_after_negative_cases_invalidates_proof(self):
        self.make_fixture("lzmesh")
        from prove_independent_corruptions import verify as real_verify

        calls = 0

        def change_original_on_final_case(*args, **kwargs):
            nonlocal calls
            calls += 1
            try:
                return real_verify(*args, **kwargs)
            finally:
                if calls == 6:
                    with self.original.open("ab") as stream:
                        stream.write(b"unexpected mutation")

        with mock.patch("prove_independent_corruptions.verify",
                        side_effect=change_original_on_final_case):
            with self.assertRaisesRegex(InvalidArchive, "proof input changed"):
                check_corruptions(
                    self.archive, self.original, self.decoder, codec="lzmesh"
                )
        self.assertEqual(calls, 6)


if __name__ == "__main__":
    unittest.main()
