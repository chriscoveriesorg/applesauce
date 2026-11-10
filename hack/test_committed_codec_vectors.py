"""Portable integrity checks for committed genuine Apple-generated ASCF vectors."""

import unittest

from prove_committed_vectors import FIXTURES, VECTORS, plaintext, run, validate_vector


class CommittedVectorTests(unittest.TestCase):
    def test_all_vectors_have_fixed_bytes_and_three_chunk_boundary(self):
        reports = run()["vectors"]
        self.assertEqual(len(reports), 4)
        self.assertEqual({r["chunk_count"] for r in reports}, {2, 3})
        self.assertTrue(all(r["status"] == "fixture_integrity_verified_only" for r in reports))

    def test_regenerated_plaintext_is_repeatable(self):
        self.assertEqual(len(plaintext(131103)), 131103)
        self.assertTrue(plaintext(65537).startswith(b'{"event":"agent"'))

    def test_corrupted_payload_is_rejected(self):
        codec, size = next(iter(VECTORS))
        data = bytearray((FIXTURES / f"{codec}-records-{size}.ascf").read_bytes())
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            validate_vector(codec, size, data)

    def test_truncated_vector_is_rejected(self):
        codec, size = next(iter(VECTORS))
        data = (FIXTURES / f"{codec}-records-{size}.ascf").read_bytes()[:-1]
        with self.assertRaises(ValueError):
            validate_vector(codec, size, data)

    def test_decoder_requires_explicit_codec(self):
        with self.assertRaisesRegex(ValueError, "requires --codec"):
            run(decoder="/does-not-exist")


if __name__ == "__main__":
    unittest.main()
