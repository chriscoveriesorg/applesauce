"""Portable integrity checks for committed genuine Apple-generated ASCF vectors."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from prove_committed_vectors import (
    FIXTURES, VECTORS, load_committed_vector, plaintext, run, validate_vector,
)
from verify_independent_lzmesh import InvalidArchive


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

    def test_fixture_loader_rejects_oversized_local_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = Path(tmp) / "oversize.ascf"
            selected.write_bytes(b"A" * 128)
            with mock.patch("prove_committed_vectors.MAX_COMMITTED_ARCHIVE_BYTES", 64):
                with self.assertRaisesRegex(ValueError, "exceeds bounded fixture size"):
                    load_committed_vector(selected)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFOs")
    def test_fixture_loader_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = Path(tmp) / "untrusted.fifo"
            os.mkfifo(selected)
            with self.assertRaisesRegex(InvalidArchive, "regular file"):
                load_committed_vector(selected)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires POSIX symlinks")
    def test_fixture_loader_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "original.ascf"
            original.write_bytes(b"ASCF0001")
            selected = Path(tmp) / "link.ascf"
            selected.symlink_to(original)
            with self.assertRaises((InvalidArchive, OSError)):
                load_committed_vector(selected)

    def test_fixture_loader_preserves_exact_vector_bytes(self):
        codec, size = next(iter(VECTORS))
        selected = FIXTURES / f"{codec}-records-{size}.ascf"
        self.assertEqual(load_committed_vector(selected), selected.read_bytes())



if __name__ == "__main__":
    unittest.main()
