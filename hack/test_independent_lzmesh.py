"""Portable synthetic ASCF parser/provenance tests.

Identity decoder mocks only parser behavior; it is not LZMESH conformance.
Real acceptance requires an independently compiled decoder on macOS 27+.
"""

import hashlib
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest import mock

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



    def test_mesh_decoder_allocation_uses_validated_clear_length(self):
        # port_cli's default output allocation follows the compressed framing.
        # A validated ASCF chunk length must override hostile inherited caps.
        self.decoder.write_text(
            "#!/usr/bin/env python3\n"
            "import os,sys\n"
            "payload = sys.stdin.buffer.read()\n"
            "if os.environ.get('DECODE_SIZE') != str(len(payload)):\n"
            "    sys.exit(42)\n"
            "sys.stdout.buffer.write(payload)\n",
            encoding="utf-8",
        )
        for inherited in ("0", "1", "999999999999999"):
            with self.subTest(inherited=inherited):
                with mock.patch.dict(os.environ, {"DECODE_SIZE": inherited}):
                    report = verify(self.archive, self.original, self.decoder)
                self.assertEqual(report["status"], "independent_lzmesh_buffer_decode_verified")

    def test_mesh_decoder_receives_clear_len_not_stored_len(self):
        # Compressed bytes need not have the same length as the plaintext.
        data = bytearray(self.archive.read_bytes())
        data.extend(b"PAD")
        struct.pack_into("<I", data, 72, len(self.plaintext) + 3)
        self.archive.write_bytes(data)
        self.decoder.write_text(
            "#!/usr/bin/env python3\n"
            "import os,sys\n"
            "payload = sys.stdin.buffer.read()\n"
            "if os.environ.get('DECODE_SIZE') != str(len(payload) - 3):\n"
            "    sys.exit(43)\n"
            "sys.stdout.buffer.write(payload[:-3])\n",
            encoding="utf-8",
        )
        report = verify(self.archive, self.original, self.decoder)
        self.assertEqual(report["chunk_count"], 1)

    def test_decoder_output_is_bounded_before_comparison(self):
        self.decoder.write_text(
            "#!/usr/bin/env python3\nimport sys\n"
            "sys.stdout.buffer.write(b'X' * (1024 * 1024))\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(InvalidArchive, "independent decoder failed"):
            verify(self.archive, self.original, self.decoder)

    def test_reaps_decoder_descendants_after_success(self):
        # A successful decoder can still leave a helper process running.
        # The proof runner must terminate the entire process group.
        leaked = self.root / "orphaned-mesh-helper"
        child = (
            "import pathlib,time; time.sleep(1.0); "
            f"pathlib.Path({str(leaked)!r}).write_text('leaked')"
        )
        self.decoder.write_text(
            "#!/usr/bin/env python3\n"
            "import subprocess,sys\n"
            f"subprocess.Popen([sys.executable, '-c', {child!r}], "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
            "stderr=subprocess.DEVNULL)\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        self.assertEqual(
            verify(self.archive, self.original, self.decoder)["chunk_count"], 1
        )
        time.sleep(1.3)
        self.assertFalse(leaked.exists(), "decoder helper escaped cleanup")

    def test_rejects_original_modified_during_decode(self):
        self.decoder.write_text(
            "#!/usr/bin/env python3\nimport os, pathlib, sys, time\n"
            f"p = pathlib.Path({str(self.original)!r})\n"
            "time.sleep(0.02)\n"
            "old = p.stat()\n"
            "with p.open('r+b') as f: f.write(b'Z')\n"
            "os.utime(p, ns=(old.st_atime_ns, old.st_mtime_ns))\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(InvalidArchive, "proof input changed"):
            verify(self.archive, self.original, self.decoder)

    def test_rejects_archive_replaced_during_decode(self):
        replacement = self.root / "replacement.ascf"
        replacement.write_bytes(self.archive.read_bytes())
        self.decoder.write_text(
            "#!/usr/bin/env python3\nimport os, sys\n"
            f"os.replace({str(replacement)!r}, {str(self.archive)!r})\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(InvalidArchive, "proof input changed"):
            verify(self.archive, self.original, self.decoder)

    def test_rejects_decoder_changed_during_decode(self):
        self.decoder.write_text(
            "#!/usr/bin/env python3\nimport sys\n"
            "with open(sys.argv[0], 'a') as f: f.write('\\\n# changed\\\n')\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(InvalidArchive, "decoder"):
            verify(self.archive, self.original, self.decoder)

    @unittest.skipUnless(hasattr(__import__('os'), 'mkfifo'), "requires POSIX FIFOs")
    def test_rejects_fifo_inputs_without_blocking(self):
        import os
        fifo = self.root / "untrusted.fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(InvalidArchive, "regular file"):
            verify(fifo, self.original, self.decoder)
        with self.assertRaisesRegex(InvalidArchive, "regular file"):
            verify(self.archive, fifo, self.decoder)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires POSIX symlinks")
    def test_rejects_leaf_symlink_inputs(self):
        for field in ("archive", "original", "decoder"):
            with self.subTest(field=field):
                alias = self.root / f"{field}.link"
                alias.symlink_to(getattr(self, field))
                paths = {
                    "archive": self.archive,
                    "original": self.original,
                    "decoder": self.decoder,
                }
                paths[field] = alias
                with self.assertRaises((OSError, InvalidArchive)):
                    verify(**paths)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires POSIX symlinks")
    def test_rejects_original_symlink_to_same_open_inode_during_decode(self):
        # This used to pass: stat() follows the link to the still-open
        # original inode, preserving every value in the identity tuple.
        retained = self.root / "retained-original.bin"
        self.decoder.write_text(
            "#!/usr/bin/env python3\n"
            "import os,sys\n"
            f"source={str(self.original)!r}\n"
            f"retained={str(retained)!r}\n"
            "os.replace(source, retained)\n"
            "os.symlink(retained, source)\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(InvalidArchive, "proof input changed"):
            verify(self.archive, self.original, self.decoder)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires POSIX symlinks")
    def test_rejects_archive_symlink_to_same_open_inode_during_decode(self):
        retained = self.root / "retained-archive.ascf"
        self.decoder.write_text(
            "#!/usr/bin/env python3\n"
            "import os,sys\n"
            f"archive={str(self.archive)!r}\n"
            f"retained={str(retained)!r}\n"
            "os.replace(archive, retained)\n"
            "os.symlink(retained, archive)\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(InvalidArchive, "proof input changed"):
            verify(self.archive, self.original, self.decoder)

if __name__ == "__main__":
    unittest.main()
