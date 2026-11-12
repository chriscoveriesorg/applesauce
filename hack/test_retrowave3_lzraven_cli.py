"""Portable safety tests for the second LZRAVEN decoder's CLI adapter.

The stub is deliberately an identity function. These tests verify I/O safety,
not LZRAVEN interoperability; pinned C11 source and Apple vectors must be
qualified separately before this candidate can be accepted.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class DecoderAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shutil.which("cc")
        if not cls.compiler:
            raise unittest.SkipTest("C compiler is unavailable")
        cls.build = tempfile.TemporaryDirectory(prefix="raven-adapter-build-")
        root = Path(cls.build.name)
        (root / "lzraven.h").write_text(
            "#include <stddef.h>\n"
            "size_t lzraven_decode_buffer(void *, size_t, const void *, size_t);\n"
        )
        (root / "stub.c").write_text(
            "#include <stddef.h>\n#include <string.h>\n"
            "size_t lzraven_decode_buffer(void *out, size_t capacity, "
            "const void *in, size_t length) {\n"
            "  size_t count = length < capacity ? length : capacity;\n"
            "  memcpy(out, in, count); return count;\n}\n"
        )
        cls.binary = root / "raven-alt"
        subprocess.run(
            [cls.compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
             "-I", str(root), str(HERE / "retrowave3_lzraven_decode.c"),
             str(root / "stub.c"), "-o", str(cls.binary)],
            check=True, capture_output=True, text=True,
        )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "build"):
            cls.build.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="raven-adapter-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "compressed.bin"
        self.output = self.root / "decoded.bin"

    def run_decoder(self, capacity, data=b"hello", *, source=None):
        if source is None:
            self.input.write_bytes(data)
            source = self.input
        return subprocess.run(
            [str(self.binary), "--cap", str(capacity), str(source), str(self.output)],
            capture_output=True, timeout=3,
        )

    def test_exact_size_passes(self):
        result = self.run_decoder(5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_bytes(), b"hello")

    def test_refuses_short_decode(self):
        self.assertNotEqual(self.run_decoder(6).returncode, 0)
        self.assertFalse(self.output.exists())

    def test_refuses_excess_decode_including_sentinel(self):
        self.assertNotEqual(self.run_decoder(5, b"hello!").returncode, 0)
        self.assertFalse(self.output.exists())

    def test_refuses_symlink_input(self):
        self.input.write_bytes(b"hello")
        alias = self.root / "alias"
        alias.symlink_to(self.input)
        self.assertNotEqual(self.run_decoder(5, source=alias).returncode, 0)
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO only")
    def test_refuses_fifo_without_blocking(self):
        os.mkfifo(self.input)
        self.assertNotEqual(self.run_decoder(5, source=self.input).returncode, 0)

    def test_existing_output_preserved(self):
        self.output.write_bytes(b"protected")
        self.assertNotEqual(self.run_decoder(5).returncode, 0)
        self.assertEqual(self.output.read_bytes(), b"protected")

    def test_invalid_clear_lengths(self):
        for value in ["0", "-1", "+5", "nan", "18446744073709551616", "8388609"]:
            with self.subTest(value=value):
                self.assertNotEqual(self.run_decoder(value).returncode, 0)
                self.assertFalse(self.output.exists())

    def test_oversized_encoded_input(self):
        self.assertNotEqual(self.run_decoder(5, b"x" * (65536 + 11)).returncode, 0)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
