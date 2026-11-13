"""Portable safety tests for the second LZRAVEN decoder's CLI adapter.

The stub is deliberately an identity function. These tests verify I/O safety,
not LZRAVEN interoperability; pinned C11 source and Apple vectors must be
qualified separately before this candidate can be accepted.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
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
        cls.swap_hook = None
        if sys.platform.startswith("linux"):
            hook_source = root / "swap_parent.c"
            hook_source.write_text(
                "#define _GNU_SOURCE\n"
                "#include <dlfcn.h>\n#include <stdlib.h>\n"
                "#include <stdio.h>\n#include <sys/stat.h>\n"
                "int linkat(int a, const char *b, int c, const char *d, int e) {\n"
                "  int (*real_link)(int, const char *, int, const char *, int) = "
                "dlsym(RTLD_NEXT, \"linkat\");\n"
                "  const char *from = getenv(\"RAVEN_SWAP_FROM\");\n"
                "  const char *to = getenv(\"RAVEN_SWAP_TO\");\n"
                "  if (from && to && (rename(from, to) || mkdir(from, 0700))) return -1;\n"
                "  return real_link(a, b, c, d, e);\n}\n"
                "#include <unistd.h>\n"
                "#include <fcntl.h>\n"
                "#include <time.h>\n"
                "ssize_t read(int fd, void *buf, size_t length) {\n"
                "  ssize_t (*real_read)(int, void *, size_t) = dlsym(RTLD_NEXT, \"read\");\n"
                "  const char *from = getenv(\"RAVEN_REPLACE_INPUT\");\n"
                "  const char *to = getenv(\"RAVEN_MOVE_INPUT\");\n"
                "  const char *rewrite = getenv(\"RAVEN_REWRITE_INPUT\");\n"
                "  struct stat opened, named;\n"
                "  if (from && to && !fstat(fd, &opened) && !stat(from, &named)\n"
                "      && opened.st_dev == named.st_dev && opened.st_ino == named.st_ino\n"
                "      && !rename(from, to)) {\n"
                "    int out = open(from, O_CREAT | O_EXCL | O_WRONLY, 0600);\n"
                "    if (out >= 0) { (void)write(out, \"world\", 5); close(out); }\n"
                "  }\n"
                "  if (rewrite && !fstat(fd, &opened) && !stat(rewrite, &named)\n"
                "      && opened.st_dev == named.st_dev && opened.st_ino == named.st_ino) {\n"
                "    int out = open(rewrite, O_WRONLY);\n"
                "    if (out >= 0) { (void)write(out, \"world\", 5); close(out); }\n"
                "    struct timespec changed[2] = {{1000000000, 0}, {1000000001, 0}};\n"
                "    (void)utimensat(AT_FDCWD, rewrite, changed, 0);\n"
                "  }\n"
                "  return real_read(fd, buf, length);\n"
                "}\n"
            )
            cls.swap_hook = root / "swap_parent.so"
            subprocess.run(
                [cls.compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-shared", "-fPIC", str(hook_source), "-ldl", "-o", str(cls.swap_hook)],
                check=True, capture_output=True, text=True,
            )
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

    def run_decoder(self, capacity, data=b"hello", *, source=None, env=None):
        if source is None:
            self.input.write_bytes(data)
            source = self.input
        return subprocess.run(
            [str(self.binary), "--cap", str(capacity), str(source), str(self.output)],
            capture_output=True, timeout=3, env=env,
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


    def test_output_stage_is_private_and_cleaned(self):
        self.assertEqual(self.run_decoder(5).returncode, 0)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),
                         ["compressed.bin", "decoded.bin"])

    def test_collision_leaves_no_private_stage(self):
        self.output.write_bytes(b"existing")
        self.assertNotEqual(self.run_decoder(5).returncode, 0)
        self.assertEqual(self.output.read_bytes(), b"existing")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),
                         ["compressed.bin", "decoded.bin"])

    def test_output_symlink_is_preserved(self):
        protected = self.root / "protected"
        protected.write_bytes(b"keep")
        self.output.symlink_to(protected)
        self.assertNotEqual(self.run_decoder(5).returncode, 0)
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(protected.read_bytes(), b"keep")
        self.assertFalse(any(p.name.startswith(".raven-alt-") for p in self.root.iterdir()))

    def test_symlink_output_parent_is_refused(self):
        alias = self.root / "alias"
        target = self.root / "target"
        target.mkdir()
        alias.symlink_to(target, target_is_directory=True)
        self.output = alias / "decoded.bin"
        self.assertNotEqual(self.run_decoder(5).returncode, 0)
        self.assertFalse((target / "decoded.bin").exists())
        self.assertEqual(list(target.iterdir()), [])

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux injection test")
    def test_parent_swap_during_link_never_targets_replacement(self):
        parent = self.root / "parent"
        moved = self.root / "moved"
        parent.mkdir()
        self.output = parent / "decoded.bin"
        env = {**os.environ, "LD_PRELOAD": str(self.swap_hook),
               "RAVEN_SWAP_FROM": str(parent), "RAVEN_SWAP_TO": str(moved)}
        result = self.run_decoder(5, env=env)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertTrue(parent.is_dir())
        self.assertEqual(list(parent.iterdir()), [])
        self.assertEqual((moved / "decoded.bin").read_bytes(), b"hello")
        self.assertFalse(any(p.name.startswith(".raven-alt-") for p in moved.iterdir()))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux injection test")
    def test_input_path_replacement_during_read_rejected(self):
        self.input.write_bytes(b"hello")
        moved = self.root / "previous-input"
        env = {**os.environ, "LD_PRELOAD": str(self.swap_hook),
               "RAVEN_REPLACE_INPUT": str(self.input),
               "RAVEN_MOVE_INPUT": str(moved)}
        result = self.run_decoder(5, source=self.input, env=env)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.input.read_bytes(), b"world")
        self.assertEqual(moved.read_bytes(), b"hello")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux injection test")
    def test_in_place_same_size_rewrite_during_read_rejected(self):
        self.input.write_bytes(b"hello")
        env = {**os.environ, "LD_PRELOAD": str(self.swap_hook),
               "RAVEN_REWRITE_INPUT": str(self.input)}
        result = self.run_decoder(5, source=self.input, env=env)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.input.read_bytes(), b"world")

    def test_output_directory_path_is_refused(self):
        self.output = self.root / "directory"
        self.output.mkdir()
        self.assertNotEqual(self.run_decoder(5).returncode, 0)
        self.assertTrue(self.output.is_dir())
        self.assertEqual(list(self.output.iterdir()), [])



if __name__ == "__main__":
    unittest.main()
