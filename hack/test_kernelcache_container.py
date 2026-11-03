"""Container fixtures never invoke a filesystem decoder or load a kernel."""
import ctypes
from pathlib import Path
import struct
import sys
import tempfile
import unittest

import kernelcache_container as kc
from test_decmpfs_binary_probe import Bytes, fixture


def der(tag, data):
    size = len(data)
    if size < 128:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([128 | len(raw)]) + raw
    return bytes([tag]) + length + data


def im4p(data, payload_type=b"krnl"):
    return der(0x30, der(0x16, b"IM4P") + der(0x16, payload_type)
               + der(0x16, b"synthetic test kernel") + der(4, data))


class ContainerTests(unittest.TestCase):
    def test_plain_macho_pass_through(self):
        source = Bytes(fixture())
        image, report = kc.prepare(source)
        self.assertIs(image, source)
        self.assertEqual(report["offset_space"], "original-file")

    def test_im4p_and_img4_unwrap_without_execution(self):
        original = fixture(fileset=True)
        bare = im4p(original)
        for data in (bare, der(0x30, der(0x16, b"IMG4") + bare + der(0xA0, b"signature ignored"))):
            image, report = kc.prepare(Bytes(data))
            self.assertEqual(image.read(0, len(original)), original)
            self.assertEqual(report["image_size"], len(original))
            self.assertEqual(report["offset_space"], "IM4P-payload-relative")
            self.assertFalse(report["container_signature_verified"])
            self.assertEqual(len(report["image_sha256"]), 64)
            offset = report["payload_offset"]
            self.assertEqual(data[offset:offset + len(original)], original)

    def test_lzfse_extraction_can_be_injected_for_fixture_tests(self):
        original = fixture()
        encoded = b"bvx2synthetic"
        def decode(source):
            self.assertEqual(source.read(0, source.size), encoded)
            return original
        image, report = kc.prepare(Bytes(im4p(encoded)), decoder=decode)
        self.assertEqual(image.read(0, image.size), original)
        self.assertEqual(report["compression"], "LZFSE")
        self.assertEqual(report["offset_space"], "decoded-Mach-O")

    def test_invalid_decoded_magic(self):
        with self.assertRaises(kc.ContainerError):
            kc.prepare(Bytes(im4p(b"bvx2fake")), decoder=lambda _: b"invalid")

    def test_wrong_payload_type(self):
        with self.assertRaises(kc.ContainerError):
            kc.prepare(Bytes(im4p(fixture(), b"ibss")))

    def test_unrecognized_encrypted_payload(self):
        with self.assertRaises(kc.ContainerError):
            kc.prepare(Bytes(im4p(b"not a plaintext Mach-O")))

    def test_indefinite_and_noncanonical_der_lengths(self):
        for data in (b"\x30\x80\0\0", b"\x30\x81\x01x", b"\x30\x82\0\x80" + bytes(128),
                     b"\x30\x85" + bytes(8), b"\x30\x81"):
            with self.subTest(data=data), self.assertRaises(kc.ContainerError):
                kc.prepare(Bytes(data))

    def test_truncations_and_trailing_bytes(self):
        original = im4p(fixture())
        for size in (0, 1, 2, 4, 10, len(original) - 1):
            with self.subTest(size=size), self.assertRaises(kc.ContainerError):
                kc.prepare(Bytes(original[:size]))
        with self.assertRaises(kc.ContainerError):
            kc.prepare(Bytes(original + b"x"))

    def test_invalid_der_tag(self):
        with self.assertRaises(kc.ContainerError):
            kc.prepare(Bytes(der(0x30, der(4, b"IM4P"))))

    def test_views_do_not_escape_parent(self):
        original = Bytes(bytes(32))
        with self.assertRaises(kc.ContainerError):
            kc.View(original, 30, 4)
        view = kc.View(original, 4, 8)
        for offset, size in ((-1, 1), (7, 2), (0, kc.MAX_READ + 1)):
            with self.assertRaises(kc.ContainerError):
                view.read(offset, size)

    def test_preboot_discovery_is_bounded_and_ignores_symlink_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            # macOS /var is a symlink; anchor fixtures at their canonical root.
            root = Path(tmp).resolve()
            relative = "System/Volumes/Preboot/UUID/boot/HASH/System/Library/Caches/com.apple.kernelcaches/kernelcache"
            candidate = root / relative
            candidate.parent.mkdir(parents=True)
            candidate.write_bytes(im4p(fixture()))
            (root / "System/Volumes/Preboot/ALIAS").symlink_to(candidate.parents[6], target_is_directory=True)
            (root / "unrelated").mkdir()
            (root / "unrelated/kernelcache").write_bytes(b"private")
            paths = kc.system_paths(root)
            self.assertIn(candidate, paths)
            self.assertEqual(len(paths), 3)  # two explicit old-style paths plus actual Preboot
            self.assertTrue(all("ALIAS" not in str(path) for path in paths))
            self.assertTrue(all("unrelated" not in str(path) for path in paths))

    def test_discovery_candidate_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            # macOS /var is a symlink; anchor fixtures at their canonical root.
            root = Path(tmp).resolve()
            for index in range(15):
                candidate = root / f"System/Volumes/Preboot/UUID/boot/H{index}/System/Library/Caches/com.apple.kernelcaches/kernelcache"
                candidate.parent.mkdir(parents=True)
                candidate.write_bytes(b"test")
            with self.assertRaises(kc.ContainerError):
                kc.system_paths(root)

    @unittest.skipUnless(sys.platform == "darwin", "requires Apple's public userspace LZFSE API")
    def test_real_userspace_lzfse_roundtrip_on_macos(self):
        original = fixture(fileset=True)
        library = ctypes.CDLL("/usr/lib/libcompression.dylib")
        encode = library.compression_encode_buffer
        encode.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                           ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
        encode.restype = ctypes.c_size_t
        source = ctypes.create_string_buffer(original, len(original))
        output = ctypes.create_string_buffer(len(original) * 2)
        count = encode(output, len(output), source, len(original), None, 0x801)
        self.assertGreater(count, 0)
        image, report = kc.prepare(Bytes(im4p(output.raw[:count])))
        self.assertEqual(image.read(0, image.size), original)
        self.assertEqual(report["compression"], "LZFSE")


if __name__ == "__main__":
    unittest.main()
