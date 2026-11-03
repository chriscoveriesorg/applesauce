"""Real instruction-window regression and synthetic table/fixup tests."""
import hashlib
import struct
import unittest

import decmpfs_binary_probe as probe
import decmpfs_table_probe as table
from test_decmpfs_binary_probe import Bytes, header, segment

# Bounded window from macOS 27.0.1 build 26A434, collected read-only in
# Actions run 41558930653. Decoded kernelcache SHA256:
# ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203
WINDOW = "f30301aaf40300aaf64601b0c8427739a80000360072ff9000101d911606009412000014180080d2b7b6ffd0f7c20b91e812188b150140b9010540f9e00315aa11060094a0030035180700911f3300f101ffff54"


def call(window=WINDOW):
    return {"instruction_window_hex": window, "window_address": "0xfffffe00083d315c",
            "call_address": "0xfffffe00083d319c",
            "window_sha256": hashlib.sha256(bytes.fromhex(window)).hexdigest()}


def chain_fixture(fmt=7, raw=None, start=0x200):
    data = bytearray(4096)
    commands = [segment(0x100000, 0, 4096, flags=0), struct.pack("<4I", 0x80000034, 16, 0x800, 60)]
    h = header(commands, filetype=12)
    data[:len(h)] = h
    if raw is None:
        raw = (1 << 63) | 0x300
    struct.pack_into("<Q", data, 0x200, raw)
    struct.pack_into("<7I", data, 0x800, 0, 28, 0, 0, 0, 0, 0)
    struct.pack_into("<2I", data, 0x81C, 1, 8)
    struct.pack_into("<IHHQIH", data, 0x824, 24, 4096, fmt, 0, 0, 1)
    struct.pack_into("<H", data, 0x83A, start)
    image = probe.Image(Bytes(data), 0, len(data), 0, "synthetic")
    return data, image


class TableTests(unittest.TestCase):
    def test_real_loop_shape_recovers_table_and_count(self):
        result = table.loop_candidate(call())
        self.assertEqual(result["table_address"], 0xfffffe0007aa92f0)
        self.assertEqual(result["count"], 12)
        self.assertEqual(result["stride"], 16)

    def test_control_or_argument_changes_are_not_recognized(self):
        original = bytearray.fromhex(WINDOW)
        for word in range(9, 21):
            mutated = original[:]
            struct.pack_into("<I", mutated, word * 4, 0xD503201F)
            with self.subTest(word=word):
                self.assertIsNone(table.loop_candidate(call(mutated.hex())))

    def test_wrong_loop_count_and_target(self):
        original = bytearray.fromhex(WINDOW)
        for value in (0, 65):
            mutated = original[:]
            struct.pack_into("<I", mutated, 19 * 4, 0xF100001F | (24 << 5) | (value << 10))
            self.assertIsNone(table.loop_candidate(call(mutated.hex())))
        mutated = original[:]
        struct.pack_into("<I", mutated, 20 * 4, 0x54000001)
        self.assertIsNone(table.loop_candidate(call(mutated.hex())))

    def test_short_window_has_no_claim(self):
        self.assertIsNone(table.loop_candidate(call(WINDOW[:32])))

    def test_authenticated_format7_chain(self):
        _, image = chain_fixture()
        result = table.Fixups(image).resolve(0x100200)
        self.assertEqual(result["status"], "chain-verified")
        self.assertEqual(result["target"], "0x100300")
        self.assertEqual(result["pointer_format"], 7)

    def test_format8_kernelcache_level_zero(self):
        _, image = chain_fixture(fmt=8)
        result = table.Fixups(image).resolve(0x100200)
        self.assertEqual(result["target"], "0x100300")

    def test_chain_membership_required(self):
        _, image = chain_fixture()
        self.assertEqual(table.Fixups(image).resolve(0x100208)["status"], "unresolved")

    def test_follow_declared_next_link(self):
        data, _ = chain_fixture(raw=(2 << 51) | 0x300)
        struct.pack_into("<Q", data, 0x208, (1 << 63) | 0x320)
        image = probe.Image(Bytes(data), 0, len(data), 0, "synthetic")
        self.assertEqual(table.Fixups(image).resolve(0x100208)["target"], "0x100320")

    def test_unsupported_formats_bind_cache_level_and_multistart(self):
        for arguments in ({"fmt": 1}, {"raw": (1 << 62) | 0x300},
                          {"fmt": 8, "raw": (1 << 30) | 0x300},
                          {"start": 0x8000}, {"start": 0xFFFF}):
            _, image = chain_fixture(**arguments)
            with self.subTest(arguments=arguments):
                self.assertEqual(table.Fixups(image).resolve(0x100200)["status"], "unresolved")

    def test_target_outside_image_remains_unresolved(self):
        _, image = chain_fixture(raw=(1 << 63) | 0xFFFFFF)
        self.assertEqual(table.Fixups(image).resolve(0x100200)["status"], "unresolved")

    def test_no_fixup_metadata_remains_unresolved(self):
        data = header([segment(0x100000, 0, 4096)], filetype=12).ljust(4096, b"\0")
        image = probe.Image(Bytes(data), 0, len(data), 0, "synthetic")
        self.assertEqual(table.Fixups(image).resolve(0x100200)["status"], "unresolved")

    def test_callback_windows_are_bounded_and_keep_branch_bytes(self):
        data = bytearray(header([segment(0x100000, 0, 4096)], filetype=12).ljust(4096, b"\0"))
        struct.pack_into("<II", data, 0x200, 0x94000008, 0x14000003)
        image = probe.Image(Bytes(data), 0, len(data), 0, "synthetic")
        result = table.callback_window(image, 0x100200)
        self.assertEqual(result["size"], 2048)
        self.assertEqual(result["direct_branches"][0]["target"], "0x100220")
        self.assertEqual(result["direct_branches"][1]["instruction"], "B")
        self.assertFalse(result["function_boundary_proven"])
        self.assertEqual(table.callback_window(image, 0x100FFC)["size"], 4)
        self.assertIsNone(table.callback_window(image, 0x100201))
        self.assertIsNone(table.callback_window(image, 0x200000))

    def test_table_preserves_type_and_raw_pointer(self):
        data, _ = chain_fixture()
        struct.pack_into("<IIQ", data, 0x100, 15, 0, (1 << 63) | 0x300)
        image = probe.Image(Bytes(data), 0, len(data), 0, "synthetic")
        result = table.read_table(image, {"table_address": 0x100100, "count": 1,
                                         "loop_window_sha256": "synthetic"}, table.Fixups(image))
        self.assertEqual(result["entries"][0]["type"], 15)
        self.assertEqual(result["entries"][0]["pointer_resolution"]["status"], "unresolved")
        self.assertNotIn("codec", result["entries"][0])


if __name__ == "__main__":
    unittest.main()
