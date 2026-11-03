"""Synthetic Mach-O tests; no Apple binaries or filesystem decoder trials."""
import contextlib
import io
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest

import decmpfs_binary_probe as probe


class Bytes:
    def __init__(self, data):
        self.data, self.size = data, len(data)

    def read(self, offset, size):
        if offset < 0 or size < 0 or size > probe.MAX_READ or offset + size > self.size:
            raise probe.EvidenceError("fixture range")
        return self.data[offset:offset + size]


def header(commands, filetype=11, cpu=0x0100000C):
    return struct.pack("<8I", 0xFEEDFACF, cpu, 0, filetype,
                       len(commands), sum(map(len, commands)), 0, 0) + b"".join(commands)


def symtab(symbol_offset, string_offset, symbols):
    strings = b"\0"
    records = b""
    for name, address, kind in symbols:
        records += struct.pack("<IBBHQ", len(strings), kind, 1 if kind & 0xE else 0, 0, address)
        strings += name.encode() + b"\0"
    command = struct.pack("<6I", 2, 24, symbol_offset, len(symbols), string_offset, len(strings))
    return command, records, strings


def segment(address, offset, size, flags=0x80000400, reserved1=0, reserved2=0):
    name = b"__text".ljust(16, b"\0")
    seg = b"__TEXT_EXEC".ljust(16, b"\0")
    command = struct.pack("<II16sQQQQiiII", 0x19, 152, seg, address, size, offset, size, 5, 5, 1, 0)
    section = struct.pack("<16s16sQQ8I", name, seg, address, size, offset, 2, 0, 0,
                          flags, reserved1, reserved2, 0)
    return command + section


def fileset_entry(offset, name):
    value = name.encode() + b"\0"
    size = (32 + len(value) + 7) & ~7
    return struct.pack("<IIQQII", 0x80000035, size, 0, offset, 32, 0) + value.ljust(size - 32, b"\0")


def branch(pc, target):
    return 0x94000000 | (((target - pc) >> 2) & 0x3FFFFFF)


def fixture(fileset=False, symbol="_register_decmpfs_decompressor", cpu=0x0100000C, stub=False):
    data = bytearray(4096)
    code_address, target = 0x100100, 0x100000
    words = [0x528001E0, 0xD503201F, branch(code_address + 8, target)]  # mov w0,#15; nop; bl
    code = struct.pack("<3I", *words)
    commands = [segment(code_address, 0x800, len(code))]
    syms = [(symbol, target, 0xF)]
    if fileset:
        ksym, records, strings = symtab(0xC00, 0xD00, syms)
        data[0x200:0x200 + len(header([ksym], 2))] = header([ksym], 2)
        data[0xC00:0xC00 + len(records)] = records
        data[0xD00:0xD00 + len(strings)] = strings
        syms = [("_lz4_decode", 0x100200, 0xF)]
    if stub:
        syms = [(symbol, 0, 1)]
        commands.append(segment(target, 0x900, 12, 8, 0, 12))
        dynamic = [0] * 18
        dynamic[12:14] = [0xE00, 1]
        commands.append(struct.pack("<20I", 0xB, 80, *dynamic))
        data[0xE00:0xE04] = struct.pack("<I", 0)
    scmd, records, strings = symtab(0xA00, 0xB00, syms)
    commands.append(scmd)
    image = header(commands, cpu=cpu)
    offset = 0x400 if fileset else 0
    data[offset:offset + len(image)] = image
    data[0x800:0x800 + len(code)] = code
    data[0xA00:0xA00 + len(records)] = records
    data[0xB00:0xB00 + len(strings)] = strings
    if fileset:
        root = header([fileset_entry(0x200, "com.apple.kernel"), fileset_entry(
            0x400, "com.apple.AppleFSCompression.AppleFSCompressionTypeZlib")], 12)
        data[:len(root)] = root
    return bytes(data)


def calls(report):
    return [call for image in report["images"] for call in image["registration_calls"]]


class BinaryTests(unittest.TestCase):
    def test_direct_call_candidate_and_provenance(self):
        result = calls(probe.inspect(Bytes(fixture())))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type_constant_candidate"], 15)
        self.assertEqual(result[0]["call_address"], "0x100108")
        self.assertEqual(result[0]["file_offset"], 0x808)
        self.assertEqual(len(result[0]["window_sha256"]), 64)
        self.assertIsNone(result[0]["registration_pointer_candidate"])

    def test_fileset_global_offsets_and_cross_image_target(self):
        result = probe.inspect(Bytes(fixture(fileset=True)))
        self.assertEqual(len(result["images"]), 3)
        self.assertEqual(len(calls(result)), 1)
        self.assertEqual(result["images"][2]["relevant_symbols"][0]["name"], "_lz4_decode")
        self.assertEqual(result["member_errors"], [])

    def test_universal_slice_origin(self):
        image = fixture(fileset=True)
        data = struct.pack(">7I", 0xCAFEBABE, 1, 0x0100000C, 0, 4096, len(image), 12)
        data = data.ljust(4096, b"\0") + image
        result = calls(probe.inspect(Bytes(data)))
        self.assertEqual(result[0]["file_offset"], 4096 + 0x808)

    def test_universal_64(self):
        image = fixture()
        data = struct.pack(">4I2Q2I", 0xCAFEBABF, 1, 0x0100000C, 0, 4096, len(image), 12, 0)
        self.assertEqual(len(calls(probe.inspect(Bytes(data.ljust(4096, b"\0") + image)))), 1)

    def test_symbol_stub(self):
        result = calls(probe.inspect(Bytes(fixture(stub=True))))
        self.assertEqual(len(result), 1)
        self.assertIn("symbol stub", result[0]["target_symbol"])

    def test_unregister_and_substrings_are_not_registration(self):
        for name in ("_unregister_decmpfs_decompressor", "_register_decmpfs_decompressor_extra",
                     "___register_decmpfs_decompressor"):
            self.assertEqual(calls(probe.inspect(Bytes(fixture(symbol=name)))), [])

    def test_debug_symbol_is_not_target(self):
        data = bytearray(fixture())
        data[0xA04] = 0xEF
        self.assertEqual(calls(probe.inspect(Bytes(data))), [])

    def test_x86_has_symbols_without_arm64_claim(self):
        result = probe.inspect(Bytes(fixture(cpu=0x01000007)))
        self.assertEqual(calls(result), [])
        self.assertTrue(result["images"][0]["relevant_symbols"])

    def test_truncated_inputs_are_rejected(self):
        data = fixture()
        for size in (0, 3, 4, 31, 32, 39, 100, 0x800, 0xA00, 0xB00):
            with self.subTest(size=size), self.assertRaises(probe.EvidenceError):
                probe.inspect(Bytes(data[:size]))

    def test_bad_load_command_size(self):
        for size in (0, 7, 9, 0xFFFFFFF8):
            data = bytearray(fixture())
            struct.pack_into("<I", data, 36, size)
            with self.assertRaises(probe.EvidenceError):
                probe.inspect(Bytes(data))

    def test_symbol_budget(self):
        data = bytearray(fixture())
        struct.pack_into("<I", data, 32 + 152 + 12, probe.MAX_SYMBOLS + 1)
        with self.assertRaises(probe.EvidenceError):
            probe.inspect(Bytes(data))

    def test_unsupported_container(self):
        with self.assertRaises(probe.EvidenceError):
            probe.inspect(Bytes(b"IM4P" + bytes(128)))

    def test_architecture_mismatch(self):
        image = fixture()
        data = struct.pack(">7I", 0xCAFEBABE, 1, 0x01000007, 0, 4096, len(image), 12)
        with self.assertRaises(probe.EvidenceError):
            probe.inspect(Bytes(data.ljust(4096, b"\0") + image))

    def test_unterminated_symbol_rejected(self):
        data = bytearray(fixture())
        name_length = len("_register_decmpfs_decompressor")
        data[0xB00 + name_length + 1] = 65
        with self.assertRaises(probe.EvidenceError):
            probe.inspect(Bytes(data))

    def test_unknown_instruction_discards_stale_argument(self):
        words = [0x528001E0, 0xAA0203E0]  # mov w0,#15; mov x0,x2 (not interpreted)
        self.assertNotIn(0, probe.local_constants(struct.pack("<2I", *words), 0x1000))

    def test_call_and_branch_discard_stale_arguments(self):
        for instruction in (0x94000000, 0x14000000, 0x54000000, 0x34000000,
                            0x36000000, 0xD63F0020, 0xD65F03C0):
            self.assertEqual(probe.local_constants(struct.pack("<2I", 0x528001E0, instruction), 0), {})

    def test_constants_after_branch_can_be_candidates(self):
        words = [0x94000000, 0x52800200]
        self.assertEqual(probe.local_constants(struct.pack("<2I", *words), 0)[0], 16)

    def test_adrp_add_registration_pointer(self):
        words = [0x90000001, 0x91008021, 0x528001E0]
        result = probe.local_constants(struct.pack("<3I", *words), 0x1000)
        self.assertEqual(result, {0: 15, 1: 0x1020})

    def test_movk_and_movn(self):
        words = [0x528001E0, 0x72A00020]
        self.assertEqual(probe.local_constants(struct.pack("<2I", *words), 0)[0], 0x1000F)
        self.assertEqual(probe.local_constants(struct.pack("<I", 0x12800000), 0)[0], 0xFFFFFFFF)

    def test_deterministic_mutations_fail_cleanly(self):
        rng = random.Random(20261103)
        for _ in range(300):
            data = bytearray(fixture(fileset=True))
            for _ in range(rng.randrange(1, 5)):
                data[rng.randrange(len(data))] ^= rng.randrange(1, 256)
            try:
                result = probe.inspect(Bytes(data))
                self.assertLessEqual(len(calls(result)), probe.MAX_CALLS)
            except probe.EvidenceError:
                pass

    def test_registration_table_bytes_and_exact_callback_symbol(self):
        table = struct.pack("<II5Q", 3, 0, 0x100200, 0, 0x100200, 0, 0)
        data = bytearray(4096)
        cmd, records, strings = symtab(0xA00, 0xB00, [("_lz4_decode", 0x100200, 0xF)])
        image = header([segment(0x200000, 0x800, len(table), flags=0), cmd])
        data[:len(image)] = image
        data[0x800:0x800 + len(table)] = table
        data[0xA00:0xA00 + len(records)] = records
        data[0xB00:0xB00 + len(strings)] = strings
        parsed = probe.Image(Bytes(data), 0, len(data), 0, "synthetic")
        result = probe.registration_record(parsed, 0x200000)
        self.assertEqual(result["bytes_hex"], table.hex())
        self.assertEqual(result["callbacks"][2]["exact_symbol"], "_lz4_decode")
        self.assertEqual(result["status"], "candidate-bytes")
        self.assertIsNone(result["callbacks"][1]["exact_symbol"])

    def test_registration_candidate_does_not_strip_pointer_bits(self):
        parsed = probe.Image(Bytes(fixture()), 0, 4096, 0, "synthetic")
        result = probe.registration_record(parsed, 0xAB00000000100200)
        self.assertEqual(result["status"], "unresolved")
        self.assertNotIn("callbacks", result)

    def test_missing_and_unaligned_registration_candidates(self):
        parsed = probe.Image(Bytes(fixture()), 0, 4096, 0, "synthetic")
        self.assertIsNone(probe.registration_record(parsed, None))
        self.assertEqual(probe.registration_record(parsed, 3)["status"], "unresolved")

    def test_cli_stays_closed_even_with_candidate_calls(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "synthetic.kext"
            path.write_bytes(fixture())
            before = path.read_bytes()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(probe.main(["--image", str(path)]), 0)
            result = json.loads(output.getvalue())
            for field in ("kernel_decoder_proven", "codec_identity_proven", "on_disk_framing_proven",
                          "native_raven_mesh_writes_permitted"):
                self.assertIs(result[field], False)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(result["inputs"][0]["status"], "inspected")

    def test_no_input_is_not_success(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.main(["--image", "/no/such/fixture.bin"]), 1)

    def test_symlink_and_fifo_refused(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "image"
            target.write_bytes(fixture())
            link = Path(root) / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                probe.Source(link)
            fifo = Path(root) / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(probe.EvidenceError):
                probe.Source(fifo)

    def test_mutating_input_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "image"
            path.write_bytes(fixture())
            source = probe.Source(path)
            try:
                path.write_bytes(b"changed")
                with self.assertRaises(probe.EvidenceError):
                    source.unchanged()
            finally:
                source.close()


if __name__ == "__main__":
    unittest.main()
