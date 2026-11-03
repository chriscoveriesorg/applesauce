"""Observed native configuration lookup with synthetic range checks."""
import hashlib
import struct
import unittest

import decmpfs_binary_probe as probe
import decmpfs_config_probe as config
from test_decmpfs_binary_probe import Bytes, header, segment

# Read-only macOS 27.0.1 evidence run 41560208293. Source kernelcache:
# ca55ea8c4c86170e870380ae5501b8b43adb2d2d3db28be4531b3040653be203
WINDOW = "5f2403d57f2303d5ff0301d1f44f02a9fd7b03a9fdc30091f30300aa010000f9280840f9080940b9094500513f45003128010054e80b00f9e80780520972ff90291d2491e92300a90072ff9000cc3891150000140905088b2af57ed30b72ff906bf116915fc12aeb69c12a8b70010a8bb075e5f22901909a2a0140b96a0000342a0540b96a010035e80b00f9c80880520972ff90291d2491e92300a90072ff90005c3991140300940972ff9029f11691280540b9200140fd600600fd1fc14071000100541f814071c00000541f4140718101005428008052681200b919000014680240f9080940f908c140f8e9ff9f520801098b08fd50d3681200b911000014680240f9000140f99dffff97f40300aa680e40b9e02301a9482180520972ff90291d2491e92300a90072ff9000782391f1020094"


def window(data=WINDOW):
    return {'address': '0xfffffe00083d3cdc', 'bytes_hex': data,
            'sha256': hashlib.sha256(bytes.fromhex(data)).hexdigest()}


class ConfigurationTests(unittest.TestCase):
    def test_observed_lookup_has_seventeen_raw_rows(self):
        result = config.configuration_candidate(window())
        self.assertEqual(result['address'], 0xfffffe00072135bc)
        self.assertEqual(result['count'], 17)
        self.assertEqual(result['stride'], 12)

    def test_changed_shape_or_guard_is_rejected(self):
        data = bytearray.fromhex(WINDOW)
        for index in list(range(0, 13)) + list(range(21, 32)):
            changed = data[:]
            struct.pack_into('<I', changed, index * 4, 0xD503201F)
            with self.subTest(index=index):
                self.assertIsNone(config.configuration_candidate(window(changed.hex())))

    def test_adjacent_function_window_is_not_a_call_target(self):
        self.assertIsNone(config.configuration_candidate(window('1f2003d5' + WINDOW)))
        data = bytearray.fromhex(WINDOW)
        struct.pack_into('<I', data, 0, 0xD503201F)
        self.assertIsNone(config.configuration_candidate(window(data.hex())))

    def test_empty_and_short_windows_are_inconclusive(self):
        for data in ('', WINDOW[:64], WINDOW[:160]):
            self.assertIsNone(config.configuration_candidate(window(data)))

    def test_raw_words_have_no_inferred_codec_names(self):
        h = header([segment(0x100000, 0x200, 36, flags=0)], filetype=11)
        raw = struct.pack('<9I', 0, 0, 0, 0x306, 0x10000, 0, 0x6ff, 0x20000, 0)
        data = h.ljust(0x200, b'\0') + raw
        image = probe.Image(Bytes(data), 0, len(data), 0, 'synthetic')
        candidate = {'address': 0x100000, 'count': 3, 'stride': 12}
        result = config.configuration_table(image, candidate)
        self.assertEqual(result['bytes_hex'], raw.hex())
        self.assertEqual(result['entries'][2], {'type_index': 2, 'raw_words': [0x6ff, 0x20000, 0]})
        self.assertNotIn('codec', result)

    def test_table_cannot_cross_section(self):
        h = header([segment(0x100000, 0x200, 12, flags=0)], filetype=11)
        data = h.ljust(0x200, b'\0') + bytes(12)
        image = probe.Image(Bytes(data), 0, len(data), 0, 'synthetic')
        with self.assertRaises(probe.EvidenceError):
            config.configuration_table(image, {'address': 0x100000, 'count': 2})

    def test_only_fetch_direct_calls_are_followed(self):
        calls = []
        cb = {'field': 'fetch', 'code_window': {'direct_branches': [
            {'instruction': 'B', 'target': '0x100'},
            {'instruction': 'BL', 'target': '0x200'},
            {'instruction': 'BL', 'target': '0x200'}]}}
        table = {'entries': [{'registration': {'callbacks': [cb]}}]}
        def no_match(image, address):
            calls.append(address)
            return window('')
        self.assertEqual(config.inspect_configuration(None, table, no_match), [])
        self.assertEqual(calls, [0x200])


if __name__ == '__main__':
    unittest.main()
