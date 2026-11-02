"""Portable, generated-only tests for read-only macOS decmpfs inventory."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import stat
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name('native-type-probe.py')
SPEC = importlib.util.spec_from_file_location('native_type_probe', SCRIPT)
assert SPEC and SPEC.loader
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def header(raw_type, logical_size=256, extra=b''):
    return b'fpmc' + raw_type.to_bytes(4, 'little') + logical_size.to_bytes(8, 'little') + extra


class ReadOnlyNativeInventoryTests(unittest.TestCase):
    def test_header_exact_magic_type_size_and_attribute_length(self):
        self.assertEqual(probe.parse_header(header(15, 0x1122334455667788)), {
            'stored_type': 15, 'logical_size': 0x1122334455667788,
            'attribute_bytes': 16,
        })
        self.assertEqual(probe.parse_header(header(16, 0, b'xyz'))['attribute_bytes'], 19)

    def test_reject_short_oversized_and_wrong_magic(self):
        for value in [b'', b'fpmc', b'x'*15, b'cmpf'+header(3)[4:], b'fpmc'+b'\0'*3800]:
            with self.subTest(length=len(value)):
                with self.assertRaises(ValueError):
                    probe.parse_header(value)

    def test_unknown_types_remain_unknown_without_native_permissions(self):
        report = probe.new_report()
        for raw_type in [15, 16, 17, 0xD05, 0xE05]:
            probe.record_header(report, probe.parse_header(header(raw_type)),
                                SimpleNamespace(st_size=256))
            self.assertIsNone(report['types'][str(raw_type)]['known_format'])
        self.assertFalse(report['kernel_decoder_proven'])
        self.assertFalse(report['codec_identity_proven'])
        self.assertFalse(report['native_raven_mesh_writes_permitted'])

    def test_known_type_labels_are_bounded_reference_only(self):
        report = probe.new_report()
        for key, name in probe.KNOWN_TYPES.items():
            probe.record_header(report, probe.parse_header(header(key, 77)),
                                SimpleNamespace(st_size=77))
            self.assertEqual(report['types'][str(key)]['known_format'], name)
        self.assertEqual(report['headers_read'], len(probe.KNOWN_TYPES))

    def test_repeated_type_aggregates_and_records_size_mismatch(self):
        report = probe.new_report()
        probe.record_header(report, probe.parse_header(header(12, 256, b'x')),
                            SimpleNamespace(st_size=256))
        probe.record_header(report, probe.parse_header(header(12, 257, b'x'*8)),
                            SimpleNamespace(st_size=256))
        result = report['types']['12']
        self.assertEqual(result['count'], 2)
        self.assertEqual(result['size_mismatches'], 1)
        self.assertEqual((result['smallest_attribute_bytes'], result['largest_attribute_bytes']),
                         (17, 24))

    def test_system_scan_bounds_are_explicit(self):
        for files, seconds in [(0, 1), (250001, 1), (1, 0), (1, 601)]:
            with self.subTest(files=files, seconds=seconds):
                with self.assertRaises(ValueError):
                    probe.scan_roots([], max_files=files, max_seconds=seconds,
                                     attribute_reader=lambda fd: b'')

    def test_empty_scan_never_claims_kernel_support(self):
        r = probe.scan_roots([], max_files=1, max_seconds=1,
                             attribute_reader=lambda fd: b'')
        self.assertEqual(r['headers_read'], 0)
        self.assertEqual(r['types'], {})
        self.assertFalse(r['native_raven_mesh_writes_permitted'])
        self.assertIn('Missing type is not evidence', r['coverage_note'])

    def test_scan_refuses_missing_nofollow_support(self):
        with mock.patch.object(probe.os, 'O_NOFOLLOW', 0):
            with self.assertRaisesRegex(OSError, 'O_NOFOLLOW'):
                probe.scan_roots([], max_files=1, max_seconds=1,
                                 attribute_reader=lambda fd: header(8))

    def test_scan_rejects_changed_metadata_after_xattr_read(self):
        # Simulate a compressed, generated-only file whose metadata changes
        # while the pinned descriptor's xattr is being read. No real file is
        # opened and no macOS filesystem state is changed.
        before = SimpleNamespace(st_mode=stat.S_IFREG | 0o444,
                                 st_flags=probe.UF_COMPRESSED,
                                 st_dev=1, st_ino=2, st_size=256,
                                 st_mtime_ns=10, st_ctime_ns=10)
        changed = SimpleNamespace(**vars(before))
        changed.st_ctime_ns = 11
        with mock.patch.object(probe.os.path, 'islink', return_value=False), \
             mock.patch.object(probe.os.path, 'isdir', return_value=True), \
             mock.patch.object(probe.os, 'walk',
                               return_value=[('/synthetic', [], ['sample'])]), \
             mock.patch.object(probe.os, 'stat', return_value=before), \
             mock.patch.object(probe.os, 'fstat',
                               side_effect=[before, changed]) as fstat, \
             mock.patch.object(probe.os, 'open', return_value=123) as opened, \
             mock.patch.object(probe.os, 'close') as closed:
            report = probe.scan_roots(['/synthetic'], max_files=1,
                                      max_seconds=1,
                                      attribute_reader=lambda fd: header(8))
        self.assertEqual(report['files_seen'], 1)
        self.assertEqual(report['headers_read'], 0)
        self.assertEqual(report['errors']['file-changed'], 1)
        self.assertEqual(report['types'], {})
        self.assertEqual(fstat.call_count, 2)
        opened.assert_called_once()
        closed.assert_called_once_with(123)

    def test_scan_accepts_unchanged_pinned_header(self):
        before = SimpleNamespace(st_mode=stat.S_IFREG | 0o444,
                                 st_flags=probe.UF_COMPRESSED,
                                 st_dev=1, st_ino=2, st_size=256,
                                 st_mtime_ns=10, st_ctime_ns=10)
        with mock.patch.object(probe.os.path, 'islink', return_value=False), \
             mock.patch.object(probe.os.path, 'isdir', return_value=True), \
             mock.patch.object(probe.os, 'walk',
                               return_value=[('/synthetic', [], ['sample'])]), \
             mock.patch.object(probe.os, 'stat', return_value=before), \
             mock.patch.object(probe.os, 'fstat', return_value=before), \
             mock.patch.object(probe.os, 'open', return_value=123), \
             mock.patch.object(probe.os, 'close'):
            report = probe.scan_roots(['/synthetic'], max_files=1,
                                      max_seconds=1,
                                      attribute_reader=lambda fd: header(8))
        self.assertEqual(report['headers_read'], 1)
        self.assertEqual(report['types']['8']['count'], 1)
        self.assertEqual(report['errors'], {})

    def test_constants_match_apple_header(self):
        self.assertEqual(probe.XATTR_SHOWCOMPRESSION, 0x20)
        self.assertEqual(probe.UF_COMPRESSED, 0x20)
        self.assertEqual(probe.MAGIC, b'fpmc')
        self.assertEqual(probe.MAX_XATTR_SIZE, 3802)


if __name__ == '__main__':
    unittest.main()
