"""Synthetic fail-closed tests for read-only decmpfs catalogue hints."""

import importlib.util
import json
import plistlib
from pathlib import Path
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "native_decoders", Path(__file__).with_name("decmpfs_catalogue_probe.py")
)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class DecoderCatalogueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def plist(self, personalities, bundle="com.apple.TestCompression"):
        path = self.root / "Sample.kext" / "Contents" / "Info.plist"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(plistlib.dumps({
            "CFBundleIdentifier": bundle,
            "IOKitPersonalities": personalities,
        }))
        return path

    def test_exact_resource_names_only(self):
        line = (
            '"com.apple.AppleFSCompression.providesType11" = 1\n'
            '"com.apple.AppleFSCompression.Type13" = 1\n'
            '"prefixcom.apple.AppleFSCompression.Type17" = 1\n'
            '"com.apple.AppleFSCompression.Type15_bad" = 1\n'
            '"com.apple.AppleFSCompression.providesType11" = 1\n'
            '"com.apple.AppleFSCompression.Type999999999999999" = 1\n'
        )
        result = mod.markers_in_log(line.encode())
        self.assertEqual([(x["type"], x["resource"]) for x in result],
                         [(11, "providesType"), (13, "Type")])

    def test_nested_iokit_personality_and_deterministic_hash(self):
        path = self.plist({
            "Valid": {"IOResourceMatch": [
                "com.apple.AppleFSCompression.providesType14",
                {"value": "com.apple.AppleFSCompression.Type15"},
                "com.apple.AppleFSCompression.Type16-extra",
            ]},
        })
        a = mod.build_report(None, [path])
        b = mod.build_report(None, [path])
        self.assertEqual(a, b)
        self.assertEqual(a["candidate_types"], [14, 15])
        self.assertTrue(all(x["plist_sha256"] for x in a["candidate_declarations"]))
        self.assertFalse(a["native_raven_mesh_writes_permitted"])
        self.assertFalse(a["codec_identity_proven"])
        self.assertFalse(a["kernel_decoder_proven"])

    def test_unknown_without_system_declarations(self):
        result = mod.build_report(None, [])
        self.assertEqual(result["candidate_types"], [])
        self.assertFalse(result["kernel_decoder_proven"])
        self.assertIn("Missing declarations are inconclusive",
                      result["interpretation"])

    def test_read_only_log_is_hashed_and_never_used_as_codec_proof(self):
        path = self.root / "components.txt"
        path.write_text(
            '"com.apple.AppleFSCompression.providesType17" = 1\n',
            encoding="utf-8"
        )
        data = mod.build_report(path, [])
        self.assertEqual(data["candidate_types"], [17])
        self.assertEqual(len(data["source"]["component_log_sha256"]), 64)
        self.assertFalse(data["codec_identity_proven"])

    def test_oversized_and_symlink_files_are_refused(self):
        path = self.root / "large.txt"
        path.write_bytes(b"A" * (mod.MAX_COMPONENT_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            mod.build_report(path, [])
        link = self.root / "linked.txt"
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "symlink"):
            mod.build_report(link, [])

    def test_malformed_plists_and_personalities_refused(self):
        path = self.plist({})
        path.write_bytes(b"invalid")
        with self.assertRaisesRegex(ValueError, "invalid Info.plist"):
            mod.build_report(None, [path])
        path.write_bytes(plistlib.dumps({"IOKitPersonalities": ["bad"]}))
        with self.assertRaisesRegex(ValueError, "dictionary"):
            mod.build_report(None, [path])

    def test_input_file_count_capped(self):
        with self.assertRaisesRegex(ValueError, "too many"):
            mod.build_report(None, [self.root / "any"] * (mod.MAX_PLISTS + 1))

    def test_cli_json_shape(self):
        path = self.root / "empty.txt"
        path.write_bytes(b"")
        data = mod.build_report(path, [])
        self.assertEqual(data["kind"], "read-only-decmpfs-catalogue-hints")
        self.assertEqual(data["schema_version"], 1)
        self.assertIn("candidate_declarations", data)
        self.assertTrue(json.loads(json.dumps(data)))


if __name__ == "__main__":
    unittest.main()
