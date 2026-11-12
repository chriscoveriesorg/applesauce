"""Regression cases for retained second-LZRAVEN evidence acceptance."""

import copy
import hashlib
import json
import struct
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from validate_second_raven_reports import (COMMITTED_ARCHIVE_SHA256, FAMILIES,
                                           NEGATIVE_CASES, SIZES, STATUS,
                                           expected_clear, expected_clear_sha256,
                                           expected_negative_hashes, validate)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class QualificationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.reports = self.root / "reports"
        self.reports.mkdir()
        (self.reports / "fresh").mkdir()
        (self.reports / "negative").mkdir()
        (self.reports / "fresh-archives").mkdir()
        self.upstream = self.root / "upstream"
        self.upstream.mkdir()
        (self.upstream / "tests").mkdir()
        for path in ("lzraven.c", "lzraven.h", "lzbitmap.c", "lzbitmap.h",
                     "lzmesh.c", "lzmesh.h", "tests/test.c", "tests/vectors.h"):
            (self.upstream / path).write_text("test source")
        # Qualification bundles must retain exact reviewable compiler inputs.
        (self.reports / "retained-sources/tests").mkdir(parents=True)
        for name in ("lzraven.c", "lzraven.h", "lzbitmap.c", "lzbitmap.h",
                     "lzmesh.c", "lzmesh.h", "tests/test.c", "tests/vectors.h"):
            target = self.reports / "retained-sources" / name
            target.write_text((self.upstream / name).read_text())
        for name in ("upstream-tests.log", "adapter-tests.log", "evidence-tests.log",
                     "toolchain.txt"):
            (self.reports / name).write_text("qualification command passed\n")
        self.decoder = self.root / "decoder"
        self.decoder.write_bytes(b"test decoder")
        (self.reports / "second-raven-decoder").write_bytes(b"test decoder")
        self.decoder_sha = sha(b"test decoder")
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.cli = self.root / "applesauce-cli"
        self.cli.write_bytes(b"test Apple encoder placeholder")
        self.rows = {}
        for size in SIZES:
            for family in FAMILIES:
                archive = self.fixture_archive(size, family)
                (self.reports / f"fresh-archives/{family}-{size}.ascf").write_bytes(archive)
                row = self.positive(size, family)
                row["archive_sha256"] = sha(archive)
                self.rows[family, size] = row
                self.write(f"fresh/{family}-{size}.json", row)
        committed = []
        for size in (65537, 131103):
            row = self.positive(size, "records")
            row["archive_sha256"] = COMMITTED_ARCHIVE_SHA256[size]
            committed.append({k: v for k, v in row.items() if k != "schema_version"})
        self.write("committed.json", {"schema_version": 1, "vectors": committed})
        for family in FAMILIES:
            archive = (self.reports / f"fresh-archives/{family}-131103.ascf").read_bytes()
            hashes = expected_negative_hashes(archive)
            reasons = {
                "payload_one_third": "independent decoder failed on chunk 0 (exit 1)",
                "payload_middle": "independent decoder failed on chunk 0 (exit 1)",
                "payload_middle_chunk": "independent decoder failed on chunk 1 (exit 1)",
                "payload_final_chunk": "independent decoder failed on chunk 2 (exit 1)",
                "index_digest": "original chunk 0 differs from ASCF chunk digest",
                "middle_index_digest": "original chunk 1 differs from ASCF chunk digest",
                "final_index_digest": "original chunk 2 differs from ASCF chunk digest",
                "truncated_payload": "ASCF index points past EOF",
                "appended_payload": "ASCF payload has trailing bytes",
            }
            self.write(f"negative/{family}.json", {
                "schema_version": 1,
                "status": "independent_corruptions_rejected",
                "codec": "lzraven",
                "case_count": len(NEGATIVE_CASES),
                "cases": [{"case": name, "archive_sha256": hashes[name],
                           "rejection": reasons[name]}
                          for name in sorted(NEGATIVE_CASES)],
                "baseline_archive_sha256": self.rows[family, 131103]["archive_sha256"],
                "baseline_original_sha256": self.rows[family, 131103]["original_sha256"],
                "baseline_decoder_sha256": self.decoder_sha,
            })

    @staticmethod
    def fixture_archive(size, family):
        """Construct synthetic ASCF geometry with clear-byte payloads.

        This is NOT a valid LZRAVEN stream. Evidence-parser tests only inspect
        the retained archive layout and deterministic corruption digests.
        """
        clear = expected_clear(family, size)
        chunks = [clear[n:n + 65536] for n in range(0, len(clear), 65536)]
        header = struct.pack("<8sIIQII", b"ASCF0001", 0xD05, 65536,
                             size, len(chunks), 0) + bytes.fromhex(sha(clear))
        index = bytearray()
        payload = bytearray()
        offset = 64 + 48 * len(chunks)
        for chunk in chunks:
            index.extend(struct.pack("<QII", offset, len(chunk), len(chunk)))
            index.extend(bytes.fromhex(sha(chunk)))
            payload.extend(chunk)
            offset += len(chunk)
        return header + index + payload

    def positive(self, size, family):
        return {"schema_version": 1, "codec": "lzraven", "status": STATUS,
                "logical_size_bytes": size,
                "chunk_count": (size + 65535) // 65536,
                "archive_sha256": sha(f"archive:{family}:{size}".encode()),
                "original_sha256": expected_clear_sha256(family, size),
                "decoder_sha256": self.decoder_sha}

    def write(self, name, obj):
        (self.reports / name).write_text(json.dumps(obj))

    def read(self, name):
        return json.loads((self.reports / name).read_text())

    def check(self, fresh=True):
        with patch("validate_second_raven_reports.git_head",
                   side_effect=["6d97f1ab520821b4d326139fdf48b658f96ee5b9", "a" * 40]):
            return validate(self.reports, self.decoder, self.upstream,
                            self.repo, fresh=fresh, bundle=True,
                            cli=self.cli if fresh else None)

    def test_complete_evidence_passes(self):
        result = self.check()
        self.assertEqual(result["committed_vectors_verified"], 2)
        self.assertEqual(result["fresh_vectors_verified"], 10)
        self.assertEqual(result["corruptions_rejected"], 18)
        self.assertEqual(len(result["report_sha256"]), 13)
        self.assertEqual(len(result["fresh_archive_sha256"]), 10)
        self.assertEqual(len(result["retained_artifacts_sha256"]), 13)
        self.assertEqual(result["retained_artifacts_sha256"]["second-raven-decoder"],
                         self.decoder_sha)

    def test_retained_decoder_mutation_rejected(self):
        (self.reports / "second-raven-decoder").write_bytes(b"imposter decoder")
        with self.assertRaisesRegex(ValueError, "retained artifact digest mismatch"):
            self.check(fresh=False)

    def test_retained_source_mutation_rejected(self):
        (self.reports / "retained-sources/lzraven.c").write_text("altered source")
        with self.assertRaisesRegex(ValueError, "retained artifact digest mismatch"):
            self.check(fresh=False)

    def test_missing_retained_test_log_rejected(self):
        (self.reports / "evidence-tests.log").unlink()
        with self.assertRaisesRegex(ValueError, "missing retained evidence artifact"):
            self.check(fresh=False)

    def test_symlinked_retained_log_rejected(self):
        log = self.reports / "adapter-tests.log"
        other = self.root / "untrusted.log"
        other.write_bytes(log.read_bytes())
        log.unlink()
        log.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "missing retained evidence artifact"):
            self.check(fresh=False)

    def test_empty_retained_log_rejected(self):
        (self.reports / "toolchain.txt").write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "invalid retained evidence artifact"):
            self.check(fresh=False)

    def test_missing_archive_bytes_rejected(self):
        (self.reports / "fresh-archives/records-65537.ascf").unlink()
        with self.assertRaisesRegex(ValueError, "missing regular fresh archive"):
            self.check()

    def test_archive_bytes_must_match_decoded_report(self):
        path = self.reports / "fresh-archives/records-65537.ascf"
        archive = bytearray(path.read_bytes())
        archive[-1] ^= 0x40
        path.write_bytes(archive)
        with self.assertRaisesRegex(ValueError, "retained archive digest mismatch"):
            self.check()

    def test_archive_geometry_forgery_rejected(self):
        path = self.reports / "fresh-archives/digest-65535.ascf"
        archive = bytearray(path.read_bytes())
        archive[8:12] = (0xE05).to_bytes(4, "little")
        path.write_bytes(archive)
        row = self.read("fresh/digest-65535.json")
        row["archive_sha256"] = sha(archive)
        self.write("fresh/digest-65535.json", row)
        with self.assertRaisesRegex(ValueError, "retained archive metadata mismatch"):
            self.check()

    def test_negative_corruption_digest_forgery_rejected(self):
        row = self.read("negative/records.json")
        row["cases"][0]["archive_sha256"] = "0" * 64
        self.write("negative/records.json", row)
        with self.assertRaisesRegex(ValueError, "corruption bytes digest mismatch"):
            self.check()

    def test_false_decoder_rejection_rejected(self):
        row = self.read("negative/digest.json")
        case = next(c for c in row["cases"] if c["case"] == "payload_middle_chunk")
        case["rejection"] = "independent decoder failed on chunk 0 (exit 1)"
        self.write("negative/digest.json", row)
        with self.assertRaisesRegex(ValueError, "rejection is not from independent decoder"):
            self.check()

    def test_false_parser_rejection_rejected(self):
        row = self.read("negative/records.json")
        case = next(c for c in row["cases"] if c["case"] == "truncated_payload")
        case["rejection"] = "independent decoder failed on chunk 0 (exit 1)"
        self.write("negative/records.json", row)
        with self.assertRaisesRegex(ValueError, "unexpected parser rejection"):
            self.check()

    def test_symlinked_archive_rejected(self):
        path = self.reports / "fresh-archives/records-65535.ascf"
        target = self.root / "archived.ascf"
        target.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "missing regular fresh archive"):
            self.check()

    def test_portable_only_counts_only_committed(self):
        result = self.check(fresh=False)
        self.assertEqual(result["committed_vectors_verified"], 2)
        self.assertEqual(result["fresh_vectors_verified"], 0)
        self.assertEqual(result["corruptions_rejected"], 0)

    def test_committed_duplicate_rejected(self):
        data = self.read("committed.json")
        data["vectors"][1] = copy.deepcopy(data["vectors"][0])
        self.write("committed.json", data)
        with self.assertRaisesRegex(ValueError, "duplicate committed"):
            self.check()

    def test_committed_archive_digest_forgery_rejected(self):
        data = self.read("committed.json")
        data["vectors"][0]["archive_sha256"] = "0" * 64
        self.write("committed.json", data)
        with self.assertRaisesRegex(ValueError, "pinned fixture digest mismatch"):
            self.check(fresh=False)

    def test_committed_original_digest_forgery_rejected(self):
        data = self.read("committed.json")
        data["vectors"][1]["original_sha256"] = "f" * 64
        self.write("committed.json", data)
        with self.assertRaisesRegex(ValueError, "pinned fixture digest mismatch"):
            self.check(fresh=False)

    def test_wrong_fresh_content_digest_rejected(self):
        data = self.read("fresh/records-65535.json")
        data["original_sha256"] = "0" * 64
        self.write("fresh/records-65535.json", data)
        with self.assertRaisesRegex(ValueError, "generated content digest mismatch"):
            self.check()

    def test_repeated_family_passoff_rejected_even_with_matching_baseline(self):
        size = 131103
        self.write(f"fresh/digest-{size}.json", self.read(f"fresh/records-{size}.json"))
        negative = self.read("negative/digest.json")
        negative["baseline_archive_sha256"] = self.rows["records", size]["archive_sha256"]
        negative["baseline_original_sha256"] = self.rows["records", size]["original_sha256"]
        self.write("negative/digest.json", negative)
        with self.assertRaisesRegex(ValueError, "generated content digest mismatch"):
            self.check()

    def test_fresh_requires_apple_encoder_binary(self):
        with self.assertRaisesRegex(ValueError, "requires the Apple encoder CLI"):
            validate(self.reports, self.decoder, self.upstream,
                     self.repo, fresh=True, cli=None)

    def test_wrong_decoder_digest_rejected(self):
        data = self.read("fresh/records-65537.json")
        data["decoder_sha256"] = "0" * 64
        self.write("fresh/records-65537.json", data)
        with self.assertRaisesRegex(ValueError, "decoder digest mismatch"):
            self.check()

    def test_missing_fresh_report_rejected(self):
        (self.reports / "fresh/digest-65535.json").unlink()
        with self.assertRaisesRegex(ValueError, "missing regular report"):
            self.check()

    def test_duplicate_negative_case_rejected(self):
        data = self.read("negative/records.json")
        data["cases"][1] = copy.deepcopy(data["cases"][0])
        self.write("negative/records.json", data)
        with self.assertRaisesRegex(ValueError, "missing or duplicate corruption"):
            self.check()

    def test_negative_baseline_mismatch_rejected(self):
        data = self.read("negative/digest.json")
        data["baseline_archive_sha256"] = "0" * 64
        self.write("negative/digest.json", data)
        with self.assertRaisesRegex(ValueError, "negative baseline differs"):
            self.check()

    def test_unpinned_source_rejected(self):
        with patch("validate_second_raven_reports.git_head",
                   return_value="b" * 40):
            with self.assertRaisesRegex(ValueError, "not pinned"):
                validate(self.reports, self.decoder, self.upstream,
                         self.repo, fresh=False)

    def test_missing_rejection_reason_rejected(self):
        data = self.read("negative/digest.json")
        data["cases"][0]["rejection"] = ""
        self.write("negative/digest.json", data)
        with self.assertRaisesRegex(ValueError, "missing rejection"):
            self.check()

    def test_symlinked_report_rejected(self):
        path = self.reports / "committed.json"
        real = self.root / "replacement.json"
        real.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "missing regular report"):
            self.check()


if __name__ == "__main__":
    unittest.main()
