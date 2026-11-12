"""Regression cases for retained second-LZRAVEN evidence acceptance."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from validate_second_raven_reports import (COMMITTED_ARCHIVE_SHA256, FAMILIES,
                                           NEGATIVE_CASES, SIZES, STATUS,
                                           expected_clear_sha256, validate)


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
        self.upstream = self.root / "upstream"
        self.upstream.mkdir()
        (self.upstream / "tests").mkdir()
        for path in ("lzraven.c", "lzraven.h", "lzbitmap.c", "lzbitmap.h",
                     "lzmesh.c", "lzmesh.h", "tests/test.c", "tests/vectors.h"):
            (self.upstream / path).write_text("test source")
        self.decoder = self.root / "decoder"
        self.decoder.write_bytes(b"test decoder")
        self.decoder_sha = sha(b"test decoder")
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.cli = self.root / "applesauce-cli"
        self.cli.write_bytes(b"test Apple encoder placeholder")
        self.rows = {}
        for size in SIZES:
            for family in FAMILIES:
                row = self.positive(size, family)
                self.rows[family, size] = row
                self.write(f"fresh/{family}-{size}.json", row)
        committed = []
        for size in (65537, 131103):
            row = self.positive(size, "records")
            row["archive_sha256"] = COMMITTED_ARCHIVE_SHA256[size]
            committed.append({k: v for k, v in row.items() if k != "schema_version"})
        self.write("committed.json", {"schema_version": 1, "vectors": committed})
        for family in FAMILIES:
            self.write(f"negative/{family}.json", {
                "schema_version": 1,
                "status": "independent_corruptions_rejected",
                "codec": "lzraven",
                "case_count": len(NEGATIVE_CASES),
                "cases": [{"case": name, "archive_sha256": sha(name.encode()),
                           "rejection": "independent decoder failed"}
                          for name in sorted(NEGATIVE_CASES)],
                "baseline_archive_sha256": self.rows[family, 131103]["archive_sha256"],
                "baseline_original_sha256": self.rows[family, 131103]["original_sha256"],
                "baseline_decoder_sha256": self.decoder_sha,
            })

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
                            self.repo, fresh=fresh,
                            cli=self.cli if fresh else None)

    def test_complete_evidence_passes(self):
        result = self.check()
        self.assertEqual(result["committed_vectors_verified"], 2)
        self.assertEqual(result["fresh_vectors_verified"], 10)
        self.assertEqual(result["corruptions_rejected"], 18)
        self.assertEqual(len(result["report_sha256"]), 13)

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
