"""Portable regression tests for the four-tool compression contract."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import family_contract as contract


def foldy(*, digest="a" * 64, path="logs/session.jsonl", identity="local:host:abc", size=28):
    return {
        "schema": "foldy_local_inventory/1", "status": "complete", "errors": [],
        "mount_skips": [], "sha256_content": True, "host": "host",
        "root": "/tmp/generated-corpus", "items": [
            {"Type": "file", "Path": path, "ID": identity, "Size": size,
             "Hashes": {"sha256": digest}, "mtime_ns": 1, "ctime_ns": 1, "inode": 2},
        ],
    }


def zgx(*, span=None, snippet="canary", hits=None):
    return {"type": "final", "quality": {"score": 0.91},
            "hits": hits if hits is not None else [
                ["logs/session.jsonl", span if span is not None else [1, 1], snippet, ["rg"]]
            ]}


class FamilyContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def write(self, name, obj):
        path = self.base / name
        path.write_text(json.dumps(obj) + "\n", encoding="utf-8")
        return path

    def execute(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = contract.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def test_all_pairs_pass_despite_changed_metadata_scores_and_sources(self):
        b = self.write("foldy-before.json", foldy())
        after = foldy()
        after["items"][0].update({"mtime_ns": 43, "ctime_ns": 44, "inode": 45})
        a = self.write("foldy-after.json", after)
        z1 = self.write("zgx-before.jsonl", zgx())
        next_result = zgx(hits=[{"path": "logs/session.jsonl", "span": [1, 1],
                                 "snippet": "canary", "score": 0.11, "sources": ["bm25"]}])
        z2 = self.write("zgx-after.jsonl", next_result)
        rc, output, err = self.execute("--foldy-before", str(b), "--foldy-after", str(a),
                                       "--zgx-before", str(z1), "--zgx-after", str(z2),
                                       "--physical-before-bytes", "8192", "--physical-after-bytes", "4096",
                                       "--require-physical-saving")
        self.assertEqual(0, rc, err)
        self.assertEqual({"schema": "applesauce_family_contract/1", "passed": True,
                          "foldy_files_unchanged": 1, "zgx_hits_unchanged": 1,
                          "physical_bytes_saved": 4096}, json.loads(output))

    def test_hash_change_fails(self):
        b = self.write("b.json", foldy())
        a = self.write("a.json", foldy(digest="b" * 64))
        rc, _, _ = self.execute("--foldy-before", str(b), "--foldy-after", str(a))
        self.assertEqual(1, rc)

    def test_path_and_stable_identity_changes_fail(self):
        for variant in (foldy(path="moved.jsonl"), foldy(identity="local:host:different"),
                        foldy(size=29)):
            with self.subTest(variant=variant):
                b = self.write("b.json", foldy())
                a = self.write("a.json", variant)
                self.assertEqual(1, self.execute("--foldy-before", str(b),
                                                 "--foldy-after", str(a))[0])

    def test_partial_unhashed_or_empty_inventory_fails(self):
        for variant in (dict(foldy(), status="partial"), dict(foldy(), sha256_content=False),
                        dict(foldy(), items=[]), dict(foldy(), mount_skips=["other"]),
                        foldy(digest="xyz")):
            with self.subTest(variant=variant):
                b = self.write("b.json", foldy())
                a = self.write("a.json", variant)
                self.assertEqual(1, self.execute("--foldy-before", str(b),
                                                 "--foldy-after", str(a))[0])

    def test_zgx_snippet_span_and_order_changes_fail(self):
        b = self.write("before.jsonl", zgx(hits=[
            ["first.jsonl", 1, "canary", ["rg"]], ["second.jsonl", [2, 4], "canary", ["rg"]]]))
        variants = [zgx(hits=[["first.jsonl", 1, "edited", ["rg"]],
                              ["second.jsonl", [2, 4], "canary", ["rg"]]]),
                    zgx(hits=[["first.jsonl", 2, "canary", ["rg"]],
                              ["second.jsonl", [2, 4], "canary", ["rg"]]]),
                    zgx(hits=[["second.jsonl", [2, 4], "canary", ["rg"]],
                              ["first.jsonl", 1, "canary", ["rg"]]])]
        for variant in variants:
            with self.subTest(variant=variant):
                a = self.write("after.jsonl", variant)
                self.assertEqual(1, self.execute("--zgx-before", str(b),
                                                 "--zgx-after", str(a))[0])

    def test_trace_records_and_non_ascii_separator_in_snippets(self):
        b = self.base / "before.jsonl"
        b.write_text(json.dumps({"type": "leg", "name": "rg"}) + "\n" +
                     json.dumps(zgx(snippet="a\u2028b"), ensure_ascii=False) + "\n", encoding="utf-8")
        a = self.write("after.jsonl", zgx(snippet="a\u2028b"))
        self.assertEqual(0, self.execute("--zgx-before", str(b), "--zgx-after", str(a))[0])

    def test_empty_zgx_results_fail_closed(self):
        b = self.write("before.jsonl", zgx(hits=[]))
        a = self.write("after.jsonl", zgx(hits=[]))
        self.assertEqual(1, self.execute("--zgx-before", str(b), "--zgx-after", str(a))[0])

    def test_measurement_requires_real_saving(self):
        b = self.write("before.jsonl", zgx())
        a = self.write("after.jsonl", zgx())
        rc, _, err = self.execute("--zgx-before", str(b), "--zgx-after", str(a),
                                   "--physical-before-bytes", "4096", "--physical-after-bytes", "8192",
                                   "--require-physical-saving")
        self.assertEqual(1, rc)
        self.assertIn("no measured physical allocation saving", err)


if __name__ == "__main__":
    unittest.main()
