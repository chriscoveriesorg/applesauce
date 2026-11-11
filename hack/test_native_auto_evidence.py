"""Portable strict-matrix and allocation-evidence regressions."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SOURCE = Path(__file__).with_name("native-auto-evidence.py")
SPEC = importlib.util.spec_from_file_location("native_auto_evidence", SOURCE)
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def sample_log():
    output = [",".join(module.HEADER)]
    for fixture, size in (("repeated", 2097152), ("jsonl", 1228890), ("mixed", 2097152)):
        for codec in module.CODECS:
            for repeat in module.REPEATS:
                allocated = {
                    "zlib": 4096, "lzvn": 16384,
                    "lzfse": 8192, "auto": 4096,
                }[codec]
                output.append(
                    f"{fixture},{codec},{repeat},{size},{allocated},"
                    f"{10000 + repeat * 100},true"
                )
    return "\n".join(output) + "\n"


class EvidenceTests(unittest.TestCase):
    def test_complete_matrix_produces_a_report(self):
        parsed = module.parse_log("running 1 test\n" + sample_log() + "test ... ok\n")
        self.assertEqual(len(parsed), 48)
        report = module.report(parsed)
        self.assertIn("| repeated |", report)
        self.assertIn("| mixed |", report)
        self.assertIn("Four disposable-file runs", report)

    def test_reject_duplicate_trial(self):
        data = sample_log()
        with self.assertRaisesRegex(ValueError, "duplicate benchmark row"):
            module.parse_log(data + data.splitlines()[1] + "\n")

    def test_reject_missing_trial(self):
        lines = sample_log().splitlines()
        with self.assertRaisesRegex(ValueError, "incomplete benchmark matrix"):
            module.parse_log("\n".join(lines[:-1]))

    def test_reject_uncompressed_or_unknown_codec(self):
        with self.assertRaisesRegex(ValueError, "uncompressed"):
            module.parse_log(sample_log().replace(",true", ",false", 1))
        with self.assertRaisesRegex(ValueError, "unknown codec"):
            module.parse_log(sample_log().replace(",zlib,", ",lzraven,", 1))

    def test_reject_mismatched_fixture_sizes(self):
        with self.assertRaisesRegex(ValueError, "fixture size differs"):
            module.parse_log(sample_log().replace(",2097152,4096,", ",1048576,4096,", 1))

    def test_reject_inconsistent_allocation(self):
        with self.assertRaisesRegex(ValueError, "unstable allocation"):
            module.parse_log(sample_log().replace(",2097152,4096,10000", ",2097152,8192,10000", 1))

    def test_reject_auto_worse_than_best_fixed_codec(self):
        # Preserve a complete, internally consistent 48-row matrix. A
        # benchmark that allocates more than the best fixed codec fails
        # acceptance even when every compression/readback trial succeeded.
        data = sample_log()
        for repeat in module.REPEATS:
            data = data.replace(
                f"repeated,auto,{repeat},2097152,4096,",
                f"repeated,auto,{repeat},2097152,12288,",
            )
        with self.assertRaisesRegex(ValueError, "auto allocation regression for repeated"):
            module.parse_log(data)

    def test_equal_allocation_passes_acceptance(self):
        # Baseline is inclusive: matching the best fixed codec is sufficient.
        rows = module.parse_log(sample_log())
        self.assertEqual(rows["repeated", "auto", 0][1], 4096)

    def test_reject_duplicated_header(self):
        with self.assertRaisesRegex(ValueError, "duplicate benchmark CSV header"):
            module.parse_log(sample_log() + ",".join(module.HEADER) + "\n")

    def test_reject_non_numeric_and_zero_duration(self):
        with self.assertRaisesRegex(ValueError, "numeric"):
            module.parse_log(sample_log().replace(",4096,10000,", ",4096,NaN,", 1))
        with self.assertRaisesRegex(ValueError, "elapsed"):
            module.parse_log(sample_log().replace(",4096,10000,", ",4096,0,", 1))

    def test_reject_oversized_log(self):
        with self.assertRaisesRegex(ValueError, "1 MiB"):
            module.parse_log(sample_log() + "x" * module.MAX_LOG_BYTES)

    def test_cli_output_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bench.log"
            path.write_text(sample_log())
            self.assertEqual(module.main(["report", str(path)]), 0)
            alias = Path(tmp) / "alias.log"
            alias.symlink_to(path)
            self.assertEqual(module.main(["report", str(alias)]), 1)


if __name__ == "__main__":
    unittest.main()
