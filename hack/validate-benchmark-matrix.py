#!/usr/bin/env python3
"""Reject incomplete or internally inconsistent Criterion fixture manifests.

Usage: python3 hack/validate-benchmark-matrix.py manifest.csv smoke|standard|extended
The expected v1 workload matrix is intentionally independent of the Rust
benchmark implementation, so an accidentally skipped codec cannot be treated
as a legitimate speed comparison.
"""

import csv
import math
from pathlib import Path
import re
import sys


CODECS = ("zlib", "lzfse", "lzbitmap", "lzmesh", "lzraven")
WORKLOADS = ("chat-jsonl", "mixed-jsonl", "binary-records", "entropy", "zeros")
SIZES = {
    "smoke": (65536,),
    "standard": (4096, 65536, 1048576),
    "extended": (4096, 65536, 1048576, 8388608),
}
GOLDEN_64K = dict(
    zip(
        WORKLOADS,
        (
            "f7aa044146c520080ec1e9c4887df117089ba2fc2c2a3a980421360d9e3176d3",
            "0ed513f185de6f4d93c7afcccdbfd608cb4c14a3fea57751e9678e47cdb44fb5",
            "eb26bf0865f4cbf53283485b94323cc0c435ccb14709fcc9a584349d52bba4bb",
            "cd42c3209f13fef9f77f3390859af4198ee7a6c81383ec02638adfff0267f9b2",
            "de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31",
        ),
    )
)

FIELDS = (
    "schema_version", "fixture_version", "suite", "workload", "input_bytes",
    "input_sha256", "layout", "chunk_bytes", "codec", "scratch_mode",
    "encode_scratch_bytes", "decode_scratch_bytes", "encoded_bytes",
    "encoded_over_input_ratio", "verified_roundtrip",
)


def expected_cases(suite: str) -> set[tuple[str, str, int, str, str, str]]:
    if suite not in SIZES:
        raise ValueError(f"unknown suite: {suite}")
    workloads = ("chat-jsonl", "entropy") if suite == "smoke" else WORKLOADS
    cases = set()
    for workload in workloads:
        for size in SIZES[suite]:
            layouts = ("whole", "independent-64k") if size >= 1048576 else ("whole",)
            for layout in layouts:
                for codec in CODECS:
                    modes = ("reused-scratch",)
                    if suite in ("smoke", "extended") or (
                        layout == "whole"
                        and size in (65536, 1048576)
                        and workload in ("chat-jsonl", "entropy")
                    ):
                        modes = ("api-managed", "reused-scratch")
                    for mode in modes:
                        cases.add((suite, workload, size, layout, codec, mode))
    return cases


def validate(manifest: Path, suite: str) -> int:
    expected = expected_cases(suite)
    with manifest.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError("unknown benchmark manifest schema")
        rows = list(reader)

    seen = set()
    hashes = {}
    for index, row in enumerate(rows, 1):
        # csv.DictReader stores excess cells under the None key. Checking
        # only the named fields would silently accept an extended CSV row.
        if None in row:
            raise ValueError(f"row {index}: unexpected trailing CSV columns")
        if not all(isinstance(row.get(field), str) for field in FIELDS):
            raise ValueError(f"row {index}: missing/extra fields")
        if row["schema_version"] != "1" or row["fixture_version"] != "1":
            raise ValueError(f"row {index}: unknown benchmark or fixture version")
        if row["verified_roundtrip"] != "true":
            raise ValueError(f"row {index}: round trip not verified")
        size = int(row["input_bytes"])
        case = (
            row["suite"], row["workload"], size,
            row["layout"], row["codec"], row["scratch_mode"],
        )
        if case not in expected:
            raise ValueError(f"row {index}: unexpected benchmark case {case}")
        if case in seen:
            raise ValueError(f"row {index}: duplicate benchmark case {case}")
        seen.add(case)

        digest = row["input_sha256"]
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError(f"row {index}: invalid fixture SHA-256")
        if size == 65536 and digest != GOLDEN_64K[row["workload"]]:
            raise ValueError(f"row {index}: fixture SHA-256 differs from v1 golden")
        fixture = (row["workload"], size)
        if fixture in hashes and hashes[fixture] != digest:
            raise ValueError(f"row {index}: inconsistent fixture SHA-256")
        hashes[fixture] = digest

        chunk_size = size if row["layout"] == "whole" else 65536
        if int(row["chunk_bytes"]) != chunk_size:
            raise ValueError(f"row {index}: incorrect chunk size")
        encoded_bytes = int(row["encoded_bytes"])
        ratio = float(row["encoded_over_input_ratio"])
        if encoded_bytes <= 0 or not math.isfinite(ratio) or not math.isclose(
            ratio, encoded_bytes / size, rel_tol=0, abs_tol=1e-8
        ):
            raise ValueError(f"row {index}: invalid encoded size or ratio")
        for field in ("encode_scratch_bytes", "decode_scratch_bytes"):
            value = row[field]
            if row["scratch_mode"] == "api-managed":
                if value != "n/a":
                    raise ValueError(f"row {index}: API-managed scratch must be n/a")
            elif not value.isdecimal() or int(value) > 128 * 1024 * 1024:
                raise ValueError(f"row {index}: invalid reusable scratch size")

    missing = expected - seen
    if missing:
        sample = sorted(missing)[:5]
        raise ValueError(
            f"incomplete {suite} suite: expected {len(expected)} cases, got {len(seen)}; "
            f"first missing cases: {sample}"
        )
    return len(seen)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        count = validate(Path(sys.argv[1]), sys.argv[2])
    except (OSError, ValueError, KeyError) as error:
        print(f"INVALID benchmark matrix: {error}", file=sys.stderr)
        return 1
    print(f"PASS: complete {sys.argv[2]} benchmark matrix ({count} verified codec cases)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
