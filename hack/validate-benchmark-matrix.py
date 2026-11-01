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
GOLDEN_SHA256 = {
    4096: dict(zip(WORKLOADS, (
        "07a256be9b2ab3ed80348beab9b56e9977bfa2d1c026dd061eb2478dec7a0612",
        "b0b80bd6898d4ad4969efbef971d7d5ed43e4c9d57737603329f230dfb3e0921",
        "1f6beb395416bd78311e7b12d1acc403b16d5f677db8a4afde36a5d2f33a2b0f",
        "5ab396e6daeee64fd4889b272844b43b0b6dcb5e65ead66975500ebe03c205e2",
        "ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7",
    ))),
    65536: dict(zip(WORKLOADS, (
        "f7aa044146c520080ec1e9c4887df117089ba2fc2c2a3a980421360d9e3176d3",
        "0ed513f185de6f4d93c7afcccdbfd608cb4c14a3fea57751e9678e47cdb44fb5",
        "eb26bf0865f4cbf53283485b94323cc0c435ccb14709fcc9a584349d52bba4bb",
        "cd42c3209f13fef9f77f3390859af4198ee7a6c81383ec02638adfff0267f9b2",
        "de2f256064a0af797747c2b97505dc0b9f3df0de4f489eac731c23ae9ca9cc31",
    ))),
    1048576: dict(zip(WORKLOADS, (
        "985fc3368f0af07347e7528fac5981fe08e2e4f35acdb90e71d454fc38e12d1c",
        "1b7e5e1fb81fd69b3d4de27c5487bae65cbf1a07310f206b1c6db97655625ae7",
        "f63223f80a014f0c08ce9b8e8d3e8d9db27d55788c8ac99df6f5a6d5628fa6fd",
        "d9f0db54fbadcac9388453d2550e7208fe7ba0e5cbf8e2e4e4c4ec35f5f8fadf",
        "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58",
    ))),
    8388608: dict(zip(WORKLOADS, (
        "1761a12b0aa68d8a5fedf766d336c8f2fee4efdbb90eb7d4348e04fc8aa70a33",
        "e1f8bbfc8ffc471787955dbc3d3b3e4b659a81492d2733b9bc9007525b7b01d2",
        "6389fe3f4591b50b5ec92e528d223e29d56ee1cdeaa3a973445f2224837bea22",
        "89f8073d9d007af9b4ded4c6c04ca7d004cffb35e979daad7f806ad7df081eb3",
        "2daeb1f36095b44b318410b3f4e8b5d989dcc7bb023d1426c492dab0a3053e74",
    ))),
}

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
        if digest != GOLDEN_SHA256[size][row["workload"]]:
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
