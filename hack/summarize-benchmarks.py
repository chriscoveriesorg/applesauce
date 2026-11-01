#!/usr/bin/env python3
"""Merge Criterion medians with the versioned Applesauce fixture manifest.

Usage: summarize-benchmarks.py manifest.csv target/criterion summary.csv
Only the Python standard library is required. Failure to find a measurement is
an error: an incomplete run should not look like a successful comparison.
"""

import csv
import json
import math
from pathlib import Path
import sys


FIELDS = (
    "schema_version",
    "fixture_version",
    "suite",
    "workload",
    "input_bytes",
    "input_sha256",
    "layout",
    "chunk_bytes",
    "codec",
    "scratch_mode",
    "encode_scratch_bytes",
    "decode_scratch_bytes",
    "encoded_bytes",
    "encoded_over_input_ratio",
    "verified_roundtrip",
)


def median_ns(root: Path, row: dict[str, str], operation: str) -> float:
    # Criterion 0.8.2 replaces slashes in each *group identifier* with '_',
    # then inserts directory separators between group, function and value.
    group_name = "_".join(
        ("apple-buffer", row["suite"], row["input_bytes"], row["workload"], row["layout"])
    )
    relative = (
        Path(group_name)
        / f"{row['codec']}-{row['scratch_mode']}"
        / operation
        / "new"
        / "estimates.json"
    )
    path = root / relative
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)["median"]["point_estimate"]
    # Python's JSON decoder permits nonstandard NaN/Infinity; malformed
    # types (including bool and numeric strings) are not Criterion estimates.
    if type(value) not in (int, float):
        raise ValueError(f"invalid {operation} median in {path}")
    try:
        duration = float(value)
    except (ValueError, OverflowError) as error:
        raise ValueError(f"invalid {operation} median in {path}") from error
    if not math.isfinite(duration) or duration <= 0:
        raise ValueError(f"invalid {operation} median in {path}")
    return duration


def summarize(manifest: Path, criterion: Path, output: Path) -> list[dict[str, str]]:
    with manifest.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError("unknown benchmark manifest schema")
        rows = list(reader)
    if not rows:
        raise ValueError("empty benchmark manifest")
    seen_cases: set[tuple[str, ...]] = set()
    for row in rows:
        if row["verified_roundtrip"] != "true":
            raise ValueError(f"unverified benchmark: {row}")
        if row["schema_version"] != "1" or row["fixture_version"] != "1":
            raise ValueError("unknown benchmark/fixture version")
        # A duplicate case can silently inflate reports or hide a corrupted
        # manifest; every codec/layout/scratch combination is unique.
        case = tuple(row[key] for key in (
            "suite", "workload", "input_bytes", "layout", "codec", "scratch_mode"
        ))
        if case in seen_cases:
            raise ValueError(f"duplicate benchmark case: {case}")
        seen_cases.add(case)
        size = int(row["input_bytes"])
        if size <= 0:
            raise ValueError(f"invalid benchmark input size: {size}")
        for operation in ("encode", "decode"):
            ns = median_ns(criterion, row, operation)
            row[f"{operation}_median_ns"] = f"{ns:.5f}"
            # MiB/s is explicitly binary, not decimal MB/s.
            row[f"{operation}_mib_per_s"] = f"{size * 1e9 / ns / 1048576:.4f}"

    extra = tuple(f"{op}_{metric}" for op in ("encode", "decode") for metric in ("median_ns", "mib_per_s"))
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS + extra)
        writer.writeheader()
        writer.writerows(rows)
    return rows


def markdown(rows: list[dict[str, str]]) -> str:
    # The headline is deliberately a small apples-to-apples slice. The CSV
    # retains every codec, size, layout, workload and scratch mode.
    available_sizes = {int(row["input_bytes"]) for row in rows}
    size = 1048576 if 1048576 in available_sizes else max(available_sizes)
    selected = [
        row
        for row in rows
        if int(row["input_bytes"]) == size
        and row["layout"] == "whole"
        and row["scratch_mode"] == "reused-scratch"
        and row["workload"] in ("chat-jsonl", "entropy")
    ]
    lines = [
        "## Apple buffer benchmark (Criterion median)",
        "",
        f"Same host, {size // 1024} KiB generated inputs; MiB/s = input bytes / measured time.",
        "These are **in-memory** public Compression.framework results, **not native APFS throughput**.",
        "",
        "| Workload | Codec | Payload / input | Encode MiB/s | Decode MiB/s |",
        "|---|---|---:|---:|---:|",
    ]
    for row in sorted(selected, key=lambda r: (r["workload"], r["codec"])):
        lines.append(
            f"| {row['workload']} | {row['codec']} | "
            f"{float(row['encoded_over_input_ratio']):.3f} | "
            f"{float(row['encode_mib_per_s']):.1f} | "
            f"{float(row['decode_mib_per_s']):.1f} |"
        )
    lines += [
        "",
        "Full per-case confidence intervals, samples, fixture SHA-256s,"
        " scratch sizes, and all layouts are in the retained raw artifacts.",
        "Hosted-runner variance means **no automated speed-regression verdict** is issued.",
    ]
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        rows = summarize(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"incomplete or invalid benchmark: {error}", file=sys.stderr)
        return 1
    print(markdown(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
