#!/usr/bin/env python3
"""Validate a complete disposable APFS auto-codec benchmark and summarize measured results.

Usage: native-auto-evidence.py native-auto-benchmark.log

Only measured file allocation and wall-clock time are compared. This is not a
statistical performance claim or evidence for experimental native codecs.
"""
import csv
import io
from pathlib import Path
import statistics
import sys

HEADER = (
    "fixture", "codec", "repeat", "logical_bytes", "allocated_bytes",
    "elapsed_microseconds", "compressed",
)
FIXTURES = ("repeated", "jsonl", "mixed")
CODECS = ("zlib", "lzvn", "lzfse", "auto")
REPEATS = range(4)
MAX_LOG_BYTES = 1024 * 1024


def parse_log(content: str) -> dict[tuple[str, str, int], tuple[int, int, int]]:
    if len(content.encode("utf-8")) > MAX_LOG_BYTES:
        raise ValueError("benchmark log exceeds 1 MiB")
    rows = {}
    seen_header = False
    for line in content.splitlines():
        if line == ",".join(HEADER):
            if seen_header:
                raise ValueError("duplicate benchmark CSV header")
            seen_header = True
            continue
        if not line.startswith(tuple(f + "," for f in FIXTURES)):
            continue
        fields = next(csv.reader(io.StringIO(line), strict=True))
        if len(fields) != len(HEADER):
            raise ValueError("invalid benchmark CSV column count")
        fixture, codec, repeat, logical, allocation, elapsed, compressed = fields
        if codec not in CODECS or compressed != "true":
            raise ValueError(f"unknown codec or uncompressed result: {fixture}/{codec}")
        try:
            repeat, logical, allocation, elapsed = map(
                int, (repeat, logical, allocation, elapsed)
            )
        except ValueError as error:
            raise ValueError("invalid benchmark numeric field") from error
        if repeat not in REPEATS or not (0 < logical <= 64 * 1024 * 1024):
            raise ValueError("invalid repeat or logical file size")
        if allocation <= 0 or elapsed <= 0:
            raise ValueError("invalid measured allocation or elapsed time")
        key = (fixture, codec, repeat)
        if key in rows:
            raise ValueError(f"duplicate benchmark row: {key}")
        rows[key] = (logical, allocation, elapsed)
    if not seen_header:
        raise ValueError("benchmark CSV header missing")
    expected = {(f, c, n) for f in FIXTURES for c in CODECS for n in REPEATS}
    if rows.keys() != expected:
        missing = sorted(expected - rows.keys())
        raise ValueError(f"incomplete benchmark matrix: missing {missing[:4]}")
    for fixture in FIXTURES:
        logical_sizes = {rows[fixture, codec, n][0] for codec in CODECS for n in REPEATS}
        if len(logical_sizes) != 1:
            raise ValueError(f"fixture size differs between trials: {fixture}")
        for codec in CODECS:
            allocated = {rows[fixture, codec, n][1] for n in REPEATS}
            if len(allocated) != 1:
                raise ValueError(f"unstable allocation within {fixture}/{codec}")
    return rows


def report(rows: dict[tuple[str, str, int], tuple[int, int, int]]) -> str:
    lines = [
        "## Native auto APFS allocation and elapsed time",
        "",
        "Four disposable-file runs per codec, measured on the same macOS host. "
        "The fixed-codec baseline is the codec with the least allocated bytes; "
        "equal allocation ties use the lower median elapsed time.",
        "",
        "| Fixture | Logical bytes | Best fixed codec | Best fixed allocation | "
        "Auto allocation | Auto median ms | Best fixed median ms | Auto time delta |",
        "|---|---:|---|---:|---:|---:|---:|---:|",
    ]
    for fixture in FIXTURES:
        logical = rows[fixture, "auto", 0][0]
        def allocation(codec):
            return rows[fixture, codec, 0][1]
        def median_us(codec):
            return statistics.median(rows[fixture, codec, n][2] for n in REPEATS)
        fixed = min(CODECS[:-1], key=lambda codec: (allocation(codec), median_us(codec)))
        time_delta = 100 * (median_us("auto") / median_us(fixed) - 1)
        lines.append(
            f"| {fixture} | {logical:,} | {fixed} | {allocation(fixed):,} | "
            f"{allocation('auto'):,} | {median_us('auto') / 1000:.3f} | "
            f"{median_us(fixed) / 1000:.3f} | {time_delta:+.1f}% |"
        )
    lines.extend([
        "",
        "Allocation is the actual on-disk allocation reported by the macOS host. "
        "Times include CLI startup, sample selection, compression, mandatory "
        "verification and process overhead. Four samples cannot establish "
        "statistical significance. The auto heuristic may perform differently "
        "on other file contents and machines.",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: native-auto-evidence.py LOG", file=sys.stderr)
        return 2
    path = Path(argv[1])
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_LOG_BYTES:
            raise ValueError("log must be a non-symlink regular file below 1 MiB")
        print(report(parse_log(path.read_text(encoding="utf-8"))), end="")
        return 0
    except (ValueError, OSError, UnicodeError) as error:
        print(f"invalid native auto benchmark: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
