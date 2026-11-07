#!/usr/bin/env python3
"""Validate Criterion median 95% intervals and emit a per-case confidence CSV.

Usage: criterion-confidence.py summary.csv target/criterion confidence.csv
The existing summary.csv contract is unchanged. This tool is read-only except
for the new output CSV, and never runs a codec or touches APFS attributes.
"""
import csv
import importlib.util
import json
import math
from pathlib import Path
import sys

_SUMMARY_PATH = Path(__file__).with_name("summarize-benchmarks.py")
_SPEC = importlib.util.spec_from_file_location("applesauce_summary", _SUMMARY_PATH)
assert _SPEC and _SPEC.loader
_summary = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_summary)

IDENTITY = (
    "suite", "workload", "input_bytes", "input_sha256",
    "layout", "codec", "scratch_mode", "encoded_over_input_ratio",
)
METRICS = (
    "median_ns", "ci95_lower_ns", "ci95_upper_ns",
    "median_mib_per_s", "ci95_lower_mib_per_s", "ci95_upper_mib_per_s",
)
COLUMNS = IDENTITY + tuple(
    f"{operation}_{metric}"
    for operation in ("encode", "decode")
    for metric in METRICS
)
SUMMARY_COLUMNS = _summary.FIELDS + tuple(
    f"{operation}_{metric}"
    for operation in ("encode", "decode")
    for metric in ("median_ns", "mib_per_s")
)


def finite_positive(value, description):
    if type(value) not in (int, float):
        raise ValueError(f"{description} must be a finite positive number")
    converted = float(value)
    if not math.isfinite(converted) or converted <= 0:
        raise ValueError(f"{description} must be a finite positive number")
    return converted


def read_median_interval(root: Path, row: dict, operation: str):
    group = "_".join((
        "apple-buffer", row["suite"], row["input_bytes"],
        row["workload"], row["layout"],
    ))
    path = (
        root / group / f'{row["codec"]}-{row["scratch_mode"]}'
        / operation / "new" / "estimates.json"
    )
    with path.open(encoding="utf-8") as stream:
        estimates = json.load(stream)
    median = estimates["median"]
    center = finite_positive(median["point_estimate"], f"{path}: median")
    interval = median["confidence_interval"]
    level = interval["confidence_level"]
    if type(level) not in (int, float) or not math.isclose(level, 0.95, abs_tol=1e-12):
        raise ValueError(f"{path}: expected a Criterion 95% confidence interval")
    low = finite_positive(interval["lower_bound"], f"{path}: lower bound")
    high = finite_positive(interval["upper_bound"], f"{path}: upper bound")
    if low > center or center > high:
        raise ValueError(f"{path}: invalid or reversed median interval")
    return center, low, high


def confidence_rows(summary_csv: Path, criterion: Path):
    with summary_csv.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != SUMMARY_COLUMNS:
            raise ValueError("unrecognized benchmark summary schema")
        rows = list(reader)
    if not rows:
        raise ValueError("empty benchmark summary")
    output = []
    seen = set()
    for index, row in enumerate(rows, 1):
        if None in row or any(not isinstance(row.get(k), str) for k in SUMMARY_COLUMNS):
            raise ValueError(f"malformed summary row {index}")
        key = tuple(row[k] for k in IDENTITY[:-1])
        if key in seen:
            raise ValueError(f"duplicate benchmark case in summary row {index}")
        seen.add(key)
        # The summary was produced by summarize-benchmarks.py, which validates
        # the complete manifest. Refuse arbitrary identifiers before using them
        # as paths, including paths supplied in hand-edited summary files.
        valid = {
            "suite": ("smoke", "standard", "extended"),
            "workload": ("chat-jsonl", "mixed-jsonl", "binary-records", "entropy", "zeros"),
            "layout": ("whole", "independent-64k"),
            "codec": ("zlib", "lzfse", "lzbitmap", "lzmesh", "lzraven"),
            "scratch_mode": ("api-managed", "reused-scratch"),
        }
        if any(row[field] not in values for field, values in valid.items()):
            raise ValueError(f"unsupported benchmark identity in row {index}")
        size_text = row["input_bytes"]
        if size_text not in ("4096", "65536", "1048576", "8388608"):
            raise ValueError(f"invalid benchmark input size in row {index}")
        size = int(size_text)
        digest = row["input_sha256"]
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"invalid fixture digest in row {index}")
        result = {field: row[field] for field in IDENTITY}
        for operation in ("encode", "decode"):
            center, lower_ns, upper_ns = read_median_interval(criterion, row, operation)
            summary_center = finite_positive(
                float(row[f"{operation}_median_ns"]), "summary median"
            )
            if abs(center - summary_center) > 0.00001:
                raise ValueError(f"summary and Criterion {operation} median disagree in row {index}")
            mib = size * 1e9 / 1048576
            throughput = mib / center
            summary_speed = finite_positive(
                float(row[f"{operation}_mib_per_s"]), "summary throughput"
            )
            if abs(throughput - summary_speed) > 0.000051:
                raise ValueError(f"summary and Criterion {operation} throughput disagree in row {index}")
            # Transforming elapsed-time CI to throughput reverses the limits.
            values = (
                center, lower_ns, upper_ns,
                throughput, mib / upper_ns, mib / lower_ns,
            )
            if not all(math.isfinite(v) and v > 0 for v in values):
                raise ValueError(f"invalid {operation} throughput interval in row {index}")
            for metric, value in zip(METRICS, values):
                decimals = 5 if metric.endswith("_ns") else 4
                result[f"{operation}_{metric}"] = f"{value:.{decimals}f}"
        output.append(result)
    return output


def write_confidence(summary_csv: Path, criterion: Path, output: Path):
    rows = confidence_rows(summary_csv, criterion)
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        count = write_confidence(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    except (OSError, ValueError, KeyError, TypeError, OverflowError, json.JSONDecodeError) as exc:
        print(f"invalid or incomplete Criterion confidence evidence: {exc}", file=sys.stderr)
        return 1
    print(f"Validated Criterion 95% median intervals for {count} codec cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
