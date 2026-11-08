#!/usr/bin/env python3
"""Compare Raven and Mesh on identical, verified Criterion benchmark fixtures.

Usage: compare-codec-evidence.py confidence.csv smoke|standard|extended output.csv
This consumes the existing confidence.csv. Derived speedup bounds use TWO
marginal 95% timing intervals and are NOT 95% confidence intervals for the
speedup ratio. The report is descriptive; hosted CI runners are noisy.
"""
import csv
import importlib.util
import math
import os
from pathlib import Path
import sys
import tempfile

_HERE = Path(__file__).resolve().parent


def load_module(filename, name):
    spec = importlib.util.spec_from_file_location(name, _HERE / filename)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


confidence = load_module("criterion-confidence.py", "applesauce_confidence")
matrix = confidence._matrix

GROUP = ("suite", "workload", "input_bytes", "input_sha256", "layout", "scratch_mode")
OUT_FIELDS = (
    *GROUP, "raven_payload_ratio", "mesh_payload_ratio",
    "raven_savings_vs_mesh_pct",
    *(f"{op}_{field}" for op in ("encode", "decode")
      for field in ("mesh_speedup_x", "bound_low_x", "bound_high_x", "separation")),
)


def positive_number(value, description):
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"invalid {description}") from exc
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"invalid {description}")
    return result


def timings(row, operation):
    center = positive_number(row[f"{operation}_median_ns"], "median time")
    low = positive_number(row[f"{operation}_ci95_lower_ns"], "lower time")
    high = positive_number(row[f"{operation}_ci95_upper_ns"], "upper time")
    if low > center or center > high:
        raise ValueError("reversed or inconsistent median time interval")
    speed = positive_number(row[f"{operation}_median_mib_per_s"], "median throughput")
    size = int(row["input_bytes"])
    if not math.isclose(speed, size * 1e9 / 1048576 / center,
                        rel_tol=1e-5, abs_tol=0.0002):
        raise ValueError("confidence throughput disagrees with median time")
    return center, low, high


def compare(confidence_csv: Path, suite: str):
    expected = matrix.expected_cases(suite)
    with confidence_csv.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != confidence.COLUMNS:
            raise ValueError("unknown confidence.csv schema")
        rows = list(reader)
    actual = set()
    paired = {}
    for number, row in enumerate(rows, 1):
        if None in row or any(not isinstance(row.get(field), str)
                              for field in confidence.COLUMNS):
            raise ValueError(f"malformed confidence row {number}")
        size = int(row["input_bytes"])
        key = (row["suite"], row["workload"], size, row["layout"],
               row["codec"], row["scratch_mode"])
        if key not in expected or key in actual:
            raise ValueError(f"unexpected or duplicate benchmark case {key}")
        actual.add(key)
        if row["input_sha256"] != matrix.GOLDEN_SHA256[size][row["workload"]]:
            raise ValueError(f"wrong golden fixture digest in row {number}")
        if row["codec"] not in ("lzraven", "lzmesh"):
            continue
        group = tuple(row[field] for field in GROUP)
        paired.setdefault(group, {})[row["codec"]] = row
    if actual != expected:
        raise ValueError(f"incomplete benchmark matrix: missing {len(expected - actual)} cases")
    output = []
    for key, pair in sorted(paired.items()):
        if set(pair) != {"lzraven", "lzmesh"}:
            raise ValueError(f"incomplete Raven/Mesh comparison for {key}")
        raven, mesh = pair["lzraven"], pair["lzmesh"]
        r_ratio = positive_number(raven["encoded_over_input_ratio"], "Raven payload ratio")
        m_ratio = positive_number(mesh["encoded_over_input_ratio"], "Mesh payload ratio")
        result = dict(zip(GROUP, key))
        result.update(
            raven_payload_ratio=f"{r_ratio:.8f}",
            mesh_payload_ratio=f"{m_ratio:.8f}",
            raven_savings_vs_mesh_pct=f"{100 * (1 - r_ratio / m_ratio):.2f}",
        )
        for op in ("encode", "decode"):
            r_mid, r_low, r_high = timings(raven, op)
            m_mid, m_low, m_high = timings(mesh, op)
            # Throughput = common cleartext size / time. Thus Mesh/Raven
            # speedup = Raven time / Mesh time. Both marginal intervals
            # contribute: these bounds are NOT a 95% ratio CI.
            speedup = r_mid / m_mid
            low = r_low / m_high
            high = r_high / m_low
            if not all(math.isfinite(n) and n > 0 for n in (speedup, low, high)):
                raise ValueError(f"invalid {op} speedup bounds")
            separation = ("mesh-faster" if low > 1.0
                          else "raven-faster" if high < 1.0
                          else "overlap")
            result.update({
                f"{op}_mesh_speedup_x": f"{speedup:.3f}",
                f"{op}_bound_low_x": f"{low:.3f}",
                f"{op}_bound_high_x": f"{high:.3f}",
                f"{op}_separation": separation,
            })
        output.append(result)
    return output


def markdown(rows):
    notable = [row for row in rows
               if row["workload"] == "mixed-jsonl"
               and row["scratch_mode"] == "reused-scratch"
               and row["input_bytes"] in ("1048576", "8388608")]
    if not notable:
        notable = [row for row in rows
                   if row["workload"] == "chat-jsonl"
                   and row["scratch_mode"] == "reused-scratch"]
    lines = [
        "## Raven/Mesh same-fixture evidence",
        "",
        f"{len(rows)} pairs verified against the complete golden fixture matrix.",
        "Mesh/Raven speedup above 1 means Mesh is faster. The speedup bounds",
        "are derived from separate marginal 95% timing intervals; they are",
        "**not 95% confidence intervals for the speedup ratio**.",
        "Public in-memory Apple buffer codecs only, not native APFS.",
        "",
        "| Workload | Size | Layout | Mesh encode speedup | Derived bounds | Raven payload saving |",
        "|---|---:|---|---:|---:|---:|",
    ]
    for row in notable:
        lines.append(
            f"| {row['workload']} | {int(row['input_bytes']) // 1024} KiB "
            f"| {row['layout']} | {row['encode_mesh_speedup_x']}x "
            f"| {row['encode_bound_low_x']}–{row['encode_bound_high_x']}x "
            f"| {row['raven_savings_vs_mesh_pct']}% |"
        )
    lines.extend(("", "All matched encode/decode cases and their bounds are in raven-mesh-comparison.csv.",
                  "No automatic speed-regression verdict is issued on shared runners."))
    return "\n".join(lines)


def emit(rows, destination: Path):
    temp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", newline="", encoding="utf-8", dir=destination.parent,
            prefix=f".{destination.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temp = Path(handle.name)
            writer = csv.DictWriter(handle, fieldnames=OUT_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temp, destination)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        source, suite, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
        if output.resolve() == source.resolve():
            raise ValueError("comparison output must differ from confidence evidence")
        # The workflow retains artifacts even after a failed job. Avoid
        # presenting a previous run's paired comparison as current evidence.
        output.unlink(missing_ok=True)
        result = compare(source, suite)
        emit(result, output)
    except (OSError, ValueError, KeyError, OverflowError) as exc:
        print(f"incomplete Raven/Mesh comparison: {exc}", file=sys.stderr)
        return 1
    print(markdown(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
