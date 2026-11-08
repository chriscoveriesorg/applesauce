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
import stat
import io
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
MAX_CONFIDENCE_BYTES = 1024 * 1024

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
    size = int(row["input_bytes"])
    bytes_per_second = size * 1e9 / 1048576
    for field, elapsed in (("median", center), ("ci95_lower", high),
                           ("ci95_upper", low)):
        throughput = positive_number(row[f"{operation}_{field}_mib_per_s"],
                                     f"{field} throughput")
        if not math.isclose(throughput, bytes_per_second / elapsed,
                            rel_tol=1e-5, abs_tol=0.000051):
            raise ValueError("confidence throughput disagrees with timing interval")
    return center, low, high


def read_confidence(path: Path):
    """Read only bounded, stable regular-file benchmark evidence."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
        raise OSError("safe confidence reads require O_NOFOLLOW and O_NONBLOCK")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("confidence evidence must be a regular file")
        if not 0 < before.st_size <= MAX_CONFIDENCE_BYTES:
            raise ValueError("empty or oversized confidence evidence")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(before.st_size + 1)
        after = os.fstat(fd)
        attrs = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(data) != before.st_size or any(
            getattr(before, attr) != getattr(after, attr) for attr in attrs
        ):
            raise ValueError("confidence evidence changed while reading")
        named = os.stat(path, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError("confidence evidence path was replaced")
        return data.decode("utf-8")
    finally:
        os.close(fd)


def compare(confidence_csv: Path, suite: str):
    expected = matrix.expected_cases(suite)
    with io.StringIO(read_confidence(confidence_csv), newline="") as stream:
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
        # Subtract before dividing: 1 - (r/m) can round to zero for
        # adjacent positive floats, hiding a real payload difference.
        savings_pct = 100 * ((m_ratio - r_ratio) / m_ratio)
        if not math.isfinite(savings_pct):
            raise ValueError("nonfinite Raven/Mesh payload savings")
        result = dict(zip(GROUP, key))
        result.update(
            # Round-trip representations keep the published input ratios
            # consistent with the full-precision savings calculation.
            raven_payload_ratio=repr(r_ratio),
            mesh_payload_ratio=repr(m_ratio),
            raven_savings_vs_mesh_pct=(
                repr(savings_pct) if savings_pct != 0 and (
                    abs(float(f"{savings_pct:.2f}") - savings_pct) /
                    abs(savings_pct) > 0.01
                ) else f"{savings_pct:.2f}"
            ),
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
                f"{op}_mesh_speedup_x": format_speedup(speedup),
                f"{op}_bound_low_x": format_speedup(low),
                f"{op}_bound_high_x": format_speedup(high),
                f"{op}_separation": separation,
            })
        output.append(result)
    return output


def format_speedup(value):
    """Keep tiny positive speedups nonzero in the published CSV."""
    fixed = f"{value:.3f}"
    # Rounding across unity must not contradict the separation verdict.
    # Retain extra precision only for near-unity values that round to 1.000.
    if fixed == "1.000" and value != 1.0:
        return repr(value)
    # Three decimals can materially distort small, nonzero ratios (for
    # example 0.0005 -> 0.001). Preserve at least three significant digits
    # whenever the rounded value differs by more than 1%.
    rounded = float(fixed)
    if rounded <= 0 or abs(rounded - value) / value > 0.01:
        return repr(value)
    return fixed


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
        if output.resolve() == source.resolve() or (
            output.exists() and os.path.samefile(output, source)
        ):
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
