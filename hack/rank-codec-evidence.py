#!/usr/bin/env python3
"""Rank all five Apple buffer codecs within identical verified Criterion cases.

Usage: rank-codec-evidence.py confidence.csv smoke|standard|extended output.csv
Ranks are descriptive within one macOS host/run, not claims of native APFS
support or statistically established differences between codec timings.
"""
import csv
import importlib.util
import io
import math
import os
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "applesauce_codec_comparison", HERE / "compare-codec-evidence.py"
)
assert SPEC is not None and SPEC.loader is not None
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)

CODECS = ("zlib", "lzfse", "lzbitmap", "lzmesh", "lzraven")
FIELDS = (
    *compare.GROUP, "codec", "encoded_over_input_ratio",
    "payload_rank", "payload_vs_best_x",
    "encode_median_mib_per_s", "encode_rank", "encode_slowdown_x",
    "decode_median_mib_per_s", "decode_rank", "decode_slowdown_x",
)


def rank_cases(source: Path, suite: str):
    expected = compare.matrix.expected_cases(suite)
    # Reuse the bounded, pinned regular-file gate of the paired-codec
    # reporter so FIFOs and substituted evidence cannot block this job.
    with io.StringIO(compare.read_confidence(source), newline="") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != compare.confidence.COLUMNS:
            raise ValueError("unknown confidence evidence schema")
        by_group = {}
        observed = set()
        for line_no, row in enumerate(reader, 2):
            if None in row or any(not isinstance(row.get(c), str)
                                  for c in compare.confidence.COLUMNS):
                raise ValueError(f"malformed confidence evidence row {line_no}")
            size = int(row["input_bytes"])
            key = (row["suite"], row["workload"], size, row["layout"],
                   row["codec"], row["scratch_mode"])
            if key not in expected or key in observed:
                raise ValueError(f"unexpected or duplicate benchmark case at row {line_no}")
            observed.add(key)
            if row["input_sha256"] != compare.matrix.GOLDEN_SHA256[size][row["workload"]]:
                raise ValueError(f"invalid golden fixture digest at row {line_no}")
            ratio = compare.positive_number(
                row["encoded_over_input_ratio"], "encoded payload ratio"
            )
            encode = compare.timings(row, "encode")[0]
            decode = compare.timings(row, "decode")[0]
            group = tuple(row[field] for field in compare.GROUP)
            by_group.setdefault(group, {})[row["codec"]] = (row, ratio, encode, decode)
    if observed != expected:
        raise ValueError(f"incomplete benchmark matrix: missing {len(expected - observed)} cases")
    results = []
    for group in sorted(by_group, key=lambda g: (g[0], g[1], int(g[2]), g[4], g[5])):
        cases = by_group[group]
        if set(cases) != set(CODECS):
            raise ValueError(f"incomplete five-codec group: {group}")
        rankings = []
        for metric in (1, 2, 3):
            rankings.append({
                codec: index + 1
                for index, codec in enumerate(sorted(
                    CODECS, key=lambda codec: (cases[codec][metric], codec)
                ))
            })
        best_ratio = min(item[1] for item in cases.values())
        best_encode = min(item[2] for item in cases.values())
        best_decode = min(item[3] for item in cases.values())
        for codec in CODECS:
            row, ratio, encode, decode = cases[codec]
            speed_unit = int(row["input_bytes"]) * 1e9 / 1048576
            payload_multiple = ratio / best_ratio
            encode_multiple = encode / best_encode
            decode_multiple = decode / best_decode
            if not all(math.isfinite(x) and x >= 1 - 1e-10
                       for x in (payload_multiple, encode_multiple, decode_multiple)):
                raise ValueError("invalid codec ranking")
            results.append({
                **dict(zip(compare.GROUP, group)),
                "codec": codec,
                "encoded_over_input_ratio": row["encoded_over_input_ratio"],
                "payload_rank": rankings[0][codec],
                "payload_vs_best_x": f"{payload_multiple:.4f}",
                "encode_median_mib_per_s": f"{speed_unit / encode:.4f}",
                "encode_rank": rankings[1][codec],
                "encode_slowdown_x": f"{encode_multiple:.3f}",
                "decode_median_mib_per_s": f"{speed_unit / decode:.4f}",
                "decode_rank": rankings[2][codec],
                "decode_slowdown_x": f"{decode_multiple:.3f}",
            })
    return results


def markdown(rows):
    relevant = [r for r in rows if
                r["workload"] == "mixed-jsonl" and
                r["scratch_mode"] == "reused-scratch" and
                r["input_bytes"] in ("1048576", "8388608")]
    lines = [
        "## All five Apple buffer codecs: same-fixture rankings",
        "",
        f"{len(rows)} validated cases; each cohort has five codecs on the same fixture, "
        "size, layout and scratch mode.",
        "Ranks: 1 is smallest compressed payload or fastest median encode/decode.",
        "Slowdown values compare median elapsed time with the fastest codec in the cohort.",
        "Rank differences are descriptive, not statistically significant verdicts.",
        "All measurements concern public Apple in-memory buffer APIs, not native APFS.",
        "",
        "| Size | Layout | Codec | Payload rank | Encode rank | Decode rank | Encode MiB/s |",
        "|---:|---|---|---:|---:|---:|---:|",
    ]
    for r in relevant:
        lines.append(
            f"| {int(r['input_bytes']) // 1024} KiB | {r['layout']} | "
            f"{r['codec']} | {r['payload_rank']} | {r['encode_rank']} | "
            f"{r['decode_rank']} | {r['encode_median_mib_per_s']} |"
        )
    lines.extend(("", "Full ratio and both encode/decode speed rankings are in "
                  "all-codecs-ranking.csv."))
    return "\n".join(lines)


def write_csv(rows, destination: Path):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", newline="", encoding="utf-8", dir=destination.parent,
            prefix=f".{destination.name}.", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            writer = csv.DictWriter(stream, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        source, suite, dest = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
        if dest.resolve() == source.resolve() or (
            dest.exists() and os.path.samefile(dest, source)
        ):
            raise ValueError("ranking output must differ from source evidence")
        dest.unlink(missing_ok=True)
        rows = rank_cases(source, suite)
        write_csv(rows, dest)
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as exc:
        print(f"invalid five-codec ranking evidence: {exc}", file=sys.stderr)
        return 1
    print(markdown(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
