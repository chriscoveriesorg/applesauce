#!/usr/bin/env python3
"""Export macOS /usr/bin/time -l whole-invocation telemetry from Criterion log.

Usage: parse-benchmark-resources.py criterion.log resource-usage.json
The benchmark timed command is cargo bench, so CPU/RSS measurements include
Cargo and its subprocesses. They cannot be assigned to individual codecs.
The resident-set value is not a Rust allocation count.
"""
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

MAX_LOG_BYTES = 8 * 1024 * 1024
# Darwin time -l can put the three durations on one line or separate lines.
_TIME = re.compile(r"^\s*(?:(\d+(?:\.\d+)?)\s+(real|user|sys)|(real|user|sys)\s+(\d+(?:\.\d+)?))\s*$")
_TRIPLE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s+real\s+(\d+(?:\.\d+)?)\s+user\s+(\d+(?:\.\d+)?)\s+sys\s*$")
_RSS = re.compile(r"^\s*(\d+)\s+maximum resident set size\s*$")


def read_log(path: Path) -> bytes:
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK")):
        raise ValueError("safe log reading requires O_NOFOLLOW and O_NONBLOCK")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_LOG_BYTES:
            raise ValueError("Criterion log must be a nonempty regular file below 8 MiB")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(before.st_size + 1)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(data) != before.st_size or any(
            getattr(before, key) != getattr(after, key) for key in fields
        ):
            raise ValueError("Criterion log changed during read")
        named = os.stat(path, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError("Criterion log pathname changed")
        return data
    finally:
        os.close(descriptor)


def parse(log: bytes) -> dict:
    lines = log.decode("utf-8").splitlines()
    # This report must occur at the END; Criterion text may mention these
    # labels in earlier output.
    tail = [line for line in lines[-25:] if line.strip()]
    durations = {}
    resident = []
    for line in tail:
        triple = _TRIPLE.fullmatch(line)
        if triple:
            for key, value in zip(("real", "user", "sys"), triple.groups()):
                if key in durations:
                    raise ValueError(f"duplicate time measurement: {key}")
                durations[key] = float(value)
            continue
        match = _TIME.fullmatch(line)
        if match:
            value, key = ((match.group(1), match.group(2)) if match.group(1)
                          else (match.group(4), match.group(3)))
            if key in durations:
                raise ValueError(f"duplicate time measurement: {key}")
            durations[key] = float(value)
        rss = _RSS.fullmatch(line)
        if rss:
            resident.append(int(rss.group(1)))
    if set(durations) != {"real", "user", "sys"} or len(resident) != 1:
        raise ValueError("missing or ambiguous macOS time -l trailer")
    if any(not math.isfinite(value) or value < 0 for value in durations.values()):
        raise ValueError("invalid duration in macOS time output")
    if durations["real"] <= 0 or resident[0] <= 0:
        raise ValueError("invalid wall time or maximum resident size")
    return {
        "schema_version": 1,
        "scope": "whole cargo bench invocation (build and harness included)",
        "rss_scope": "macOS /usr/bin/time -l maximum resident set size, bytes; not per-codec allocations",
        "wall_seconds": durations["real"],
        "user_cpu_seconds": durations["user"],
        "system_cpu_seconds": durations["sys"],
        "maximum_resident_bytes": resident[0],
        "criterion_log_sha256": hashlib.sha256(log).hexdigest(),
    }


def export(source: Path, output: Path) -> dict:
    if output.resolve() == source.resolve() or (
        output.exists() and os.path.samefile(output, source)
    ):
        raise ValueError("resource output must differ from Criterion log")
    # Avoid uploading a prior run's resource evidence after a failed rerun.
    output.unlink(missing_ok=True)
    report = parse(read_log(source))
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output.parent,
            prefix=f".{output.name}.", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write("\n")
        os.replace(temporary, output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return report


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        result = export(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"invalid macOS benchmark resource evidence: {exc}", file=sys.stderr)
        return 1
    print(f"Whole-command CPU {result['user_cpu_seconds'] + result['system_cpu_seconds']:.2f}s; "
          f"peak RSS {result['maximum_resident_bytes'] / 1048576:.1f} MiB "
          "(includes Cargo; not per codec)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
