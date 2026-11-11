#!/usr/bin/env python3
"""Fail-closed corruption checks on genuine Apple-generated ASCF proof vectors.

Run the unmodified vector through the independent decoder first. Then reject
payload bit flips and index/length damage using that same decoder. These
checks exercise Apple's encoded bytes; synthetic parser tests alone cannot.
No filesystem-native compression or FSKit operations are performed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import time

from verify_independent_lzmesh import (
    DEFAULT_TOTAL_DECODE_TIMEOUT_SECONDS, InvalidArchive, identity,
    open_regular, require_unchanged, verify,
)

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
DEFAULT_NEGATIVE_SUITE_TIMEOUT_SECONDS = 180.0


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_corruptions(archive, original, decoder, *, codec,
                      total_timeout_seconds=DEFAULT_NEGATIVE_SUITE_TIMEOUT_SECONDS):
    if not 0 < total_timeout_seconds <= 3600:
        raise InvalidArchive("negative suite time budget must be between 0 and 3600 seconds")
    deadline = time.monotonic() + total_timeout_seconds

    def remaining_budget():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise InvalidArchive("negative proof suite exceeded total time budget")
        return remaining

    def verify_with_budget(path):
        # Bound all six validations to one deadline. A stalled decoder in an
        # intentionally damaged fixture must not multiply the per-proof cap.
        budget = min(DEFAULT_TOTAL_DECODE_TIMEOUT_SECONDS, remaining_budget())
        try:
            return verify(
                path, original, decoder, codec=codec,
                total_timeout_seconds=budget,
            )
        finally:
            # A timeout is a failed qualification, including on the last case.
            remaining_budget()

    archive = Path(archive)
    original = Path(original)
    decoder = Path(decoder)
    # Keep the original archive descriptor open across baseline decoding and
    # mutation construction. A pathname swap to a FIFO, symlink or an equally
    # sized replacement must not hang read_bytes() or change the proof input.
    # O_NONBLOCK/O_NOFOLLOW and fstat() in open_regular() reject special files.
    with open_regular(archive) as source:
        archive_snapshot = identity(os.fstat(source.fileno()))
        if archive_snapshot[3] > MAX_ARCHIVE_BYTES:
            raise InvalidArchive("negative-test archive exceeds fixture budget")

        # A decoder which fails every attempt must never produce a passing
        # report. The held descriptor pins the bytes used for later mutations.
        baseline = verify_with_budget(archive)
        data = source.read(MAX_ARCHIVE_BYTES + 1)
        if len(data) > MAX_ARCHIVE_BYTES:
            raise InvalidArchive("negative-test archive grew beyond fixture budget")
        require_unchanged(archive, archive_snapshot, source)
    if digest(data) != baseline["archive_sha256"]:
        raise InvalidArchive("negative-test source changed after baseline proof")

    offset, stored_len, _ = struct.unpack_from("<QII", data, 64)
    if stored_len < 3 or offset < 112 or offset + stored_len > len(data):
        raise InvalidArchive("negative tests require a nonempty validated chunk")

    mutations = {}
    for name, position in (
        ("payload_one_third", offset + stored_len // 3),
        ("payload_middle", offset + stored_len // 2),
    ):
        damaged = bytearray(data)
        damaged[position] ^= 0x40
        mutations[name] = bytes(damaged)

    digest_damage = bytearray(data)
    digest_damage[80] ^= 0x01  # First chunk SHA-256, not payload geometry.
    mutations["index_digest"] = bytes(digest_damage)
    mutations["truncated_payload"] = data[:-1]
    mutations["appended_payload"] = data + b"\x00"

    cases = []
    with tempfile.TemporaryDirectory(prefix="ascf-negative-proof-") as tmp:
        path = Path(tmp) / "corrupted.ascf"
        for name, damaged in mutations.items():
            path.write_bytes(damaged)
            try:
                verify_with_budget(path)
            except (InvalidArchive, OSError) as exc:
                message = str(exc)
                if "timed out" in message or "time budget" in message:
                    raise InvalidArchive(
                        f"{name} decoder timeout cannot qualify as corruption rejection"
                    ) from exc
                if name.startswith("payload_") and not (
                    "independent decoder" in message
                ):
                    raise AssertionError(
                        f"{name} failed before the independent decoder: {message}"
                    ) from exc
                expected_parser_failure = {
                    "index_digest": "original chunk 0 differs from ASCF chunk digest",
                    "truncated_payload": "ASCF index points past EOF",
                    "appended_payload": "ASCF payload has trailing",
                }.get(name)
                if expected_parser_failure and expected_parser_failure not in message:
                    raise AssertionError(
                        f"{name} failed outside expected parser gate: {message}"
                    ) from exc
                cases.append({
                    "case": name,
                    "archive_sha256": digest(damaged),
                    "rejection": message[:300],
                })
            else:
                raise AssertionError(
                    f"independent proof ACCEPTED corrupted archive ({name})"
                )

    remaining_budget()
    return {
        "schema_version": 1,
        "status": "independent_corruptions_rejected",
        "codec": codec,
        "baseline_archive_sha256": baseline["archive_sha256"],
        "baseline_original_sha256": baseline["original_sha256"],
        "baseline_decoder_sha256": baseline["decoder_sha256"],
        "case_count": len(cases),
        "suite_timeout_seconds": total_timeout_seconds,
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--decoder", type=Path, required=True)
    parser.add_argument("--codec", choices=("lzmesh", "lzraven"), required=True)
    parser.add_argument("--total-timeout-seconds", type=float,
                        default=DEFAULT_NEGATIVE_SUITE_TIMEOUT_SECONDS)
    args = parser.parse_args()
    report = check_corruptions(
        args.archive, args.original, args.decoder, codec=args.codec,
        total_timeout_seconds=args.total_timeout_seconds,
    )
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
