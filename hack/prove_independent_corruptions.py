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
    open_regular, require_unchanged, sha256_file, verify,
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
    # Pin both proof inputs before executing an independent decoder. A decoder
    # that rewrites itself after the successful baseline must not turn its
    # subsequent failures into false corruption-rejection evidence.
    with open_regular(original) as clear_source, open_regular(decoder) as decoder_source:
        original_snapshot = identity(os.fstat(clear_source.fileno()))
        decoder_snapshot = identity(os.fstat(decoder_source.fileno()))
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

    count = struct.unpack_from("<I", data, 24)[0]
    offset, stored_len, _ = struct.unpack_from("<QII", data, 64)
    if stored_len < 3 or offset < 64 + 48 * count or offset + stored_len > len(data):
        raise InvalidArchive("negative tests require a nonempty validated chunk")
    middle_chunk = count // 2
    final_chunk = count - 1
    final_entry = 64 + 48 * final_chunk
    final_offset, final_stored_len, _ = struct.unpack_from("<QII", data, final_entry)

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

    # Probe the first, middle and final chunks on multi-chunk fixtures.
    # For the three-chunk Apple proof vectors this covers every chunk.
    # Keep larger archives bounded by probing at most three distinct chunks.
    if count > 2:
        middle_entry = 64 + 48 * middle_chunk
        middle_offset, middle_stored_len, _ = struct.unpack_from(
            "<QII", data, middle_entry
        )
        if (middle_stored_len < 3
                or middle_offset + middle_stored_len > len(data)):
            raise InvalidArchive("negative tests require a nonempty middle chunk")
        middle_damage = bytearray(data)
        middle_damage[middle_offset + middle_stored_len // 2] ^= 0x40
        mutations["payload_middle_chunk"] = bytes(middle_damage)

        middle_digest_damage = bytearray(data)
        middle_digest_damage[middle_entry + 16] ^= 0x01
        mutations["middle_index_digest"] = bytes(middle_digest_damage)

    if count > 1:
        if final_stored_len < 3 or final_offset + final_stored_len > len(data):
            raise InvalidArchive("negative tests require a nonempty final chunk")
        final_damage = bytearray(data)
        final_damage[final_offset + final_stored_len // 2] ^= 0x40
        mutations["payload_final_chunk"] = bytes(final_damage)

        final_digest_damage = bytearray(data)
        final_digest_damage[final_entry + 16] ^= 0x01
        mutations["final_index_digest"] = bytes(final_digest_damage)

    cases = []
    with tempfile.TemporaryDirectory(prefix="ascf-negative-proof-") as tmp:
        path = Path(tmp) / "corrupted.ascf"
        for name, damaged in mutations.items():
            path.write_bytes(damaged)
            try:
                verify_with_budget(path)
            except (InvalidArchive, OSError) as exc:
                message = str(exc)
                if "negative proof suite exceeded total time budget" in message:
                    raise
                if "timed out" in message or "time budget" in message:
                    raise InvalidArchive(
                        f"{name} decoder timeout cannot qualify as corruption rejection"
                    ) from exc
                # Only codec-specific decoding failures count as payload
                # corruption rejection. Decoder provenance changes, missing
                # inputs and unrelated proof failures must fail qualification.
                expected_chunk = {
                    "payload_middle_chunk": middle_chunk,
                    "payload_final_chunk": final_chunk,
                }.get(name, 0)
                if name.startswith("payload_") and not message.startswith((
                    f"independent decoder failed on chunk {expected_chunk} (exit ",
                    f"independent decoder omitted chunk {expected_chunk}",
                    f"independent decoder returned incorrect bytes/length at chunk {expected_chunk}",
                    f"independent decoder returned wrong digest at chunk {expected_chunk}",
                )):
                    raise AssertionError(
                        f"{name} failed outside decoder result gate: {message}"
                    ) from exc
                expected_parser_failure = {
                    "index_digest": "original chunk 0 differs from ASCF chunk digest",
                    "middle_index_digest": (
                        f"original chunk {middle_chunk} differs from ASCF chunk digest"
                    ),
                    "final_index_digest": (
                        f"original chunk {final_chunk} differs from ASCF chunk digest"
                    ),
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
    # The baseline archive is an input to all negative claims. Recheck its
    # pathname, inode and complete bytes after the decoder has executed every
    # mutation; otherwise a late archive replacement can go unreported.
    with open_regular(archive) as final_archive:
        require_unchanged(archive, archive_snapshot, final_archive)
        final_archive_hash = hashlib.sha256()
        for block in iter(lambda: final_archive.read(1024 * 1024), b""):
            final_archive_hash.update(block)
        require_unchanged(archive, archive_snapshot, final_archive)
    if final_archive_hash.hexdigest() != baseline["archive_sha256"]:
        raise InvalidArchive("negative proof archive bytes changed during suite")
    remaining_budget()
    require_unchanged(original, original_snapshot)
    require_unchanged(decoder, decoder_snapshot)
    if sha256_file(original) != baseline["original_sha256"]:
        raise InvalidArchive("negative proof original bytes changed during suite")
    if sha256_file(decoder) != baseline["decoder_sha256"]:
        raise InvalidArchive("negative proof decoder bytes changed during suite")
    require_unchanged(original, original_snapshot)
    require_unchanged(decoder, decoder_snapshot)
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
