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

from verify_independent_lzmesh import (
    InvalidArchive, identity, open_regular, require_unchanged, verify,
)

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def check_corruptions(archive, original, decoder, *, codec):
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
        baseline = verify(archive, original, decoder, codec=codec)
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
                verify(path, original, decoder, codec=codec)
            except (InvalidArchive, OSError) as exc:
                message = str(exc)
                if name.startswith("payload_") and not (
                    "independent decoder" in message
                ):
                    raise AssertionError(
                        f"{name} failed before the independent decoder: {message}"
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

    return {
        "schema_version": 1,
        "status": "independent_corruptions_rejected",
        "codec": codec,
        "baseline_archive_sha256": baseline["archive_sha256"],
        "baseline_original_sha256": baseline["original_sha256"],
        "baseline_decoder_sha256": baseline["decoder_sha256"],
        "case_count": len(cases),
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--decoder", type=Path, required=True)
    parser.add_argument("--codec", choices=("lzmesh", "lzraven"), required=True)
    args = parser.parse_args()
    report = check_corruptions(
        args.archive, args.original, args.decoder, codec=args.codec
    )
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
