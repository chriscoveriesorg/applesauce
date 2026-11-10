#!/usr/bin/env python3
"""Validate pinned, Apple-generated ASCF vectors; optionally cross-decode in C11.

The portable check confirms repository fixture integrity and index geometry.
Only --decoder provides independent LZRAVEN/LZMESH codec interoperability proof.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile

from verify_independent_lzmesh import verify

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests/fixtures/codec-crossdecode"
ROW = b'{"event":"agent","turn":27,"payload":"repeatable proof"}\n'
# Exact archives from Actions runs 42757335827 (Mesh) and 42757335808 (Raven).
# Source files were generated on macOS 27.0.1 using Apple buffer compression.
VECTORS = {
    ("lzmesh", 65537): ("75c090b5ce7790c1e406ce115eea57fba041ca57da8576ffeb3eadf1cf068f14", 2),
    ("lzmesh", 131103): ("73a7850d2bfa2ce356a7f362061d0071058547050a410d480e78353c0f2a767d", 3),
    ("lzraven", 65537): ("c363bd0b549ff77f3f572bdd710c3aec156f8057189afc85368f06bdcc9c8d37", 2),
    ("lzraven", 131103): ("0226c649ef454b21ceea88b0b783e429c54204fe63276591ab585fa662118792", 3),
}
CODEC_IDS = {"lzmesh": 0xE05, "lzraven": 0xD05}


def plaintext(size):
    return (ROW * ((size + len(ROW) - 1) // len(ROW)))[:size]


def validate_vector(codec, size, archive):
    """Inspect checked-in exact bytes, including every chunk's declared hash."""
    expected_digest, expected_count = VECTORS[(codec, size)]
    if hashlib.sha256(archive).hexdigest() != expected_digest:
        raise ValueError(f"{codec} {size}: committed archive SHA-256 mismatch")
    if len(archive) < 64 + 48 * expected_count or archive[:8] != b"ASCF0001":
        raise ValueError("invalid ASCF vector header/index length")
    codec_id, chunk_size, logical_size, count, reserved = struct.unpack_from("<IIQII", archive, 8)
    clear = plaintext(size)
    if (codec_id, chunk_size, logical_size, count, reserved) != (
        CODEC_IDS[codec], 65536, size, expected_count, 0
    ) or archive[32:64] != hashlib.sha256(clear).digest():
        raise ValueError("ASCF vector metadata or whole-file digest mismatch")
    offset = 64 + 48 * count
    for i in range(count):
        pos, stored, length = struct.unpack_from("<QII", archive, 64 + i * 48)
        expected = clear[i * chunk_size : (i + 1) * chunk_size]
        if (pos != offset or not stored or length != len(expected)
                or archive[64 + i * 48 + 16 : 64 + (i + 1) * 48] != hashlib.sha256(expected).digest()):
            raise ValueError(f"ASCF vector chunk {i} geometry or hash mismatch")
        offset += stored
    if offset != len(archive):
        raise ValueError("ASCF vector has missing or trailing payload bytes")
    return {
        "codec": codec, "logical_size_bytes": size, "chunk_count": count,
        "original_sha256": hashlib.sha256(clear).hexdigest(),
        "archive_sha256": expected_digest,
    }


def run(codec_filter=None, decoder=None):
    reports = []
    if decoder is not None and codec_filter is None:
        raise ValueError("--decoder requires --codec")
    for (codec, size), _ in VECTORS.items():
        if codec_filter is not None and codec != codec_filter:
            continue
        path = FIXTURES / f"{codec}-records-{size}.ascf"
        # Read the checked-in vector, never rewrite it in the proof tool.
        with path.open("rb") as stream:
            archive = stream.read()
        summary = validate_vector(codec, size, archive)
        if decoder is not None:
            with tempfile.TemporaryDirectory(prefix="ascf-committed-") as directory:
                original = Path(directory) / "original.bin"
                original.write_bytes(plaintext(size))
                proof = verify(path, original, decoder, codec=codec)
                for key in ("codec", "logical_size_bytes", "chunk_count",
                            "original_sha256", "archive_sha256"):
                    if proof[key] != summary[key]:
                        raise ValueError(f"independent decoder report disagrees on {key}")
                summary["decoder_sha256"] = proof["decoder_sha256"]
                summary["status"] = proof["status"]
        else:
            summary["status"] = "fixture_integrity_verified_only"
        reports.append(summary)
    return {"schema_version": 1, "scope": "Apple ASCF buffer codec, not APFS decmpfs",
            "vectors": reports}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codec", choices=sorted(CODEC_IDS))
    parser.add_argument("--decoder", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.codec, args.decoder), sort_keys=True, indent=2))
    except (OSError, ValueError) as exc:
        print(f"committed codec vector check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
