#!/usr/bin/env python3
"""Independent LZMESH buffer proof for owner-generated ASCF archives.

Requires an externally audited, separately built LZMESH decoder executable.
No network, filesystem mutations, native decmpfs writes or FSKit operations.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

MAGIC = b"ASCF0001"
MESH_CODEC = 0xE05
MAX_LOGICAL = 64 * 1024 * 1024


class InvalidArchive(ValueError):
    """Untrusted archive geometry, provenance or decoded content."""


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise InvalidArchive("truncated ASCF archive or original fixture")
    return data


def verify(archive, original, decoder, *, max_logical_bytes=MAX_LOGICAL):
    """Verify strict ASCF geometry, independent decode and original-byte hashes."""
    archive = Path(archive).resolve(strict=True)
    original = Path(original).resolve(strict=True)
    decoder = Path(decoder).resolve(strict=True)
    if not decoder.is_file() or not os.access(decoder, os.X_OK):
        raise InvalidArchive("decoder must be an executable regular file")
    if max_logical_bytes <= 0:
        raise InvalidArchive("maximum logical fixture size must be positive")

    file_size = archive.stat().st_size
    with archive.open("rb") as reader, original.open("rb") as source:
        header = read_exact(reader, 64)
        if header[:8] != MAGIC or header[28:32] != bytes(4):
            raise InvalidArchive("invalid ASCF magic or reserved header")
        codec, chunk_size = struct.unpack_from("<II", header, 8)
        logical_size = struct.unpack_from("<Q", header, 16)[0]
        count = struct.unpack_from("<I", header, 24)[0]
        logical_digest = header[32:64]
        if codec != MESH_CODEC:
            raise InvalidArchive("independent proof only accepts LZMESH codec 0xE05")
        if not (65536 <= chunk_size <= 8388608 and chunk_size & (chunk_size - 1) == 0):
            raise InvalidArchive("invalid ASCF chunk size")
        if not 0 < logical_size <= max_logical_bytes:
            raise InvalidArchive("logical size zero or exceeds bounded fixture budget")
        expected_count = (logical_size + chunk_size - 1) // chunk_size
        if count != expected_count or count > 65536:
            raise InvalidArchive("ASCF chunk count does not match logical size")
        if source.seek(0, os.SEEK_END) != logical_size:
            raise InvalidArchive("original fixture length differs from ASCF header")
        source.seek(0)

        next_offset = 64 + count * 48
        if next_offset > file_size:
            raise InvalidArchive("truncated ASCF chunk index")
        remaining = logical_size
        entries = []
        for _ in range(count):
            entry = read_exact(reader, 48)
            offset, stored_len, clear_len = struct.unpack_from("<QII", entry)
            expected_clear = min(remaining, chunk_size)
            if (
                offset != next_offset
                or clear_len != expected_clear
                or stored_len == 0
                or stored_len > 2 * clear_len + 65536
            ):
                raise InvalidArchive("ASCF index has invalid chunk geometry")
            next_offset += stored_len
            if next_offset > file_size:
                raise InvalidArchive("ASCF index points past EOF")
            entries.append((offset, stored_len, clear_len, entry[16:48]))
            remaining -= clear_len
        if next_offset != file_size or remaining:
            raise InvalidArchive("ASCF payload has trailing, overlapping or missing data")

        original_hash = hashlib.sha256()
        independent_hash = hashlib.sha256()
        for index, (offset, stored_len, clear_len, digest) in enumerate(entries):
            reader.seek(offset)
            payload = read_exact(reader, stored_len)
            clear = read_exact(source, clear_len)
            original_hash.update(clear)
            if hashlib.sha256(clear).digest() != digest:
                raise InvalidArchive(f"original chunk {index} differs from ASCF chunk digest")
            try:
                decoded = subprocess.run(
                    [str(decoder), "dec", "e05"],
                    input=payload,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=30,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise InvalidArchive(f"independent decoder timed out on chunk {index}") from exc
            if decoded.returncode != 0:
                raise InvalidArchive(f"independent decoder failed on chunk {index} (exit {decoded.returncode})")
            if len(decoded.stdout) != clear_len or decoded.stdout != clear:
                raise InvalidArchive(f"independent decoder returned incorrect bytes/length at chunk {index}")
            if hashlib.sha256(decoded.stdout).digest() != digest:
                raise InvalidArchive(f"independent decoder returned wrong digest at chunk {index}")
            independent_hash.update(decoded.stdout)
        if source.read(1):
            raise InvalidArchive("original fixture has trailing bytes")
        if original_hash.digest() != logical_digest or independent_hash.digest() != logical_digest:
            raise InvalidArchive("ASCF whole-file SHA-256 differs from independently decoded original")

    return {
        "schema_version": 1,
        "status": "independent_lzmesh_buffer_decode_verified",
        "scope": "ASCF Apple buffer payload; not native APFS decmpfs",
        "archive_sha256": sha256_file(archive),
        "original_sha256": original_hash.hexdigest(),
        "decoder_sha256": sha256_file(decoder),
        "codec": "lzmesh",
        "codec_id": "0xE05",
        "logical_size_bytes": logical_size,
        "chunk_count": count,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--decoder", required=True, type=Path)
    parser.add_argument("--max-logical-bytes", type=int, default=MAX_LOGICAL)
    args = parser.parse_args(argv)
    try:
        report = verify(
            args.archive, args.original, args.decoder,
            max_logical_bytes=args.max_logical_bytes,
        )
    except (OSError, InvalidArchive) as exc:
        print(f"independent LZMESH proof failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
