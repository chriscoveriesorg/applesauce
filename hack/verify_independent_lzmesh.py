#!/usr/bin/env python3
"""Independent Raven/Mesh buffer proof for owner-generated ASCF archives.

Requires a separately audited and built codec-specific C11 decoder executable.
No network, source mutations, native decmpfs writes or FSKit operations.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time

MAGIC = b"ASCF0001"
CODECS = {"lzmesh": 0xE05, "lzraven": 0xD05}
MAX_LOGICAL = 64 * 1024 * 1024
DEFAULT_TOTAL_DECODE_TIMEOUT_SECONDS = 120.0


class InvalidArchive(ValueError):
    """Untrusted archive geometry, provenance or decoded content."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open_regular(path) as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(part)
    return digest.hexdigest()


def open_regular(path):
    # O_NONBLOCK prevents an input FIFO with no writer from hanging on open.
    # The descriptor type check also closes the pathname-swap window.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise InvalidArchive(f"proof input must be a regular file: {path.name}")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def identity(info):
    """Detect inode/path substitution, including same-size rewrites with restored mtime."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def require_unchanged(path, expected, stream=None):
    # stat() follows a replacement symlink to the *same* open inode, making
    # pathname substitution invisible. lstat() checks the leaf pathname.
    current = path.lstat()
    if (not stat.S_ISREG(current.st_mode)
            or identity(current) != expected
            or (stream is not None
                and identity(os.fstat(stream.fileno())) != expected)):
        raise InvalidArchive(f"proof input changed during decode: {path.name}")


def limit_decoder_output(clear_len):
    """Cap decoder output with one extra byte to detect attempted overproduction."""
    # If the limit equals clear_len, a decoder can ignore SIGXFSZ, attempt
    # another byte, then exit 0 with only the expected prefix on disk.
    # Preserve a sentinel byte so verification rejects that output instead.
    limit = clear_len + 1
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def decode_bounded(decoder, payload, clear_len, index, codec, *, timeout_seconds=30):
    # A pipe captured by subprocess.run can grow without bound if a decoder
    # malfunctions. A regular temporary file with RLIMIT_FSIZE bounds output.
    # Mesh's independent CLI accepts stdin/stdout. Raven's independent C11
    # test tool accepts filenames and a strict --cap argument. Keep both
    # decoders isolated from the real source file and bound their outputs.
    with tempfile.TemporaryDirectory(prefix="ascf-independent-") as directory:
        # Give the external decoder a regular, private input file instead of
        # a pipe. On timeout, an escaped grandchild holding a pipe descriptor
        # open can otherwise make communicate() block forever after killpg().
        # A regular file has no pipe writer/reader lifetime to await.
        input_path = Path(directory) / "payload.bin"
        input_path.write_bytes(payload)
        if codec == "lzraven":
            output_path = Path(directory) / "decoded.bin"
            command = [
                str(decoder), "--cap", str(clear_len), str(input_path), str(output_path)
            ]
        else:
            command = [str(decoder), "dec", "e05"]

        # The pinned Mesh port_cli otherwise allocates the decoded size
        # advertised by *untrusted compressed framing*. Its DECODE_SIZE
        # override caps that allocation to the trusted ASCF index clear_len.
        # Override any inherited caller value, including an enormous one.
        # These C11 decoders are independently supplied executables. Never
        # forward CI tokens, developer credentials or dynamic-loader overrides
        # from the proof caller's ambient environment to a decoder process.
        # Use a temporary working directory for any incidental relative I/O.
        decoder_env = {
            "PATH": os.defpath,
            "LANG": "C",
            "LC_ALL": "C",
            "HOME": directory,
            "TMPDIR": directory,
        }
        if codec == "lzmesh":
            decoder_env["DECODE_SIZE"] = str(clear_len)

        with open_regular(input_path) as input_file, tempfile.TemporaryFile() as output:
            # Run each external decoder in its own process group and kill any
            # same-group descendants before releasing its temporary input.
            # wait() observes only the direct child. It cannot hang waiting
            # for an escaped descendant to close an inherited stdin pipe.
            process = subprocess.Popen(
                command,
                stdin=input_file if codec == "lzmesh" else subprocess.DEVNULL,
                stdout=output if codec == "lzmesh" else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=decoder_env,
                cwd=directory,
                preexec_fn=lambda: limit_decoder_output(clear_len),
                start_new_session=True,
            )
            timeout_error = None
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                timeout_error = exc
            finally:
                # Best-effort process-group cleanup. A malicious self-daemonized
                # descendant can escape the group, but cannot hold our proof
                # process open through a pipe because no pipe is passed.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            if timeout_error is not None:
                raise InvalidArchive(
                    f"independent decoder timed out on chunk {index}"
                ) from timeout_error
            if process.returncode != 0:
                raise InvalidArchive(
                    f"independent decoder failed on chunk {index} (exit {process.returncode})"
                )
            if codec == "lzraven":
                try:
                    with open_regular(output_path) as result:
                        return result.read(clear_len + 1)
                except FileNotFoundError as exc:
                    raise InvalidArchive(f"independent decoder omitted chunk {index}") from exc
            output.seek(0)
            return output.read(clear_len + 1)


def read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise InvalidArchive("truncated ASCF archive or original fixture")
    return data


def verify(archive, original, decoder, *, codec="lzmesh", max_logical_bytes=MAX_LOGICAL,
           total_timeout_seconds=DEFAULT_TOTAL_DECODE_TIMEOUT_SECONDS):
    """Verify strict ASCF geometry, independent decode and original-byte hashes."""
    if codec not in CODECS:
        raise InvalidArchive(f"unsupported independent codec: {codec}")
    requested_codec = codec
    # Keep the final path component for O_NOFOLLOW and lstat().
    # resolve() would follow symlinks before either safety check.
    archive = Path(os.path.abspath(archive))
    original = Path(os.path.abspath(original))
    decoder = Path(os.path.abspath(decoder))
    if decoder.is_symlink() or not decoder.is_file() or not os.access(decoder, os.X_OK):
        raise InvalidArchive("decoder must be an executable regular file")
    decoder_snapshot = identity(decoder.stat())
    decoder_hash = sha256_file(decoder)
    require_unchanged(decoder, decoder_snapshot)
    if max_logical_bytes <= 0:
        raise InvalidArchive("maximum logical fixture size must be positive")
    if not 0 < total_timeout_seconds <= 3600:
        raise InvalidArchive("total decoder time budget must be between 0 and 3600 seconds")

    with open_regular(archive) as reader, open_regular(original) as source:
        archive_snapshot = identity(os.fstat(reader.fileno()))
        original_snapshot = identity(os.fstat(source.fileno()))
        require_unchanged(archive, archive_snapshot, reader)
        require_unchanged(original, original_snapshot, source)
        file_size = os.fstat(reader.fileno()).st_size
        header = read_exact(reader, 64)
        if header[:8] != MAGIC or header[28:32] != bytes(4):
            raise InvalidArchive("invalid ASCF magic or reserved header")
        codec, chunk_size = struct.unpack_from("<II", header, 8)
        logical_size = struct.unpack_from("<Q", header, 16)[0]
        count = struct.unpack_from("<I", header, 24)[0]
        logical_digest = header[32:64]
        if codec != CODECS[requested_codec]:
            raise InvalidArchive(
                f"independent proof only accepts {requested_codec.upper()} codec "
                f"0x{CODECS[requested_codec]:03X}"
            )
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

        # A per-chunk timeout alone can permit 1024 chunks * 30 seconds of
        # stalled decoder work. Bound the entire proof using a monotonic clock.
        deadline = time.monotonic() + total_timeout_seconds
        original_hash = hashlib.sha256()
        independent_hash = hashlib.sha256()
        for index, (offset, stored_len, clear_len, digest) in enumerate(entries):
            reader.seek(offset)
            payload = read_exact(reader, stored_len)
            clear = read_exact(source, clear_len)
            original_hash.update(clear)
            if hashlib.sha256(clear).digest() != digest:
                raise InvalidArchive(f"original chunk {index} differs from ASCF chunk digest")
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise InvalidArchive("independent decoder exceeded total time budget")
            decoded = decode_bounded(
                decoder, payload, clear_len, index, requested_codec,
                timeout_seconds=min(30, remaining_seconds),
            )
            if len(decoded) != clear_len or decoded != clear:
                raise InvalidArchive(f"independent decoder returned incorrect bytes/length at chunk {index}")
            if hashlib.sha256(decoded).digest() != digest:
                raise InvalidArchive(f"independent decoder returned wrong digest at chunk {index}")
            independent_hash.update(decoded)
        if source.read(1):
            raise InvalidArchive("original fixture has trailing bytes")
        if original_hash.digest() != logical_digest or independent_hash.digest() != logical_digest:
            raise InvalidArchive("ASCF whole-file SHA-256 differs from independently decoded original")
        reader.seek(0)
        archive_hash = hashlib.sha256()
        for part in iter(lambda: reader.read(1024 * 1024), b""):
            archive_hash.update(part)
        require_unchanged(archive, archive_snapshot, reader)
        require_unchanged(original, original_snapshot, source)

    require_unchanged(decoder, decoder_snapshot)
    if sha256_file(decoder) != decoder_hash:
        raise InvalidArchive("independent decoder binary changed during proof")
    require_unchanged(decoder, decoder_snapshot)

    return {
        "schema_version": 1,
        "status": f"independent_{requested_codec}_buffer_decode_verified",
        "scope": "ASCF Apple buffer payload; not native APFS decmpfs",
        "archive_sha256": archive_hash.hexdigest(),
        "original_sha256": original_hash.hexdigest(),
        "decoder_sha256": decoder_hash,
        "codec": requested_codec,
        "codec_id": f"0x{CODECS[requested_codec]:03X}",
        "logical_size_bytes": logical_size,
        "chunk_count": count,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--decoder", required=True, type=Path)
    parser.add_argument("--codec", choices=sorted(CODECS), default="lzmesh")
    parser.add_argument("--max-logical-bytes", type=int, default=MAX_LOGICAL)
    parser.add_argument("--total-timeout-seconds", type=float,
                        default=DEFAULT_TOTAL_DECODE_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    try:
        report = verify(
            args.archive, args.original, args.decoder,
            codec=args.codec,
            max_logical_bytes=args.max_logical_bytes,
            total_timeout_seconds=args.total_timeout_seconds,
        )
    except (OSError, InvalidArchive) as exc:
        print(f"independent ASCF proof failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
