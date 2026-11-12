#!/usr/bin/env python3
"""Verify and attest retained second-decoder ASCF qualification reports.

This checks evidence consistency and completeness. It does not certify source
independence or validate a native APFS decmpfs registration.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys

SIZES = (65535, 65536, 65537, 131103, 262151)
FAMILIES = ("records", "digest")
NEGATIVE_CASES = frozenset({
    "payload_one_third", "payload_middle", "index_digest", "truncated_payload",
    "appended_payload", "payload_middle_chunk", "middle_index_digest",
    "payload_final_chunk", "final_index_digest",
})
STATUS = "independent_lzraven_buffer_decode_verified"
COMMITTED_SIZES = (65537, 131103)
# Immutable SHA-256 values from prove_committed_vectors.py. A plausible report
# with two arbitrary 64-character digests is not a committed-vector proof.
COMMITTED_ARCHIVE_SHA256 = {
    65537: "c363bd0b549ff77f3f572bdd710c3aec156f8057189afc85368f06bdcc9c8d37",
    131103: "0226c649ef454b21ceea88b0b783e429c54204fe63276591ab585fa662118792",
}
RECORD = b'{"event":"agent","turn":27,"payload":"repeatable proof"}\n'


def expected_clear(family, size):
    """Reproduce the original Apple-encoder input, independent of proof JSON."""
    require(family in FAMILIES and size in SIZES,
            "unsupported fresh proof family or size")
    if family == "records":
        return (RECORD * ((size + len(RECORD) - 1) // len(RECORD)))[:size]
    return b"".join(
        hashlib.sha256(f"{size}:{i}".encode()).digest()
        for i in range((size + 31) // 32)
    )[:size]


def expected_clear_sha256(family, size):
    return hashlib.sha256(expected_clear(family, size)).hexdigest()

HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest_file(path):
    checksum = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def git_head(root):
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True,
    ).strip()


def read_report(root, relpath, report_digests):
    # Only fixed, script-generated report names are accepted here.
    path = root / relpath
    require(path.is_file() and not path.is_symlink(), f"missing regular report: {relpath}")
    raw = path.read_bytes()
    require(len(raw) <= 512 * 1024, f"oversized evidence report: {relpath}")
    obj = json.loads(raw)
    require(isinstance(obj, dict), f"report must be a JSON object: {relpath}")
    report_digests[str(relpath)] = hashlib.sha256(raw).hexdigest()
    return obj


def check_digest(value, field):
    require(isinstance(value, str) and HEX_SHA256.fullmatch(value) is not None,
            f"invalid SHA-256 in {field}")


def check_positive(row, *, size, decoder_digest, label, has_schema=True):
    if has_schema:
        require(row.get("schema_version") == 1 and type(row.get("schema_version")) is int,
                f"{label}: unsupported evidence schema")
    require(row.get("codec") == "lzraven" and row.get("status") == STATUS,
            f"{label}: codec/status mismatch")
    require(type(row.get("logical_size_bytes")) is int
            and row["logical_size_bytes"] == size,
            f"{label}: size mismatch")
    require(type(row.get("chunk_count")) is int
            and row["chunk_count"] == (size + 65535) // 65536,
            f"{label}: chunk count mismatch")
    for key in ("archive_sha256", "original_sha256", "decoder_sha256"):
        check_digest(row.get(key), f"{label}.{key}")
    require(row["decoder_sha256"] == decoder_digest,
            f"{label}: decoder digest mismatch")
    return row



MAX_FRESH_ARCHIVE_BYTES = 2 * 1024 * 1024


def read_fresh_archive(reports, family, size):
    """Retain actual Apple-generated archive bytes for independent JSON replay.

    Refuse special files, symlinks, oversized archives and replacement during
    reading. This is evidence from a trusted qualification runner, not a codec
    oracle: reviewers must still assess the executable and source lineage.
    """
    path = reports / "fresh-archives" / f"{family}-{size}.ascf"
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"missing regular fresh archive: {path.name}") from exc
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and
                0 < before.st_size <= MAX_FRESH_ARCHIVE_BYTES,
                f"missing or oversized regular fresh archive: {path.name}")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(MAX_FRESH_ARCHIVE_BYTES + 1)
        after = os.fstat(fd)
        leaf = path.lstat()
        snapshot = lambda x: (x.st_dev, x.st_ino, x.st_size,
                              x.st_mtime_ns, x.st_ctime_ns)
        require(len(raw) == before.st_size and
                snapshot(before) == snapshot(after) == snapshot(leaf) and
                stat.S_ISREG(leaf.st_mode),
                f"fresh archive changed during read: {path.name}")
        return raw
    finally:
        os.close(fd)


def check_archive(raw, family, size):
    """Validate actual ASCF header, index and clear-text digests, not claims."""
    label = f"{family}-{size}"
    require(len(raw) >= 64 and raw[:8] == b"ASCF0001",
            f"{label}: invalid retained ASCF archive")
    codec, chunk_bytes, logical, count, reserved = struct.unpack_from("<IIQII", raw, 8)
    expected_count = (size + 65535) // 65536
    clear = expected_clear(family, size)
    require((codec, chunk_bytes, logical, count, reserved) ==
            (0xD05, 65536, size, expected_count, 0) and
            raw[32:64] == hashlib.sha256(clear).digest(),
            f"{label}: retained archive metadata mismatch")
    offset = 64 + 48 * count
    require(len(raw) >= offset, f"{label}: truncated retained ASCF index")
    for i in range(count):
        entry = 64 + i * 48
        position, stored, length = struct.unpack_from("<QII", raw, entry)
        original = clear[i * 65536:(i + 1) * 65536]
        require(position == offset and stored > 0 and
                offset + stored <= len(raw) and length == len(original) and
                raw[entry + 16:entry + 48] == hashlib.sha256(original).digest(),
                f"{label}: retained archive chunk {i} mismatch")
        offset += stored
    require(offset == len(raw), f"{label}: retained archive trailing bytes")


def expected_negative_hashes(raw):
    """Rebuild the nine exact mutations from prove_independent_corruptions.py."""
    count = struct.unpack_from("<I", raw, 24)[0]
    require(count == 3, "negative fixture must contain three chunks")
    first_offset, first_stored, _ = struct.unpack_from("<QII", raw, 64)
    middle_offset, middle_stored, _ = struct.unpack_from("<QII", raw, 64 + 48)
    last_offset, last_stored, _ = struct.unpack_from("<QII", raw, 64 + 96)
    require(min(first_stored, middle_stored, last_stored) >= 3,
            "negative fixture chunks must be at least three bytes")
    mutations = {}
    for name, at in (
        ("payload_one_third", first_offset + first_stored // 3),
        ("payload_middle", first_offset + first_stored // 2),
        ("index_digest", 80),
        ("payload_middle_chunk", middle_offset + middle_stored // 2),
        ("middle_index_digest", 64 + 48 + 16),
        ("payload_final_chunk", last_offset + last_stored // 2),
        ("final_index_digest", 64 + 96 + 16),
    ):
        damaged = bytearray(raw)
        damaged[at] ^= 0x01 if name.endswith("digest") else 0x40
        mutations[name] = hashlib.sha256(damaged).hexdigest()
    mutations["truncated_payload"] = hashlib.sha256(raw[:-1]).hexdigest()
    mutations["appended_payload"] = hashlib.sha256(raw + b"\x00").hexdigest()
    return mutations


def check_negative_reason(name, reason):
    if name.startswith("payload_"):
        chunk = {"payload_middle_chunk": 1, "payload_final_chunk": 2}.get(name, 0)
        allowed = (
            f"independent decoder failed on chunk {chunk} (exit ",
            f"independent decoder omitted chunk {chunk}",
            f"independent decoder returned incorrect bytes/length at chunk {chunk}",
            f"independent decoder returned wrong digest at chunk {chunk}",
        )
        require(reason.startswith(allowed),
                f"{name}: rejection is not from independent decoder")
    else:
        expected = {
            "index_digest": "original chunk 0 differs from ASCF chunk digest",
            "middle_index_digest": "original chunk 1 differs from ASCF chunk digest",
            "final_index_digest": "original chunk 2 differs from ASCF chunk digest",
            "truncated_payload": "ASCF index points past EOF",
            "appended_payload": "ASCF payload has trailing",
        }[name]
        require(expected in reason, f"{name}: unexpected parser rejection")


def validate(reports, decoder, upstream, repository, *, fresh=False, cli=None):
    reports = Path(reports)
    report_digests = {}
    decoder_digest = digest_file(decoder)
    committed = read_report(reports, Path("committed.json"), report_digests)
    require(committed.get("schema_version") == 1 and
            type(committed.get("schema_version")) is int,
            "committed proof schema mismatch")
    rows = committed.get("vectors")
    require(isinstance(rows, list) and len(rows) == 2,
            "committed proof must include exactly two vectors")
    actual = {}
    for row in rows:
        require(isinstance(row, dict), "malformed committed vector")
        size = row.get("logical_size_bytes")
        require(type(size) is int and size in COMMITTED_SIZES and size not in actual,
                "wrong, missing or duplicate committed vector")
        actual[size] = check_positive(row, size=size,
                                      decoder_digest=decoder_digest,
                                      label=f"committed-{size}", has_schema=False)
    require(set(actual) == set(COMMITTED_SIZES), "incomplete committed proof")
    for size, row in actual.items():
        require(row["archive_sha256"] == COMMITTED_ARCHIVE_SHA256[size] and
                row["original_sha256"] == expected_clear_sha256("records", size),
                f"committed-{size}: pinned fixture digest mismatch")

    fresh_count = 0
    negative_count = 0
    fresh_archive_hashes = {}
    if fresh:
        require(cli is not None, "fresh proof requires the Apple encoder CLI binary")
        for family in FAMILIES:
            positive = {}
            for size in SIZES:
                label = f"{family}-{size}"
                row = read_report(reports, Path("fresh") / f"{label}.json",
                                  report_digests)
                positive[size] = check_positive(row, size=size,
                                                decoder_digest=decoder_digest,
                                                label=label)
                require(row["original_sha256"] == expected_clear_sha256(family, size),
                        f"{label}: generated content digest mismatch")
                archive = read_fresh_archive(reports, family, size)
                require(hashlib.sha256(archive).hexdigest() == row["archive_sha256"],
                        f"{label}: retained archive digest mismatch")
                check_archive(archive, family, size)
                fresh_archive_hashes[label] = row["archive_sha256"]
                if size == 131103:
                    negative_fixture = archive
                fresh_count += 1
            negative = read_report(reports, Path("negative") / f"{family}.json",
                                   report_digests)
            label = f"negative-{family}"
            require(negative.get("schema_version") == 1 and
                    type(negative.get("schema_version")) is int and
                    negative.get("status") == "independent_corruptions_rejected" and
                    negative.get("codec") == "lzraven", f"{label}: schema/status mismatch")
            require(type(negative.get("case_count")) is int
                    and negative["case_count"] == len(NEGATIVE_CASES),
                    f"{label}: negative count mismatch")
            cases = negative.get("cases")
            require(isinstance(cases, list) and len(cases) == len(NEGATIVE_CASES)
                    and all(isinstance(c, dict) for c in cases),
                    f"{label}: malformed cases")
            require({c.get("case") for c in cases} == NEGATIVE_CASES,
                    f"{label}: missing or duplicate corruption cases")
            expected_hashes = expected_negative_hashes(negative_fixture)
            for case in cases:
                name = case["case"]
                check_digest(case.get("archive_sha256"), f"{label}.case")
                require(case["archive_sha256"] == expected_hashes[name],
                        f"{label}.{name}: corruption bytes digest mismatch")
                require(isinstance(case.get("rejection"), str)
                        and case["rejection"], f"{label}: missing rejection")
                check_negative_reason(name, case["rejection"])
            require(negative.get("baseline_archive_sha256") ==
                    positive[131103]["archive_sha256"] and
                    negative.get("baseline_original_sha256") ==
                    positive[131103]["original_sha256"] and
                    negative.get("baseline_decoder_sha256") == decoder_digest,
                    f"{label}: negative baseline differs from accepted fresh proof")
            negative_count += len(cases)

    upstream = Path(upstream)
    repository = Path(repository)
    # Attest every translation unit and private header in the upstream tests,
    # including the Mesh/Bitmap sources executed by its native test binary.
    source_files = ("lzraven.c", "lzraven.h", "lzbitmap.c", "lzbitmap.h",
                    "lzmesh.c", "lzmesh.h", "tests/test.c", "tests/vectors.h")
    upstream_hashes = {name: digest_file(upstream / name) for name in source_files}
    head = git_head(upstream)
    require(head == "6d97f1ab520821b4d326139fdf48b658f96ee5b9",
            "upstream source is not pinned to reviewed commit")
    manifest = {
        "schema_version": 1,
        "status": "second_decoder_evidence_consistent_pending_independent_review",
        "scope": "Apple ASCF LZRAVEN buffer only; APFS native writes prohibited",
        "applesauce_head": git_head(repository),
        "upstream_commit": head,
        "upstream_source_sha256": upstream_hashes,
        "decoder_sha256": decoder_digest,
        "committed_vectors_verified": len(actual),
        "fresh_vectors_verified": fresh_count,
        "fresh_archive_sha256": dict(sorted(fresh_archive_hashes.items())),
        "corruptions_rejected": negative_count,
        "report_sha256": dict(sorted(report_digests.items())),
        "apple_encoder_cli_sha256": digest_file(cli) if cli is not None else None,
    }
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--decoder", type=Path, required=True)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--cli", type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = validate(args.reports, args.decoder, args.upstream,
                            args.repository, fresh=args.fresh, cli=args.cli)
    except (OSError, ValueError, json.JSONDecodeError,
            subprocess.CalledProcessError) as exc:
        print(f"second Raven qualification evidence rejected: {exc}", file=sys.stderr)
        return 1
    with (args.reports / "manifest.json").open("x", encoding="utf-8") as out:
        json.dump(manifest, out, sort_keys=True, indent=2)
        out.write("\n")
    print(json.dumps({"status": manifest["status"],
                      "committed": manifest["committed_vectors_verified"],
                      "fresh": manifest["fresh_vectors_verified"],
                      "corruptions": manifest["corruptions_rejected"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
