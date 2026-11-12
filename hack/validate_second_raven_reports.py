#!/usr/bin/env python3
"""Verify and attest retained second-decoder ASCF qualification reports.

This checks evidence consistency and completeness. It does not certify source
independence or validate a native APFS decmpfs registration.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
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

    fresh_count = 0
    negative_count = 0
    if fresh:
        for family in FAMILIES:
            positive = {}
            for size in SIZES:
                label = f"{family}-{size}"
                row = read_report(reports, Path("fresh") / f"{label}.json",
                                  report_digests)
                positive[size] = check_positive(row, size=size,
                                                decoder_digest=decoder_digest,
                                                label=label)
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
            for case in cases:
                check_digest(case.get("archive_sha256"), f"{label}.case")
                require(isinstance(case.get("rejection"), str)
                        and case["rejection"], f"{label}: missing rejection")
            require(negative.get("baseline_archive_sha256") ==
                    positive[131103]["archive_sha256"] and
                    negative.get("baseline_original_sha256") ==
                    positive[131103]["original_sha256"] and
                    negative.get("baseline_decoder_sha256") == decoder_digest,
                    f"{label}: negative baseline differs from accepted fresh proof")
            negative_count += len(cases)

    upstream = Path(upstream)
    repository = Path(repository)
    source_files = ("lzraven.c", "lzraven.h", "tests/test.c", "tests/vectors.h")
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
