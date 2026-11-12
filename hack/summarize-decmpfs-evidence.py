#!/usr/bin/env python3
"""Cross-check read-only decmpfs probes without inferring a codec mapping.

This tool can only produce preliminary evidence. It cannot authorise native
LZRAVEN/LZMESH writes or claim that a registered kernel handler decodes them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_INPUT_BYTES = 32 << 20
EXPECTED = {
    "binary": "read-only-decmpfs-binary-evidence",
    "table": "read-only-decmpfs-registration-table-evidence",
    "catalogue": "read-only-decmpfs-catalogue-hints",
    "inventory": "existing-system-decmpfs-headers-readonly",
}
GATES = (
    "kernel_decoder_proven",
    "codec_identity_proven",
    "on_disk_framing_proven",
    "cold_remount_readback_proven",
    "native_raven_mesh_writes_permitted",
)


class EvidenceError(ValueError):
    pass


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def read_evidence(path: Path) -> tuple[dict, str, tuple[int, int]]:
    """Read one bounded regular-file descriptor; reject name swaps and links."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    if not getattr(os, "O_NOFOLLOW", 0):
        raise EvidenceError("O_NOFOLLOW is required")
    fd = os.open(path, flags | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_INPUT_BYTES:
            raise EvidenceError("evidence must be a nonempty regular file <= 32 MiB")
        chunks, remaining = [], before.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1 << 20))
            if not chunk:
                raise EvidenceError("evidence was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(item, field)
               for item in (after, named) for field in fields):
            raise EvidenceError("evidence changed or was replaced during read")
        raw = b"".join(chunks)
        try:
            document = json.loads(raw, object_pairs_hook=unique_pairs)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise EvidenceError(f"invalid JSON evidence: {error}") from error
        if not isinstance(document, dict):
            raise EvidenceError("evidence root must be an object")
        return document, hashlib.sha256(raw).hexdigest(), (before.st_dev, before.st_ino)
    finally:
        os.close(fd)


def unsigned(value, what: str, max_value: int = 1 << 32) -> int:
    if type(value) is not int or not 0 <= value < max_value:
        raise EvidenceError(f"invalid {what}")
    return value


def checked_gate(data: dict, kind: str):
    if data.get("kind") != EXPECTED[kind] or data.get("schema_version") != 1:
        raise EvidenceError(f"unexpected {kind} evidence kind/schema")
    if data.get("native_raven_mesh_writes_permitted") is not False:
        raise EvidenceError(f"{kind} evidence improperly permits native writes")
    for name in GATES:
        if name in data and data[name] is not False:
            raise EvidenceError(f"unreviewed positive proof field {kind}.{name}")


def source_index(report: dict, kind: str) -> dict[str, str | None]:
    sources = report.get("inputs")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 16:
        raise EvidenceError(f"{kind} has no bounded source list")
    result = {}
    for item in sources:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise EvidenceError(f"malformed {kind} source entry")
        name = item["path"]
        if not name or name in result:
            raise EvidenceError(f"duplicate/empty {kind} source path")
        status = item.get("status")
        if status not in ("inspected", "unavailable"):
            raise EvidenceError(f"invalid {kind} source status")
        digest = None
        if status == "inspected":
            digest = item.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64 or any(
                    ch not in "0123456789abcdef" for ch in digest):
                raise EvidenceError(f"missing {kind} source SHA-256")
        # Preserve failed attempts too: otherwise sources missing on one side
        # could be silently ignored while the successful subset appears pinned.
        result[name] = digest
    return result


def verified_catalogue_types(catalogue: dict) -> list[int]:
    """Cross-check type hints against the declarations actually captured."""
    source = catalogue.get("source")
    if not isinstance(source, dict):
        raise EvidenceError("missing catalogue source provenance")
    unsigned(source.get("plists_scanned"), "catalogue plist count", 257)
    log_digest = source.get("component_log_sha256")
    if log_digest is not None and (
            not isinstance(log_digest, str) or len(log_digest) != 64 or
            any(ch not in "0123456789abcdef" for ch in log_digest)):
        raise EvidenceError("invalid catalogue component-log SHA-256")
    declarations = catalogue.get("candidate_declarations")
    if not isinstance(declarations, list) or len(declarations) > 16384:
        raise EvidenceError("invalid catalogue declarations")
    observed = set()
    for entry in declarations:
        if not isinstance(entry, dict):
            raise EvidenceError("invalid catalogue declaration entry")
        number = unsigned(entry.get("type"), "catalogue declaration type", 255)
        if entry.get("resource") not in ("Type", "providesType"):
            raise EvidenceError("invalid catalogue declaration resource")
        origin = entry.get("origin")
        if origin not in ("iokit_personality", "ioreg_text"):
            raise EvidenceError("invalid catalogue declaration origin")
        if origin == "iokit_personality":
            digest = entry.get("plist_sha256")
            if not isinstance(digest, str) or len(digest) != 64 or any(
                    ch not in "0123456789abcdef" for ch in digest):
                raise EvidenceError("missing catalogue plist SHA-256")
        observed.add(number)
    declared = sorted(observed)
    if declared != catalogue.get("candidate_types"):
        raise EvidenceError("catalogue type hints differ from captured declarations")
    return declared


def collect_types(table: dict) -> tuple[list[int], int]:
    found = set()
    unresolved = 0
    for source in table["inputs"]:
        if source["status"] != "inspected":
            continue
        tables = source.get("tables")
        if not isinstance(tables, list) or len(tables) > 128:
            raise EvidenceError("malformed registration tables")
        for entry in tables:
            if not isinstance(entry, dict) or not isinstance(entry.get("table"), dict):
                raise EvidenceError("malformed registration table")
            rows = entry["table"]
            observations = rows.get("entries")
            count = rows.get("count")
            if type(count) is not int or not isinstance(observations, list) or (
                    len(observations) != count or not 1 <= count <= 64):
                raise EvidenceError("registration table length mismatch")
            seen = set()
            for record in observations:
                if not isinstance(record, dict):
                    raise EvidenceError("malformed registration record")
                number = unsigned(record.get("type"), "registration type", 255)
                if number in seen:
                    raise EvidenceError("duplicate type within registration table")
                seen.add(number)
                found.add(number)
                resolved = record.get("pointer_resolution")
                if not isinstance(resolved, dict) or not isinstance(resolved.get("status"), str):
                    raise EvidenceError("malformed registration pointer resolution")
                if resolved["status"] != "chain-verified":
                    unresolved += 1
    return sorted(found), unresolved


def summarize(binary: dict, table: dict, catalogue: dict, inventory: dict,
              digests: dict[str, str]) -> dict:
    for name, document in (
        ("binary", binary), ("table", table),
        ("catalogue", catalogue), ("inventory", inventory),
    ):
        checked_gate(document, name)
    binary_sources = source_index(binary, "binary")
    table_sources = source_index(table, "table")
    if not any(value is not None for value in binary_sources.values()) \
            or binary_sources != table_sources:
        raise EvidenceError("binary/table inputs must inspect identical source SHA-256s")
    catalogue_numbers = verified_catalogue_types(catalogue)
    observed = inventory.get("types")
    if not isinstance(observed, dict) or len(observed) > 255:
        raise EvidenceError("invalid inventory type counts")
    stored = {}
    for key, value in observed.items():
        if not key.isdecimal() or str(int(key)) != key or not isinstance(value, dict):
            raise EvidenceError("invalid inventory type key")
        number = unsigned(int(key), "stored type", 255)
        count = unsigned(value.get("count"), "stored type count")
        if not count:
            raise EvidenceError("zero-count inventory entry")
        stored[number] = count
    if sum(stored.values()) != unsigned(inventory.get("headers_read"), "headers_read"):
        raise EvidenceError("inventory header count mismatch")
    for field in ("files_seen", "compressed_flagged"):
        unsigned(inventory.get(field), field)
    if not inventory["files_seen"] >= inventory["compressed_flagged"] >= inventory["headers_read"]:
        raise EvidenceError("invalid inventory file count ordering")
    if type(inventory.get("timed_out")) is not bool \
            or type(inventory.get("file_limit_reached")) is not bool:
        raise EvidenceError("missing bounded-inventory completion flags")
    static_types, unresolved = collect_types(table)
    return {
        "schema_version": 1,
        "kind": "read-only-decmpfs-crosscheck",
        "result": "inconclusive_kernel_codec_mapping",
        "source_document_sha256": dict(sorted(digests.items())),
        "matched_binary_sources": sum(x is not None for x in binary_sources.values()),
        "unavailable_binary_sources": sorted(k for k, v in binary_sources.items() if v is None),
        "kernelcache_sha256": sorted({x for x in binary_sources.values() if x is not None}),
        "static_registration_type_candidates": static_types,
        "unresolved_static_registration_pointers": unresolved,
        "catalogue_declared_type_hints": catalogue_numbers,
        "observed_stored_type_counts": {str(k): v for k, v in sorted(stored.items())},
        "registration_candidates_without_catalogue_hint":
            sorted(set(static_types) - set(catalogue_numbers)),
        "catalogue_hints_without_static_registration_candidate":
            sorted(set(catalogue_numbers) - set(static_types)),
        "inventory_bounded": inventory["timed_out"] or inventory["file_limit_reached"],
        "kernel_decoder_proven": False,
        "codec_identity_proven": False,
        "on_disk_framing_proven": False,
        "cold_remount_readback_proven": False,
        "native_raven_mesh_writes_permitted": False,
        "limitations": (
            "Compiled registrations, catalogue declarations, and existing file headers "
            "are separate observations, not proof of a live registered Raven/Mesh "
            "decoder. Static searches and bounded system-file inventories cannot "
            "prove absence. No decmpfs writes or mounts are performed."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in EXPECTED:
        parser.add_argument(name, type=Path)
    args = parser.parse_args(argv)
    try:
        loaded = {key: read_evidence(getattr(args, key)) for key in EXPECTED}
        ids = [v[2] for v in loaded.values()]
        if len(set(ids)) != len(ids):
            raise EvidenceError("evidence inputs alias the same file")
        output = summarize(
            *(loaded[k][0] for k in EXPECTED),
            {k: loaded[k][1] for k in EXPECTED},
        )
    except (EvidenceError, OSError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
