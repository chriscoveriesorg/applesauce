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
import struct
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
        # Do not mask the original evidence rejection if descriptor cleanup fails.
        if sys.exc_info()[0] is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        else:
            os.close(fd)


def unsigned(value, what: str, max_value: int = 1 << 32) -> int:
    if type(value) is not int or not 0 <= value < max_value:
        raise EvidenceError(f"invalid {what}")
    return value


def checked_gate(data: dict, kind: str):
    if data.get("kind") != EXPECTED[kind] or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
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
        else:
            # Unavailable sources cannot attest to image or table observations.
            # Do not silently ignore contradictory payloads on a failed probe.
            for field in ("images", "tables"):
                if item.get(field) not in (None, []):
                    raise EvidenceError(f"unavailable {kind} source has {field}")
            # An unavailable source has no inspected bytes to attest. Reject a
            # contradictory digest rather than silently dropping its claim.
            if item.get("sha256") is not None:
                raise EvidenceError(f"unavailable {kind} source has SHA-256")
        # Preserve failed attempts too: otherwise sources missing on one side
        # could be silently ignored while the successful subset appears pinned.
        result[name] = digest
    return result


def canonical_u64_hex(value, what: str) -> int:
    """Accept the canonical 64-bit VM-address spelling emitted by the probes."""
    if not isinstance(value, str) or not 3 <= len(value) <= 18 or not value.startswith("0x"):
        raise EvidenceError(f"invalid {what}")
    try:
        address = int(value[2:], 16)
    except ValueError as error:
        raise EvidenceError(f"invalid {what}") from error
    if not 0 <= address < 1 << 64 or hex(address) != value:
        raise EvidenceError(f"invalid {what}")
    return address


def checked_binary_callsite(call: dict) -> None:
    """Decode a bounded ARM64 BL call from its reported source instruction bytes.

    The two probes could contain the same corrupted callsite. Comparing their
    JSON alone cannot detect forged instruction bytes or a forged branch target.
    """
    pc = canonical_u64_hex(call.get("call_address"), "binary callsite address")
    target = canonical_u64_hex(call.get("target_address"), "binary callsite target")
    origin = canonical_u64_hex(call.get("window_address"), "binary callsite window")
    if pc % 4 or target % 4 or origin % 4:
        raise EvidenceError("unaligned ARM64 callsite address")
    offset = call.get("file_offset")
    if type(offset) is not int or not 0 <= offset < (1 << 48):
        raise EvidenceError("invalid binary callsite file offset")
    if not all(isinstance(call.get(key), str) and call[key]
               for key in ("section", "target_symbol")):
        raise EvidenceError("invalid binary callsite section/target symbol")
    if call.get("type_constant_candidate") is not None:
        unsigned(call["type_constant_candidate"], "binary callsite type", 255)
    if call.get("registration_pointer_candidate") is not None:
        canonical_u64_hex(call["registration_pointer_candidate"], "binary callsite pointer")
    record = call.get("registration_record_candidate")
    if record is not None and not isinstance(record, dict):
        raise EvidenceError("invalid binary callsite registration record")
    encoded = call.get("instruction_window_hex")
    if (not isinstance(encoded, str) or not 8 <= len(encoded) <= 168
            or len(encoded) % 8 or any(ch not in "0123456789abcdef" for ch in encoded)):
        raise EvidenceError("invalid binary callsite instruction bytes")
    raw = bytes.fromhex(encoded)
    if call.get("window_sha256") != hashlib.sha256(raw).hexdigest():
        raise EvidenceError("binary callsite instruction digest mismatch")
    delta = pc - origin
    if not 0 <= delta <= 64 or delta % 4 or delta + 4 > len(raw):
        raise EvidenceError("invalid binary callsite instruction position")
    word, = struct.unpack_from("<I", raw, delta)
    if word & 0xFC000000 != 0x94000000:
        raise EvidenceError("binary callsite instruction is not ARM64 BL")
    immediate = word & 0x03FFFFFF
    if immediate & (1 << 25):
        immediate -= 1 << 26
    if target != pc + (immediate << 2):
        raise EvidenceError("binary callsite branch target disagrees with instruction")


def verified_registration_callsites(binary: dict, table: dict) -> tuple[int, int]:
    """Require each table-probe callsite to occur in the pinned binary probe.

    Hash equality alone proves that two tools read the same kernelcache bytes,
    not that their static registration observations agree. Match the complete
    callsite record inside the same image name and UUID of the same input path.
    """
    by_source = {}
    observed = 0
    for source in binary["inputs"]:
        if source["status"] != "inspected":
            continue
        images = source.get("images")
        if not isinstance(images, list) or not 1 <= len(images) <= 256:
            raise EvidenceError("missing or unbounded binary image evidence")
        index = {}
        for image in images:
            if not isinstance(image, dict):
                raise EvidenceError("malformed binary image evidence")
            name, uuid = image.get("image"), image.get("uuid")
            if not isinstance(name, str) or not name or (
                    uuid is not None and not isinstance(uuid, str)):
                raise EvidenceError("invalid binary image identity")
            identity = (name, uuid)
            if identity in index:
                raise EvidenceError("duplicate binary image identity")
            calls = image.get("registration_calls")
            if not isinstance(calls, list) or len(calls) > 2048 or any(
                    not isinstance(call, dict) for call in calls):
                raise EvidenceError("malformed binary registration callsites")
            # The probes both reuse decmpfs_binary_probe.callsites(). Equality
            # includes address, target, instruction window and byte digest.
            for call in calls:
                checked_binary_callsite(call)
            signatures = [
                json.dumps(call, sort_keys=True, separators=(",", ":"))
                for call in calls
            ]
            # One instruction address can represent only one callsite within
            # a pinned image. Distinct windows or metadata must not make a
            # duplicate physical callsite look like independent evidence.
            addresses = [call["call_address"] for call in calls]
            if len(set(signatures)) != len(signatures) or len(set(addresses)) != len(addresses):
                raise EvidenceError("duplicate binary registration callsite")
            index[identity] = set(signatures)
            observed += len(calls)
        by_source[source["path"]] = index

    matched = 0
    for source in table["inputs"]:
        if source["status"] != "inspected":
            continue
        images = by_source[source["path"]]
        tables = source.get("tables")
        if not isinstance(tables, list) or len(tables) > 128:
            raise EvidenceError("malformed registration table evidence")
        used = set()
        for entry in tables:
            if not isinstance(entry, dict) or not isinstance(entry.get("callsite"), dict):
                raise EvidenceError("registration table missing binary callsite")
            identity = (entry.get("image"), entry.get("uuid"))
            calls = images.get(identity)
            signature = json.dumps(
                entry["callsite"], sort_keys=True, separators=(",", ":"))
            if calls is None or signature not in calls:
                raise EvidenceError("registration callsite disagrees with binary evidence")
            key = (identity, signature)
            if key in used:
                raise EvidenceError("duplicate registration callsite attribution")
            used.add(key)
            matched += 1
    return matched, observed


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


def checked_table_bytes(rows: dict, entry: dict, observations: list) -> None:
    """Verify every summarized type and pointer against captured table bytes.

    A matching kernelcache digest only pins the source file. The table probe
    also emits its exact registration bytes, so reported types, pointers and
    callsite linkage must agree with that bounded byte sequence. This is
    internal consistency evidence, not independent runtime decoder proof.
    """
    count = rows["count"]
    if type(rows.get("stride")) is not int or rows["stride"] != 16:
        raise EvidenceError("invalid registration table stride")
    encoded = rows.get("bytes_hex")
    if not isinstance(encoded, str) or len(encoded) != count * 32 or any(
            char not in "0123456789abcdef" for char in encoded):
        raise EvidenceError("invalid registration table raw bytes")
    raw = bytes.fromhex(encoded)
    if rows.get("sha256") != hashlib.sha256(raw).hexdigest():
        raise EvidenceError("registration table raw byte digest mismatch")
    callsite = entry.get("callsite")
    window = callsite.get("window_sha256") if isinstance(callsite, dict) else None
    if not isinstance(window, str) or len(window) != 64 or any(
            char not in "0123456789abcdef" for char in window) or (
            rows.get("loop_window_sha256") != window):
        raise EvidenceError("registration table callsite window digest mismatch")
    try:
        address = int(rows["address"], 16)
    except (KeyError, TypeError, ValueError) as error:
        raise EvidenceError("invalid registration table address") from error
    if hex(address) != rows["address"] or not 0 <= address <= (1 << 64) - count * 16:
        raise EvidenceError("invalid registration table address")
    for index, record in enumerate(observations):
        number, padding, pointer = struct.unpack_from("<IIQ", raw, index * 16)
        if padding != 0 or number >= 255 or number != record["type"]:
            raise EvidenceError("registration table type or padding differs from raw bytes")
        if record.get("raw_registration_pointer") != hex(pointer):
            raise EvidenceError("registration pointer differs from raw bytes")
        resolution = record["pointer_resolution"]
        if resolution.get("address") != hex(address + index * 16 + 8):
            raise EvidenceError("registration pointer resolution address mismatch")


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
            checked_table_bytes(rows, entry, observations)
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
    matched_calls, observed_calls = verified_registration_callsites(binary, table)
    catalogue_numbers = verified_catalogue_types(catalogue)
    observed = inventory.get("types")
    if not isinstance(observed, dict) or len(observed) > 255:
        raise EvidenceError("invalid inventory type counts")
    stored = {}
    for key, value in observed.items():
        if (not isinstance(key, str) or not 1 <= len(key) <= 3 or
                not key.isascii() or not key.isdecimal() or
                str(int(key)) != key or not isinstance(value, dict)):
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
        "matched_static_registration_callsites": matched_calls,
        "observed_binary_registration_callsites": observed_calls,
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
