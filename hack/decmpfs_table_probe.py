#!/usr/bin/env python3
"""Read-only extraction of compiler-shaped decmpfs registration tables.

Raw pointer interpretation requires declared chained-fixup metadata and exact
chain membership. No type is assigned a codec identity; native gates stay shut.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct

import decmpfs_binary_probe as probe
from decmpfs_config_probe import inspect_configuration, named_decoder_windows
from kernelcache_container import ContainerError, prepare, system_paths


class TableError(probe.EvidenceError):
    pass


def loop_candidate(call):
    code = bytes.fromhex(call["instruction_window_hex"])
    origin = int(call["window_address"], 16)
    call_address = int(call["call_address"], 16)
    delta = call_address - origin
    if delta % 4 or delta < 28 or delta + 20 > len(code):
        return None
    words = struct.unpack_from("<12I", code, delta - 28)
    zero, adrp, add, indexed, ldr_type, ldr_pointer, move, branch, error, step, compare, back = words
    index, base, addr, value = zero & 31, adrp & 31, indexed & 31, ldr_type & 31
    if not (19 <= index <= 28 and 19 <= base <= 28 and index != base):
        return None
    checks = [
        zero & 0xFFFFFFE0 == 0xD2800000,
        adrp & 0x9F000000 == 0x90000000,
        add & 0xFFC00000 == 0x91000000 and add & 31 == base and add >> 5 & 31 == base,
        indexed & 0xFFE0FC00 == 0x8B001000 and indexed >> 5 & 31 == base and indexed >> 16 & 31 == index,
        ldr_type & 0xFFFFFC00 == 0xB9400000 and ldr_type >> 5 & 31 == addr,
        ldr_pointer & 0xFFFFFC1F == 0xF9400401 and ldr_pointer >> 5 & 31 == addr,
        move & 0xFFE0FFFF == 0xAA0003E0 and move >> 16 & 31 == value,
        branch & 0xFC000000 == 0x94000000,
        error & 0xFF00001F == 0x35000000,
        step & 0xFFC00000 == 0x91000000 and step >> 10 & 4095 == 1
        and step & 31 == index and step >> 5 & 31 == index,
        compare & 0xFFC0001F == 0xF100001F and compare >> 5 & 31 == index,
        back & 0xFF00001F == 0x54000001,
    ]
    count = compare >> 10 & 4095
    target = call_address + 16 + (probe.signed(back >> 5 & 0x7FFFF, 19) << 2)
    if not all(checks) or not 1 <= count <= 64 or target != call_address - 16:
        return None
    constants = probe.local_constants(struct.pack("<2I", adrp, add), call_address - 24)
    if base not in constants:
        return None
    return {"table_address": constants[base], "count": count, "stride": 16,
            "call_address": call_address, "loop_window_sha256": call["window_sha256"]}


def metadata(image):
    _, _, _, _, count, size, _, _ = probe.unpack("<8I", image.read(image.header, 32))
    data = image.read(image.header + 32, size)
    segments, fixups = [], None
    cursor = 0
    for _ in range(count):
        command, length = probe.unpack("<II", data, cursor)
        if command == 0x19:
            vmaddr, vmsize, fileoff, filesize = probe.unpack("<4Q", data, cursor + 24)
            segments.append({"vmaddr": vmaddr, "vmsize": vmsize,
                             "fileoff": fileoff, "filesize": filesize})
        elif command == 0x80000034:
            if length != 16 or fixups is not None:
                raise TableError("invalid or duplicate chained-fixup command")
            fixups = probe.unpack("<2I", data, cursor + 8)
        cursor += length
    return segments, fixups


class Fixups:
    """Resolve only declared format 7/8 pointers present in a page chain."""
    def __init__(self, root):
        self.root = root
        self.segments, self.command = metadata(root)
        bases = [s["vmaddr"] for s in self.segments if s["fileoff"] == 0 and s["filesize"]]
        self.base = bases[0] if len(bases) == 1 else None

    def resolve(self, address):
        result = {"address": hex(address), "status": "unresolved"}
        try:
            result.update(self._resolve(address))
        except (probe.EvidenceError, ContainerError) as error:
            result["reason"] = str(error)
        return result

    def _resolve(self, address):
        if self.base is None or self.command is None:
            raise TableError("missing unique image base or chained-fixup metadata")
        offset, size = self.command
        if not 28 <= size <= 8 << 20:
            raise TableError("chained-fixup metadata exceeds bounds")
        data = self.root.read(offset, size)
        version, starts = probe.unpack("<II", data)
        if version != 0 or not 28 <= starts <= size - 4:
            raise TableError("unsupported chained-fixup header")
        count, = probe.unpack("<I", data, starts)
        if count != len(self.segments) or count > 128 or starts + 4 + count * 4 > size:
            raise TableError("chained-fixup segment count mismatch")
        for index, segment in enumerate(self.segments):
            relative = address - segment["vmaddr"]
            if not 0 <= relative <= segment["filesize"] - 8:
                continue
            entry, = probe.unpack("<I", data, starts + 4 + index * 4)
            position = starts + entry
            if not entry or position < starts + 4 + count * 4 or position + 22 > size:
                raise TableError("no valid segment chain metadata")
            total, page_size, fmt, segment_offset, _, page_count = probe.unpack("<IHHQIH", data, position)
            if total < 22 + page_count * 2 or position + total > size:
                raise TableError("invalid chain page array")
            if fmt not in (7, 8) or page_size not in (4096, 16384):
                raise TableError("unsupported pointer format or page size")
            if self.base + segment_offset != segment["vmaddr"]:
                raise TableError("chain segment base disagrees with Mach-O")
            page, within = divmod(relative, page_size)
            if page >= page_count:
                raise TableError("pointer outside chained pages")
            start, = probe.unpack("<H", data, position + 22 + page * 2)
            if start & 0x8000:
                raise TableError("page has no chain or uses unsupported multi-start chains")
            cursor = start
            for _ in range(page_size // 4):
                if cursor > within or cursor + 8 > page_size:
                    break
                fileoff = segment["fileoff"] + page * page_size + cursor
                if page * page_size + cursor + 8 > segment["filesize"]:
                    raise TableError("chain escapes file-backed segment")
                raw, = probe.unpack("<Q", self.root.read(fileoff, 8))
                if cursor == within:
                    if fmt == 7:
                        if raw >> 62 & 1:
                            raise TableError("bound ARM64E pointer is unsupported")
                        auth = raw >> 63
                        if not auth and (raw >> 43 & 255):
                            raise TableError("nonzero ARM64E high8 requires separate validation")
                        target_offset = raw & ((1 << (32 if auth else 43)) - 1)
                    else:
                        if raw >> 30 & 3:
                            raise TableError("nonzero kernel-cache level requires another verified base")
                        target_offset = raw & ((1 << 30) - 1)
                    target = self.base + target_offset
                    if not any(s["vmaddr"] <= target < s["vmaddr"] + s["vmsize"] for s in self.segments):
                        raise TableError("decoded target escapes image VM ranges")
                    return {"status": "chain-verified", "pointer_format": fmt,
                            "raw_pointer": hex(raw), "target": hex(target),
                            "image_base": hex(self.base), "file_offset": self.root.base + fileoff,
                            "metadata_file_offset": self.root.base + offset + position,
                            "metadata_sha256": hashlib.sha256(data).hexdigest()}
                hop = (raw >> 51 & (0x7FF if fmt == 7 else 0xFFF)) * 4
                if not hop:
                    break
                cursor += hop
            raise TableError("address is not a member of the declared page chain")
        raise TableError("address outside file-backed segments")


def callback_window(image, address):
    """Capture bounded code bytes; the window is not a function-boundary claim."""
    definitions = {value: name for name, kind, _, value in image.symbols
                   if kind & 0xE == 0xE and not kind & 0xE0}
    for section in image.sections:
        delta = address - section["address"]
        if not section["flags"] & 0x80000400 or address % 4 or not 0 <= delta < section["size"]:
            continue
        length = min(2048, section["size"] - delta) & ~3
        code = image.read(section["offset"] + delta, length)
        branches = []
        for offset in range(0, length, 4):
            word, = probe.unpack("<I", code, offset)
            if word & 0x7C000000 == 0x14000000:
                target = address + offset + (probe.signed(word & 0x3FFFFFF, 26) << 2)
                branches.append({"address": hex(address + offset), "target": hex(target),
                                 "instruction": "BL" if word & 0x80000000 else "B",
                                 "exact_target_symbol": definitions.get(target)})
        return {"address": hex(address), "bytes_hex": code.hex(), "size": length,
                "sha256": hashlib.sha256(code).hexdigest(),
                "file_offset": image.base + section["offset"] + delta,
                "direct_branches": branches, "function_boundary_proven": False}
    return None


def read_table(image, candidate, fixups):
    address, count = candidate["table_address"], candidate["count"]
    length = count * 16
    for section in image.sections:
        delta = address - section["address"]
        if section["flags"] & 255 in (1, 12, 18) or not 0 <= delta <= section["size"] - length:
            continue
        fileoff = section["offset"] + delta
        raw = image.read(fileoff, length)
        entries = []
        for index in range(count):
            type_number, padding, pointer = probe.unpack("<IIQ", raw, index * 16)
            if type_number >= 255 or padding != 0:
                raise TableError("registration table has unsupported type or nonzero padding")
            resolution = fixups.resolve(address + index * 16 + 8)
            entry = {"type": type_number, "raw_registration_pointer": hex(pointer),
                     "pointer_resolution": resolution}
            if resolution["status"] == "chain-verified":
                regaddr = int(resolution["target"], 16)
                record = probe.registration_record(image, regaddr)
                entry["registration"] = record
                if record and record["status"] == "candidate-bytes":
                    for number, callback in enumerate(record["callbacks"]):
                        if int(callback["raw_pointer"], 16):
                            callback["resolution"] = fixups.resolve(regaddr + 8 + number * 8)
                            if callback["resolution"]["status"] == "chain-verified":
                                callback["code_window"] = callback_window(
                                    image, int(callback["resolution"]["target"], 16))
            entries.append(entry)
        return {"address": hex(address), "file_offset": image.base + fileoff, "count": count,
                "stride": 16, "bytes_hex": raw.hex(), "sha256": hashlib.sha256(raw).hexdigest(),
                "loop_window_sha256": candidate["loop_window_sha256"], "entries": entries}
    raise TableError("registration table is outside file-backed image sections")


def inspect(source):
    reports = []
    for base, length in probe.slices(source):
        root = probe.Image(source, base, length, 0, "top-level")
        fixups = Fixups(root)
        selected = [probe.Image(source, base, length, offset, name)
                    for offset, name in root.entries if "AppleFSCompression" in name or name == "com.apple.kernel"]
        targets = root.registration_targets()
        for image in selected:
            targets.update(image.registration_targets())
        for image in selected:
            if "AppleFSCompression" not in image.name:
                continue
            for call in probe.callsites(image, targets):
                candidate = loop_candidate(call)
                if candidate:
                    table = read_table(image, candidate, fixups)
                    reports.append({"image": image.name, "uuid": image.uuid,
                                    "callsite": call, "table": table,
                                    "type_configuration": inspect_configuration(image, table, callback_window),
                                    "named_decoders": named_decoder_windows(image, callback_window)})
    return reports


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", action="store_true")
    parser.add_argument("--image", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    paths = list(dict.fromkeys(args.image + (system_paths() if args.system else [])))
    if not paths or len(paths) > 16:
        parser.error("supply 1..16 --image paths or --system")
    report = {"schema_version": 1, "kind": "read-only-decmpfs-registration-table-evidence",
              "inputs": [], "native_raven_mesh_writes_permitted": False,
              "kernel_decoder_proven": False,
              "codec_identity_proven": False, "on_disk_framing_proven": False,
              "fixup_layout_source": {"repository": "apple-oss-distributions/dyld",
                  "path": "include/mach-o/fixup-chains.h",
                  "blob_sha": "d5e1b3bdf8e4e2dcec2359313a8f3146efbd64b0"},
              "limitations": ["Recognizes one bounded compiler loop shape; other registration paths can exist.",
                              "Compiled registrations do not establish runtime registration success or codec identity.",
                              "Only declared format 7/8 chains with a verified base are resolved; binds and multi-start pages remain unresolved."]}
    for path in paths:
        entry = {"path": str(path)}
        source = None
        try:
            source = probe.Source(path)
            entry["sha256"] = source.digest()
            image, entry["extraction"] = prepare(source)
            entry["tables"] = inspect(image)
            source.unchanged()
            entry["status"] = "inspected"
        except (OSError, probe.EvidenceError, ContainerError) as error:
            entry.pop("sha256", None)
            entry.update(status="unavailable", error=str(error))
        finally:
            if source:
                source.close()
        report["inputs"].append(entry)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if any(item["status"] == "inspected" for item in report["inputs"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
