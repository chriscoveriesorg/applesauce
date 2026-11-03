#!/usr/bin/env python3
"""Read-only Mach-O evidence for Apple's decmpfs registration callsites.

Parses existing binaries; never loads a kext, mounts a volume, calls a codec,
sets an xattr or executes extracted instructions. Local instruction constants
are research candidates, never a codec/type mapping or writer authorization.
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

MAX_FILE = 1 << 30
MAX_READ = 32 << 20
MAX_SYMBOLS = 250_000
MAX_IMAGES = 512
MAX_CALLS = 256
REGISTER = "register_decmpfs_decompressor"


class EvidenceError(ValueError):
    pass


class Source:
    """Bounded pread on one pinned, non-symlink regular file descriptor."""
    def __init__(self, path: Path):
        if not hasattr(os, "O_NOFOLLOW"):
            raise EvidenceError("O_NOFOLLOW is required")
        self.fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        self.before = os.fstat(self.fd)
        self.size = self.before.st_size
        if not stat.S_ISREG(self.before.st_mode) or self.size > MAX_FILE:
            os.close(self.fd)
            raise EvidenceError("input must be a regular file of at most 1 GiB")

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or size > MAX_READ or offset + size > self.size:
            raise EvidenceError("out-of-bounds or oversized read")
        result = os.pread(self.fd, size, offset)
        if len(result) != size:
            raise EvidenceError("short read; input may have changed")
        return result

    def digest(self) -> str:
        result = hashlib.sha256()
        for offset in range(0, self.size, 1 << 20):
            result.update(self.read(offset, min(1 << 20, self.size - offset)))
        return result.hexdigest()

    def unchanged(self) -> None:
        after = os.fstat(self.fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(self.before, key) != getattr(after, key) for key in fields):
            raise EvidenceError("input changed during evidence collection")

    def close(self) -> None:
        os.close(self.fd)


def unpack(fmt: str, data: bytes, offset: int = 0):
    try:
        return struct.unpack_from(fmt, data, offset)
    except struct.error as error:
        raise EvidenceError("truncated Mach-O structure") from error


def cstring(data: bytes, offset: int = 0) -> str:
    if offset < 0 or offset >= len(data):
        raise EvidenceError("invalid string offset")
    end = data.find(b"\0", offset)
    if end < 0 or end - offset > 4096:
        raise EvidenceError("unterminated or oversized string")
    try:
        return data[offset:end].decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise EvidenceError("invalid UTF-8 symbol or identifier") from error


def signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def slices(source) -> list[tuple[int, int]]:
    magic = source.read(0, 4)
    if magic == b"\xcf\xfa\xed\xfe":
        return [(0, source.size)]
    if magic not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        raise EvidenceError("unsupported container; require uncompressed 64-bit Mach-O")
    count, = unpack(">I", source.read(4, 4))
    if not 0 < count <= 16:
        raise EvidenceError("invalid universal architecture count")
    stride = 32 if magic[-1] == 0xBF else 20
    table_end = 8 + count * stride
    result = []
    ranges = []
    for index in range(count):
        entry = source.read(8 + index * stride, stride)
        cpu, = unpack(">I", entry)
        offset, size = unpack(">QQ" if stride == 32 else ">II", entry, 8)
        if offset < table_end or size < 32 or offset + size > source.size:
            raise EvidenceError("invalid universal slice range")
        if any(offset < other + length and other < offset + size for other, length in ranges):
            raise EvidenceError("overlapping universal slices")
        ranges.append((offset, size))
        # ARM64 / x86_64. Other architectures remain unsupported, not absent.
        if cpu in (0x0100000C, 0x01000007):
            if unpack("<I", source.read(offset + 4, 4))[0] != cpu:
                raise EvidenceError("universal/header architecture mismatch")
            result.append((offset, size))
    if not result:
        raise EvidenceError("no supported 64-bit architecture")
    return result


class Image:
    def __init__(self, source, base: int, size: int, header: int, name: str):
        self.source, self.base, self.size = source, base, size
        self.header, self.name = header, name
        self.sections, self.entries, self.symbols = [], [], []
        self.uuid = None
        self.symtab = self.indirect = None
        values = unpack("<8I", self.read(header, 32))
        magic, self.cpu, self.subtype, self.filetype, count, command_size, _, _ = values
        if magic != 0xFEEDFACF or count > 16384 or command_size > 8 << 20:
            raise EvidenceError("unsupported header or excessive load commands")
        commands = self.read(header + 32, command_size)
        offset = 0
        for _ in range(count):
            command, length = unpack("<II", commands, offset)
            if length < 8 or length % 8 or offset + length > len(commands):
                raise EvidenceError("invalid load command length")
            data = commands[offset:offset + length]
            if command == 0x1B:  # LC_UUID
                if length != 24:
                    raise EvidenceError("invalid UUID command")
                self.uuid = data[8:24].hex()
            elif command == 2:  # LC_SYMTAB
                if length != 24 or self.symtab is not None:
                    raise EvidenceError("invalid or duplicate symbol table")
                self.symtab = unpack("<4I", data, 8)
            elif command == 0xB:  # LC_DYSYMTAB
                if length != 80 or self.indirect is not None:
                    raise EvidenceError("invalid or duplicate dynamic symbol table")
                self.indirect = unpack("<II", data, 56)
            elif command == 0x19:  # LC_SEGMENT_64
                if length < 72:
                    raise EvidenceError("truncated segment")
                count_sections, = unpack("<I", data, 64)
                if length != 72 + count_sections * 80:
                    raise EvidenceError("invalid section count")
                for index in range(count_sections):
                    sec = data[72 + index * 80:152 + index * 80]
                    addr, secsize, fileoff = unpack("<QQI", sec, 32)
                    flags, reserved1, reserved2 = unpack("<III", sec, 64)
                    self.sections.append({
                        "name": sec[:16].split(b"\0")[0].decode("ascii", "replace"),
                        "address": addr, "size": secsize, "offset": fileoff,
                        "flags": flags, "reserved1": reserved1, "reserved2": reserved2,
                    })
            elif command == 0x80000035:  # LC_FILESET_ENTRY
                if length < 40 or self.filetype != 12:
                    raise EvidenceError("invalid fileset entry")
                _, fileoff, stringoff = unpack("<QQI", data, 8)
                if stringoff < 32 or fileoff < 32 or fileoff + 32 > size:
                    raise EvidenceError("invalid fileset entry offset")
                self.entries.append((fileoff, cstring(data, stringoff)))
            offset += length
        if offset != len(commands):
            raise EvidenceError("load command count/size mismatch")
        if len(self.entries) > MAX_IMAGES or len({v[0] for v in self.entries}) != len(self.entries):
            raise EvidenceError("too many or duplicate fileset entries")
        if self.symtab is not None:
            symoff, count, stroff, strsize = self.symtab
            if count > MAX_SYMBOLS or strsize > MAX_READ:
                raise EvidenceError("symbol table exceeds evidence budget")
            strings = self.read(stroff, strsize)
            symbols = self.read(symoff, count * 16)
            for offset in range(0, len(symbols), 16):
                strx, kind, section, _, address = unpack("<IBBHQ", symbols, offset)
                name = cstring(strings, strx) if strx else ""
                self.symbols.append((name, kind, section, address))

    def read(self, offset: int, length: int) -> bytes:
        # Offsets inside fileset members refer to the enclosing Mach-O slice.
        if offset < 0 or length < 0 or offset + length > self.size:
            raise EvidenceError("range escapes Mach-O slice")
        return self.source.read(self.base + offset, length)

    def registration_targets(self) -> dict[int, str]:
        targets = {address: name for name, kind, _, address in self.symbols
                   if name in (REGISTER, "_" + REGISTER) and kind & 0xE == 0xE
                   and not kind & 0xE0 and address}
        if self.indirect is not None:
            offset, count = self.indirect
            if count > MAX_SYMBOLS:
                raise EvidenceError("too many indirect symbols")
            entries = self.read(offset, count * 4)
            for section in self.sections:
                if section["flags"] & 0xFF != 8:  # S_SYMBOL_STUBS
                    continue
                stride = section["reserved2"]
                if not stride or section["size"] % stride:
                    raise EvidenceError("invalid symbol stub size")
                total, start = section["size"] // stride, section["reserved1"]
                if start + total > count:
                    raise EvidenceError("stub range exceeds indirect symbols")
                for index in range(total):
                    symbol, = unpack("<I", entries, (start + index) * 4)
                    if symbol & 0xC0000000:
                        continue
                    if symbol >= len(self.symbols):
                        raise EvidenceError("invalid indirect symbol index")
                    name = self.symbols[symbol][0]
                    if name in (REGISTER, "_" + REGISTER):
                        targets[section["address"] + index * stride] = name + " (symbol stub)"
        return targets


def local_constants(code: bytes, address: int) -> dict[int, int]:
    """Conservative straight-line candidates, not a control-flow proof."""
    registers = {}
    for offset in range(0, len(code), 4):
        word, = unpack("<I", code, offset)
        rd, rn, pc = word & 31, word >> 5 & 31, address + offset
        sf = word >> 31
        width_mask = (1 << (64 if sf else 32)) - 1
        if word & 0x7C000000 == 0x14000000 or word & 0xFF000000 == 0x54000000 \
                or word & 0x7E000000 in (0x34000000, 0x36000000) \
                or word & 0xFE000000 == 0xD6000000:
            registers.clear()  # all calls, branches and indirect returns
        elif word & 0x1F800000 == 0x12800000:  # MOVN, MOVZ, MOVK
            op, shift = word >> 29 & 3, (word >> 21 & 3) * 16
            immediate = (word >> 5 & 0xFFFF) << shift
            if (not sf and shift >= 32) or op == 1:
                registers.clear()
            elif op == 2:
                registers[rd] = immediate
            elif op == 0:
                registers[rd] = (~immediate) & width_mask
            elif rd in registers:
                registers[rd] = ((registers[rd] & ~(0xFFFF << shift)) | immediate) & width_mask
        elif word & 0x9F000000 in (0x90000000, 0x10000000):  # ADRP / ADR
            imm = signed(((word >> 5 & 0x7FFFF) << 2) | (word >> 29 & 3), 21)
            registers[rd] = ((pc & ~4095) + (imm << 12)) if word & 0x80000000 else pc + imm
        elif word & 0x7F000000 == 0x11000000:  # ADD immediate, without flags
            if rn in registers and rn != 31:
                registers[rd] = (registers[rn] + ((word >> 10 & 0xFFF) <<
                                                (12 if word & 0x400000 else 0))) & width_mask
            else:
                registers.pop(rd, None)
        elif word == 0xD503201F:  # NOP
            pass
        else:
            # Unknown instructions may write multiple registers or affect flow.
            # Losing candidates is safer than attaching a stale type to a call.
            registers.clear()
        registers.pop(31, None)
    return registers



def registration_record(image: Image, address: int | None) -> dict | None:
    """Preserve a candidate XNU V1/V3 table without guessing pointer fixups."""
    if address is None:
        return None
    result = {"address": hex(address), "status": "unresolved",
              "pointer_interpretation": "raw; no rebasing or PAC stripping"}
    if address % 8:
        result["reason"] = "unaligned candidate"
        return result
    for section in image.sections:
        if section["flags"] & 0xFF in (1, 12, 18):
            continue
        delta = address - section["address"]
        if not 0 <= delta <= section["size"] - 4:
            continue
        version, = unpack("<I", image.read(section["offset"] + delta, 4))
        if version not in (1, 3):
            result["reason"] = "candidate is not an XNU V1/V3 registration"
            return result
        length = 40 if version == 1 else 48
        if delta + length > section["size"]:
            result["reason"] = "candidate registration crosses a section boundary"
            return result
        raw = image.read(section["offset"] + delta, length)
        names = ("validate", "adjust_fetch", "fetch", "free_data", "get_flags")
        definitions = {value: name for name, kind, _, value in image.symbols
                       if kind & 0xE == 0xE and not kind & 0xE0}
        callbacks = []
        for index in range((length - 8) // 8):
            pointer, = unpack("<Q", raw, 8 + index * 8)
            callbacks.append({"field": names[index], "raw_pointer": hex(pointer),
                              "exact_symbol": definitions.get(pointer) if pointer else None})
        result.update(status="candidate-bytes", version=version,
                      file_offset=image.base + section["offset"] + delta,
                      bytes_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest(),
                      callbacks=callbacks)
        return result
    result["reason"] = "candidate address is outside file-backed sections"
    return result


def callsites(image: Image, targets: dict[int, str]) -> list[dict]:
    if image.cpu != 0x0100000C:
        return []
    result = []
    scanned = 0
    for section in image.sections:
        if not (section["flags"] & 0x80000400) or section["flags"] & 0xFF in (1, 12, 18):
            continue
        scanned += section["size"]
        if scanned > MAX_READ or section["size"] % 4:
            raise EvidenceError("instruction section exceeds budget or alignment")
        code = image.read(section["offset"], section["size"])
        for offset in range(0, len(code), 4):
            word, = unpack("<I", code, offset)
            if word & 0xFC000000 != 0x94000000:  # direct AArch64 BL only
                continue
            pc = section["address"] + offset
            target = pc + (signed(word & 0x3FFFFFF, 26) << 2)
            if target not in targets:
                continue
            if len(result) >= MAX_CALLS:
                raise EvidenceError("too many registration callsites")
            start, end = max(0, offset - 64), min(len(code), offset + 20)
            constants = local_constants(code[start:offset], section["address"] + start)
            candidate = constants.get(0)
            result.append({
                "call_address": hex(pc), "target_address": hex(target),
                "target_symbol": targets[target], "section": section["name"],
                "file_offset": image.base + section["offset"] + offset,
                "window_address": hex(section["address"] + start),
                "instruction_window_hex": code[start:end].hex(),
                "window_sha256": hashlib.sha256(code[start:end]).hexdigest(),
                "type_constant_candidate": candidate if candidate is not None and 0 <= candidate < 255 else None,
                "registration_pointer_candidate": hex(constants[1]) if 1 in constants else None,
                "registration_record_candidate": registration_record(image, constants.get(1)),
            })
    return result


def inspect(source) -> dict:
    reports, errors = [], []
    for base, length in slices(source):
        root = Image(source, base, length, 0, "top-level")
        images = [root]
        for offset, name in root.entries:
            if name == "com.apple.kernel" or "AppleFSCompression" in name:
                try:
                    image = Image(source, base, length, offset, name)
                    if image.entries:
                        raise EvidenceError("nested filesets are unsupported")
                    images.append(image)
                except EvidenceError as error:
                    errors.append({"image": name, "error": str(error)})
        targets = {}
        for image in images:
            targets.update(image.registration_targets())
        for image in images:
            is_compressor = "AppleFSCompression" in image.name or image.filetype == 11
            relevant = []
            for name, kind, section, address in image.symbols:
                low = name.lower()
                if any(key in low for key in ("decmpfs", "lzraven", "lzmesh", "lzbitmap", "lzfse", "lzvn", "lz4")):
                    if len(relevant) >= 512:
                        raise EvidenceError("too many relevant symbols")
                    relevant.append({"name": name, "address": hex(address), "n_type": kind,
                                     "section": section})
            reports.append({
                "image": image.name, "uuid": image.uuid, "cpu_type": image.cpu,
                "cpu_subtype": image.subtype, "file_type": image.filetype,
                "header_file_offset": base + image.header,
                "fileset_entry_count": len(image.entries),
                "symbol_count": len(image.symbols), "relevant_symbols": relevant,
                "registration_calls": callsites(image, targets) if is_compressor else [],
                "registration_target_addresses": [hex(value) for value in sorted(targets)],
            })
    return {"images": reports, "member_errors": errors}


def system_paths() -> list[Path]:
    result = {
        Path("/System/Library/KernelCollections/BootKernelExtensions.kc"),
        Path("/System/Library/KernelCollections/SystemKernelExtensions.kc"),
    }
    for root in ("/System/Library/Extensions", "/Library/Apple/System/Library/Extensions"):
        result.update(Path(root).glob("*FSCompression*.kext/Contents/MacOS/*"))
    if len(result) > 16:
        raise EvidenceError("too many system binary candidates")
    return sorted(result)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system", action="store_true")
    parser.add_argument("--image", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    paths = list(dict.fromkeys(args.image + (system_paths() if args.system else [])))
    if not paths or len(paths) > 16:
        parser.error("supply 1..16 --image inputs, or --system")
    report = {
        "schema_version": 1, "kind": "read-only-decmpfs-binary-evidence",
        "inputs": [], "kernel_decoder_proven": False, "codec_identity_proven": False,
        "registration_layout_source": {
            "repository": "apple-oss-distributions/xnu", "path": "bsd/sys/decmpfs.h",
            "blob_sha": "a7a68d304a3f261be26eb4e4a470b39a204f85b1",
            "supported_versions": [1, 3],
        },
        "on_disk_framing_proven": False, "native_raven_mesh_writes_permitted": False,
        "limitations": [
            "Only uncompressed little-endian 64-bit Mach-O and supported universal slices are parsed.",
            "Direct ARM64 BL calls and symbol stubs only; stripped symbols, indirect calls and veneers may hide registrations.",
            "Constants are local straight-line candidates, not a control-flow or successful-registration proof.",
            "Symbol names and callsites do not identify an on-disk format or establish kernel readback.",
        ],
    }
    for path in paths:
        entry = {"path": str(path)}
        source = None
        try:
            source = Source(path)
            entry["size"] = source.size
            entry["sha256"] = source.digest()
            evidence = inspect(source)
            source.unchanged()
            entry.update(evidence)
            entry["status"] = "inspected"
        except (OSError, EvidenceError) as error:
            entry["status"] = "unavailable"
            entry["error"] = str(error)
        finally:
            if source is not None:
                source.close()
        report["inputs"].append(entry)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if any(entry["status"] == "inspected" for entry in report["inputs"]) else 1


if __name__ == "__main__":
    sys.exit(main())
