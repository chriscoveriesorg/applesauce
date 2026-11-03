"""Bounded read-only extraction of unencrypted Apple kernelcache containers.

IMG4/IM4P layout follows img4tool's primary implementation. Only extraction
and the public userspace LZFSE decoder are used; nothing is loaded or executed.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
from pathlib import Path
import sys

MAX_PAYLOAD = 128 << 20
MAX_EXPANDED = 256 << 20
MAX_READ = 32 << 20
MACH_MAGICS = (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
LZFSE_MAGICS = (b"bvx2", b"bvx1", b"bvxn", b"bvx-")


class ContainerError(ValueError):
    pass


class View:
    def __init__(self, source, base: int, size: int):
        if base < 0 or size < 0 or base + size > source.size:
            raise ContainerError("container view escapes source")
        self.source, self.base, self.size = source, base, size

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or size > MAX_READ or offset + size > self.size:
            raise ContainerError("container read escapes view or budget")
        return self.source.read(self.base + offset, size)


class Memory:
    def __init__(self, data: bytes):
        self.data, self.size = data, len(data)

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or size > MAX_READ or offset + size > self.size:
            raise ContainerError("memory read escapes decoded image or budget")
        return self.data[offset:offset + size]


def digest(source) -> str:
    value = hashlib.sha256()
    for offset in range(0, source.size, 1 << 20):
        value.update(source.read(offset, min(1 << 20, source.size - offset)))
    return value.hexdigest()


def element(source, offset: int, limit: int) -> tuple[int, int, int]:
    """Read one definite-length DER TLV, returning tag, content offset and end."""
    if offset < 0 or limit > source.size or offset + 2 > limit:
        raise ContainerError("truncated DER element")
    tag, first = source.read(offset, 2)
    if tag & 31 == 31:
        raise ContainerError("high-tag DER element is unsupported")
    cursor = offset + 2
    if first & 128:
        count = first & 127
        if not 1 <= count <= 4 or cursor + count > limit:
            raise ContainerError("indefinite, excessive or truncated DER length")
        raw = source.read(cursor, count)
        length = int.from_bytes(raw, "big")
        if raw[0] == 0 or length < 128:
            raise ContainerError("non-canonical DER length")
        cursor += count
    else:
        length = first
    if cursor + length > limit:
        raise ContainerError("DER element escapes parent")
    return tag, cursor, cursor + length


def field(source, offset: int, limit: int, wanted: int):
    tag, start, end = element(source, offset, limit)
    if tag != wanted:
        raise ContainerError("unexpected DER field tag")
    return start, end


def payload(source):
    """Unwrap only the explicit IMG4 -> IM4P -> payload structure."""
    start, end = field(source, 0, source.size, 0x30)
    if end != source.size:
        raise ContainerError("trailing bytes after DER container")
    label_start, cursor = field(source, start, end, 0x16)
    label = source.read(label_start, cursor - label_start)
    kind = "IM4P"
    if label == b"IMG4":
        start, end = field(source, cursor, end, 0x30)
        label_start, cursor = field(source, start, end, 0x16)
        label = source.read(label_start, cursor - label_start)
        kind = "IMG4/IM4P"
    if label != b"IM4P":
        raise ContainerError("expected IMG4 or IM4P container")
    type_start, cursor = field(source, cursor, end, 0x16)
    if cursor - type_start != 4:
        raise ContainerError("IM4P payload type must have four bytes")
    payload_type = source.read(type_start, 4)
    if payload_type != b"krnl":
        raise ContainerError("only unencrypted krnl payloads are accepted")
    desc_start, cursor = field(source, cursor, end, 0x16)
    if cursor - desc_start > 4096:
        raise ContainerError("oversized IM4P description")
    description = source.read(desc_start, cursor - desc_start).decode("ascii", "replace")
    data_start, data_end = field(source, cursor, end, 4)
    if not 4 <= data_end - data_start <= MAX_PAYLOAD:
        raise ContainerError("IM4P payload exceeds extraction budget")
    return View(source, data_start, data_end - data_start), {
        "container": kind, "payload_type": "krnl", "description": description,
        "payload_offset": data_start, "payload_size": data_end - data_start,
        "container_signature_verified": False,
    }


def decode_lzfse(source) -> bytes:
    """Public userspace codec only, with a sentinel byte to detect truncation."""
    if sys.platform != "darwin":
        raise ContainerError("LZFSE payload requires macOS public libcompression")
    if not 4 <= source.size <= MAX_PAYLOAD:
        raise ContainerError("LZFSE input exceeds extraction budget")
    library = ctypes.CDLL("/usr/lib/libcompression.dylib")
    decode = library.compression_decode_buffer
    decode.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                       ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]
    decode.restype = ctypes.c_size_t
    data = b"".join(source.read(offset, min(1 << 20, source.size - offset))
                    for offset in range(0, source.size, 1 << 20))
    encoded = ctypes.create_string_buffer(data, len(data))
    capacity = 8 << 20
    while capacity <= MAX_EXPANDED:
        output = ctypes.create_string_buffer(capacity + 1)
        count = decode(output, capacity + 1, encoded, len(data), None, 0x801)
        if not count:
            raise ContainerError("LZFSE payload failed to decode")
        if count <= capacity:
            return output.raw[:count]
        del output
        capacity *= 2
    raise ContainerError("LZFSE expanded image exceeds 256 MiB budget")


def prepare(source, decoder=None):
    magic = source.read(0, min(4, source.size))
    if magic in MACH_MAGICS:
        return source, {"container": "Mach-O", "offset_space": "original-file"}
    if magic[:1] == b"\x30":
        image, report = payload(source)
    elif magic in LZFSE_MAGICS:
        image = source
        report = {"container": "LZFSE", "payload_offset": 0, "payload_size": source.size}
    else:
        raise ContainerError(f"unsupported kernelcache magic {magic.hex()}")
    report["payload_sha256"] = digest(image)
    magic = image.read(0, 4)
    if magic in LZFSE_MAGICS:
        decoded = (decoder or decode_lzfse)(image)
        if not isinstance(decoded, bytes) or not 4 <= len(decoded) <= MAX_EXPANDED:
            raise ContainerError("invalid or oversized decoded image")
        image = Memory(decoded)
        report["compression"] = "LZFSE"
        report["offset_space"] = "decoded-Mach-O"
    else:
        report["compression"] = "none"
        report["offset_space"] = "IM4P-payload-relative"
    if image.read(0, 4) not in MACH_MAGICS:
        raise ContainerError("payload is not a supported Mach-O image")
    report["image_size"] = image.size
    report["image_sha256"] = digest(image)
    return image, report


def child_directories(path: Path):
    """Bounded, non-recursive directory discovery without following symlinks."""
    try:
        with os.scandir(path) as entries:
            result = []
            for count, entry in enumerate(entries, 1):
                if count > 256:
                    raise ContainerError("system directory discovery exceeds budget")
                if entry.is_dir(follow_symlinks=False):
                    result.append(Path(entry.path))
            return sorted(result)
    except FileNotFoundError:
        return []


def system_paths(root=Path("/")) -> list[Path]:
    candidates = {
        root / "System/Library/KernelCollections/BootKernelExtensions.kc",
        root / "System/Library/KernelCollections/SystemKernelExtensions.kc",
    }
    preboot = root / "System/Volumes/Preboot"
    for volume in child_directories(preboot):
        boot = volume / "boot"
        if boot.is_symlink():
            continue
        for manifest in child_directories(boot):
            candidate = manifest / "System/Library/Caches/com.apple.kernelcaches/kernelcache"
            if any(parent.is_symlink() for parent in candidate.parents if parent != root):
                continue
            if candidate.exists():
                candidates.add(candidate)
            if len(candidates) > 16:
                raise ContainerError("too many system kernelcache candidates")
    for path in ("System/Library/Extensions", "Library/Apple/System/Library/Extensions"):
        for candidate in (root / path).glob("*FSCompression*.kext/Contents/MacOS/*"):
            if not any(parent.is_symlink() for parent in candidate.parents if parent != root):
                candidates.add(candidate)
            if len(candidates) > 16:
                raise ContainerError("too many system binary candidates")
    return sorted(candidates)
