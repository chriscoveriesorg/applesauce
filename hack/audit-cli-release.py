#!/usr/bin/env python3
"""Fail-closed audit of the two downloaded macOS Applesauce CLI release archives.

This never installs or executes a downloaded binary. Real install/smoke testing
remains mandatory on disposable arm64 and x86_64 macOS hosts.
"""
import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tarfile
import unicodedata
from pathlib import Path

REPO = "chriscoveriesorg/applesauce"
TAG = "applesauce-cli/v0.5.31"
QUALIFIED_SHA = "1585dceb6c745cebf822588526ee5005255818c9"
ARCH_CPUS = {"aarch64": 0x0100000C, "x86_64": 0x01000007}
# The public archives must run on baseline machines for each target, not
# require arm64e pointer authentication or the x86_64h Haswell variant.
ARCH_SUBTYPES = {"aarch64": 0, "x86_64": 3}
SUFFIXES = (".tar.xz", ".tar.gz")


class AuditError(Exception):
    pass


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def find_archives(directory):
    result = {}
    for arch in ARCH_CPUS:
        candidates = [
            p for p in directory.iterdir()
            if p.is_file() and not p.is_symlink() and p.name.endswith(SUFFIXES)
            and p.name.endswith(tuple("-" + arch + "-apple-darwin" + s for s in SUFFIXES))
            and p.name in tuple(
                f"applesauce-cli-v0.5.31-{arch}-apple-darwin{s}"
                for s in SUFFIXES
            )
        ]
        if len(candidates) != 1:
            raise AuditError(
                f"expected exactly one {arch} Apple archive, found {len(candidates)}"
            )
        result[arch] = candidates[0]
    return result


def check_macho(archive, arch):
    # A verified archive is later extracted by an installer. Validate every tar
    # entry before certifying it, even though this auditor never extracts files.
    found_binary = False
    executable_digest = None
    total_size = 0
    seen_paths = set()
    mac_paths = set()
    regular_files = set()
    nested_prefixes = set()
    try:
        with tarfile.open(archive, "r:*") as tar:
            for index, member in enumerate(tar):
                if index >= 4096:
                    raise AuditError(f"{archive.name}: excessive tar entries")
                # Reject absolute/traversing paths and ambiguous separators.
                # A leading './' is customary in some otherwise safe tarballs.
                name = member.name
                if name.startswith("./"):
                    name = name[2:]
                # A regular file ending in "/" can be interpreted as a directory
                # by extractors; never certify ambiguous file/directory paths.
                if member.isfile() and name.endswith("/"):
                    raise AuditError(f"{archive.name}: regular file has directory-style path")
                parts = name.rstrip("/").split("/")
                if (not name or name.startswith("/") or "\\" in name
                        or any(part in ("", ".", "..") for part in parts)):
                    raise AuditError(f"{archive.name}: unsafe archive member path")
                # Duplicate paths are extraction-order dependent, even when
                # neither entry is the executable. Refuse ambiguous archives.
                if name in seen_paths:
                    raise AuditError(f"{archive.name}: duplicate archive member path")
                seen_paths.add(name)
                # The verified archive will be unpacked onto a macOS filesystem.
                # Reject paths that become aliases under canonical Unicode
                # decomposition and case-insensitive lookup. Otherwise a second
                # file can replace a previously audited 'applesauce' executable.
                mac_parts = [unicodedata.normalize("NFD", part).casefold()
                             for part in parts]
                mac_path = "/".join(mac_parts)
                if mac_path in mac_paths:
                    raise AuditError(
                        f"{archive.name}: archive member path collides on macOS"
                    )
                mac_paths.add(mac_path)

                parents = ["/".join(mac_parts[:count])
                           for count in range(1, len(mac_parts))]
                if any(parent in regular_files for parent in parents):
                    raise AuditError(
                        f"{archive.name}: archive file obstructs nested path"
                    )
                if member.isfile() and mac_path in nested_prefixes:
                    raise AuditError(
                        f"{archive.name}: archive file conflicts with directory"
                    )
                nested_prefixes.update(parents)
                if member.isfile():
                    regular_files.add(mac_path)
                if not (member.isfile() or member.isdir()):
                    raise AuditError(f"{archive.name}: unsafe tar member type")
                # Never certify privileged or sticky extraction modes, even on
                # non-executable archive members.
                if member.mode & 0o7000:
                    raise AuditError(f"{archive.name}: unsafe archive member permissions")
                # Group/world-writable directories can permit replacement of
                # otherwise protected files after extraction. Refuse them too.
                if member.isdir() and member.mode & 0o022:
                    raise AuditError(f"{archive.name}: writable archive directory")
                # Installed regular files must not be modifiable by other users.
                if member.isfile() and member.mode & 0o022:
                    raise AuditError(f"{archive.name}: writable archive regular file")
                # Directory entries have no payload. Reject malformed headers
                # rather than certifying archives with ambiguous extraction behavior.
                if member.isdir() and member.size != 0:
                    raise AuditError(f"{archive.name}: nonempty archive directory entry")
                if member.size < 0 or member.size > 128 * 1024 * 1024:
                    raise AuditError(f"{archive.name}: excessive member size")
                total_size += member.size
                if total_size > 512 * 1024 * 1024:
                    raise AuditError(f"{archive.name}: excessive archive expansion")

                if parts[-1] != "applesauce":
                    continue
                if parts != ["applesauce-cli", "applesauce"]:
                    raise AuditError(f"{archive.name}: unexpected executable path")
                if found_binary or not member.isfile():
                    raise AuditError(f"{archive.name}: duplicate or unsafe applesauce binary")
                found_binary = True
                if (member.size < 40 or not (member.mode & 0o111)
                        or member.mode & 0o022):
                    raise AuditError(f"{archive.name}: invalid or writable executable mode")
                with tar.extractfile(member) as binary:
                    header = binary.read(32)
                    if len(header) != 32:
                        raise AuditError(f"{archive.name}: truncated Mach-O header")
                    magic = header[:4]
                    if magic == b"\xcf\xfa\xed\xfe":
                        endian = "<"
                    elif magic == b"\xfe\xed\xfa\xcf":
                        endian = ">"
                    else:
                        raise AuditError(f"{archive.name}: executable is not a thin Mach-O 64")
                    cpu, subtype, filetype, ncmds, sizeofcmds, _, _ = struct.unpack(
                        endian + "7I", header[4:]
                    )
                    # The reserved word in a 64-bit Mach-O header must be zero.
                    # Refuse malformed headers before certifying executable bytes.
                    reserved = struct.unpack_from(endian + "I", header, 28)[0]
                    if reserved != 0:
                        raise AuditError(f"{archive.name}: nonzero Mach-O reserved header")
                    if filetype != 2:
                        raise AuditError(
                            f"{archive.name}: Mach-O filetype {filetype}, expected executable"
                        )
                    if cpu != ARCH_CPUS[arch]:
                        raise AuditError(f"{archive.name}: Mach-O CPU {cpu:#x}, expected {arch}")
                    # The high capability byte can contain the ordinary LIB64
                    # flag; refuse unknown feature bits and special CPU subtypes.
                    if ((subtype & 0x00ffffff) != ARCH_SUBTYPES[arch]
                            or subtype & 0x7f000000):
                        raise AuditError(
                            f"{archive.name}: Mach-O CPU subtype {subtype:#x} "
                            f"is not baseline {arch}"
                        )
                    if (not 1 <= ncmds <= 4096 or not 8 <= sizeofcmds <= 8 * 1024 * 1024
                            or sizeofcmds > member.size - 32):
                        raise AuditError(f"{archive.name}: invalid Mach-O load command table")
                    commands = binary.read(sizeofcmds)
                    if len(commands) != sizeofcmds:
                        raise AuditError(f"{archive.name}: truncated Mach-O load commands")
                    # Hash the exact executable bytes, not merely the enclosing
                    # attested archive. A full bounded read also refuses a
                    # truncated binary whose initial Mach-O table looks valid.
                    binary_hash = hashlib.sha256()
                    binary_hash.update(header)
                    binary_hash.update(commands)
                    offset = 0
                    macos_marker_seen = False
                    main_entry_seen = False
                    for _ in range(ncmds):
                        if offset + 8 > sizeofcmds:
                            raise AuditError(f"{archive.name}: truncated Mach-O load command")
                        command, size = struct.unpack_from(endian + "II", commands, offset)
                        # A 64-bit Mach-O load command must be eight-byte aligned.
                        # A command with an odd cmdsize can otherwise make the
                        # auditor accept a binary that dyld cannot load.
                        if size < 8 or size % 8 != 0 or offset + size > sizeofcmds:
                            raise AuditError(f"{archive.name}: invalid Mach-O load command size or alignment")
                        # Architecture alone does not distinguish macOS from
                        # iOS/tvOS/watchOS Mach-O executables. Modern toolchains
                        # emit LC_BUILD_VERSION; older ones emit LC_VERSION_MIN_*.
                        if command in (0x32, 0x24, 0x25, 0x2f, 0x30):
                            if macos_marker_seen:
                                raise AuditError(f"{archive.name}: duplicate Mach-O platform marker")
                            if command == 0x32:
                                if size < 24:
                                    raise AuditError(f"{archive.name}: short Mach-O build version")
                                platform = struct.unpack_from(
                                    endian + "I", commands, offset + 8
                                )[0]
                                if platform != 1:  # PLATFORM_MACOS
                                    raise AuditError(
                                        f"{archive.name}: Mach-O targets platform {platform}, not macOS"
                                    )
                                tools = struct.unpack_from(
                                    endian + "I", commands, offset + 20
                                )[0]
                                if size != 24 + tools * 8:
                                    raise AuditError(
                                        f"{archive.name}: inconsistent Mach-O build tool table"
                                    )
                            elif command != 0x24:  # LC_VERSION_MIN_MACOSX
                                raise AuditError(f"{archive.name}: foreign Mach-O platform")
                            elif size != 16:
                                raise AuditError(f"{archive.name}: malformed macOS version command size")
                            macos_marker_seen = True
                        if command == 0x80000028:  # LC_MAIN
                            if main_entry_seen:
                                raise AuditError(f"{archive.name}: duplicate Mach-O LC_MAIN")
                            main_entry_seen = True
                            if size != 24:
                                raise AuditError(f"{archive.name}: malformed Mach-O LC_MAIN")
                            entryoff = struct.unpack_from(
                                endian + "Q", commands, offset + 8
                            )[0]
                            if entryoff < 32 + sizeofcmds:
                                raise AuditError(
                                    f"{archive.name}: Mach-O entry offset overlaps load commands"
                                )
                            if entryoff >= member.size:
                                raise AuditError(
                                    f"{archive.name}: Mach-O entry offset outside executable"
                                )
                        offset += size
                    if offset != sizeofcmds:
                        raise AuditError(f"{archive.name}: unaccounted Mach-O load command bytes")
                    if not macos_marker_seen:
                        raise AuditError(f"{archive.name}: missing macOS Mach-O platform marker")
                    remaining = member.size - 32 - sizeofcmds
                    while remaining:
                        block = binary.read(min(1024 * 1024, remaining))
                        if not block:
                            raise AuditError(f"{archive.name}: truncated Mach-O executable")
                        binary_hash.update(block)
                        remaining -= len(block)
                    executable_digest = binary_hash.hexdigest()
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise AuditError(f"{archive.name}: cannot read tar archive: {exc}") from exc
    if not found_binary:
        raise AuditError(f"{archive.name}: missing or unsafe applesauce binary")
    return executable_digest


def gh(*args):
    try:
        return subprocess.run(
            ["gh", *args], check=True, text=True, capture_output=True
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AuditError(f"gh command failed: {' '.join(args)}: {exc}") from exc


def audit(directory):
    if not directory.is_dir():
        raise AuditError(f"missing downloads folder: {directory}")
    if not shutil.which("gh"):
        raise AuditError("GitHub CLI 'gh' is required for release and provenance checks")

    release = json.loads(
        gh("release", "view", TAG, "-R", REPO, "--json", "tagName,isDraft")
    )
    if release.get("tagName") != TAG or release.get("isDraft") is not False:
        raise AuditError("expected published, non-draft release with exact tag")

    archives = find_archives(directory)
    evidence = {}
    for arch, asset in archives.items():
        executable_digest = check_macho(asset, arch)
        digest = sha256(asset)
        # Remote asset correspondence is checked independently of downloaded
        # checksum files. The attestation binds these same bytes to source SHA.
        gh("release", "verify-asset", TAG, str(asset), "-R", REPO)
        gh(
            "attestation", "verify", str(asset), "-R", REPO,
            "--source-ref", "refs/tags/" + TAG,
            "--source-digest", QUALIFIED_SHA,
            "--signer-workflow",
            REPO + "/.github/workflows/applesauce-cli-release.yml",
        )
        evidence[arch] = {
            "filename": asset.name,
            "sha256": digest,
            "executable_sha256": executable_digest,
        }
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("downloads", type=Path, help="folder containing both downloaded .tar.xz/.tar.gz assets")
    args = parser.parse_args()
    try:
        evidence = audit(args.downloads)
    except (AuditError, ValueError, json.JSONDecodeError) as exc:
        print(f"Release audit FAILED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"tag": TAG, "source_sha": QUALIFIED_SHA, "archives": evidence}, indent=2))
    print("Archive integrity and attestation verified. Signed macOS installation and execution remain outstanding.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
