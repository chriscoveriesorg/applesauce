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
from pathlib import Path

REPO = "chriscoveriesorg/applesauce"
TAG = "applesauce-cli/v0.5.31"
QUALIFIED_SHA = "1585dceb6c745cebf822588526ee5005255818c9"
ARCH_CPUS = {"aarch64": 0x0100000C, "x86_64": 0x01000007}
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
            and p.name.startswith("applesauce")
        ]
        if len(candidates) != 1:
            raise AuditError(
                f"expected exactly one {arch} Apple archive, found {len(candidates)}"
            )
        result[arch] = candidates[0]
    return result


def check_macho(archive, arch):
    try:
        with tarfile.open(archive, "r:*") as tar:
            matches = [
                member for member in tar.getmembers()
                if member.name.split("/")[-1] == "applesauce"
            ]
            if len(matches) != 1 or not matches[0].isfile():
                raise AuditError(f"{archive.name}: missing or unsafe applesauce binary")
            member = matches[0]
            if member.size < 16 or member.size > 128 * 1024 * 1024:
                raise AuditError(f"{archive.name}: invalid executable size")
            with tar.extractfile(member) as binary:
                header = binary.read(16)
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise AuditError(f"{archive.name}: cannot read tar archive: {exc}") from exc

    magic = header[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        endian = "<"
    elif magic == b"\xfe\xed\xfa\xcf":
        endian = ">"
    else:
        raise AuditError(f"{archive.name}: executable is not a thin Mach-O 64")
    cpu = struct.unpack(endian + "I", header[4:8])[0]
    filetype = struct.unpack(endian + "I", header[12:16])[0]
    if filetype != 2:  # MH_EXECUTE; refuse dynamic libraries or fabricated headers
        raise AuditError(f"{archive.name}: Mach-O filetype {filetype}, expected executable")
    if cpu != ARCH_CPUS[arch]:
        raise AuditError(f"{archive.name}: Mach-O CPU {cpu:#x}, expected {arch}")


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
        check_macho(asset, arch)
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
        evidence[arch] = {"filename": asset.name, "sha256": digest}
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
