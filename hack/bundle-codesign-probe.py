#!/usr/bin/env python3
"""Disposable, stable-codec APFS/codesign acceptance probe for issue #93.

Runs only on macOS, with an executable generated in a temporary checkout-local
.app bundle. This does not authorize mutation of installed or user apps.
"""
import hashlib
import mmap
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile


def run(*command, timeout=90):
    result = subprocess.run(
        [str(part) for part in command],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(map(str, command))}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result.stdout


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mmap_digest(path):
    """Prove compressed resources remain directly memory-mappable."""
    with path.open("rb") as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return hashlib.sha256(data).hexdigest()


def xattrs(path):
    """Snapshot macOS extended attributes as raw bytes.

    The macOS Python shipped by the runner does not expose os.listxattr or
    os.getxattr. The system xattr command supports both binary-safe hex
    output and native macOS metadata semantics. Any failed read aborts the
    acceptance probe rather than treating an attribute as absent.
    """
    names = subprocess.run(
        ["/usr/bin/xattr", str(path)],
        capture_output=True, check=True,
    ).stdout.splitlines()
    found = {}
    for raw_name in names:
        if not raw_name:
            raise AssertionError(f"empty extended attribute name on {path}")
        name = os.fsdecode(raw_name)
        if name in found:
            raise AssertionError(f"duplicate extended attribute name on {path}: {name}")
        encoded = subprocess.run(
            ["/usr/bin/xattr", "-px", name, str(path)],
            capture_output=True, check=True,
        ).stdout
        found[name] = bytes.fromhex(encoded.decode("ascii"))
    return found


def signature_and_execution(app, binary):
    run("/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app)
    actual = run(binary).strip()
    if actual != "APPLESauce signed bundle fixture":
        raise AssertionError(f"unexpected executable output: {actual!r}")


def fnv1a64(payload):
    """A small, dependency-free expected-byte checksum for the C fixture."""
    value = 0xcbf29ce484222325
    for byte in payload:
        value = ((value ^ byte) * 0x100000001b3) & 0xffffffffffffffff
    return value


def resource_reader_source(small, large):
    """Build an executable that checks both signed resources via mmap itself.

    This makes launch checks meaningful: the executable must actually consume
    the compressed file's logical bytes, rather than merely print a constant.
    """
    source = r'''#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct expected_resource {
    const char *name;
    size_t length;
    uint64_t checksum;
};

static const struct expected_resource resources[] = {
    {"small.txt", @SMALL_SIZE@u, UINT64_C(0x@SMALL_HASH@)},
    {"events.jsonl", @LARGE_SIZE@u, UINT64_C(0x@LARGE_HASH@)}
};

static uint64_t fnv1a64(const unsigned char *bytes, size_t length) {
    uint64_t checksum = UINT64_C(0xcbf29ce484222325);
    for (size_t i = 0; i < length; ++i) {
        checksum ^= bytes[i];
        checksum *= UINT64_C(0x100000001b3);
    }
    return checksum;
}

static int check_resource(const char *directory, const struct expected_resource *expected) {
    char path[4096];
    int length = snprintf(path, sizeof(path), "%s/../Resources/%s",
                          directory, expected->name);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        fprintf(stderr, "resource path too long\n");
        return 1;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open resource");
        return 1;
    }
    struct stat metadata;
    if (fstat(fd, &metadata) != 0 || metadata.st_size < 0 ||
        (uintmax_t)metadata.st_size != (uintmax_t)expected->length) {
        fprintf(stderr, "resource length mismatch: %s\n", expected->name);
        close(fd);
        return 1;
    }
    void *mapping = mmap(NULL, expected->length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap resource");
        close(fd);
        return 1;
    }
    uint64_t checksum = fnv1a64((const unsigned char *)mapping, expected->length);
    int unmap_result = munmap(mapping, expected->length);
    int close_result = close(fd);
    if (checksum != expected->checksum || unmap_result || close_result) {
        fprintf(stderr, "resource readback mismatch: %s\n", expected->name);
        return 1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 1 || argv[0] == NULL) {
        return 2;
    }
    const char *slash = strrchr(argv[0], '/');
    char directory[4096];
    if (slash == NULL || (size_t)(slash - argv[0]) >= sizeof(directory)) {
        fprintf(stderr, "executable path unavailable\n");
        return 2;
    }
    size_t prefix_length = (size_t)(slash - argv[0]);
    memcpy(directory, argv[0], prefix_length);
    directory[prefix_length] = '\0';
    for (size_t i = 0; i < sizeof(resources) / sizeof(resources[0]); ++i) {
        if (check_resource(directory, &resources[i]) != 0) {
            return 3;
        }
    }
    puts("APPLESauce signed bundle fixture");
    return 0;
}
'''
    return (source.replace("@SMALL_SIZE@", str(len(small)))
                  .replace("@SMALL_HASH@", f"{fnv1a64(small):016x}")
                  .replace("@LARGE_SIZE@", str(len(large)))
                  .replace("@LARGE_HASH@", f"{fnv1a64(large):016x}"))


def fixture(root):
    app = root / "ApplesauceProbe.app"
    executable = app / "Contents" / "MacOS" / "applesauce-probe"
    resources = app / "Contents" / "Resources"
    executable.parent.mkdir(parents=True)
    resources.mkdir(parents=True)
    with (app / "Contents" / "Info.plist").open("wb") as stream:
        plistlib.dump(
            {
                "CFBundleIdentifier": "org.chriscoveries.applesauce.probe",
                "CFBundleExecutable": executable.name,
                "CFBundlePackageType": "APPL",
                "CFBundleName": "Applesauce Probe",
                "CFBundleVersion": "1",
                "CFBundleShortVersionString": "1.0",
            }, stream,
        )
    small = resources / "small.txt"
    small.write_bytes(b"A" * 2048)
    large = resources / "events.jsonl"
    records = [
        f'{{"index":{i},"digest":"{hashlib.sha256(str(i).encode()).hexdigest()}"}}\n'
        for i in range(6000)
    ]
    large.write_bytes("".join(records).encode())
    source = root / "probe.c"
    source.write_text(
        resource_reader_source(small.read_bytes(), large.read_bytes()),
        encoding="utf-8",
    )
    run("/usr/bin/xcrun", "clang", "-std=c11", "-Wall", "-Wextra",
        "-Werror", "-O2", "-o", executable, source)
    run("/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", app)
    sealed = app / "Contents" / "_CodeSignature" / "CodeResources"
    if not sealed.is_file():
        raise AssertionError("codesign did not produce sealed CodeResources")
    return app, executable, (small, large), sealed


def require_report(output, path, codec, storage):
    report = json.loads(run(output, "info", "--json", path))
    if report.get("complete") is not True:
        raise AssertionError(f"incomplete actual storage report: {report}")
    rows = [row for row in report["paths"] if row["path"]["display"] == str(path)]
    if len(rows) != 1:
        raise AssertionError(f"wrong actual storage row count: {rows}")
    row = rows[0]
    if row["codec"] != codec or row["storage"] != storage or row["source"] != "decmpfs":
        raise AssertionError(f"unexpected compressed storage: {row}")



def verify_readback(path, expected):
    """Compare complete kernel and mmap reads to the original content hash."""
    expected_sha256 = hashlib.sha256(expected).hexdigest()
    if digest(path) != expected_sha256:
        raise AssertionError(f"kernel readback changed {path}")
    if mmap_digest(path) != expected_sha256:
        raise AssertionError(f"mmap readback changed {path}")


def assert_sealed_paths_unchanged(paths, baseline):
    """Neither code-signature manifest nor executable may be modified."""
    for path in paths:
        current = (digest(path), path.stat().st_mtime_ns, xattrs(path))
        if current != baseline[path]:
            raise AssertionError(f"signed executable or seal changed {path}")


def main():
    if sys.platform != "darwin" or len(sys.argv) != 2:
        raise SystemExit("usage: macOS only, bundle-codesign-probe.py /path/to/applesauce")
    applesauce = Path(sys.argv[1]).resolve(strict=True)
    if applesauce.name != "applesauce" or not applesauce.is_file():
        raise ValueError("expected a built applesauce CLI executable")
    with tempfile.TemporaryDirectory(
        prefix="applesauce-signed-fixture-", dir=Path.cwd()
    ) as scratch:
        app, executable, files, sealed = fixture(Path(scratch))
        small, large = files
        signature_and_execution(app, executable)
        before = {
            path: (digest(path), path.stat().st_mtime_ns, xattrs(path))
            for path in (*files, sealed, executable)
        }
        dry = json.loads(run(
            applesauce, "compress", "--dry-run", "--profile", "bundles",
            "--compression", "zlib", "--json", app,
        ))
        if dry.get("complete") is not True:
            raise AssertionError(f"incomplete bundle audit: {dry}")
        for path in files:
            rows = [
                row for row in dry["paths"]
                if row["path"]["display"] == str(path)
            ]
            if len(rows) != 1 or rows[0]["would_compress"] is not True:
                raise AssertionError(f"eligible bundle resource not selected: {path}: {rows}")
        for path, original in before.items():
            now = (digest(path), path.stat().st_mtime_ns, xattrs(path))
            if now != original:
                raise AssertionError(f"read-only bundle audit modified {path}")
        signature_and_execution(app, executable)

        # Keep both generated resources compressed simultaneously. The
        # per-file success case alone cannot prove the mixed-storage state.
        expected_bytes = {path: path.read_bytes() for path in files}
        compressed = []
        for path, storage in ((small, "inline_xattr"), (large, "resource_fork")):
            run(
                applesauce, "compress", "--compression", "zlib",
                "--verify", "--minimum-compression-ratio", "0.95", path,
            )
            compressed.append((path, storage))
            # Every existing compressed resource must stay readable after
            # another resource is compressed, not just its own operation.
            for active_path, active_storage in compressed:
                verify_readback(active_path, expected_bytes[active_path])
                require_report(applesauce, active_path, "zlib", active_storage)
            assert_sealed_paths_unchanged((sealed, executable), before)
            signature_and_execution(app, executable)

        # Reverse-order restoration also exercises a mixed compressed/plain
        # bundle. Retain on-disk attribution checks for every survivor.
        for path, _storage in reversed(tuple(compressed)):
            run(applesauce, "decompress", "--verify", path)
            verify_readback(path, expected_bytes[path])
            compressed = [entry for entry in compressed if entry[0] != path]
            for active_path, active_storage in compressed:
                verify_readback(active_path, expected_bytes[active_path])
                require_report(applesauce, active_path, "zlib", active_storage)
            assert_sealed_paths_unchanged((sealed, executable), before)
            signature_and_execution(app, executable)
        for path in files:
            verify_readback(path, expected_bytes[path])

        print(json.dumps({
            "schema_version": 1,
            "kind": "disposable-ad-hoc-signed-app-probe",
            "generated_files_only": True,
            "profile_audit_unchanged": True,
            "stable_codec": "zlib",
            "compressed_storage_modes": ["inline_xattr", "resource_fork"],
            "mmap_readback_verified": True,
            "both_storage_modes_active_together": True,
            "readback_after_each_transition": True,
            "sealed_paths_unchanged_during_writes": True,
            "strict_codesign_valid_after_each_step": True,
            "signed_executable_runs_after_each_step": True,
            "launchservices_gate_tested": False,
            "installed_app_mutation_authorized": False,
            "native_raven_mesh_writes_authorized": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
