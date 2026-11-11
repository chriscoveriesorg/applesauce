#!/usr/bin/env python3
"""Disposable, stable-codec APFS/codesign acceptance probe for issue #93.

Runs only on macOS, with an executable generated in a temporary checkout-local
.app bundle. This does not authorize mutation of installed or user apps.
"""
import hashlib
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


def xattrs(path):
    return {name: os.getxattr(path, name) for name in os.listxattr(path)}


def signature_and_execution(app, binary):
    run("/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app)
    actual = run(binary).strip()
    if actual != "APPLESauce signed bundle fixture":
        raise AssertionError(f"unexpected executable output: {actual!r}")


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
    source = root / "probe.c"
    source.write_text(
        '#include <stdio.h>\nint main(void) { puts("APPLESauce signed bundle fixture"); return 0; }\n',
        encoding="utf-8",
    )
    run("/usr/bin/xcrun", "clang", "-O2", "-o", executable, source)
    small = resources / "small.txt"
    small.write_bytes(b"A" * 2048)
    large = resources / "events.jsonl"
    records = [
        f'{{"index":{i},"digest":"{hashlib.sha256(str(i).encode()).hexdigest()}"}}\n'
        for i in range(6000)
    ]
    large.write_bytes("".join(records).encode())
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

        # Only generated files in the disposable app are ever modified.
        for path, storage in ((small, "inline_xattr"), (large, "resource_fork")):
            expected = path.read_bytes()
            run(
                applesauce, "compress", "--compression", "zlib",
                "--verify", "--minimum-compression-ratio", "0.95", path,
            )
            if path.read_bytes() != expected:
                raise AssertionError(f"kernel readback changed {path}")
            require_report(applesauce, path, "zlib", storage)
            signature_and_execution(app, executable)
            run(applesauce, "decompress", "--verify", path)
            if path.read_bytes() != expected:
                raise AssertionError(f"decompressed bytes changed {path}")
            signature_and_execution(app, executable)

        print(json.dumps({
            "schema_version": 1,
            "kind": "disposable-ad-hoc-signed-app-probe",
            "generated_files_only": True,
            "profile_audit_unchanged": True,
            "stable_codec": "zlib",
            "compressed_storage_modes": ["inline_xattr", "resource_fork"],
            "strict_codesign_valid_after_each_step": True,
            "signed_executable_runs_after_each_step": True,
            "launchservices_gate_tested": False,
            "installed_app_mutation_authorized": False,
            "native_raven_mesh_writes_authorized": False,
        }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
