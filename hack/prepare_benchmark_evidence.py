#!/usr/bin/env python3
"""Reset only this checkout's generated Criterion evidence before a fresh run.

A reused benchmark runner can otherwise certify old ``new/estimates.json``
files for cases the current run skipped. The compiled Cargo target cache and
all other workspace files remain unchanged. Called only from the owner-run
benchmark workflow with GITHUB_WORKSPACE supplied by Actions.
"""
import os
from pathlib import Path
import shutil
import sys


def prepare(workspace: Path) -> None:
    if not workspace.is_absolute() or workspace.is_symlink() or not workspace.is_dir():
        raise ValueError("GITHUB_WORKSPACE must be a real absolute checkout directory")
    target = workspace / "target"
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError("refusing non-directory or symlinked Cargo target")
    destinations = (target / "criterion", target / "applesauce-bench")
    # Check *both* before removing anything: an unsafe sibling must not
    # leave a partly cleaned evidence tree that could be uploaded as valid.
    for destination in destinations:
        if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
            raise ValueError(f"refusing non-directory or symlinked evidence path: {destination}")
    target.mkdir(exist_ok=True)
    for destination in destinations:
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir()


def main() -> int:
    try:
        workspace = os.environ.get("GITHUB_WORKSPACE", "")
        if not workspace:
            raise ValueError("GITHUB_WORKSPACE is required")
        prepare(Path(workspace))
    except (OSError, ValueError) as exc:
        print(f"cannot reset benchmark evidence: {exc}", file=sys.stderr)
        return 1
    print("Cleared prior Criterion estimates and benchmark evidence; Cargo build cache retained")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
