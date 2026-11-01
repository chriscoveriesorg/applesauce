#!/usr/bin/env python3
"""Check the stable Foldy and ZGX contracts across a compression-only change.

Read-only, stdlib-only, and safe to run on Linux as well as macOS. This tool
never compresses a file, invokes another program, or reads the original corpus.
It consumes *private* before/after evidence files created by their owners.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


class ContractError(ValueError):
    """A missing, ambiguous, or changed logical-content contract."""


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ContractError(f"cannot read evidence file {path}: {exc}") from exc


def _json_document(path: Path) -> dict:
    try:
        doc = json.loads(_read_text(path))
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid JSON document {path}: {exc.msg}") from exc
    if not isinstance(doc, dict):
        raise ContractError(f"expected a JSON object in {path}")
    return doc


def read_foldy(path: Path) -> tuple[tuple[str, str], dict[str, tuple[str, int, str]]]:
    """Return (host, root), and path -> (stable identity, logical size, SHA256)."""
    doc = _json_document(path)
    if doc.get("schema") != "foldy_local_inventory/1":
        raise ContractError(f"{path}: unsupported Foldy inventory schema")
    if doc.get("status") != "complete" or doc.get("errors") or doc.get("mount_skips"):
        raise ContractError(f"{path}: incomplete Foldy scan; do not compare partial evidence")
    if doc.get("sha256_content") is not True:
        raise ContractError(f"{path}: Foldy inventory must be created with --sha256")
    host, root = doc.get("host"), doc.get("root")
    if not isinstance(host, str) or not host or not isinstance(root, str) or not root:
        raise ContractError(f"{path}: missing Foldy host/root identity")
    items = doc.get("items")
    if not isinstance(items, list):
        raise ContractError(f"{path}: missing Foldy items array")

    records: dict[str, tuple[str, int, str]] = {}
    identities: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            raise ContractError(f"{path}: non-object Foldy item")
        if item.get("Type") != "file":
            continue
        relpath, identity, size = item.get("Path"), item.get("ID"), item.get("Size")
        hashes = item.get("Hashes")
        digest = hashes.get("sha256") if isinstance(hashes, dict) else None
        if not isinstance(relpath, str) or not relpath:
            raise ContractError(f"{path}: file with missing Path")
        if not isinstance(identity, str) or not identity.startswith("local:"):
            raise ContractError(f"{path}: file with missing stable local ID")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ContractError(f"{path}: file with invalid logical Size")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ContractError(f"{path}: file with missing/invalid SHA256")
        if relpath in records or identity in identities:
            raise ContractError(f"{path}: duplicate path or stable ID")
        records[relpath] = (identity, size, digest)
        identities.add(identity)
    if not records:
        raise ContractError(f"{path}: no hashed regular files; test would be vacuous")
    return (host, root), records


def _stable_hit(hit: object) -> tuple[str, str, str | None]:
    """Read protocol-4 positional or --receipt object hits, ignoring rank scores."""
    if isinstance(hit, list) and len(hit) == 4:
        path, span, snippet, _sources = hit
    elif isinstance(hit, dict):
        path, span, snippet = hit.get("path"), hit.get("span"), hit.get("snippet")
    else:
        raise ContractError("ZGX returned a non-file hit; expected file hit protocol")
    if not isinstance(path, str) or not path:
        raise ContractError("ZGX hit is missing its logical path")
    if not (span is None or isinstance(span, int) and not isinstance(span, bool)
            or isinstance(span, list) and len(span) == 2
            and all(isinstance(n, int) and not isinstance(n, bool) for n in span)):
        raise ContractError("ZGX hit has an invalid source span")
    if snippet is not None and not isinstance(snippet, str):
        raise ContractError("ZGX hit has a non-text snippet")
    # JSON serialization keeps both int and line-range spans comparable.
    return (path, json.dumps(span, separators=(",", ":")), snippet)


def read_zgx(path: Path) -> list[tuple[str, str, str | None]]:
    """Read one final result from JSONL; ignore optional trace leg records.

    Split on U+000A, not str.splitlines(), per ZGX's wire-format contract.
    """
    finals = []
    for line in _read_text(path).split("\n"):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ContractError(f"{path}: invalid ZGX JSONL: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise ContractError(f"{path}: ZGX JSONL record must be an object")
        if record.get("type") == "final":
            finals.append(record)
    if len(finals) != 1:
        raise ContractError(f"{path}: expected exactly one ZGX final record, found {len(finals)}")
    hits = finals[0].get("hits")
    if not isinstance(hits, list) or not hits:
        raise ContractError(f"{path}: no ZGX hits; empty evidence is not a search regression test")
    return [_stable_hit(hit) for hit in hits]


def compare_foldy(before: Path, after: Path) -> int:
    before_scope, old = read_foldy(before)
    after_scope, new = read_foldy(after)
    if before_scope != after_scope:
        raise ContractError("Foldy host/root changed; cannot compare different logical trees")
    if old.keys() != new.keys():
        raise ContractError("Foldy file paths changed after compression")
    for path in old:
        if old[path] != new[path]:
            raise ContractError("Foldy stable ID, logical size, or SHA256 changed after compression")
    return len(old)


def compare_zgx(before: Path, after: Path) -> int:
    old, new = read_zgx(before), read_zgx(after)
    if old != new:
        raise ContractError("ZGX ordered paths, source spans, or snippets changed after compression")
    return len(old)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--foldy-before", type=Path)
    parser.add_argument("--foldy-after", type=Path)
    parser.add_argument("--zgx-before", type=Path)
    parser.add_argument("--zgx-after", type=Path)
    parser.add_argument("--physical-before-bytes", type=int)
    parser.add_argument("--physical-after-bytes", type=int)
    parser.add_argument("--require-physical-saving", action="store_true")
    args = parser.parse_args(argv)

    def paired(a: object, b: object, name: str) -> bool:
        if (a is None) != (b is None):
            parser.error(f"--{name}-before and --{name}-after must be supplied together")
        return a is not None

    has_foldy = paired(args.foldy_before, args.foldy_after, "foldy")
    has_zgx = paired(args.zgx_before, args.zgx_after, "zgx")
    has_physical = paired(args.physical_before_bytes, args.physical_after_bytes, "physical")
    if not (has_foldy or has_zgx):
        parser.error("supply at least one Foldy or ZGX before/after evidence pair")
    if args.require_physical_saving and not has_physical:
        parser.error("--require-physical-saving requires both physical byte measurements")

    try:
        result = {"schema": "applesauce_family_contract/1", "passed": True}
        if has_foldy:
            result["foldy_files_unchanged"] = compare_foldy(args.foldy_before, args.foldy_after)
        if has_zgx:
            result["zgx_hits_unchanged"] = compare_zgx(args.zgx_before, args.zgx_after)
        if has_physical:
            if args.physical_before_bytes < 0 or args.physical_after_bytes < 0:
                raise ContractError("physical byte measurements must be nonnegative")
            saved = args.physical_before_bytes - args.physical_after_bytes
            result["physical_bytes_saved"] = saved
            if args.require_physical_saving and saved <= 0:
                raise ContractError("no measured physical allocation saving")
    except ContractError as exc:
        print(f"family-contract: FAIL: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
