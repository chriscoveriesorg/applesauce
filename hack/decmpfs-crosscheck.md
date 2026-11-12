# Read-only kernel decmpfs evidence crosscheck (issue #88)

This produces an **inconclusive diagnostic report**, never permission to write
LZRAVEN/LZMESH compressed files. Buffer API support (selectors 0xD05 and 0xE05),
compiled registration data, catalogue plist claims and existing stored headers
are separate observations. None of them identifies a live kernel decoder by
itself. The permission bit stays false regardless of any positive candidate.

## Capturing one pinned macOS host

The [Read-only decmpfs provenance workflow](../.github/workflows/decmpfs-readonly-evidence.yml)
runs the portable negative controls, then collects these macOS system observations:

- `binary.json`: Mach-O callsites and source hash from the system kernel cache.
- `table.json`: compiler-shaped registration tables and fixup status from
  exactly the same kernelcache SHA-256.
- `catalogue.json`: candidate type declarations from system plugin plists.
- `inventory.json`: aggregate decmpfs header types from at most 30,000 existing
  Apple system files, with a 60-second inventory budget.
- `crosscheck.json`: joined, source-hash-checked type sets and explicit failed
  kernel/identity/framing/cold-remount/native-write proof gates.

The crosscheck now requires every static registration table to reference a
specific binary-observed callsite within the same source path, Mach-O image
name and UUID. It compares complete callsite records, including instruction
bytes and their digest, and rejects missing, conflicting or duplicate
attributions. These matches support static provenance only; they do not show
that a handler was registered or invoked by the running kernel.

All scan operations are read-only. This workflow never mounts a disk image,
sets compression attributes, runs a synthetic kernel payload or changes a
writer gate. It records OS and script checksums. At least one kernelcache source must be inspected successfully. An unavailable
source is retained by path and status in both binary and table reports; the
join fails if either probe used a different set of sources, inspection states
or hashes. Divergent hashes, corrupt reports and missing mandatory write gates
also fail. Diagnostic artifacts remain available on job failure. Partial
coverage cannot establish decoder absence or qualify a release.

## Offline replay

Given the four probe JSON reports from one run:

```sh
python3 hack/summarize-decmpfs-evidence.py \
  binary.json table.json catalogue.json inventory.json > crosscheck.json
python3 -m unittest discover -s hack -p 'test_summarize_decmpfs_evidence.py' -v
```

The join reads bounded, regular, no-follow evidence files, rejects duplicate
JSON keys and aliased inputs, reconciles both successful and unavailable
kernelcache observations, and checks matching SHA-256s for inspected inputs.
Catalogue candidate types must exactly match their captured declarations,
including checked declaration kinds and digest-bearing plist records. Stored
header counts and nested registration entries are checked for consistency.
Any asserted kernel, framing, cold-remount or native-write proof is rejected. The result is deliberately
`inconclusive_kernel_codec_mapping` even when a static type or stored-file
header appears.

To qualify issue #88, a separate independently reviewed proof must establish
the live handler/type registration, exact Raven/Mesh payload identity, on-disk
framing and cold read-only remount hash equality on an owner-approved disposable
host. This crosscheck supplies provenance and identifies gaps; it cannot satisfy
those gates. FSKit #86 and Raven/Mesh native writes stay frozen.
