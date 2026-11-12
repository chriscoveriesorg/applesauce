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

All scan operations are read-only. This workflow never mounts a disk image,
sets compression attributes, runs a synthetic kernel payload or changes a
writer gate. It records OS and script checksums. An unavailable/unparseable
kernelcache source, divergent binary/table hashes, corrupt report or missing
mandatory gate causes a failing job. Diagnostic artifacts remain available
for investigation on job failure. Incomplete evidence must not be treated as a
negative decoder proof or a release qualification.

## Offline replay

Given the four probe JSON reports from one run:

```sh
python3 hack/summarize-decmpfs-evidence.py \
  binary.json table.json catalogue.json inventory.json > crosscheck.json
python3 -m unittest discover -s hack -p 'test_summarize_decmpfs_evidence.py' -v
```

The join reads bounded, regular, no-follow evidence files, refuses duplicate
JSON keys and aliased inputs, checks the same inspected kernelcache identities
and SHA-256s, rejects inconsistent type/count reports, and refuses any input
claiming positive proof or write permission. The result is deliberately
`inconclusive_kernel_codec_mapping` even when a static type or stored-file
header appears.

To qualify issue #88, a separate independently reviewed proof must establish
the live handler/type registration, exact Raven/Mesh payload identity, on-disk
framing and cold read-only remount hash equality on an owner-approved disposable
host. This crosscheck supplies provenance and identifies gaps; it cannot satisfy
those gates. FSKit #86 and Raven/Mesh native writes stay frozen.
