# Roadmap: modern compression in our Applesauce fork

Main engineering repository: [chriscoveriesorg/applesauce](https://github.com/chriscoveriesorg/applesauce).
The goal is safe, measurable compression of cold agent logs while preserving
ordinary app/search reads. **Native transparent LZRAVEN/LZMESH remains an
unproven capability, not a released mode.**

## Current implementation

- Rust Apple buffer codecs: LZFSE/ZLIB controls, LZBitmap, LZMESH and LZRAVEN.
- Runtime OS gates, positive round-trip availability tests, bounded allocations,
  and exact-size decode checks with overflow detection.
- `applesauce capabilities --json [--require-native CODEC]`: the shared,
  fail-closed contract for companion tools.
- `applesauce benchmark-codecs`: generated or explicitly selected local data,
  whole-buffer and independent-64-KiB comparisons, byte verification and JSON.
- Default-off native LZBitmap writer: known decmpfs 13/14 framing, raw-block
  fallback, runtime self-test, forced verification and atomic replacement.
- Portable format tests, native generated-file tests, automatic macOS buffer
  CI, and manually opted-in private filesystem probes with remount verification.

The default transparent writers remain LZFSE, LZVN and ZLIB. Modern buffer
support never upgrades a codec to a native file writer automatically.
See [the exact implementation/JSON contract](modern-compression.md).

## Stage 1: qualify this implementation

1. Pass the normal CI feature matrix, including generated-file LZBitmap tests:
   actual stored type, full and random logical reads, metadata preservation,
   and manual restore. Test supported OS/build/architecture combinations.
2. Pass Rust and Swift reference buffer round trips on macOS 27+; retain exact
   OS/build/SDK and machine-readable measurements. 27.0.1 is sufficient for
   the documented buffer APIs; 27.2 is not a buffer prerequisite.
3. Run the explicit disposable-image trial on a backed-up 27.2+ test Mac.
   Prove controls survive detach/read-only reattach. The 27.2 gate is project
   risk policy, not proof of any filesystem decoder.
4. Benchmark stable local copies of representative agent JSONL. Keep log
   contents local. Report encoded payload bytes separately from actual disk
   allocation. Compare whole-file savings against 64-KiB dictionary resets;
   Raven's larger dictionary may not benefit small independent blocks.
5. Keep LZBitmap opt-in until remount, backup/restore, interrupted operation,
   and app resume/rewrite behavior have been qualified. Never test on the only
   copy of session history.

## Stage 2: resolve the native Raven/Mesh question

A native filesystem codec needs a registered kernel decompressor **and** a
verified on-disk framing/type mapping. Public Compression API selectors
0xD05/0xE05 are not decmpfs IDs.

The private AppleFSCompression queue can accept a numeric request and silently
write a different codec. Our probe records actual type and flags, then verifies
exact logical bytes after remount. Even matching type plus readable bytes is
insufficient until the compressed payload is independently identified.

New research to use, with attribution and independent verification:

| Project | Useful evidence / role | Limit |
| --- | --- | --- |
| [Siguza/fscmp](https://github.com/Siguza/fscmp) | Reconstructed private queue API, named LZBitmap 13/14 | Private ABI is not stable or a Raven support guarantee |
| [deploymenttheory/go-apfs-v2](https://github.com/deploymenttheory/go-apfs-v2/blob/main/docs/compression-writer.md) | Native type/framing fixtures, queue fallback and lifecycle qualification | Its results do not replace tests of our writer |
| [gregordinary/apfs-probes](https://github.com/gregordinary/apfs-probes) | Raven/Mesh/LZ4 buffer-to-type/layout sweep, positive/negative controls and remount method | Methodology is not proof of a successful mapping |
| [SocketDev/decmpfs](https://github.com/SocketDev/decmpfs) | Alternative Rust implementation and safety/recovery approaches | API abstraction cannot register a missing kernel decoder |
| [Apple XNU](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/decmpfs.c) | Decoder registration/lookup and error behavior | Private codec implementations are not all in open-source XNU |

In particular, go-apfs-v2 identifies **15/16 as Apple-framed LZ4 on macOS 27**,
not Raven/Mesh. Never assign those numbers based on their position after 13/14.
This is a possible later native backend, separate from the Raven objective.

**Native GO:** demonstrate actual new stored type(s), independently identified
Raven/Mesh payload/framing, exact kernel reads after full remount, negative
controls that reject wrong codecs/corrupt data, random reads and recovery on
recorded builds. Only then add `Kind`, decmpfs mapping, opt-in writer and native
capability permission. Validate cloning/copying/backups and an older host's
failure behavior before recommending real logs.

**Native blocked:** if no compatible kernel type/framing is established, keep
`native_decmpfs.writable=false`. A finite sweep is not proof that every possible
format is unsupported, but it is sufficient reason not to expose a writer.
Do not load custom kernel code or alter production xattrs to guess.

## Stage 3: make the companion tools work together

### compress-agent-sessions

[Our frontend fork](https://github.com/chriscoveriesorg/compress-agent-sessions)
owns age/grace-period eligibility, open-handle exclusions, protected-path checks,
dry runs, scheduling and restore. It calls:

```sh
applesauce capabilities --json --require-native lzraven
```

for an explicit Raven request, and likewise for Mesh/Bitmap. Nonzero exit
refuses before scanning/mutation and never falls back to another codec/tool.
The existing LZFSE default and restore paths stay compatible with old upstream
Applesauce. Its estimator uses a different backend and must not treat a raw
buffer ratio as proof of native support.

[Integration details](https://github.com/chriscoveriesorg/compress-agent-sessions/blob/main/docs/experimental-lzraven.md).

### ZGX and Foldy

[ZGX](https://github.com/chriscoveriesorg/zgx) and its
[private acceptance issue #504](https://github.com/chriscoveriesorg/zgx/issues/504)
cover the search side. Native transparent APFS needs no search codec decoder:
content, path, hit ordering, byte spans and snippets should remain stable.
Physical metadata, timings and cache receipts may change. Do not require
byte-identical entire receipts or blanket re-embedding for storage-only changes.

[Foldy](https://github.com/chriscoveries/foldy) remains a separate private
indexing/space-reporting companion. Cross-links do not install, run, or alter
any companion automatically; no private implementation is copied into this fork.

## Stage 4: mounted fallback, only if needed

If native mapping remains blocked, build a **separate FSKit mounted filesystem**
using [Apple's passthrough sample](https://developer.apple.com/documentation/fskit/building-a-passthrough-file-system)
and the new buffer core. This would expose unchanged logical JSONL bytes under
an explicit mounted root backed by versioned compressed chunks. It is not a
transparent change to arbitrary existing APFS paths.

Start read-only. Prove signing/entitlements and mount lifecycle before storage
engineering. Then qualify chunk sizes (256 KiB, 1 MiB, 4 MiB, 8 MiB), checksums,
indexes, random reads, decoded-cache limits, metadata and crash recovery. Keep
originals until verified publication. Point ZGX at the logical mounted root,
never at backing chunks. Active sessions remain ordinary files.

Apple Archive's public Raven option is another possible export path, but
requires extraction or an archive-aware reader. Neither fallback is currently
implemented or silently enabled by this fork.

## Release gate

Default-enable nothing on the strength of an algorithm name or buffer ratio.
Require verified bytes, native allocation benefit on representative cold logs,
restart/remount/restore behavior, preserved metadata, and recoverable failure
paths. Until Raven/Mesh satisfy the native gate, explicit requests fail with a
clear reason; users may separately choose the existing LZFSE path.
