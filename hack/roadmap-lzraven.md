# Roadmap: LZRAVEN for cold macOS chat logs

Status: design and discovery. **Native transparent APFS LZRAVEN is not proven.**
Target: macOS 27.2 or newer. Work is opt-in and must not touch personal
session files until readback, allocation, and recovery tests pass.

## What counts as transparent?

1. **Native APFS / decmpfs:** any app opens the same file path; the kernel
   decodes it, and no extra service or mount is required. This requires a
   registered filesystem decompressor *and* an identified on-disk format.
2. **FSKit-mounted archive:** an app opens the logical path **inside a mounted
   RavenFS volume** and sees the original bytes; the backing file is stored
   using LZRAVEN. Apps must access the mount path. This is not native decmpfs.
3. **Apple Archive:** LZRAVEN compression exists now, but extracting or using
   an application-aware reader is required. It is not transparent to ordinary
   `open()` calls on a JSONL file.

Apple only documents `COMPRESSION_LZRAVEN` and `COMPRESSION_LZMESH` for the
Compression framework's **buffer** encode/decode APIs. Neither algorithm
selector is a `com.apple.decmpfs` type number. Therefore adding a codec name
to the Applesauce CLI cannot by itself deliver native transparent reads.

## Which tools contribute what?

| Project | Use | Do not assume |
| --- | --- | --- |
| [Applesauce](https://github.com/Dr-Emann/applesauce) | Native decmpfs CLI, filesystem framing, Rust integration and tests | A new kernel decoder can be added by changing Rust alone |
| [fscmp](https://github.com/Siguza/fscmp) | Research API for `AppleFSCompression.framework`; known LZBitmap types 13/14 | Private ABI stability or LZRAVEN support |
| [SocketDev/decmpfs](https://github.com/SocketDev/decmpfs) | Reference for guarded atomic writes, explicit outcomes, clone-preserving copy, and readback/rollback | Cross-platform abstractions solve macOS codec registration |
| [DiskPress](https://diskpress.app/faq/) | UX: scheduling, size accounting, compression plus APFS clones | DiskPress's existing LZFSE writes are LZRAVEN |
| [compress-agent-sessions](https://github.com/ariccio/compress-agent-sessions) | Cold session discovery, age-based eligibility and launchd scheduling | It adds a new decmpfs decoder |
| [Apple FSKit passthrough sample](https://developer.apple.com/documentation/fskit/building-a-passthrough-file-system) | Fallback mounted filesystem implementation | It transparently intercepts arbitrary paths outside its mount |

## Milestone 0: decide native APFS support (1-2 days)

**On macOS 27+ (including the GitHub Actions xcode-27 runner):**

```sh
swift hack/modern-compression-probe.swift
swift hack/modern-compression-probe.swift --file /path/to/LOCAL-COPY.jsonl
```

The probe compares LZFSE, LZMESH and LZRAVEN with byte-for-byte decode checks.
Real logs must stay local; CI only uses generated inputs. Its timing is a
single-run sanity check, not a release-quality benchmark.

**On macOS 27.2+ only:**

```sh
bash hack/run-local-apfs-probe.sh
```

The script creates and mounts a **fresh disposable APFS disk image**, runs the
private API probe, checks the known filesystem type 12 (LZFSE), also tries 14
(LZBitmap), and checks unverified candidate IDs 15-22. It verifies stored
`com.apple.decmpfs` type, the `UF_COMPRESSED` flag and exact readback. The image
is detached but retained for inspection. The script never targets user files.
Because the filesystem decoder lives in the host kernel, an isolated image
cannot eliminate the risk of a kernel crash. Use a backed-up test Mac.

GitHub's hosted `xcode-27` image currently runs **macOS 27.0.1**. Our manual
workflow thus defaults the native trial *off* and refuses to run it on hosts
older than 27.2. It can still perform buffer round-trips on the hosted runner.

**Native GO condition:** an OS-accepted new filesystem ID, verified transparent
readback, and positive identification of the compressed payload as LZRAVEN
(or LZMESH) using independent decode, including verification after volume
remount. A passing unknown type alone is insufficient.

**Native NO-GO condition:** no registered compatible filesystem type, or no
identified compatible framing after this bounded discovery pass. Do not set
arbitrary `com.apple.decmpfs` type bytes on real files or try to load custom
kernel code. Proceed to FSKit instead.

## Milestone 1: shared codec and trustworthy benchmarks (2-4 days)

- Wrap Apple's Compression.framework **buffer API** in a small macOS-only
  Rust codec module. Runtime-gate LZRAVEN/LZMESH to macOS 27+. Do not re-create
  Apple's codec or conflate a buffer algorithm selector with a decmpfs ID.
- Round-trip randomized, highly repetitive, real JSONL, empty, tiny, and
  incompressible data. Exercise corruption detection and failure outcomes.
- Compare LZFSE, LZMESH and LZRAVEN: compressed bytes, actual allocated disk
  bytes where applicable, encode/decode throughput, and partial-read latency.
- Test indexed chunk sizes of 256 KiB, 1 MiB, 4 MiB and 8 MiB for the FSKit
  branch. LZRAVEN's documented 8 MB dictionary makes blindly adopting the
  64 KiB chunk size of older decmpfs resource forks questionable. Measure it.
- Select policies based on evidence: LZMESH for read-heavy files if its speed
  wins; LZRAVEN for cold logs only when extra savings justify CPU cost.

## Milestone 2A: native path, **only if GO** (estimated 1-2 weeks)

1. Introduce verified filesystem kind IDs and documented resource-fork framing
   in `crates/applesauce-core/src/decmpfs.rs` and its compressor modules.
2. Add an opt-in `--experimental-lzraven` (and optionally `--experimental-lzmesh`)
   CLI selection. If a macOS build lacks the decoder, fail before changing a file.
3. Use a same-volume temporary file and atomic replacement; verify full
   byte-for-byte kernel reads and logical metadata before replacement. Preserve
   rollback material on any failure. Borrow safety patterns from SocketDev's
   MIT-licensed project with attribution where copied.
4. Validate across remount, reboot, clone/copy/restore, Xcode process restarts,
   app reads, backup tools, and cases where a file is opened for writing.
5. Enable only on positively tested OS builds. Keep LZFSE the stable fallback.

This is the **only** branch that gives existing APFS file paths genuine kernel
transparent LZRAVEN without a mounted filesystem service.

## Milestone 2B: RavenFS, **if native NO-GO**

Prototype estimate: ~1 week; hardened release estimate: ~3-6 weeks.

Build a separate FSKit-based volume, while reusing the codec/benchmark core:

1. Adapt Apple's official FSKit passthrough sample. Prove a mounted volume can
   list files, perform random reads and return exact bytes from a read-only
   LZRAVEN chunk store. Verify entitlement, signing and mount behavior first.
2. Define a versioned backing format: path metadata, original size, chunk
   offsets/lengths, integrity checksums, and per-chunk codec selection. Store
   chunks at the sizes justified by benchmark results; cache decoded chunks.
3. Keep active sessions as ordinary files. Archive only closed sessions, with
   atomic publication and a recoverable original until validation is complete.
4. Handle directory trees, `stat`, seek, reads, xattrs, symlinks, permissions,
   concurrent readers, Spotlight behavior and crash recovery. Add write support
   only after the read-only implementation is reliable.
5. Make the mount/path transition explicit. Existing session applications
   will not see RavenFS unless they read the mounted location (or a carefully
   configured path alias). Never silently redirect live session storage.

Apple Archive's public LZRAVEN option is a usable *nontransparent* interim
export format if FSKit packaging takes longer than expected.

## Milestone 3: cold-chatlog product and release gate (3-7 days after backend)

- Reuse `compress-agent-sessions` policy: preview and select only dormant
  Claude/Codex/Gemini JSONL sessions, with an adjustable age threshold.
- Exclude actively written files, symlinks and protected paths; confirm the
  file did not change between scan, compression and publication.
- Provide `scan --dry-run`, `compress --cold-only`, `verify`, `restore`, and
  `status` commands; show logical size vs **allocated** bytes, and estimates
  separately from verified savings.
- Preserve original bytes, permissions, timestamps and required extended
  attributes. Do not touch the user's session history without an explicit
  selected path, dry run, and successful recovery tests.
- Demonstrate lossless reads with `cat`, `tail`, an editor, and actual agent
  session viewers. Exercise resume/rewrite after compression.

Release criteria: every tested file has identical original/readback hashes;
crash interruption leaves an accessible original or valid compressed copy;
random reads and restarts work; observed disk allocation improves on real
sessions; no unexplained decoder or metadata failures. On failure, report the
reason and fall back to native LZFSE, not an unsafe new decmpfs ID.

## Current repository state

The local checkout already contains `modern-compression-probe.swift`,
`apfs-type-probe.c`, and the manual GitHub Actions workflow. This roadmap and
the 27.2-only local runner are present as uncommitted local changes. **None of
this is published to the user's public GitHub fork yet.**

## Sources

- <https://developer.apple.com/documentation/compression/compression_lzraven>
- <https://developer.apple.com/documentation/compression/compression_lzmesh>
- <https://developer.apple.com/documentation/compression/compression_algorithm>
- <https://developer.apple.com/documentation/applearchive/archivecompression>
- <https://developer.apple.com/documentation/fskit/building-a-passthrough-file-system>
- <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/decmpfs.c>
- <https://github.com/actions/runner-images/blob/main/images/macos/xcode-27-arm64-Readme.md>
