# macOS 27 LZMESH/LZRAVEN experiment

**Status: experimental; no new transparent-compression mode is enabled.**

macOS 27 exposes `COMPRESSION_LZMESH` and `COMPRESSION_LZRAVEN` through the
public Compression framework's **buffer** encode/decode functions. Those
algorithm selectors are **not** `com.apple.decmpfs` filesystem compression
type IDs. Files transparently compressed by APFS require a separate, registered
kernel decompressor and a compatible on-disk representation. Merely adding new
options to Applesauce would risk unreadable files.

This repository starts with the minimal reproducible experiment:

1. On a **macOS 27 or newer** machine with Xcode, run
   `swift hack/modern-compression-probe.swift`. It compresses generated JSONL
   chat-log-shaped text and high-entropy data with LZFSE, LZMESH, and LZRAVEN
   using the system Compression framework, decodes both, verifies byte-for-byte
   equality, and prints sizes and single-run timing. It never modifies files.
2. To compare one of your own logs locally, run
   `swift hack/modern-compression-probe.swift --file /path/to/log.jsonl`.
   The input file is only read in memory, not modified or uploaded.
3. The manually triggered GitHub Actions workflow **Probe macOS 27 compression
   codecs** runs the generated-input test on GitHub's `xcode-27` runner.
   The currently published runner image is macOS 27.0.1, not 27.2. Open the
   repository's Actions tab, select the workflow, and click **Run workflow**.
   The results appear in its run summary. The workflow also reports loaded
   filesystem compressor components for initial inspection. Absence from
   `kmutil`/`ioreg` output is not proof of missing built-in support.
4. The same button optionally requests a more ambitious APFS test, **disabled
   by default and automatically skipped on macOS releases earlier than 27.2**.
   On your own macOS 27.2+ Mac, run `bash hack/run-local-apfs-probe.sh` instead.
   This creates a
   disposable 128 MiB APFS disk image, checks known LZFSE and LZBitmap type
   IDs, then asks Apple's private AppleFSCompression API to try types 15–22.
   For each candidate it reports whether compression was accepted, the stored
   type, the compressed flag, physical disk allocation, and an exact readback
   check. The local script detaches but retains the image for inspection.

The private AppleFSCompression API is undocumented. Its availability and
accepted type IDs may differ between macOS builds. A candidate type that
passes readback must still be identified as LZMESH or LZRAVEN before Applesauce
can expose it to users.

The decision tree for integrating these codecs or building an FSKit fallback is
documented in [the LZRAVEN roadmap](roadmap-lzraven.md).

An earlier transparent-compression opportunity is **LZBitmap**. The
reverse-engineered `fscmp` header identifies filesystem types 13 and 14 for
LZBitmap, which Applesauce currently does not expose. The APFS trial includes
type 14 as a second known control so we can assess this simpler integration
route as well.

**Isolation rule:** The native probe refuses a non-APFS path, a non-root mount,
or a mount whose path lacks the `applesauce-probe` marker. The workflow creates
an exclusive fresh disk image and only writes generated sample files there.
Never point `hack/apfs-type-probe.c` at personal files or a live volume.

**System stability warning:** An isolated image limits file-data risk, but APFS
decompression runs in the host kernel. Undocumented or malformed types could
still trigger a kernel error or panic. The private-type trial is opt-in, requires
macOS 27.2+, and should be run only on a backed-up test machine. Start with the
read-only buffer test and OS component inspection.

## Before integrating into Applesauce's `decmpfs` writer

- Determine, with evidence from macOS 27, whether APFS's kernel actually
  provides LZMESH or LZRAVEN transparent decompressor registrations.
- Identify the filesystem `decmpfs` type number(s), block framing, any raw
  fallbacks, and xattr/resource-fork layout. Neither new Compression framework
  algorithm constant can be used as a filesystem type number.
- If supported, implement decoding and writing in a feature-gated path. Only
  test new on-disk formats on disposable files in a dedicated APFS disk image,
  validating byte-for-byte reads and recovery before using real chat logs.
- If unsupported by APFS, report that clearly and pursue conventional archive
  storage or the already-supported LZFSE `decmpfs` path instead.

References:

- <https://developer.apple.com/documentation/compression/compression_lzmesh>
- <https://developer.apple.com/documentation/compression/compression_lzraven>
- <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/decmpfs.c>
- <https://github.com/Siguza/fscmp>
