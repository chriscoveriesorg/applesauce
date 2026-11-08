# Applesauce

**Fork focus: modern Apple compression, especially LZRAVEN and LZMESH.**
This fork adds Rust buffer codecs, read-only capability/benchmark commands,
an opt-in native LZBitmap writer, and guarded filesystem research. **LZRAVEN
and LZMESH are not yet native transparent-compression modes.** Follow the
[implementation roadmap](hack/roadmap-lzraven.md) and
[capability contract](hack/modern-compression.md).

Applesauce is a command-line interface (CLI) program written in Rust that
compresses, decompresses, and prints information about compressed files for
HFS+/APFS transparent compression on macOS. It is based on
[afsctool](https://github.com/RJVB/afsctool) and offers several key
improvements, including better performance, improved multithreading (even for a
single file), and reduced memory usage. Its default native writers are LZFSE,
LZVN, and ZLIB; this fork also offers experimental LZBitmap behind a build flag.

![compression example](https://github.com/user-attachments/assets/3f78a011-7db4-4e7f-9cc9-89781ed78609)

## Related tools for agents

Companion projects in the same tooling family. They are separate tools; links do
not install or run anything automatically:

- **[Foldy](https://github.com/chriscoveries/foldy)** *(private; access required)*: local-first filesystem indexing, duplicate review and disk-space reporting.
- **[compress-agent-sessions](https://github.com/chriscoveriesorg/compress-agent-sessions)**: cold-session selection and optional transparent compression. Its [modern-codec integration](https://github.com/chriscoveriesorg/compress-agent-sessions/blob/main/docs/experimental-lzraven.md) uses Applesauce's fail-closed native capability gate.
- **[ZGX](https://github.com/chriscoveriesorg/zgx)** *(private; access required)*: agent-oriented local metasearch. [Integration tracking](https://github.com/chriscoveriesorg/zgx/issues/504) checks unchanged logical bytes, search hits and byte spans after compression.

The [four-tool integration guide](hack/family-integration.md) defines the
Foldy → session policy → Applesauce → ZGX flow and ships a **read-only
before/after contract checker** for file hashes and search results. Start with
verified native LZFSE on generated data; Raven/Mesh filesystem writes remain
blocked until their decoder/framing are proven.

## Installation

### Build this fork and run read-only diagnostics

On macOS with Rust and Xcode Command Line Tools:

```sh
git clone https://github.com/chriscoveriesorg/applesauce.git
cd applesauce
cargo build --locked --release -p applesauce-cli
./target/release/applesauce capabilities --json
./target/release/applesauce benchmark-codecs --json
```

LZRAVEN and LZMESH buffer APIs require macOS **27.0+**, including 27.0.1.
They do not require 27.2. The benchmark uses generated JSONL and high-entropy
data unless you explicitly supply `--file /path/to/STABLE-COPY.jsonl` (64 MiB
maximum). It never compresses that file on disk, changes xattrs, or uploads it.
Results compare whole buffers with independent 64 KiB buffers; these are raw
payload measurements, not APFS allocation savings.

### Reproducible speed and ratio benchmarks

The [benchmark standards](hack/benchmark-standard.md) define deterministic
chat JSONL, mixed JSONL, structured binary, high-entropy and zero-filled
workloads, fixed sizes, SHA-256 fixture identities, per-algorithm encode/decode
MiB/s, 64 KiB independent blocks, and scratch-reuse comparisons. The
[Benchmark Apple buffer codecs](https://github.com/chriscoveriesorg/applesauce/actions/workflows/benchmark-codecs.yml)
workflow has a **Run workflow** button with `smoke`, `standard` and `extended`
presets. It uploads raw Criterion samples, confidence intervals, environment,
compression ratios and a per-case CSV; PR CI validates the smoke suite.
These measurements concern the public in-memory buffer API—not transparent
APFS compression or filesystem read/write throughput.

### Create and restore LZRAVEN/LZMESH archives on macOS 27+

The experimental cold-file format writes a **separate**, seekable, checksummed
archive that a future FSKit mount can expose through an ordinary read-only path.
It leaves the original file unchanged and refuses to overwrite existing outputs.

```sh
applesauce archive create chatlog.jsonl chatlog.ascf --codec lzraven
applesauce archive info chatlog.ascf
applesauce archive verify chatlog.ascf
applesauce archive extract chatlog.ascf chatlog-restored.jsonl
applesauce archive extract chatlog.ascf chatlog-slice.jsonl --range 65535:131073
# Or choose --codec lzmesh for the create command.
```

`archive info` reads the header and validated index without loading a
codec or decompressing any chunk. It reports the archive's declared logical
SHA-256, codec, chunk dimensions and file size, not a whole-file verification.
This inspection also works on Linux. `extract --range OFFSET:LENGTH` uses
decimal logical byte offsets, authenticates every touched chunk with SHA-256
and writes a new no-clobber file through a verified temporary file. It skips
unrelated chunks, so the range digest is evidence for the selected bytes.
Run `archive verify` to authenticate the complete logical archive; that
requires an available Raven/Mesh decoder on macOS 27+.

The writer rereads and hashes the original, verifies every staged chunk and
publishes a new file only after verification. Archives that cannot save space
are refused unless you set `--allow-expansion`. Use `--chunk-bytes 1048576`
to select a power-of-two chunk size between 64 KiB and 8 MiB. Keep the original
log until you have validated its restoration. The archive is not an APFS
`decmpfs` compressed file and existing applications must open a restored copy
until a separate filesystem mount is implemented.

For the optional native LZBitmap writer, build with
`cargo build --locked --release -p applesauce-cli --features lzbitmap`.
Then check `./target/release/applesauce capabilities --json --require-native lzbitmap`
before trying `compress -c lzbitmap --verify` on a **disposable copy**. This
backend requires macOS 12+ with a working codec and a compatible volume;
it is not enabled by default. Verification is forced before atomic replacement.

The Homebrew and prebuilt-release commands below install **upstream Applesauce**,
not this fork's new commands or optional backend.

### Install via Homebrew

To install Applesauce using Homebrew, run the following command:

```console
brew install Dr-Emann/homebrew-tap/applesauce
```

### Install prebuilt binaries via shell script

```console
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Dr-Emann/applesauce/releases/latest/download/applesauce-cli-installer.sh | sh
```

### Manual build with Cargo

<details>
<summary>Details</summary>

To install Applesauce using Cargo, follow these steps:

1. Install Rust and Cargo using the instructions provided at [rust-lang.org](https://www.rust-lang.org/tools/install).
2. Clone this repository to your local machine.
3. In the project directory, run `cargo build --release` to build the program.
4. The built binary can be found in the `target/release` directory.

</details>

## Usage

To use Applesauce, run the following command:

```console
applesauce [compress|decompress|info] file/directory
applesauce capabilities [--json] [--require-native CODEC]
applesauce benchmark-codecs [--codec lzfse,lzmesh,lzraven] [--file COPY.jsonl] [--json]
applesauce archive [create|verify|extract] ...
```

The options are as follows:

- `compress`: Compresses the specified file/directory using one of three compression algorithms (LZFSE, LZVN, or ZLIB).
- `decompress`: Decompresses the specified file/directory.
- `info`: Prints information about the specified compressed file/directory, including the compression ratio and
  compression algorithm used.

For example, to compress a file named `example.txt` using the ZLIB compression algorithm, you would run:

```console
applesauce compress -c ZLIB example.txt
```

### Opt-in per-file native codec selection

```console
applesauce compress -c auto --verify PATH...
```

`-c auto` selects a supported native `lzfse`, `lzvn`, or `zlib` codec separately
for each eligible file. The default codec is unchanged. Selection is
deterministic: it encodes at most **64 KiB total** per file from the same opened
descriptor, using a whole-file window for small inputs, head/tail windows for
medium inputs, or head/middle/tail windows for larger inputs. The codec whose
sample has the fewest encoded bytes wins, with ties favouring LZFSE, then
LZVN, then zlib. The source descriptor's read cursor is unchanged.

The full file is encoded normally after selection, and the existing real
compressed-size gate (`--minimum-compression-ratio`), staging and `--verify`
continue to apply. This opt-in heuristic does not guarantee that a sample's
winner is the smallest final file, particularly for heterogeneous sources.
`lzbitmap` and Raven/Mesh never enter native auto selection. Selected codec,
sample bytes and window count are logged for each file at INFO verbosity;
`info` reports the resulting native codec.

Full-encoding `--dry-run -c auto` is currently refused explicitly because the
dry-run projection measures a single chosen codec and cannot yet present a
per-file selection. Use `--dry-run -c lzfse`, `-c lzvn`, or `-c zlib`
for a read-only projection instead. Compare generated corpus outcomes and
elapsed time against fixed codecs before treating auto as a performance gain.

### Read-only compression projection

`compress --dry-run PATH...` performs the same full 64 KiB block encoding and
native `decmpfs` writer finalization as a real compression, but uses a
memory-only counting/seek sink. It does not sample and does not create writer
temporary files, xattrs, flags, trace files, or timestamp resetters. It reports
each path, each directory subtree, and the combined total. Overlapping roots are
deduplicated. A symlink supplied as a root or directory entry is skipped.
Regular files and directories are opened with Darwin `O_NOFOLLOW_ANY`, which
atomically rejects a symlink in any pathname component; opened directories are
identity-checked and enumerated through their descriptor. A symlink in a
supplied root's ancestors, including compatibility aliases such as `/tmp`, is an
error. Pathname classification can still race, but no file content is encoded
and no directory is traversed unless that no-follow descriptor open succeeds.

```console
applesauce compress --dry-run -c lzfse PATH...
applesauce compress --dry-run --json -c zlib PATH...
```

With `--dry-run`, `--json` emits the projection schema below; without it,
`--json` emits the actual-storage report described later. `--chrome-tracing` is rejected before
its output file is opened. Dry-run supports the normal stable native codecs
`zlib`, `lzvn`, and `lzfse`; opt-in `lzbitmap` appears only in builds with that
feature and a supported host. Raven and Mesh are buffer/archive codecs and are
never emitted as native `decmpfs` projections. Non-finite ratio values (`NaN`
and infinities) are rejected before output or tracing setup; finite values at or
below zero and above one retain the normal compressor semantics.

The JSON contract has `schema_version: 1`. Byte counts are integer bytes:

The top-level keys are `schema_version`, `complete`, `codec`,
`minimum_compression_ratio`, `full_encoding`, `paths`, `directories`, `totals`,
and `allocation_estimate_limitations`. `full_encoding` is always `true`;
`codec` is the selected lowercase encoder name, including on skipped paths.
Each directory has `path`, `totals`, and nullable `error` fields.

- `paths[]` contains regular files plus skipped/error non-regular inputs.
  `path.display` is for people; `path.bytes_hex` is the authoritative,
  lossless lowercase encoding of Unix pathname bytes, including non-UTF-8
  names. `entry_type` is `file`, `symlink`, `other`, or `unknown`.
- `codec`, `would_compress`, and stable `reason` describe the decision.
  Reasons are `compress`, `below_minimum_ratio`, `already_compressed`,
  `empty_file`, `too_large`, `filesystem_unsupported`,
  `required_compression_xattr`, `hard_link`, `symlink`,
  `not_regular_file`, or `error`.
- `logical_size_bytes` is `st_size`; `current_allocation_bytes` is exactly
  `st_blocks * 512`. `allocation_block_bytes` is the real allocation unit from
  `fstatfs().f_bsize`, not the preferred-I/O `st_blksize`.
- `raw_compressed_bytes` is the sum of all encoded block payloads and is the
  value used by the shared minimum-ratio gate. `decmpfs_xattr_bytes` and
  `resource_fork_bytes` include the finalized native framing. `storage` is
  `inline_xattr` or `resource_fork`.
- `projected_native_allocation_bytes` rounds the finalized resource-fork
  framing and carries forward allocation already attributable to non-data
  metadata. Inline `decmpfs` and preserved xattr bytes are measured but do not
  assume a separate extent.
  `projected_native_allocation_upper_bound_bytes` is an independently-rounded
  accounting upper estimate for the measured resource fork and xattrs. It is
  always at least the central projection, but is not a filesystem-wide physical
  allocation guarantee. `savings_bytes` is signed `current - projected`, so a
  negative number means growth.
- `directories[]` gives descendant totals for every traversed directory;
  `totals` combines the deduplicated input roots. Skipped files retain their
  current allocation in projected totals. Hard-linked files are reported but
  excluded entirely from logical/allocation totals because replacing one name
  would break link identity; `hard_links_excluded` counts those names.
  Each totals object has `complete`, `files_included`, `files_would_compress`,
  `files_skipped`, `hard_links_excluded`, `logical_size_bytes`,
  `current_allocation_bytes`, `projected_native_allocation_bytes`,
  `projected_native_allocation_upper_bound_bytes`, and `savings_bytes`.
  Included-file counts exclude symlinks, other non-regular entries, and hard
  links; `files_skipped` counts included files with `would_compress: false`.
- Any unavailable/unknown numeric value is JSON `null`, never zero. An error is
  attached to its path with stable `kind` plus a human message, makes affected
  directory and overall totals incomplete/null, sets `complete: false`, and
  causes a nonzero exit. This makes the schema fail closed for automation.
  Error kinds are `not_found`, `permission_denied`, `invalid_input`,
  `invalid_data`, `unexpected_eof`, `unsupported`, `would_block`, or `io_error`.

Allocation remains an estimate because APFS/HFS+ can place small xattrs inline
and cloning, sparse extents, filesystem metadata, and compression-attribute
placement are not exactly observable without performing a write. The report's
`allocation_estimate_limitations` repeats these constraints for machine
consumers. The central projection is intended for projected-versus-actual
comparisons. The synthetic accuracy test checks actual allocation against the
accounting upper estimate, but APFS/HFS+ placement outside these measured
components can differ, so neither estimate is a general capacity guarantee.

### Actual size and storage reports

`info PATH...` and `compress PATH...` use the same actual-storage report.
`info --json PATH...` and `compress --json PATH...` emit one JSON document on
stdout with `schema_version: 1` and `report_kind: "actual_storage"`. Compression
reports the files as they exist after the operation; running `info` immediately
afterward gives the same measurements. Progress and diagnostics use stderr.
`info` opens inputs for reading only and rejects `--chrome-tracing` before opening
its output. Symlinks and other non-regular entries are listed and excluded from
byte totals. An unavailable input or malformed storage metadata makes the report
incomplete and exits nonzero.

```console
applesauce info --json example.txt directory cold.ascf
applesauce compress --json -c zlib example.txt
```

The size vocabulary matches compression projections. All byte counts are integer
bytes; fields that are unknown or inapplicable are JSON `null`.

| Field | Definition |
| --- | --- |
| `logical_size_bytes` | File content length (`st_size`); for ASCF, the logical length declared in its validated header. |
| `current_allocation_bytes` | Exactly `st_blocks * 512`, including allocation charged to the file by the filesystem. No additional rounding by preferred I/O block size is applied. |
| `raw_compressed_bytes` | Native encoded block payloads, excluding decmpfs/resource-fork framing; for ASCF, the sum of indexed encoded chunk lengths. Null for an ordinary file or an unknown native type. |
| `decmpfs_xattr_bytes` | Entire `com.apple.decmpfs` attribute, including its 16-byte header; zero when absent. |
| `resource_fork_bytes` | Entire resource fork, including native framing when present; zero when absent. A fork may also contain ordinary application data. |
| `archive_bytes` | Entire ASCF file length (`st_size`), including its header, index and encoded chunks. Null for other files. |
| `entry_count` | ASCF indexed chunk count, not a count of archived files. Null for other files. |
| `savings_bytes` | Signed `logical_size_bytes - current_allocation_bytes`, as stated in `savings_basis`. Negative values mean allocation exceeds logical content length. |
| `savings_fraction` | `savings_bytes / logical_size_bytes`; zero for zero logical bytes. Negative values remain negative. |

`source` is `none`, `decmpfs`, or `ascf`. `codec` is the lowercase mapped codec
name, `none` for ordinary files, or `unknown` for an unrecognized type.
`decmpfs_type` preserves the raw native type number. Known mappings are zlib
(3/4), lzvn (7/8), lzfse (11/12), and lzbitmap (13/14); reporting a mapping does
not enable its encoder or decoder. `storage` is `inline_xattr` or `resource_fork`
for recognized native compression and null otherwise. Unknown native types are
never guessed from payload contents. ASCF inspection validates its header and
index using `ArchiveReader::open`; it does not extract, decode, or authenticate
payloads. A damaged payload can still have readable metadata. Unknown ASCF codec
selectors fail closed with `codec: "unknown"` and an attached error.

Do not add payload, xattr, resource-fork or archive bytes to allocation: these are
views of storage already represented by `current_allocation_bytes`. An inline
native payload is contained in `decmpfs_xattr_bytes`; a resource-fork payload is
contained in `resource_fork_bytes`; an ASCF payload is contained in `archive_bytes`.
The actual report's savings basis is logical versus allocated bytes. A compression
projection's `savings_bytes` has the explicitly different current-versus-projected
allocation basis; it measures the expected operation delta, not content savings.

`paths[]` lists each encountered name with `path.display` for people and
`path.bytes_hex` as the authoritative lowercase hex encoding of Unix pathname
bytes. A second hard-link name has `duplicate_of` pointing to the first listed
name. `directories[]` contains descendant totals for each directory; `roots[]`
contains independent totals for each supplied root; `totals` covers their union.
Each total counts an inode once by `(st_dev, st_ino)`, including hard-linked files
that the compressor skips. Overlapping roots are counted once in combined totals.
Directory inodes themselves are excluded. Sum distinct inode contributions to
reconcile totals; do not sum every name, overlapping root, or nested directory.
Total payload/framing/archive fields use zero for inapplicable files and null if
an included value is unknown. `codecs` and `storage_forms` list the distinct forms
observed in each total. `files_included` counts successfully measured unique
regular files, even when other paths failed.

Errors have stable `kind` and human `message` fields. An inspection error makes
affected directory/root/combined byte totals null and `complete: false`.
Notified compression errors appear in `operation_errors`, make the overall report
incomplete and exit nonzero; readable post-operation measurements remain available.
Completeness describes inspection and notified errors, not a promise that every
file was compressed: eligibility skips and minimum-ratio refusals remain normal
compressor behavior. The report is not an atomic filesystem snapshot. Concurrent
metadata changes detected during inspection are errors.

`allocation_measurement` states `st_blocks * 512`, and
`allocation_estimate_limitations` records that clone-shared extents and snapshots
are not deduplicated and directory/filesystem metadata is excluded. Sparse files
can have zero allocation; small compressed xattrs can also be inline with zero
charged blocks. Allocation is neither exclusive physical usage nor a prediction
of space reclaimed by deletion. The library's legacy `total_compressed_size`
field now uses this same allocation definition and deduplicates hard links.

## Experimental macOS 27 codec investigation

The [codec workflow](.github/workflows/modern-compression-probe.yml) runs
generated-data buffer tests and CLI contract checks on relevant pull requests
and pushes. It also has an **Actions → Probe macOS 27 compression codecs →
Run workflow** button. Reports retain exact OS/build/SDK versions and JSON
measurements. Standard CI separately checks the opt-in LZBitmap native writer
on generated temporary files.

Private APFS trials are manual-only, default off, and require macOS 27.2+
as a project safety policy. They use disposable disk images and verify after
detach/read-only reattach. Additional type requests require a second opt-in.
An image does not isolate the host kernel from crashes. See
[methods and safety notes](hack/modern-compression.md).

`compress -c lzraven` and `compress -c lzmesh` intentionally remain unavailable:
buffer support does not establish a native `decmpfs` decoder or on-disk format.

## Features

Applesauce has the following key features:

- Supports three compression algorithms: LZFSE, LZVN, and ZLIB.
- Can print information about compressed files, including the compression ratio and compression algorithm used.
- Supports transparent compression for HFS+/APFS on macOS.

## Compression Algorithms

Applesauce supports three compression algorithms:

- LZFSE: This compression algorithm was developed by Apple for use on iOS and
  macOS. It is a fast compression algorithm that offers a good balance
  between compression ratio and speed.
- LZVN: This compression algorithm was also developed by Apple for use on iOS
  and macOS. It is optimized for use on 64-bit processors and offers a high
  compression ratio.
- ZLIB: This is a widely used compression algorithm that is implemented in many
  software packages. It is slower than LZFSE and LZVN, but can offer a higher
  compression ratio (especially with `-l 9`, but not always: it depends on the
  type of data being compressed).

Applesauce defaults to using LZFSE compression.
Depending on the type of data being compressed and the desired balance between
compression ratio and speed, one of these algorithms may be more suitable than
the others.

## Improvements Over Afsctool

Applesauce is based on afsctool, but offers several key improvements, including:

#### Improved Performance

afcstool can compress multiple files in parallel, but applesauce parallelizes at
the block level, so even a single file can be compressed in parallel. Applesauce
can often be several times faster than afsctool, especially for small numbers of
large files.

#### Reduced Memory Usage

afcstool will load the entire file into memory before compressing it
(although it does attempt to use mmap for large files). Applesauce will only
keep the block(s) currently being compressed in memory.

#### Better User Interface

Applesauce outputs a pretty progress bar while it's working, providing a more
user-friendly experience than afsctool's sparse output.

#### Better Compression With Many Small Files

afsctool will compress a file which fits in the xattr after compression, even
if doing so actually adds more overhead than leaving the file uncompressed.
Applesauce will not compress a file if it would result in a larger file.

#### Better Error Handling

afcstool overwrites files in place. Although it attempts to restore the file
if an error occurs, if it is forcefully terminated while compressing a file,
the file may be left in an invalid state.

Applesauce compresses/decompresses files to a temporary file and then atomically
renames the temporary file to the original file only when the operation is
complete: the file is never left in an invalid state, even if the program is
harshly terminated.

This is no replacement for backups: please do not use applesauce on files you
cannot afford to lose.

## License

Applesauce is licensed under the GNU General Public License version 3 (GPLv3).

## Contributions

Contributions to Applesauce are welcome! If you would like to contribute code,
please open a pull request on the GitHub repository. If you find a bug or have
a feature request, please open an issue on the repository.
