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
