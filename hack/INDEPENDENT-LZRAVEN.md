# Independent LZRAVEN ASCF buffer-codec proof (#95)

This procedure tests Apple's **buffer encoder** against an independently
built C11 decoder. It does not test APFS `decmpfs` codec registration, permit
transparent filesystem writes, or satisfy FSKit #86 physical acceptance.

## Pinned decoder and provenance

- Source: [anat0m1a/liblzraven](https://github.com/anat0m1a/liblzraven)
- Source commit: `700b88c4b2e1b1d96e499d172dfa0b8e5d9134ab`
- License: 0BSD ([LICENSE](https://github.com/anat0m1a/liblzraven/blob/700b88c4b2e1b1d96e499d172dfa0b8e5d9134ab/LICENSE))
- Scope: independent C11 `lzraven_decode_buffer_ex`, invoked through
  `build/lzraven_dec`; no call into Apple's `libcompression`.
- Caveats: upstream owner states the library is AI-authored and unmaintained.
  Upstream tests and its claims of native differential conformance are
  useful evidence, but independent Applesauce verification is required.

On macOS 27 or later, run in a disposable workspace:

```sh
git clone https://github.com/anat0m1a/liblzraven.git
git -C liblzraven checkout --detach 700b88c4b2e1b1d96e499d172dfa0b8e5d9134ab
make -C liblzraven -j2 all
make -C liblzraven test
otool -L liblzraven/build/lzraven_dec
cargo build --locked -p applesauce-cli
target/debug/applesauce archive create generated.bin generated-raven.ascf \
  --codec lzraven --chunk-bytes 65536 --allow-expansion
target/debug/applesauce archive verify generated-raven.ascf
python3 hack/verify_independent_lzmesh.py \
  --archive generated-raven.ascf --original generated.bin \
  --decoder ./liblzraven/build/lzraven_dec --codec lzraven \
  > independent-raven-evidence.json
```

The `generated.bin` fixture must be disposable and remain unchanged during
proof. The CI workflow `.github/workflows/independent-lzraven-proof.yml`
generates ten deterministic archives in two content families at 65,535,
65,536, 65,537, 131,103 and 262,151 bytes with 64 KiB chunks. It checks
multiple chunks, pins the source, runs the upstream test suite, rejects dynamic
`libcompression` linkage, and uploads JSON evidence with the environment.

## Acceptance

The proof validates the ASCF header, index geometry and logical digests before
running the external decoder. Each compressed chunk is decoded with a strict
`--cap` equal to its declared logical length and a POSIX output-file limit.
The restored bytes must exactly equal the fixture and the index SHA-256.
The concatenated bytes must match the archive's whole-file SHA-256.
Source archive, original and executable identity changes fail verification;
the executable is hashed before and after proof. Decoder operations time out
after 30 seconds each, and total fixture size is bounded to 64 MiB by default.

The portable Python tests use a synthetic identity decoder only to validate
parsing, subprocess, provenance and failure conditions. They cannot prove
codec interoperability. Keep the independent source review and approval gates.
The upstream coder's cross-platform tests and Applesauce's prior local Raven
checks do not replace macOS 27 cross-decoding of freshly generated payloads.

A successful buffer proof is relevant to #95. APFS codec/type mapping under
#88, native transparent writes and FSKit #86 remain blocked.
