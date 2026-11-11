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
Final-component symlinks are rejected, including substitutions pointing
to the same open inode. Source archive, original and executable identity changes fail verification;
the executable is hashed before and after proof. Decoder operations time out
after 30 seconds each. An additional 120-second monotonic deadline caps the
entire fixture's decoder invocations, preventing a many-chunk archive from
multiplying per-chunk timeouts indefinitely. A reviewer may adjust this with
`--total-timeout-seconds` up to 3600 seconds. Total fixture size is bounded
to 64 MiB by default.
Each decoder runs in a new POSIX session; the harness kills its process group
on successful exit, error or timeout, to reap normal forked helpers. This
is best-effort lifecycle cleanup rather than a sandbox against code that
explicitly creates another session.

The portable Python tests use a synthetic identity decoder only to validate
parsing, subprocess, provenance and failure conditions. They cannot prove
codec interoperability. Keep the independent source review and approval gates.
The upstream coder's cross-platform tests and Applesauce's prior local Raven
checks do not replace macOS 27 cross-decoding of freshly generated payloads.

A successful buffer proof is relevant to #95. APFS codec/type mapping under
#88, native transparent writes and FSKit #86 remain blocked.

## Corruption rejection and evidence preservation

For an independently decoded Apple-generated fixture, also run the negative
qualification suite from the repository root:

```sh
python3 hack/prove_independent_corruptions.py \
  --archive generated-raven.ascf --original generated.bin \
  --decoder ./liblzraven/build/lzraven_dec --codec lzraven \
  > independent-lzraven-negative.json
```

The suite first requires the untouched archive to decode successfully. It then
changes compressed payload bytes at two positions, flips the first chunk
digest, truncates the last byte and appends a byte. Multi-chunk fixtures also
mutate the final chunk and its index digest. Fixtures with at least three chunks
add middle-chunk payload and digest mutations, covering every chunk in the
three-chunk proof fixtures. All nine changes must be rejected. Payload-only changes must reach the independent decoder, preventing
a parser-only failure from being mistaken for codec conformance testing.
Every index-digest, truncated-payload and appended-payload case must fail at its intended parser gate.
Decoder timeouts cannot count as successful corruption rejection. Baseline and
all nine negative cases share one **180-second decoder budget**, with an optional
`--total-timeout-seconds` override (maximum 3600) for reviewed diagnostic use.
An exhausted shared budget fails even if the final case was otherwise rejected.

The independent decoder's output file limit permits one extra sentinel byte,
so an executable that ignores `SIGXFSZ` cannot qualify by silently discarding
attempted excess output. The suite snapshots the original plaintext (64 MiB cap)
and independent executable (32 MiB cap) **once** into private files. Both the
clean baseline and every mutated archive use those same pinned inputs, closing
the transient decoder-substitution gap between proof invocations. Snapshot and
verification work share the suite's monotonic deadline. After all negative
cases, archive identity and complete SHA-256 are rechecked along with the
original caller-supplied plaintext and executable identities and hashes.

The macOS proof workflow runs nine cases on each generated content
family at the 131,103-byte three-chunk boundary (18 negative cases per codec).
It attaches the generated `.ascf` archives, original `.bin` files, positive
JSON reports, negative JSON reports and environment provenance. The workflow
requests 30-day artifact retention, but the repository's current effective
expiry is approximately 24 hours (verified from the run 42757335808
artifact metadata on 10 November 2026). Reviewers must retrieve the artifacts
promptly. Four durable Apple-generated differential vectors are committed
under `tests/fixtures/codec-crossdecode/` and replayed with the pinned C11
decoder on Linux before the native macOS proof job is allocated. Independent
source/evidence review and PR approval are still required.

## Private decoder executable snapshot

The independent proof first copies the pinned C11 decoder to a mode-0700
private temporary directory, checks a 32 MiB executable limit and SHA-256,
then runs only the mode-0500 snapshot for each ASCF chunk. It rejects changes
to either the copied executable or its original pathname and cleans up the
snapshot on all exits. This closes the temporary decoder-path substitution
gap during provenance checks. Independent source review and native CI evidence
remain mandatory before qualifying the proof.
