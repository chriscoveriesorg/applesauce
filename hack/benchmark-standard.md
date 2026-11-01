# Applesauce compression benchmark standard (v1)

This is the reproducible **public Apple Compression.framework buffer** speed
and ratio benchmark. A buffer round trip is **not** evidence that APFS supports
LZRAVEN or LZMESH for `decmpfs` transparent file compression. Benchmark code
never mutates file attributes or a user's logs.

## Button, inputs and artifacts

Use **[Actions → Benchmark Apple buffer codecs (speed and ratio) → Run
workflow](https://github.com/chriscoveriesorg/applesauce/actions/workflows/benchmark-codecs.yml)**, choose the suite, and
download its `applesauce-criterion-…` artifact. Runs use the macOS 27
`xcode-27` runner, stable Rust, and pinned `Cargo.lock` dependencies.

| Suite | Generated workloads | Uncompressed sizes | Layouts | Scratch comparison | Typical use |
|---|---|---|---|---|---|
| `smoke` | Chat JSONL-like, entropy | 64 KiB | Whole | Both | Correctness/quick measurement |
| `standard` (default) | All five | 4 KiB, 64 KiB, 1 MiB | Whole, plus 1 MiB independent 64 KiB | Reused throughout; API-managed for representative Chat/entropy | Repeatable comparison |
| `extended` | All five | 4 KiB, 64 KiB, 1 MiB, 8 MiB | Whole, plus 1/8 MiB independent 64 KiB | Both throughout | Detailed scaling / scratch study |

The fixture generator in
[`crates/applesauce-core/benches/fixtures.rs`](../crates/applesauce-core/benches/fixtures.rs)
has `VERSION = 1` and a fixed pseudo-random seed. It emits five deliberately
different byte distributions:

1. `chat-jsonl`: highly repetitive synthetic assistant messages and session IDs;
2. `mixed-jsonl`: timestamped events and distinctive pseudorandom identifiers;
3. `binary-records`: repeating 512-byte records, interspersed with noisy bodies;
4. `entropy`: deterministic pseudorandom bytes, a near-incompressible control;
5. `zeros`: a highly compressible lower-bound control.

Fixtures always have the requested exact byte count, so the last synthetic
JSONL record can end mid-line. These are *compression distributions*, not
parser-conformance samples. No private chat logs or other customer data are
collected or uploaded. Each workload+size has its SHA-256 in `manifest.csv`;
changing the fixture version or digest means cross-run comparisons need a
separate cohort.

Every case tests Apple's public in-memory `ZLIB`, `LZFSE`, `LZBITMAP`, `LZMESH`
and `LZRAVEN` selectors when present on the host. Legacy LZVN belongs to the
separate native-core compressor interface and is not quietly mislabeled as an
Apple buffer selector. The original native-core microbenchmark still exists at
`cargo bench -p applesauce-core --bench bench` (with its ZLIB labeling fixed).

## Speed, ratio and correctness contract

- **Encode time and decode time are separate** Criterion measurements, not
  their sum. For both, throughput uses **uncompressed input bytes per second**
  (MiB/s = bytes / time / 1,048,576); one operation processes all chunks in
  the selected layout. Its compressed payload ratio is
  `encoded_bytes / input_bytes` (smaller is better).
- **Whole** lets the codec exploit long-range redundancy within one input;
  **independent-64k** resets the codec on each block. The sum of the encoded
  block lengths excludes APFS metadata, resource-fork tables, alignment,
  allocations and xattrs, so it is **not on-disk space saved**.
- Timed loops reuse caller-owned input, output buffers and precomputed encoded
  data. Every case first encodes and decodes **outside** timing and compares
  exact bytes; decoding reserves a one-byte overflow guard to reject silent
  truncation. A mismatch fails the run.
- **`api-managed`** passes `NULL` scratch to Apple, letting the framework
  allocate/manage any scratch itself. **`reused-scratch`** preallocates the
  sizes requested by `compression_{encode,decode}_scratch_buffer_size` and
  reuses them. Zero requested bytes is valid and is recorded as zero; neither
  mode allocates or frees destination buffers inside the timed Rust loop.
  This isolates codec scratch costs, not total end-user application costs.
- Criterion warms up, gathers repeated samples, and retains both median timing
  and statistical confidence estimates. CI presets: smoke (1 s warmup / 2 s
  measurement / 20 samples), standard (1 s / 3 s / 30), extended (2 s / 5 s /
  50). Each benchmark case is calibrated separately.

Artifacts include:

| Artifact | Role |
|---|---|
| `environment.txt` | UTC, full commit SHA, OS/build, model/CPU/memory, Xcode/SDK, Rust version |
| `config.txt` | Suite, warmup, measurement duration, sample count |
| `manifest.csv` | Fixture version, SHA-256, sizes, codec, layout, scratch sizes/mode, payload ratio, round-trip status |
| `criterion/**/new/estimates.json` and `sample.json` | Raw Criterion timing estimates, confidence intervals and samples for encode and decode |
| `summary.csv` | Full-case median ns and derived encode/decode MiB/s joined by exact case key |
| `summary.md` | Small same-host Chat JSONL vs entropy comparison |
| `criterion.log` | Complete runner output, including measurement warnings and skips |

The pure-Python
[`hack/summarize-benchmarks.py`](summarize-benchmarks.py) exits nonzero when
an expected result is missing; it will never silently fabricate speed data.

## Reproduce locally on a macOS 27 host

From the checkout root:

```sh
mkdir -p target/applesauce-bench
export APPLESAUCE_BENCH_SUITE=standard
export APPLESAUCE_BENCH_MANIFEST="$PWD/target/applesauce-bench/manifest.csv"
cargo bench --locked -p applesauce-core --bench modern_buffer -- \
  --noplot --warm-up-time 1 --measurement-time 3 --sample-size 30
python3 hack/summarize-benchmarks.py \
  "$APPLESAUCE_BENCH_MANIFEST" target/criterion \
  target/applesauce-bench/summary.csv
```

If modifying a codec or its build flags, capture exact commit/runner metadata
and repeat at least three full runs of both revisions on the **same hardware**.
Avoid compiling in the background during measurement; keep power source,
thermal state and workload constant, and compare confidence intervals and raw
distributions. CPU frequency variation and shared-host contention can dwarf
small changes. Report the regression/improvement only after independently
reproducing it on a controlled host. The public hosted workflow intentionally
**does not fail CI on percentage speed changes**. It fails on broken builds,
round trips, missing reports or invalid contracts.

The everyday command `applesauce benchmark-codecs --json` remains a quick
diagnostic and schema-v1 capability contract for `compress-agent-sessions` and
ZGX. Its few `Instant` measurements are **not Criterion speed estimates**.

## What this standard cannot claim

Buffer codec performance is not transparent APFS read/write performance. Native
`decmpfs` support, resource-fork or xattr overhead, file replacement, kernel
decode, filesystem metadata, page cache, directory walk and storage bandwidth
are absent here. Even if Raven outperforms LZFSE on generated 1 MiB JSONL,
that does not mean Raven can be safely applied to real files. A later native
suite must use disposable copies and *verified, OS-supported `decmpfs` types*,
with cold/warm cache trials, physical allocation, and exact-byte/search-span
readbacks. **Never turn on an unverified Raven/Mesh file writer to benchmark it.**

External methodology references:
[Criterion.rs](https://bheisler.github.io/criterion.rs/book/user_guide/advanced_configuration.html)
for warmup/sampling/statistics, [Criterion throughput](https://bheisler.github.io/criterion.rs/book/user_guide/advanced_configuration.html#throughput),
and [Google Benchmark guidance](https://github.com/google/benchmark/blob/main/docs/user_guide.md)
for environment and run-to-run variance.
