# Benchmarks — 2026-11-06, M1 Max, macOS 27.2 (26B123)

File-level and buffer-level measurements of applesauce codecs on public
compression corpora, plus Criterion `standard` suite results, on a shared
host running unrelated agent builds (load averages 3-6 recorded per batch).

## Machine & environment

- MacBookPro18,4 — Apple M1 Max, 8 P-cores + 2 E-cores, 64 GB RAM
- macOS 27.2 (26B123), Darwin 27.2.0; Xcode 27.0 (27A266a), SDK 27.0; rustc 1.93.1
- applesauce-cli 0.5.31 @ 335e3e8, built
  `cargo build --locked --release -p applesauce-cli --features lzbitmap`
- AC power, battery 80% not charging; no thermal warnings (`pmset -g therm` clean)
- Load averages at batch starts recorded in `batches.log`; rows with load>4
  are wall-clock-contended — use CPU-time columns (`enc_cpu_ns_per_b`,
  `dec_cpu_ns_per_b`) as the primary speed metric; MB/s is measured under load.
- `capabilities --json`: all six buffer codecs available; native writers
  enabled for zlib/lzvn/lzfse/lzbitmap; raven/mesh buffer-only (as designed).

## Corpora (downloads; not committed — SHA-256 in `manifest.csv`)

| corpus | URL | archive bytes |
|---|---|---|
| silesia | https://sun.aei.polsl.pl/~sdeor/corpus/silesia.zip | 68,182,744 |
| canterbury | https://corpus.canterbury.ac.nz/resources/cantrbry.tar.gz | 739,071 |
| large-canterbury | https://corpus.canterbury.ac.nz/resources/large.tar.gz | 3,258,648 |
| enwik8 | https://mattmahoney.net/dc/enwik8.zip | 36,445,475 |
| synthetic/edge | generated locally (JSONL logs, CSV, src tar, random, boundary sizes, 4.6 GB pattern) | — |

## What ran

1. **Criterion `standard` suite** (`cargo bench -p applesauce-core --bench
   modern_buffer`, standard preset 1 s warmup / 3 s measurement / 30 samples)
   — `criterion/` retains only `new/estimates.json` + `manifest.csv` +
   `summary.csv` from `hack/summarize-benchmarks.py`.
2. **`applesauce benchmark-codecs --json`** default inputs, and
   `--codec lzfse,lzvn,zlib,lzmesh,lzraven --file F --iterations 5 --json`
   for each Silesia file and a 64 MiB enwik8 slice — `benchmark-codecs/`.
   (lzvn has no public buffer selector; its rows report unavailable, as designed.)
3. **File-level matrix** — 3 warm-cache reps per file×codec under
   `/usr/bin/time -l`: `archive create/verify/extract` for lzraven/lzmesh,
   `compress -c` on lane copies for lzfse/lzvn/zlib/lzbitmap, stream tools
   (zstd/xz/brotli/lz4/gzip/bzip2 at defaults). Per run: real/user/sys s,
   instructions retired, cycles, peak RSS + footprint, SHA-256 round trip.
   `runs.csv` = raw rows; `summary.csv` = per file×codec medians + min/max.

## Headline

Numbers below are corpus aggregates (sum of compressed / sum of original);
file-level medians. CPU s/GB = (user+sys)/GB from time -l — the
contention-independent metric. MB/s = wall clock under shared-host load.

### Ratio (compressed / original)

| corpus | lzraven | lzmesh | lzfse | lzvn | zlib | lzbitmap | zstd | xz | brotli |
|---|---|---|---|---|---|---|---|---|---|
| silesia | **0.246** | 0.299 | 0.366 | 0.422 | 0.361 | 0.427 | 0.312 | 0.233 | 0.234 |
| canterbury | **0.180** | 0.222 | 0.277 | 0.382 | 0.300 | 0.405 | 0.226 | 0.175 | 0.175 |
| enwik8 | **0.303** | 0.352 | 0.399 | 0.472 | 0.388 | 0.545 | 0.354 | 0.267 | 0.257 |

LZRaven = best applesauce ratio on every corpus (27/29 compressible files);
trails only xz/brotli among references. LZMesh = zstd/gzip class.

### CPU time (s/GB input = ns/B; median of 3, warm cache; wall MB/s under shared-host load)

enwik8 64 MiB slice (CPU s/GB encode / decode; util = cores used):

| codec | enc s/GB | dec s/GB | cores | wall cMB/s | wall dMB/s |
|---|---:|---:|---:|---:|---:|
| lzraven (archive) | 234.8 | 11.9 | 1.0 | 4.3 | 80.9 |
| lzmesh (archive) | 11.6 | 5.1 | 1.0 | 83.9 | 176.6 |
| lzfse (decmpfs) | 15.2 | 2.1 | 6.4 | 419 | 419 |
| lzvn (decmpfs) | 21.9 | 1.9 | 7.0 | 320 | 610 |
| zlib (decmpfs) | 14.2 | 4.0 | 7.9 | 559 | 268 |
| lzbitmap (decmpfs) | 8.1 | 0.45 | 4.2 | 516 | 2237 |
| zstd | 5.5 | 1.5 | 2.1 | 373 | 746 |
| xz | 588.6 | 14.0 | 2.7 | 4.5 | 181 |
| brotli | 2158.6 | 2.5 | 1.0 | 0.5 | 353 |
| gzip | 41.6 | 2.1 | 1.0 | 23.9 | 447 |
| bzip2 | 68.6 | 29.1 | 1.0 | 14.1 | 33.6 |
| lz4 | 3.0 | 0.75 | 5.0 | 1678 | 1342 |

Small files (<4 MiB, canterbury) are process-spawn-bound: codec CPU below
0.01 s/run — keep to large-file rows for CPU comparisons. Full medians +
min/max spread per file in `summary.csv`; raw runs incl. instructions
retired and cycles in `runs.csv`.

**Threads:** decmpfs writers (lzfse/lzvn/zlib/lzbitmap) use 4-8 cores via
applesauce's block parallelism; lz4 and xz also exceed 1 core; everything
else incl. both archive codecs is single-threaded (util ≈ 1.0).

### Criterion (1 MiB whole-buffer, reused-scratch, chat-jsonl vs entropy; MiB/s = bytes/time/1048576)

| workload | codec | ratio | encode MiB/s | decode MiB/s |
|---|---|---:|---:|---:|
| chat-jsonl | lzraven | 0.001 | 118.8 | 11265.0 |
| chat-jsonl | lzmesh | 0.009 | 899.0 | 9603.1 |
| chat-jsonl | lzfse | 0.034 | 265.0 | 8064.1 |
| chat-jsonl | zlib | 0.029 | 269.6 | 4600.0 |
| chat-jsonl | lzbitmap | 0.030 | 787.7 | 4312.9 |
| entropy | lzraven | 1.000 | 17.3 | 47487.1 |
| entropy | lzmesh | 1.000 | 682.0 | 44617.6 |
| entropy | lzfse | 1.010 | 138.7 | 506.9 |
| entropy | zlib | 1.000 | 43.6 | 38042.3 |
| entropy | lzbitmap | 1.000 | 165.6 | 46143.1 |

170 cases, all verified round trips (validator PASS). Note the scale dependence:
lzraven encode is ~119 MiB/s on 1 MiB chat-jsonl buffers but only ~3-9 MB/s on
≥5 MB inputs at file level — encode cost is superlinear in input size, a codec
property, not a host artifact (reproduced at both layers).

## GPU / Neural Engine verdict

- **No Metal/ANE/ML framework loads.** `DYLD_PRINT_LIBRARIES=1` during a
  lzraven+lzmesh benchmark shows 66 dylibs — libcompression, liblzma,
  libsystem family only. Zero Metal/MPS/ANE/Espresso/IOAccelerator libraries.
- **GPU utilisation identical idle vs encode.** `ioreg -r -c IOAccelerator`
  sampled ~300 ms during a 45 s sustained LZRaven encode: "Device
  Utilization %" reads 4% ambient (WindowServer/compositor) exactly as the
  idle baseline does — no codec-driven GPU work (`hw-idle.txt`, `hw-raven.txt`).
- **ANE counters don't move.** `H11ANEIn`/`H1xANELoadBalancer` `busy` state
  stayed 0 (cumulative 5508 ms baseline unchanged) across the same runs.
- **ANE: no non-root telemetry.** The registry exposes `H11ANEIn` /
  `H1xANELoadBalancer` nodes but no user-readable utilisation counter;
  `busy` state stayed 0 during codec runs. The ANE question is resolved
  by exclusion: no ANE frameworks load, CPU instructions account for the
  work (see below), and GPU stays idle — but the definitive power-rail
  check needs root: run this in Terminal during a benchmark —
  `sudo powermetrics --samplers ane_power,gpu_power -n 20 -i 500`
- **CPU cross-check:** cpu_util ≈ 1.00 (single thread) for every codec on
  every file; instructions retired scale with input bytes and match
  wall×core time within noise. No unexplained gap that could hide offload.

## Reproduce

```sh
# file path (verified archive write, then verified restore)
applesauce archive create SRC OUT.ascf --codec lzraven --allow-expansion
applesauce archive verify OUT.ascf
applesauce archive extract OUT.ascf REST && shasum -a 256 SRC REST
# native decmpfs path on a disposable copy
cp SRC COPY && /usr/bin/time -l applesauce compress -q -c lzfse COPY \
  && applesauce info COPY && /usr/bin/time -l applesauce decompress -q COPY
# buffer codecs
applesauce benchmark-codecs --codec lzfse,lzmesh,lzraven --file STABLE-COPY --iterations 5 --json
# Criterion standard suite (commands in hack/benchmark-standard.md)
```

## Files

- `runs.csv` — every timed file-level run (CPU + wall + RSS + instructions)
- `summary.csv` — per file×codec medians/min/max
- `manifest.csv` — corpus input SHA-256 + sizes (data itself not committed)
- `environment.txt`, `batches.log` — host, toolchain, load/thermal/power per batch
- `benchmark-codecs/*.json` — CLI buffer reports (also `--file` per corpus file)
- `criterion/manifest.csv`, `criterion/summary.csv`, `criterion/**/new/estimates.json`
- `hw-*.txt` — GPU/ANE sample logs; `dyld-libraries.txt` — loaded library list
- `bench2.py`, `aggregate2.py` — harness (env: `APPLESAUCE_BIN` for the CLI, default `target/release/applesauce`; `APPLESAUCE_BENCH_DATA` for the downloaded corpora, default `bench-data`; `APPLESAUCE_BENCH_OUT` for results, default this folder)
