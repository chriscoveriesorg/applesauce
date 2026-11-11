# Native per-file auto codec: disposable APFS measurements

Measured on 9 November 2026 Sydney time (8 November UTC in the GitHub run) using the
[`xcode-27` macOS runner](https://github.com/chriscoveriesorg/applesauce/actions/runs/42536645581)
at source commit [`23f20c2`](https://github.com/chriscoveriesorg/applesauce/commit/23f20c2cb28b19d1c359fe24616918e16716f9f5).
The follow-up commit `9ce192b` only updated the README. The measurement
suite tests native stable Zlib, LZVN and LZFSE, plus per-file `auto`;
it is not evidence for native LZRAVEN or LZMESH.

The ignored benchmark in `crates/applesauce-cli/tests/native_auto.rs` generated
each input on disposable APFS storage. For every fixture and codec it measured
**four independently created files** with rotating codec execution order.
Every run invoked `compress --verify --minimum-compression-ratio 1.10`,
asserted successful native compression, then read the full logical file
through macOS and compared its contents with the generated input.
Numbers below are the observed file allocation (`on_disk_size`) and the
median total elapsed wall time, including CLI process overhead and
verification.

| Fixture | Logical bytes | Best fixed codec by allocated bytes | Best fixed allocated bytes | Auto allocated bytes | Auto median ms | Best fixed median ms | Auto time delta |
|---|---:|---|---:|---:|---:|---:|---:|
| Repeated bytes | 2,097,152 | Zlib | 4,096 | 4,096 | 10.672 | 11.425 | -6.6% |
| JSONL | 1,228,890 | LZFSE | 49,152 | 49,152 | 9.790 | 9.082 | +7.8% |
| Mixed high-entropy/repeated | 2,097,152 | Zlib | 1,052,672 | 1,052,672 | 13.025 | 12.228 | +6.5% |

Additional measured fixed-codec allocations:

| Fixture | Zlib | LZVN | LZFSE | Auto |
|---|---:|---:|---:|---:|
| Repeated | 4,096 | 16,384 | 8,192 | 4,096 |
| JSONL | 135,168 | 204,800 | 49,152 | 49,152 |
| Mixed | 1,052,672 | 2,101,248 | 2,109,440 | 1,052,672 |

On these three fixtures, auto achieved the smallest allocation observed
among fixed codecs with no more than 7.8% additional median wall time against
the best-allocation fixed-codec baseline. This is **a small synthetic sample**,
not a bound for arbitrary files. The output does not prove a statistically
significant speed difference, nor does it measure CPU time separately.
Different file compositions, disks, APFS block sizes and hosts may change
the outcome. Auto may make an inferior choice for heterogeneous data.

The `hack/native-auto-evidence.py` parser now requires every expected
fixture, codec and repeat, matching logical lengths and per-codec allocation,
positive durations and successful compressed outcomes. It now **fails
acceptance when auto allocates more bytes than the best fixed codec** on any
generated fixture, even if every trial returns successfully. This is an
allocation-only acceptance gate for the bounded fixture corpus, not a claim
that auto will win for arbitrary files. Deliberate regression fixtures
exercise the gate. The benchmark workflow now reruns after changes to any
Rust crate or workspace dependency on the feature branch, so a later codec
pipeline change cannot bypass measurement by avoiding `reader.rs`.
It emits a concise measured summary as a workflow artifact.
Acceptance still requires independent review before merging
[PR #114](https://github.com/chriscoveriesorg/applesauce/pull/114).
