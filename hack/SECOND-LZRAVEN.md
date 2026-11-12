# Second LZRAVEN decoder candidate for issue #95

## Scope and source

This is **qualification scaffolding**, not codec approval. Apple's buffer API
can generate LZRAVEN payloads, and the existing proof harness has independently
decoded those payloads with the pinned
[anat0m1a/liblzraven](https://github.com/anat0m1a/liblzraven) decoder.
A second implementation may uncover shared format mistakes.

A separate candidate is
[retrowave3/apple-compressions](https://github.com/retrowave3/apple-compressions),
pinned at commit
[6d97f1ab520821b4d326139fdf48b658f96ee5b9](https://github.com/retrowave3/apple-compressions/commit/6d97f1ab520821b4d326139fdf48b658f96ee5b9).
Its public repository declares MIT licensing, provides the independent C
entrypoint lzraven_decode_buffer, includes codec vectors and builds a C
test executable without the Apple compression framework. **These are source
observations, not reviewed evidence of independent derivation or correctness.**
An independent reviewer must examine the exact source and lineage before it
counts as a second implementation for #95, including license/provenance.

The adapter in hack/retrowave3_lzraven_decode.c accepts
--cap EXPECTED_CLEAR_BYTES INPUT OUTPUT, so the existing ASCF
proof tools can invoke it without changing archive or kernel code.
It rejects nonregular inputs, length mismatches, existing output paths,
unbounded encoded input and oversized clear lengths. Its private output is
created with no-clobber/no-follow flags. It runs only as an external
qualification executable, never as a product dependency.

## Reproduction on a disposable test runner

Run from the checkout root:

    bash hack/run_second_raven_proof.sh

The script checks out exactly the pinned upstream commit into a fresh
temporary directory, builds and runs its native unit suite, compiles the
adapter with strict C11 warnings, rejects dynamic Apple compression linkage,
runs adapter safety regressions, then independently decodes the two committed
Apple LZRAVEN ASCF fixtures with exact content and SHA-256 checks.

On a *reviewed* macOS 27 runner with the Applesauce CLI already built from the
same checkout, run:

    bash hack/run_second_raven_proof.sh "$PWD/target/debug/applesauce"

This additionally generates and verifies ten fresh Apple-buffer ASCF archives
from two deterministic content families, sizes 65,535, 65,536, 65,537,
131,103 and 262,151 bytes. The same external C decoder must restore all
bytes and match chunk/whole-file SHA-256. The existing negative qualification
harness then checks nine corruptions for each of two three-chunk archives.

**Review gate:** capture the exact checkout SHA, pinned upstream SHA,
compiler and system versions, external executable SHA-256 and positive and
negative proof reports. Require independent C source/lineage review and
review of byte-level evidence before claiming acceptance. Keep any future CI
changes with the CI maintainer under #123; do not introduce GitHub-hosted
runner labels here or silently run builds on a host.

## Offline qualification and reviewable evidence

On an approved isolated runner, reuse a source mirror without a fresh GitHub
clone. The checkout must be at exactly the pinned commit, with no tracked
changes; the script refuses a wrong revision or dirty tracked source.

    bash hack/run_second_raven_proof.sh \
      --upstream-checkout /path/to/pinned/apple-compressions \
      --evidence-dir /trusted/new-raven-proof-directory

For a full fresh Apple-buffer run on an approved macOS 27 host, add the path
to the matching checkout's executable:

    bash hack/run_second_raven_proof.sh \
      --upstream-checkout /path/to/pinned/apple-compressions \
      --evidence-dir /trusted/new-macos-proof-directory \
      "$PWD/target/debug/applesauce"

The requested evidence directory must not already exist, and its parent must
be trusted. The resulting bundle includes logs of the upstream C tests,
adapter regressions and evidence-validator regressions, JSON for the committed
vectors, ten fresh cross-decodes and two nine-case corruption suites (when
the macOS CLI is supplied), and \`manifest.json\`. The manifest records the
Applesauce Git HEAD, exact upstream commit, source-file SHA-256 values,
independent decoder binary SHA-256, optional Apple encoder CLI SHA-256, report
hashes and case totals.

\`validate_second_raven_reports.py\` checks that exactly two committed
Apple fixtures were independently decoded. For a full run it also requires
ten correctly sized positive results, eighteen distinct expected corruption
rejections, consistent decoder hashes and negative-suite baseline hashes
that match the corresponding fresh positive fixtures. A missing, forged,
duplicated or mismatched report fails qualification.

The manifest describes technical evidence that an independent reviewer
can inspect. It does **not** prove source independence, binary provenance
beyond the recorded hashes, or a working native APFS handler. Native writes
remain disabled and this PR stays draft until the independent review and
owner acceptance gates are complete. No runner workflow is changed here.

## Local verification and limitations

The adapter's synthetic identity stub is deliberately *not* a Raven decoder.
On a POSIX development host, test the wrapper itself with:

    python3 -m unittest discover -s hack -p 'test_retrowave3_lzraven_cli.py' -v

The eight cases exercise exact output, short/long decoded counts, symlink and
FIFO refusal, output no-clobber, invalid caps and oversized input. This
establishes adapter behavior only. The upstream build and Apple-vector
cross-decoding must run separately with access to the pinned source.

This remains **ASCF buffer-format interoperability**. It cannot establish
a native macOS APFS decmpfs type/handler mapping. Native Raven/Mesh APFS writes
remain disabled under #88. FSKit #86 stays frozen. This change makes no
filesystem writer, release or runner-policy modification.
