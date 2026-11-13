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
the macOS CLI is supplied), and `manifest.json`. The ten actual Apple-generated ASCF archives are retained
under `fresh-archives/`, alongside their JSON reports. The manifest records the
Applesauce Git HEAD, exact upstream commit, source-file SHA-256 values,
independent decoder binary SHA-256, optional Apple encoder CLI SHA-256, report
hashes and case totals.

`validate_second_raven_reports.py` also pins both committed archive hashes and their expected clear-content hashes, rather than accepting arbitrary digest strings. For a full run it independently reproduces the two deterministic input families and rejects replay of one family as the other. It requires the actual Apple encoder CLI binary, ten correctly sized positive results, eighteen distinct expected corruption rejections, consistent decoder hashes and negative-suite baselines tied to the corresponding positive fixtures.

For full Apple-buffer evidence, the validator now reopens each retained ASCF
archive as a bounded regular file, verifies its exact SHA-256 against the
positive report, validates the codec header, archive index, chunk lengths and
clear-content digests, and reconstructs all nine byte mutations from each
three-chunk archive. It matches their SHA-256s to the eighteen negative cases
and checks that rejection reasons came from the expected decoder or parser
gate. A copied or invented negative report cannot substitute arbitrary digest
strings. The retained archive bytes make these checks independently replayable;
only authorised macOS qualification proves their Apple encoder provenance. The manifest hashes all eight upstream C sources/headers used to build and run tests. A missing, forged, duplicated or mismatched report fails qualification.

The qualification validator requires exact fields for the committed, fresh and
negative reports. Fresh reports must retain the LZRAVEN codec ID `0xD05` and
the buffer-only scope emitted by the independent proof harness. Extra claims
about kernel decmpfs support or native-write permission are rejected. Negative
suite time budgets must be numeric, positive and no greater than 3,600 seconds.
Corruption reasons must match the exact parser error or a specific independent
decoder failure, including a nonzero numeric exit status. A report that labels
exit status zero as a rejected corruption is invalid.

All JSON reports are read from bounded, pinned regular-file descriptors, with nonblocking opens and symlink refusal. The validator rejects duplicate JSON keys at any depth, non-finite JSON literals, and oversized or replaced reports. Decoder/CLI binaries and upstream source hashes now use the same bounded no-follow file-identity checks. These controls protect evidence intake on a shared runner; they do not replace independent review or exact-head execution of the Python regression suite.

The proof bundle also includes `second-raven-decoder`, the exact built
C executable, `retained-sources/` with all eight pinned C compilation and test
inputs, and `toolchain.txt` with compiler, operating-system, Python and Git
versions. The validator's `--bundle` gate checks these retained source and
binary hashes against the files used for qualification. It also requires
bounded regular-file test logs and records SHA-256 values for all thirteen
retained artifacts in `manifest.json`. Any missing, altered, empty or
symlinked retained artifact rejects the bundle before it is accepted.
Reviewers can therefore inspect the precise executable and source snapshot
after the ephemeral job has exited. They must still assess independent source
lineage and test results; a self-consistent bundle cannot authenticate itself.

The proof runner requires `--bundle --replay` on its final validation pass.
Replay executes the retained C decoder again against both pinned committed
archives and every retained fresh archive, regenerating the deterministic
reference bytes and comparing the full observed positive reports. It reruns
all eighteen corruption cases through the bounded independent harness and
compares its actual failures with the retained negative reports. A
self-consistent JSON report cannot substitute for a successful replay.
The manifest records `replayed_decoder_vectors` (2 on portable runs, 12
with fresh macOS evidence) and `replayed_corruptions` (0 or 18). The
manifest status distinguishes replayed evidence from parsed-only reports, so
reviewers must require `second_decoder_evidence_replayed_pending_independent_review`.
Pure
evidence-parser unit tests use `validate(..., replay=False)` with synthetic
non-Raven fixtures; those tests do not qualify a decoder. The runner's
Python suite must pass before either replay or evidence publication.

The manifest describes technical evidence that an independent reviewer
can inspect. It does **not** prove source independence, binary provenance
beyond the recorded hashes, or a working native APFS handler. Native writes
remain disabled and this PR stays draft until the independent review and
owner acceptance gates are complete. No runner workflow is changed here.

## Local verification and limitations

The adapter's synthetic identity stub is deliberately *not* a Raven decoder.
On a POSIX development host, test the wrapper itself with:

    python3 -m unittest discover -s hack -p 'test_retrowave3_lzraven_cli.py' -v

The fourteen cases exercise the original eight adapter checks plus private
0600 staging, staging cleanup after a no-clobber collision, preservation of an
existing output symlink, output-parent symlink refusal, directory-path refusal
and a deterministic Linux `LD_PRELOAD` parent-rename test at the exact
`linkat` publication call. On other POSIX systems the Linux-only injection
test is skipped.

The adapter checks the opened compressed-input descriptor against its
original pathname after the bounded read, including device/inode, file length,
and nanosecond modification/change times. Same-length in-place rewrites and
same-length path replacements now fail before decoding or output publication.
This is a final-read snapshot check; mutations after that point still require
the caller's whole-archive SHA-256 and independent proof validation.

The adapter now writes and synchronizes a private, 128-bit-random stage
through an opened output-parent directory, then uses descriptor-relative
`linkat` to publish the complete output without overwriting a destination.
It checks the staged inode and output-parent identity before publication,
rechecks both the published inode and parent afterward, unlinks the verified
staging name through the pinned directory and synchronizes the directory.
Failure after publication leaves the output for inspection, avoiding deletion
of an unrelated file. An actor with write access to the output directory can
still race individual stage and destination names; this is a best-effort
defense, not a hostile-directory transaction.

These tests use an identity stub, so they establish adapter behavior only.
The pinned upstream C build, full evidence regressions, Apple-vector
cross-decoding, independent source-lineage review and macOS compatibility
still require authorised exact-head execution.

This remains **ASCF buffer-format interoperability**. It cannot establish
a native macOS APFS decmpfs type/handler mapping. Native Raven/Mesh APFS writes
remain disabled under #88. FSKit #86 stays frozen. This change makes no
filesystem writer, release or runner-policy modification.
