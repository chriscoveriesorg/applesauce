ci-way v1 (2026-11-12)

# CI: the cifast way

Every repository in this organisation runs its CI the same way. This file is the same
text in every repo, rendered from one template against the live runner fleet, so read
it as the house rule, not as a description of this repo alone.

## 1. Where CI runs

GitHub Actions on our own GARM runners. Nothing else, ever: no builds or tests over
ssh on claw, webclip, firestar or the Mac, and no "claw run" output offered as evidence.

Live labels and sizes (2026-11-12 10:56 UTC) — read from the GARM scale sets and the incus
profiles behind them:

| `runs-on` | use it for | size | where |
|---|---|---|---|
| `[self-hosted, bosn]` | a build with a toolchain: Rust, C, node, anything that compiles | 7 CPU · 7GiB · 20 GiB root · warm compile cache | `claw-org` on `claw` (max 1) and `webclip-org` on `webclip` (max 2) |
| `[self-hosted, bosn, rust]`, `[self-hosted, bosn, avx512]`, `[self-hosted, bosn, spiderwick]` | the same runners, narrower tags; `avx512` exists only on `claw` | 7 CPU · 7GiB · 20 GiB root · warm compile cache | the same Linux sets |
| `claw-small` — that label alone, not `[self-hosted, claw-small]` | a light job that brings no toolchain | 2 CPU · 3GiB · 10 GiB root | `claw-small` on `claw` (max 2) |
| `[self-hosted, macOS, ARM64]` | macOS work, after the Mac set is accepted | 4 CPU · 12 GiB (declared) · the Mac's own disk | the Mac set (max 1) |
| `[self-hosted, own-ci]`, `[self-hosted, own-ci, spiderwick]`, `[self-hosted, own-ci, rustcite-oracle]`, `[self-hosted, docpipe]`, `[self-hosted, claw]` | repo tags that resolve to the same Linux sets as `bosn` | 7 CPU · 7GiB · 20 GiB root · warm compile cache | the same Linux sets |

Rules:

- Use the narrowest label that fits. `bosn` is the default for Linux work.
- `claw-small` is for jobs that need no toolchain of their own; it is not a place to
  put a build to make it faster.
- macOS jobs are allowed only on the Mac set, and only once it exists.
- **Public repos use GitHub-hosted runners only.** A private repo uses the sets above.
  That is the whole rule today; there is no allowance to move a public repo's job onto
  a GARM runner.
- A repo whose Actions are disabled (the cccc fork, for one) does not move its build
  to a host. It gets a `workflow_dispatch` workflow in an org repo that checks out the
  exact sha and runs the job on the same runners (cwf carries this pattern in #802),
  and the run id from that dispatch is the evidence.

## 2. How PRs land

Merging is automatic. `devkit merge-ready --go` lands a PR when its CI is green at the
head (owner, 11 Nov: "Auto merge green"). There is no review ceremony, no LGTM to wait
for, and no one has to watch the gate in order to merge.

Only two things stop a merge:

- the PR is a **draft** — that is how you say "not ready to land";
- a **`HOLD <head sha>`** comment from a trusted marker.

Green means green: a PR with no checks at all does not count, and any check that is not
a concluded success holds it. A conflicting PR is not merged; update the branch.

Two repos are `signed` rather than green today — devkit and cwf — because each one
lands the machinery (or a flow item) that would otherwise merge itself. In those two a
signed `LGTM <head sha>` at the head is also required. That is a per-repo setting in
devkit's `[merge_policy]`, not a second ceremony elsewhere, and every other repo is
`green`.

Changes that touch what runs on our boxes (a C3 change) open as drafts and are marked
ready only after the review that names their exact head sha.

## 3. Batches

Where a repo is batched, devkit merges a group of green PRs as one batch instead of one
by one, through the same single merger: a batch profile names the repository, the
member limit, a deadline and the exact jobs that must be green in each workflow. Batch
profiles are inactive until one is applied; every repo without one keeps individual
merges. cifast holds the first profile (`profiles/cifast-batch.toml`: up to 16 members,
a six-hour deadline, named jobs in `ci.yml` and `batch-go.yml`).

## 4. Evidence

- Name the **run id** at the **exact head sha**. "CI is green" without both is not a
  claim, it is a hope.
- Never offer a local run as evidence of CI. A green run is a run id that exists on
  github.com and passed at the head you pushed.
- Never cancel or re-run someone else's run, and never re-run by age alone. A stale
  green at an old sha is history, not proof.

## 5. Workflow rules

- **`timeout-minutes` on every job.** Runners are ephemeral; a job without a timeout
  can hold a slot for hours.
- **No `actions/cache` and no cache uploads.** Each runner carries its own local
  compile cache, automatically: sccache runs per runner and its slot is warm from earlier jobs on the same box, so there is nothing to upload or restore. Set `CARGO_INCREMENTAL=0` in Rust
  jobs — incremental output is not a cache hit and only fills the slot.
- **`retention-days` on every upload.** Artifact storage on the Free plan is 500 MB in
  total for the org. Keep the shortest retention that still lets you debug a failure.
- **GitHub reads are budgeted.** Our API gate allows 500 calls per hour
  per host. Read through the one shared reader, add `--revalidate` only for values you
  act on, and never poll or wait-loop.

## 6. Code tools

Before every push, run the pinned tools on the files you changed, and say so in the PR
body on a `Tools:` line:

- `ruff check` and `ruff format --check` (0.17.0);
- `shellcheck` (0.9.0) on shell;
- `vulture` (2.16), with the repo's own whitelist;
- `ast-grep scan` (0.50.0; the command is `ast-grep`, never `sg`);
- `code-tools-probe` prints the pinned versions; `/opt/code-tools/VERSIONS.tsv` lists them.

A new finding blocks the PR. Existing findings ratchet down and are never re-baselined
upward. Nothing is executed on firestar to produce this: CI is where code runs.

## 7. Asking for changes

Open an issue titled `CI:` in this repo — a new label, a bigger runner, a cache problem,
a workflow that needs a rule — and the CI maintainer picks it up from there.

---
*ci-way v1 (2026-11-12). Rendered from one shared template against the live fleet on 2026-11-12 10:56 UTC;
the same text is in every repo.*
