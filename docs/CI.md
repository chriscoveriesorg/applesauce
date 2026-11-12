# ci-way v1 (2026-11-12)

How CI works in this repository. Same text in every repo the CI maintainer
manages; the values below are read from the live system, not from a plan.

## 1. Where CI runs

GitHub Actions on GARM runners. Nothing runs on a host: no ssh builds or tests
on claw, webclip, firestar or the Mac, and no "claw run" evidence.

Live labels (2026-11-12):

| runs-on | What it is for | Size |
|---|---|---|
| `[self-hosted, bosn]` | heavy Rust, full suites | 7 CPU, 7 GiB RAM, 20 GiB disk |
| `[self-hosted, claw-small]` | light jobs: lint, docs, scripts | 2 CPU, 3 GiB RAM, 10 GiB disk |

`bosn` runners also carry `rust`, `X64`, `Linux`, `own-ci`, and on the claw box
`claw`, `claw-rust`, `avx512`. Heavy Rust runs at most one job on claw and two
on webclip at a time; plan for the queue, not for parallelism.

There is no macOS label. macOS jobs stay where they are until a Mac runner is
accepted; do not invent a label for them.

If Actions is disabled in a repository, dispatch the workflow from an
organisation repository instead of running it by hand. A repo with no CI at all
should get a workflow here rather than a manual runbook.

## 2. How a PR lands

Merges are automatic on green, by devkit. A PR that is green at its head, based
on current main and not held, merges without anyone saying "LGTM".

The only brakes are:

- leave it a **draft**, or
- `devkit hold <repo> <pr>` — this cancels any approval at the head.

Changes that touch the box path open as drafts until their review, then land on
green like everything else. Two repositories are stricter: `devkit` and `cwf`
land only on a signed approval at the head, and fork PRs need one too.

Stale bases are refreshed first: a green on an old main is not a green.

## 3. Batches

Batching exists for the `cifast` repository only, and it is not switched on.
Until it is, every repo lands one PR at a time. When it is switched on, it
collects up to 16 PRs behind a single integration run with a six-hour deadline;
the run's checks, not each PR's own checks, are what make the batch green.

Nothing else in this repo needs to change for that, and no repo should assume a
batch exists.

## 4. Evidence

- Name the exact head sha and the run id you are relying on.
- A local run is not CI. Never call CI green because a command passed locally.
- Do not cancel or re-run someone else's run, and never by age alone.
- If a run is red, fix the head; do not re-run hoping for a different answer.

## 5. Workflow rules

- Always set `timeout-minutes` on a job.
- No `actions/cache` and no cache upload/download steps: the runner's compile
  cache is per-slot and automatic. Uploading a cache duplicates it and can
  corrupt the slot.
- Rust: set `CARGO_INCREMENTAL=0` — incremental artefacts are worthless on an
  ephemeral runner and cost time and disk.
- Set `retention-days` on every artifact upload. The account has 500 MB of free
  artifact storage in total; an unexpired artifact is storage someone else
  cannot use.
- GitHub reads go through the shared API budget: 500 calls per hour from the
  agent host. No polling loops, no scheduled watchers.
- Runners are ephemeral. Nothing you write survives the job.

## 6. Code tools

Before every push, run the pinned tools on the files you changed:

- `ruff check` and `ruff format --check` (0.17.0)
- `shellcheck` (0.9.0)
- `vulture` (2.16, with the repo's whitelist)
- `ast-grep scan` (0.50.0) — the command is `ast-grep`, never `sg`

A new finding blocks the PR. Existing findings ratchet down and are never
re-baselined upward. Python that parses outside data (JSON, TOML, API payloads,
receipts, CLI output) uses pinned pydantic v2 (2.14.0), never raw dict poking.

The PR body carries a `Tools:` line saying what you ran.

## 7. Asking for changes

Open an issue titled `CI:` in this repository. The CI maintainer picks it up.
For a new label, a bigger runner, a cache change or a workflow exception, say
what job needs what and why; do not add a runner or a workflow yourself.
