# Agent instructions

## CI: the cifast way

- CI runs as GitHub Actions jobs on GARM runners only: `[self-hosted, bosn]`
  for heavy Rust (7 CPU, 7 GiB RAM, 20 GiB disk) and `[self-hosted, claw-small]`
  for light jobs (2 CPU, 3 GiB RAM, 10 GiB disk). No builds or tests on a host.
- PRs land automatically on green; only a draft or `devkit hold` stops them.
- Always set `timeout-minutes`; no `actions/cache`; `CARGO_INCREMENTAL=0` for Rust.
- Evidence is an exact-head run id. A local run is not CI.
- The full rules — batches, workflow limits, the pinned code tools, how to ask
  for a label — are in `docs/CI.md` in this repository.
