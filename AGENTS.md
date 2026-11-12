## CI: the cifast way

CI runs as GitHub Actions jobs on our own GARM runners, never over ssh on a host: use
`[self-hosted, bosn]` for anything with a toolchain and `claw-small` for light jobs.
PRs land on green automatically — a draft or a `HOLD <head sha>` is the only brake, and
a local run is never evidence of CI.
Full rules, labels and sizes: [docs/CI.md](docs/CI.md).
