# Stable releases from the Applesauce fork

This fork ships **macOS binaries** through its own GitHub Releases. It does not
publish upstream-named crates to crates.io or write to Dr-Emann's Homebrew tap.
Those external release workflows remain restricted to the upstream repository.

## Stable release gate

The existing cargo-dist workflow builds ARM64 and x86_64 macOS binaries,
archives, a shell installer, SHA-256 checksums and attestations from an exact
tag:

```
applesauce-cli/v<the version in crates/applesauce-cli/Cargo.toml>
```

For this fork, the tag must point to a commit reachable from `main` whose
**exact SHA** has a successful `Continuous integration` run on `main`. The
release's custom cargo-dist build-setup step checks the version, GitHub commit
ancestry and successful push CI through the public API before either macOS
binary build. A failed builder blocks artifact hosting. Inspect checksums
afterward. A green CI job does not prove native LZRAVEN/LZMESH filesystem
decoding.

Tag creation must use the **qualified CI-green source commit**, even if
`main` has moved to a newer commit with the same CLI version. The owner runs
the fail-closed helper from the up-to-date fork checkout. The helper fetches
`origin/main`, checks commit ancestry and the CLI package version at that SHA,
requires successful exact-SHA main push CI, and rejects an existing tag.
Before any remote operation it also rejects configured Git URL rewrites
(`insteadOf`/`pushInsteadOf`), extra origin URLs and `pushurl` overrides,
and checks that the effective fetch and push destinations match the approved
GitHub origin. Remove or isolate those settings in the release checkout
rather than circumventing the guard.
Without `--push` it creates no tag.

For **v0.5.31**, the only authorized source is
`1585dceb6c745cebf822588526ee5005255818c9`:

```sh
bash hack/tag-cli-release.sh 0.5.31 1585dceb6c745cebf822588526ee5005255818c9
bash hack/tag-cli-release.sh 0.5.31 1585dceb6c745cebf822588526ee5005255818c9 --push
```

The `--push` action requires the owner's GitHub authentication. Use
the helper rather than issuing `git tag` directly. GitHub evaluates release
workflows and their guard scripts from the **tagged source commit**; the
qualified v0.5.31 commit predates the newer exact-SHA publisher check and
cannot inherit it retroactively. The owner-side helper therefore supplies
the essential exact-SHA gate before creating this historical release tag.
If it refuses, resolve the stated failure rather than bypassing the check.
Never force-move a tag.

The `Release` GitHub Actions workflow builds and publishes the matching GitHub
release after its gates pass. Binary downloadability, both macOS architectures,
installability, SHA-256 and provenance must be checked against the produced
artifacts before declaring v0.5.31 shipped.

Until a version is tagged and its release artifacts pass validation, the fork
has a **release candidate only**, regardless of how many PRs or benchmarks
have passed. Binary distribution is separate from native Raven/Mesh
qualification. See [the codec roadmap](roadmap-lzraven.md).
