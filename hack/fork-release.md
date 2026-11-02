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
**exact SHA** has a successful `Continuous integration` run on `main`. A tag
for a different package version, or an unverified commit, stops before the
release builder starts. Inspect the release's built artifacts and checksums
afterward. A green CI job does not prove native LZRAVEN/LZMESH filesystem
decoding.

The owner can push the validated tag from a local Git checkout, after
reviewing `main` CI and the current package version:

```sh
git fetch origin main --tags
git switch main
git pull --ff-only origin main
git tag applesauce-cli/v<CLI-VERSION>
git push origin applesauce-cli/v<CLI-VERSION>
```

Replace `<CLI-VERSION>` with the actual version. The `Release` GitHub Actions
workflow builds and publishes the matching GitHub release after its gates pass.
Do not reuse an already-published version tag or force-move one.

Until a version is tagged and its release artifacts pass validation, the fork
has a **release candidate only**, regardless of how many PRs or benchmarks
have passed. Binary distribution is separate from native Raven/Mesh
qualification. See [the codec roadmap](roadmap-lzraven.md).
