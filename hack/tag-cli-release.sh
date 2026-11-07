#!/usr/bin/env bash
# Owner-operated, exact-SHA tag creation for this fork. Check mode is default.
set -euo pipefail

usage() {
  echo 'usage: hack/tag-cli-release.sh VERSION 40_HEX_MAIN_SHA [--push]' >&2
  exit 2
}
[[ $# -ge 2 && $# -le 3 ]] || usage
version=$1
source_sha=$2
mode=${3:---check}
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
[[ "$source_sha" =~ ^[[:xdigit:]]{40}$ ]] || usage
[[ "$mode" == '--check' || "$mode" == '--push' ]] || usage

# This specific release has been qualified at a particular merged commit.
# Keep the pin here even if main subsequently advances at the same version.
if [[ "$version" == '0.5.31' && "$source_sha" != '1585dceb6c745cebf822588526ee5005255818c9' ]]; then
  echo 'v0.5.31 must use its qualified exact source SHA' >&2
  exit 1
fi

remote=$(git remote get-url origin)
if [[ ! "$remote" =~ (^|[:/])chriscoveriesorg/applesauce(\.git)?$ ]]; then
  echo 'origin must point to chriscoveriesorg/applesauce' >&2
  exit 1
fi

git fetch --no-tags origin main >&2
git cat-file -e "${source_sha}^{commit}"
if ! git merge-base --is-ancestor "$source_sha" refs/remotes/origin/main; then
  echo 'Requested source commit is not reachable from origin/main' >&2
  exit 1
fi

manifest=$(git show "${source_sha}:crates/applesauce-cli/Cargo.toml")
actual_version=$(printf '%s\n' "$manifest" | awk '
  /^\[package\]$/ { within_package=1; next }
  /^\[/ { within_package=0 }
  within_package && $1 == "version" && $2 == "=" {gsub(/"/, "", $3); print $3; exit}
')
if [[ "$actual_version" != "$version" ]]; then
  echo "Tagged source contains CLI version $actual_version, expected $version" >&2
  exit 1
fi

tag="applesauce-cli/v${version}"
if git show-ref --verify --quiet "refs/tags/$tag" || \
    git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
  echo "Tag $tag already exists, refusing to replace it" >&2
  exit 1
fi

runs=$(curl --fail --silent --show-error --location --retry 3 --max-time 30 \
  --header 'Accept: application/vnd.github+json' \
  "https://api.github.com/repos/chriscoveriesorg/applesauce/actions/workflows/cargo.yml/runs?head_sha=${source_sha}&event=push&per_page=100")
green=$(jq -er --arg sha "$source_sha" '[.workflow_runs[] |
  select(.head_sha == $sha and .head_branch == "main" and .event == "push" and .conclusion == "success")] | length' <<< "$runs")
if (( green < 1 )); then
  echo "No successful exact-SHA main CI for $source_sha" >&2
  exit 1
fi

printf 'Qualified %s at %s; main CI passes.\n' "$tag" "$source_sha"
if [[ "$mode" == '--push' ]]; then
  git tag "$tag" "$source_sha"
  git push origin "refs/tags/$tag"
else
  echo 'Read-only check complete. Add --push for owner-authenticated tag creation.'
fi
