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

# Refuse URL rewrite and pushurl config across all active Git scopes:
# these can redirect Git transport despite a canonical remote.origin.url.
if git config --get-regexp '^url\..*\.(insteadof|pushinsteadof)$' >/dev/null; then
  echo 'Git URL rewrites (insteadOf/pushInsteadOf) must be removed before release tagging' >&2
  exit 1
fi
if git config --get-all remote.origin.pushurl >/dev/null; then
  echo 'origin pushurl overrides must be removed before release tagging' >&2
  exit 1
fi
# --get-all rejects multiple configured origin URLs.
remote=$(git config --get-all remote.origin.url) || {
  echo 'origin must point to chriscoveriesorg/applesauce on github.com' >&2
  exit 1
}
case "$remote" in
  https://github.com/chriscoveriesorg/applesauce|\
  https://github.com/chriscoveriesorg/applesauce.git|\
  git@github.com:chriscoveriesorg/applesauce|\
  git@github.com:chriscoveriesorg/applesauce.git|\
  ssh://git@github.com/chriscoveriesorg/applesauce|\
  ssh://git@github.com/chriscoveriesorg/applesauce.git) ;;
  *) echo 'origin must point to chriscoveriesorg/applesauce on github.com' >&2; exit 1 ;;
esac
# Confirm the effective fetch and push destinations are both the single
# approved origin. Refuse overrides before any remote transport or tag change.
fetch_url=$(git remote get-url --all origin)
push_url=$(git remote get-url --push --all origin)
if [[ "$fetch_url" != "$remote" || "$push_url" != "$remote" ]]; then
  echo 'Effective origin fetch/push URL differs from configured approved origin' >&2
  exit 1
fi

# FETCH_HEAD is the main branch obtained from this network fetch. A locally
# cached refs/remotes/origin/main may be stale or remapped by an unusual
# remote.origin.fetch configuration and must not certify a release.
git fetch --no-tags origin refs/heads/main >&2
fetched_main=$(git rev-parse --verify 'FETCH_HEAD^{commit}') || {
  echo 'Could not identify the freshly fetched origin main commit' >&2
  exit 1
}
git cat-file -e "${source_sha}^{commit}"
if ! git merge-base --is-ancestor "$source_sha" "$fetched_main"; then
  echo 'Requested source commit is not reachable from freshly fetched origin main' >&2
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
if git show-ref --verify --quiet "refs/tags/$tag"; then
  echo "Tag $tag already exists locally, refusing to replace it" >&2
  exit 1
fi
# Git's --exit-code uses 2 for a confirmed absent remote ref, and 0 for
# present. A transport/auth failure (normally 128) is not evidence of absence.
remote_tag_status=0
git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null || remote_tag_status=$?
case "$remote_tag_status" in
  0) echo "Tag $tag already exists remotely, refusing to replace it" >&2; exit 1 ;;
  2) ;;
  *) echo "Unable to verify remote tag absence (git exit $remote_tag_status)" >&2; exit 1 ;;
esac

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
  if ! git push origin "refs/tags/$tag"; then
    # Leave no orphan local tag after failed authentication/transport. The
    # expected old SHA makes cleanup conditional, preserving a ref changed
    # concurrently by a different process. A push whose reply was lost may
    # have succeeded remotely; the next invocation will detect that tag.
    if ! git update-ref -d "refs/tags/$tag" "$source_sha"; then
      echo "Push failed; local tag $tag changed and needs manual inspection" >&2
    else
      echo "Push failed; removed the local tag created by this attempt" >&2
    fi
    exit 1
  fi
else
  echo 'Read-only check complete. Add --push for owner-authenticated tag creation.'
fi
