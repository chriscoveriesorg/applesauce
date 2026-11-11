#!/usr/bin/env bash
# Runs on fork release builders. Uses only public GitHub API reads.
set -euo pipefail

if [[ "${GITHUB_REPOSITORY:-}" != 'chriscoveriesorg/applesauce' ]]; then
  echo 'Refusing to qualify a release outside the Applesauce fork' >&2
  exit 1
fi
if [[ ! "${GITHUB_SHA:-}" =~ ^[[:xdigit:]]{40}$ ]] ||
    [[ "${GITHUB_REF:-}" != refs/tags/* ]]; then
  echo 'Release requires a tag event with a 40-digit commit SHA' >&2
  exit 1
fi

version=$(cargo metadata --no-deps --format-version 1 | jq -er '.packages[] | select(.name == "applesauce-cli") | .version')
if [[ "${GITHUB_REF_NAME:-}" != "applesauce-cli/v$version" ]]; then
  echo "Release tag must match applesauce-cli/v$version" >&2
  exit 1
fi

# Never publish v0.5.31 from a newer main commit that still carries
# the same Cargo version. Pinning only the owner's tag helper would leave
# hand-created tags unguarded on source commits containing this check.
if [[ "${GITHUB_REF_NAME:-}" == 'applesauce-cli/v0.5.31' &&
      "$GITHUB_SHA" != '1585dceb6c745cebf822588526ee5005255818c9' ]]; then
  echo 'v0.5.31 release source must be the qualified exact commit' >&2
  exit 1
fi

# Anonymous GitHub reads keep this gate independent of write tokens/secrets.
api="https://api.github.com/repos/${GITHUB_REPOSITORY}"
compare=$(curl --fail --silent --show-error --location --retry 3 --max-time 30 \
  --header 'Accept: application/vnd.github+json' "$api/compare/${GITHUB_SHA}...main")
relation=$(jq -er '.status' <<< "$compare")
if [[ "$relation" != 'ahead' && "$relation" != 'identical' ]]; then
  echo 'Release commit must be reachable from main' >&2
  exit 1
fi

runs=$(curl --fail --silent --show-error --location --retry 3 --max-time 30 \
  --header 'Accept: application/vnd.github+json' \
  "$api/actions/workflows/cargo.yml/runs?head_sha=${GITHUB_SHA}&event=push&per_page=100")
green=$(jq -er --arg sha "$GITHUB_SHA" '[.workflow_runs[] |
  select(.head_sha == $sha and .head_branch == "main" and .event == "push" and .conclusion == "success")] | length' <<< "$runs")
if (( green < 1 )); then
  echo 'Main CI must pass on this exact commit before a fork release' >&2
  exit 1
fi

echo "Verified $GITHUB_REF_NAME from main ($GITHUB_SHA) with passing main CI"
