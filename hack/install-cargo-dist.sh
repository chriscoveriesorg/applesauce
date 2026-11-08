#!/usr/bin/env bash
# CI-only, version-pinned cargo-dist bootstrap. Keep this separate from the
# release tag helper: a failed transfer must never be treated as a release.
set -euo pipefail

version=0.33.0
url="https://github.com/axodotdev/cargo-dist/releases/download/v0.33.0/cargo-dist-installer.sh"
installer="$(mktemp "$RUNNER_TEMP/cargo-dist-installer.XXXXXXXX")"
trap 'rm -f -- "$installer"' EXIT

# Download to a complete, private file before executing. GitHub's asset CDN
# sometimes returns HTTP 504; curl retries bounded transient transfer errors.
curl --proto '=https' --tlsv1.2 --location --silent --show-error --fail \
  --retry 3 --retry-all-errors --retry-delay 2 --connect-timeout 15 \
  --max-time 120 --output "$installer" "$url"
if [[ ! -s "$installer" ]]; then
  printf 'cargo-dist installer was empty\n' >&2
  exit 1
fi

# The version-pinned installer fetches the platform archive internally. Retry
# the complete operation because a single external tarball HTTP 504 is fatal
# inside its shell script. Attempts are bounded, with no fallback version.
for attempt in 1 2 3; do
  if sh "$installer"; then
    reported="$(dist --version)" || {
      printf 'cargo-dist installer completed but dist is unavailable\n' >&2
      exit 1
    }
    if [[ ! "$reported" =~ (^|[[:space:]])0\.33\.0($|[[:space:]]) ]]; then
      printf 'cargo-dist reported an unexpected version: %s\n' "$reported" >&2
      exit 1
    fi
    printf '%s\n' "$reported"
    exit 0
  fi
  if (( attempt == 3 )); then
    printf 'cargo-dist v%s install failed after %s attempts\n' "$version" "$attempt" >&2
    exit 1
  fi
  printf 'cargo-dist install attempt %s failed; retrying pinned version\n' "$attempt" >&2
  sleep "$((attempt * 2))"
done
