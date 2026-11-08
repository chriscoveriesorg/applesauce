#!/usr/bin/env bash
# CI-only, version-pinned cargo-dist bootstrap. Keep this separate from the
# release tag helper: a failed transfer must never be treated as a release.
set -euo pipefail

version=0.33.0
url="https://github.com/axodotdev/cargo-dist/releases/download/v0.33.0/cargo-dist-installer.sh"
installer="$(mktemp "$RUNNER_TEMP/cargo-dist-installer.XXXXXXXX")"
trap 'rm -f -- "$installer"' EXIT

# Independent GitHub API asset route for the immutable upstream v0.33.0
# release. Pin both the asset ID and its published SHA-256: an API JSON error,
# replacement asset or incomplete response must never become executable code.
# This fallback is deliberately limited to the Ubuntu x86_64 planning job.
install_pinned_asset_fallback() {
  if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
    printf 'cargo-dist asset fallback supports Linux x86_64 only\n' >&2
    return 1
  fi
  local archive binary observed
  archive="$(mktemp "$RUNNER_TEMP/cargo-dist-asset.XXXXXXXX")"
  binary="$(mktemp "$RUNNER_TEMP/cargo-dist-binary.XXXXXXXX")"
  local asset_url="https://api.github.com/repos/axodotdev/cargo-dist/releases/assets/556576992"
  local expected_sha="4b3f0a5f0ebbdb798f6db649d01b32ba1518376b6f7a0502b7d92b75cc2c8293"
  local curl_args=(--proto '=https' --tlsv1.2 --location --silent --show-error --fail
    --retry 2 --retry-all-errors --retry-delay 2 --connect-timeout 15 --max-time 120
    --header 'Accept: application/octet-stream')
  if [[ -n "${GH_TOKEN:-}" ]]; then
    curl_args+=(--header "Authorization: Bearer $GH_TOKEN")
  fi
  if ! curl "${curl_args[@]}" --output "$archive" "$asset_url"; then
    rm -f -- "$archive" "$binary"
    printf 'pinned cargo-dist GitHub API asset transfer failed\n' >&2
    return 1
  fi
  observed="$(sha256sum "$archive" | cut -d ' ' -f 1)"
  if [[ "$observed" != "$expected_sha" ]]; then
    rm -f -- "$archive" "$binary"
    printf 'pinned cargo-dist asset SHA-256 mismatch\n' >&2
    return 1
  fi
  # Never extract a tar tree into the runner. Stream exactly one regular
  # dist executable from the SHA-verified archive into a private temporary.
  if ! python3 - "$archive" "$binary" <<'PY'
import shutil
import sys
import tarfile

with tarfile.open(sys.argv[1], mode="r:xz") as archive:
    matches = [m for m in archive.getmembers() if m.name.rsplit("/", 1)[-1] == "dist"]
    if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= 128 * 1024 * 1024:
        raise SystemExit("cargo-dist asset has no unique bounded regular dist executable")
    with archive.extractfile(matches[0]) as source, open(sys.argv[2], "wb") as target:
        shutil.copyfileobj(source, target)
PY
  then
    rm -f -- "$archive" "$binary"
    return 1
  fi
  chmod 700 "$binary"
  if ! reported="$("$binary" --version)" || [[ ! "$reported" =~ (^|[[:space:]])0\.33\.0($|[[:space:]]) ]]; then
    rm -f -- "$archive" "$binary"
    printf 'pinned cargo-dist asset has unexpected or unavailable version\n' >&2
    return 1
  fi
  mkdir -p "$HOME/.cargo/bin"
  install -m 755 "$binary" "$HOME/.cargo/bin/dist"
  rm -f -- "$archive" "$binary"
  printf 'Installed SHA-verified pinned cargo-dist fallback: %s\n' "$reported"
}

# Download to a complete, private file before executing. GitHub's asset CDN
# sometimes returns HTTP 504; curl retries bounded transient transfer errors.
if ! curl --proto '=https' --tlsv1.2 --location --silent --show-error --fail \
  --retry 3 --retry-all-errors --retry-delay 2 --connect-timeout 15 \
  --max-time 120 --output "$installer" "$url"; then
  printf 'primary cargo-dist installer transfer failed; trying pinned API asset\n' >&2
  install_pinned_asset_fallback
  exit $?
fi
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
    printf 'cargo-dist v%s installer failed after %s attempts; trying pinned API asset\n' "$version" "$attempt" >&2
    install_pinned_asset_fallback
    exit $?
  fi
  printf 'cargo-dist install attempt %s failed; retrying pinned version\n' "$attempt" >&2
  sleep "$((attempt * 2))"
done
