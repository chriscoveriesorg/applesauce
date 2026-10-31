#!/usr/bin/env bash
# Run only on a backed-up test Mac with macOS 27.2+. Generated fixtures only.
# 27.2 is a conservative project policy, NOT evidence that it supports any ID.
set -euo pipefail

try_candidates=0
acknowledged=0
for argument in "$@"; do
  case "$argument" in
    --candidates) try_candidates=1 ;;
    --acknowledge-kernel-panic-risk) acknowledged=1 ;;
    --help|-h)
      printf 'Usage: %s [--candidates] [--acknowledge-kernel-panic-risk]\n' "$0"
      printf 'Default: known controls 12/14. --candidates additionally tries type requests 15..22.\n'
      printf 'The acknowledgement flag replaces interactive confirmation for explicitly requested trials.\n'
      exit 0
      ;;
    *) printf 'Unknown argument: %s\n' "$argument" >&2; exit 2 ;;
  esac
done

if ! command -v sw_vers >/dev/null 2>&1 || ! command -v xcrun >/dev/null 2>&1; then
  echo "This probe requires macOS with Xcode Command Line Tools." >&2
  exit 2
fi

installed_version="$(sw_vers -productVersion)"
IFS='.' read -r major minor patch <<< "$installed_version"
major=${major:-0}
minor=${minor:-0}
if [[ ! $major =~ ^[0-9]+$ || ! $minor =~ ^[0-9]+$ ]]; then
  printf 'Unrecognized macOS version: %s\n' "$installed_version" >&2
  exit 2
fi
if (( 10#$major < 27 || (10#$major == 27 && 10#$minor < 2) )); then
  echo "Refusing private APFS trial on macOS $installed_version; use 27.2 or newer." >&2
  echo "The read-only buffer experiment is safe to run separately on macOS 27+." >&2
  exit 2
fi

printf 'WARNING: private APFS compression trials can crash the HOST kernel.\n' >&2
printf 'A disk image isolates test files, NOT the host kernel. Use a backed-up test Mac.\n' >&2
printf 'The helper has a 120-second timeout; a host-kernel hang may not be interruptible.\n' >&2
printf 'Only generated data will be written. Logs and disposable images will be retained.\n' >&2
if (( try_candidates )); then
  printf 'Additional type requests 15..22 are enabled. They are NOT Raven/Mesh codec IDs.\n' >&2
else
  printf 'Only established filesystem controls 12 (LZFSE) and 14 (LZBitmap) will be requested.\n' >&2
fi
if (( ! acknowledged )); then
  if [[ ! -t 0 ]]; then
    echo "An interactive terminal or explicit --acknowledge-kernel-panic-risk is required." >&2
    exit 2
  fi
  read -r -p 'Type YES to accept the kernel-panic risk and continue: ' confirmation
  if [[ "$confirmation" != "YES" ]]; then
    echo "APFS trial cancelled." >&2
    exit 2
  fi
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/applesauce-probe.XXXXXXXX")"
probe_dir="$(cd "$probe_dir" && pwd -P)"
report_dir="$probe_dir/reports"
probe_mount=""
probe_bin="$probe_dir/apfs-type-probe"
attached=0
mkdir "$report_dir"

cleanup() {
  local result=$?
  trap - EXIT
  if (( attached )); then
    if ! /usr/bin/hdiutil detach "$probe_mount" -quiet; then
      printf 'WARNING: could not detach %s; inspect this mount manually.\n' "$probe_mount" >&2
      if (( result == 0 )); then result=1; fi
    fi
  fi
  printf 'Disposable APFS image and test artifacts retained at: %s\n' "$probe_dir"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

{
  date -u '+UTC: %Y-%m-%dT%H:%M:%SZ'
  sw_vers
  uname -srm
  xcrun --sdk macosx --show-sdk-version
  xcrun --sdk macosx --show-sdk-path
  xcrun clang --version
  # Xcode itself is optional for local runs; Command Line Tools suffice.
  xcodebuild -version || true
} 2>&1 | tee "$report_dir/environment.log"

xcrun clang -std=c11 -Wall -Wextra -Werror -framework CoreFoundation \
  "$script_dir/apfs-type-probe.c" -o "$probe_bin" 2>&1 | tee "$report_dir/compile.log"

run_trial() {
  local label=$1
  shift
  local probe_image="$probe_dir/$label.sparseimage"
  probe_mount="$probe_dir/$label-mount"
  mkdir "$probe_mount"

  /usr/bin/hdiutil create -size 128m -fs APFS -type SPARSE \
    -volname ApplesauceProbe "$probe_image" 2>&1 | tee "$report_dir/$label-mount.log"
  # Mark this before attach so cleanup also attempts to recover a partial attach.
  attached=1
  /usr/bin/hdiutil attach -nobrowse -mountpoint "$probe_mount" "$probe_image" \
    2>&1 | tee -a "$report_dir/$label-mount.log"
  touch "$probe_mount/.applesauce-disposable-image"

  "$probe_bin" --write "$@" "$probe_mount" \
    2> >(tee "$report_dir/$label-write.stderr.log" >&2) | tee "$report_dir/$label-write.tsv"

  # A true detach/reattach discards the original volume's vnode/page cache.
  # Merely closing a file, fsync, F_NOCACHE, or remounting in place is insufficient.
  /usr/bin/hdiutil detach "$probe_mount" 2>&1 | tee -a "$report_dir/$label-mount.log"
  attached=0
  mkdir -p "$probe_mount"
  attached=1
  /usr/bin/hdiutil attach -readonly -nobrowse -mountpoint "$probe_mount" "$probe_image" \
    2>&1 | tee -a "$report_dir/$label-mount.log"
  "$probe_bin" --verify "$@" "$probe_mount" \
    2> >(tee "$report_dir/$label-verify.stderr.log" >&2) | tee "$report_dir/$label-verify.tsv"

  /usr/bin/hdiutil detach "$probe_mount" 2>&1 | tee -a "$report_dir/$label-mount.log"
  attached=0
}

printf 'macOS %s: testing known controls, including verification after a read-only remount.\n' "$installed_version"
run_trial controls
if (( try_candidates )); then
  # The complete known-control remount trial must succeed before additional IDs
  # are attempted. Use a separate fresh image so files are never overwritten.
  run_trial additional-types --candidates
fi
printf 'Completed. A matching filesystem type still does not identify its codec.\n'
