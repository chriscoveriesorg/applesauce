#!/usr/bin/env bash
# Run only on a macOS 27.2+ machine. The probe writes generated files to a
# fresh APFS disk image and refuses to target an ordinary user volume.
set -euo pipefail

if ! command -v sw_vers >/dev/null 2>&1 || ! command -v xcrun >/dev/null 2>&1; then
  echo "This probe requires macOS with Xcode Command Line Tools." >&2
  exit 2
fi

installed_version="$(sw_vers -productVersion)"
IFS='.' read -r major minor patch <<< "$installed_version"
if (( major < 27 || (major == 27 && minor < 2) )); then
  echo "Refusing private APFS trial on macOS $installed_version; use 27.2 or newer." >&2
  echo "The read-only buffer experiment is safe to run separately on macOS 27+." >&2
  exit 2
fi

printf 'WARNING: unknown APFS compression types can crash the host kernel.\n' >&2
printf 'Use a backed-up test Mac. Only generated files will be written.\n' >&2
if [[ ! -t 0 ]]; then
  echo "An interactive terminal is required for this private API trial." >&2
  exit 2
fi
read -r -p 'Type YES to continue: ' confirmation
if [[ "$confirmation" != "YES" ]]; then
  echo "APFS trial cancelled." >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
probe_dir="$(mktemp -d "${TMPDIR:-/tmp}/applesauce-probe.XXXXXXXX")"
probe_dir="$(cd "$probe_dir" && pwd -P)"
probe_image="$probe_dir/apfs.sparseimage"
probe_mount="$probe_dir/mount"
probe_bin="$probe_dir/apfs-type-probe"
attached=0

cleanup() {
  local result=$?
  if (( attached )); then
    /usr/bin/hdiutil detach "$probe_mount" -quiet || true
  fi
  printf 'Disposable APFS image and test artifacts retained at: %s\n' "$probe_dir"
  exit "$result"
}
trap cleanup EXIT

xcrun clang -std=c11 -Wall -Wextra -Werror -framework CoreFoundation \
  "$script_dir/apfs-type-probe.c" -o "$probe_bin"

mkdir "$probe_mount"
/usr/bin/hdiutil create -size 128m -fs APFS -type SPARSE \
  -volname ApplesauceProbe "$probe_image"
/usr/bin/hdiutil attach -nobrowse -mountpoint "$probe_mount" "$probe_image"
attached=1
touch "$probe_mount/.applesauce-disposable-image"

printf 'macOS %s: probing known controls 12/14 and unverified types 15..22.\n' "$installed_version"
printf 'Tests write only generated data to the fresh disposable image.\n'
"$probe_bin" "$probe_mount"
