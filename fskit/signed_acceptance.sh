#!/usr/bin/env bash
# Owner-run acceptance. Never writes APFS xattrs, mounted data or unknown decmpfs types.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
# Xcode links from <repo>/target/release, and packaging needs reproducible paths.
export CARGO_TARGET_DIR="$ROOT/target"
cd "$ROOT"
die() { printf 'ASCF acceptance: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }
mac_only() { test "$(uname -s)" = Darwin || die "requires a disposable macOS 27+ host"; }
usage() {
  cat <<'HELP'
Usage:
  bash fskit/signed_acceptance.sh preflight
  bash fskit/signed_acceptance.sh signed-build
  bash fskit/signed_acceptance.sh fixture [lzraven|lzmesh]
  bash fskit/signed_acceptance.sh package
  bash fskit/signed_acceptance.sh manifest-check BUNDLE_DIR
  bash fskit/signed_acceptance.sh bundle-code-check BUNDLE_DIR
  bash fskit/signed_acceptance.sh cli-mount BUNDLE_DIR lzraven|lzmesh
  bash fskit/signed_acceptance.sh bundle-readback BUNDLE_DIR MOUNT_DIR lzraven|lzmesh
  bash fskit/signed_acceptance.sh acceptance-check BUNDLE_DIR CODEC FIRST_JSON UNMOUNT_JSON REMOUNT_JSON REFUSAL_TXT REPLACEMENT_JSON
  bash fskit/signed_acceptance.sh acceptance-all BUNDLE_DIR RAVEN_5_EVIDENCE_PATHS MESH_5_EVIDENCE_PATHS
  bash fskit/signed_acceptance.sh readback SIGNED_HOST_APP MOUNT_DIR ORIGINAL
  bash fskit/signed_acceptance.sh unmounted MOUNT_DIR READBACK_JSON
  bash fskit/signed_acceptance.sh bundle-unmounted BUNDLE_DIR MOUNT_DIR READBACK_JSON
  bash fskit/signed_acceptance.sh replacement-stage BUNDLE_DIR lzraven|lzmesh
  bash fskit/signed_acceptance.sh replacement-check STAGE_DIR MOUNT_DIR ORIGINAL_JSONL

preflight: verify macOS 27+, matching SDK, local tools, unlocked
Apple Development identity and BOTH local restricted FSKit provisioning grants.
Xcode may need an interactive profile download before this read-only check.
signed-build: set ASCFSKIT_TEAM_ID to your Apple Developer Team ID, with
FSKit mount and module capabilities enabled for their respective App IDs.
The local Xcode account must already have matching provisioning profiles.
The script requires XcodeGen, Rust and the macOS 27 SDK.
fixture: creates an independent, synthetic >8 MiB original and verified ASCF.
package: builds signed host + BOTH codecs and prepares a portable acceptance
bundle with SHA-256 manifest, its own verifier, and negative fixtures.
manifest-check: independently verify all critical bundle bytes and coverage
before installation; does not require signing or attempt to mount anything.
bundle-code-check: authenticate the manifest and require that this invoked
helper has EXACTLY the same bytes as the manifest-covered packaged helper.
A mismatched repository checkout must not certify the signed package.
cli-mount: on an authorized disposable Mac with the signed extension installed
and enabled, ask macOS FSKit to mount one authenticated synthetic archive into
a fresh, private /private/tmp mount directory using the system mount command.
It then verifies actual read-only ascf VFS identity, SHA-256 and random reads.
This alternate Terminal route never uses sudo, overwrites a path, or unmounts.
If macOS rejects the filesystem or privileges, preserve diagnostics and use
the host UI route. Finder acceptance remains a separate bundle-readback step.
bundle-readback: verify the portable bundle manifest, signed host, restored
filename, full logical SHA-256, random reads, Finder copy/readback and FSKit mount identity.
readback: checks signed host + extension provisioned capabilities and runs
actual statfs, SHA-256, unaligned reads, EOF, Finder-copied byte comparison and denied write-open acceptance.
unmounted: after normal host/Finder unmount, independently inspect Darwin's
complete kernel mount table. Refuse relocated/still-mounted ASCF volumes,
reused mountpoints and untrusted first-readback evidence.
acceptance-check: validate a complete two-mount and corruption-control evidence
chain for one codec, with signed bundle and source hashes checked first.
acceptance-all: require BOTH codec lifecycles, matching logical bytes and macOS
build, and four independent readback IDs before claiming joint acceptance.
Each command uses a new temporary directory and preserves existing data.
Only the explicit cli-mount command performs a real, synthetic-file FSKit
mount into a fresh private directory. Other commands never initiate mounts.
No installation, elevation, forced unmount or APFS writes are automated.
replacement-stage creates private synthetic /tmp archive copies. replacement-check
only atomically replaces the copy after real mounted readback.
HELP
}
# Fail early with a useful local diagnosis before compiling Rust or creating
# signed build artifacts. The actual entitlement/profile grant is independently
# checked against the finished bundles by verify_host().
signing_preflight() {
  mac_only
  local tool product major sdk sdk_major team identity
  for tool in cargo rustc xcodegen xcodebuild xcrun codesign security python3 shasum ditto git; do
    need "$tool"
  done
  product="$(/usr/bin/sw_vers -productVersion)" || die "cannot read macOS version"
  major="${product%%.*}"
  [[ "$major" =~ ^[0-9]+$ ]] && (( 10#$major >= 27 )) \
    || die "macOS 27+ required for Raven/Mesh mounted acceptance (found $product)"
  sdk="$(xcrun --sdk macosx --show-sdk-version)" || die "macOS SDK unavailable in active Xcode"
  sdk_major="${sdk%%.*}"
  [[ "$sdk_major" =~ ^[0-9]+$ ]] && (( 10#$sdk_major >= 27 )) \
    || die "macOS 27+ SDK required for FSClient mountSingleVolume (found $sdk)"
  team="${ASCFSKIT_TEAM_ID:-}"
  [[ "$team" =~ ^[A-Z0-9]{10}$ ]] \
    || die "export ASCFSKIT_TEAM_ID as the provisioned 10-character Apple Developer Team ID"
  identity="$(/usr/bin/python3 "$ROOT/fskit/signing_profile.py" --preflight-identity "$team")" \
    || die "no available Apple Development signing identity for team $team; install/unlock its certificate before signed-build"
  # macOS FSKit capabilities are restricted: a usable signing identity by
  # itself does not supply the host mount and extension fsmodule grants.
  # Catch missing/expired local profiles before a long Rust/Xcode build.
  /usr/bin/python3 "$ROOT/fskit/signing_profile.py" --preflight-profiles "$team" \
    || die "missing restricted FSKit provisioning profile(s); create/download both App ID profiles in Xcode and rerun preflight"
  printf 'Signing preflight: macOS %s, SDK %s, developer team %s, signing identity %s, tools and local profile grants present.\n' \
    "$product" "$sdk" "$team" "$identity"
  printf 'Signed binaries and embedded profile grants will be independently verified after the build.\n'
}
# Signed-source SHA alone cannot identify the build toolchain. Pin the
# compiler, SDK and generator executable used to build the signed package.
# Package compares this witness before and after building.
record_build_tools() {
  local generator
  printf 'cargo: '; cargo --version || return 1
  printf 'rustc:\n'; rustc --version --verbose || return 1
  printf 'Xcode:\n'; xcodebuild -version || return 1
  printf 'macOS SDK: '; xcrun --sdk macosx --show-sdk-version || return 1
  generator="$(command -v xcodegen)" || return 1
  test -f "$generator" || return 1
  printf 'XcodeGen executable SHA-256: '
  /usr/bin/shasum -a 256 "$generator" | /usr/bin/awk '{print $1}' || return 1
  # Include exact compiler bytes, PATH resolution and inherited build flags.
  # Environment VALUES are hashed to avoid leaking local paths in the bundle.
  printf 'Resolved compiler and build environment witness:\n'
  /usr/bin/python3 "$ROOT/fskit/build_toolchain.py" --record || return 1
}
verify_bundle() {
  local bundle="$1" key="$2" name="$3" out="$4" helper_root="${5:-$ROOT}"
  test -d "$bundle" || die "missing bundle: $bundle"
  /usr/bin/codesign --verify --strict --verbose=2 "$bundle" \
    > "$out/$name.signature-check.log" 2>&1 || die "$name code signature invalid"
  /usr/bin/codesign -d --entitlements :- "$bundle" \
    > "$out/$name.entitlements.plist" 2> "$out/$name.codesign.log" \
    || die "cannot inspect signed $name entitlements"
  local profile="$bundle/Contents/embedded.provisionprofile"
  test -f "$profile" || die "$name missing provisioning profile"
  /usr/bin/security cms -D -i "$profile" \
    > "$out/$name.provisioning.plist" || die "$name invalid provisioning profile"
  # codesign and CMS have already checked the cryptographic envelopes.
  # Bind each provisioning profile to the actual code-signing team, bundle
  # identifier, nonexpired grant and restricted FSKit entitlement.
  /usr/bin/codesign -dv --verbose=4 "$bundle" > "$out/$name.identity.txt" 2>&1 \
    || die "cannot inspect $name signing identity"
  local signing_team bundle_id
  signing_team="$(/usr/bin/sed -n 's/^TeamIdentifier=//p' "$out/$name.identity.txt" | /usr/bin/head -n 1)"
  bundle_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$bundle/Contents/Info.plist")" \
    || die "$name signed bundle identifier unavailable"
  /usr/bin/python3 "$helper_root/fskit/signing_profile.py" \
    "$out/$name.entitlements.plist" "$out/$name.provisioning.plist" \
    "$key" "$name" "$signing_team" "$bundle_id" \
    || die "$name code signature and provisioning profile disagree"
}
verify_host() {
  local host="$1" out="$2" helper_root="${3:-$ROOT}"
  verify_bundle "$host" com.apple.developer.fskit.mount host "$out" "$helper_root"
  verify_bundle "$host/Contents/Extensions/ASCFExtension.appex" \
    com.apple.developer.fskit.fsmodule extension "$out" "$helper_root"
  local extension="$host/Contents/Extensions/ASCFExtension.appex"
  /usr/bin/codesign -dv --verbose=4 "$host" > "$out/host.identity.txt" 2>&1
  /usr/bin/codesign -dv --verbose=4 "$extension" > "$out/extension.identity.txt" 2>&1
  # Entitlements alone are not product identity. Refuse a different signed
  # extension or a host/extension signed by different developer teams.
  local host_id extension_id host_team extension_team
  host_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$host/Contents/Info.plist")" \
    || die "signed host bundle identifier unavailable"
  extension_id="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$extension/Contents/Info.plist")" \
    || die "signed extension bundle identifier unavailable"
  test "$host_id" = "org.chriscoveries.applesauce.ascfhost" \
    || die "unexpected signed host bundle ID: $host_id"
  test "$extension_id" = "$host_id.ascfextension" \
    || die "extension is not the ASCF module belonging to the signed host: $extension_id"
  # macOS FSKit discovery can reject a correctly signed extension whose
  # built Info.plist omits the activation-option grammar. Check the ACTUAL
  # installed artifact, not just the source template.
  local extension_plist actual_syntax
  extension_plist="$extension/Contents/Info.plist"
  actual_syntax="$(/usr/libexec/PlistBuddy -c \
    'Print :EXAppExtensionAttributes:FSActivateOptionSyntax:shortOptions' "$extension_plist")" \
    || die "signed FSKit extension missing FSActivateOptionSyntax.shortOptions"
  test "$actual_syntax" = "g:m:o:u:" \
    || die "signed FSKit extension has unexpected FSActivateOptionSyntax: $actual_syntax"
  test "$(/usr/libexec/PlistBuddy -c \
    'Print :EXAppExtensionAttributes:FSShortName' "$extension_plist")" = "ascf" \
    || die "signed FSKit extension is not registered with short name ascf"
  host_team="$(/usr/bin/sed -n 's/^TeamIdentifier=//p' "$out/host.identity.txt" | /usr/bin/head -n 1)"
  extension_team="$(/usr/bin/sed -n 's/^TeamIdentifier=//p' "$out/extension.identity.txt" | /usr/bin/head -n 1)"
  test -n "$host_team" && test "$host_team" != "not set" \
    || die "signed host lacks an Apple Developer team identity"
  test "$extension_team" = "$host_team" \
    || die "signed extension and host have different developer team identities"
  printf 'Verified bundle IDs: %s / %s; signing team: %s\n' \
    "$host_id" "$extension_id" "$host_team" > "$out/host-extension-identity.txt"
}
# Critical bundle members must all be covered by the portable manifest.
# Code signing validates each bundle internally; these hashes additionally
# bind the signed binaries and provisioning profiles to the source handoff.
required_manifest_paths() {
  cat <<'PATHS'
source.lzmesh.jsonl
source.lzraven.jsonl
source.lzmesh.ascf
source.lzraven.ascf
source.lzmesh.corrupt.ascf
source.lzraven.corrupt.ascf
source-provenance.txt
macos.txt
build-tools.txt
NEXT-STEPS.txt
fskit/signed_acceptance.sh
fskit/verify_mount.py
fskit/finder_mount_witness.py
fskit/unmount_acceptance.py
fskit/acceptance_evidence.py
fskit/signing_profile.py
fskit/source_provenance.py
fskit/build_toolchain.py
fskit/replacement_acceptance.py
fskit/finder_readback.applescript
ASCFHost.app/Contents/Info.plist
ASCFHost.app/Contents/MacOS/ASCFHost
ASCFHost.app/Contents/embedded.provisionprofile
ASCFHost.app/Contents/_CodeSignature/CodeResources
ASCFHost.app/Contents/Extensions/ASCFExtension.appex/Contents/Info.plist
ASCFHost.app/Contents/Extensions/ASCFExtension.appex/Contents/MacOS/ASCFExtension
ASCFHost.app/Contents/Extensions/ASCFExtension.appex/Contents/embedded.provisionprofile
ASCFHost.app/Contents/Extensions/ASCFExtension.appex/Contents/_CodeSignature/CodeResources
PATHS
}
verify_package_manifest() {
  local bundle="$1" out="$2"
  test -f "$bundle/SHA256SUMS" || die "bundle SHA256SUMS missing"
  # Validate the manifest BEFORE shasum -c processes any filenames. Only
  # packaged members may be read. Extra entries, duplicates and any symlink
  # along a member's path could otherwise redirect verification outside the
  # selected portable bundle, even with a matching SHA-256.
  need python3
  test ! -L "$bundle/SHA256SUMS" || die "symlinked SHA256SUMS manifest"
  # Copy before validation so shasum checks the identical reviewed list.
  # All callers use their own mode-0700 staging/evidence directory.
  /bin/cp "$bundle/SHA256SUMS" "$out/SHA256SUMS.checked" \
    || die "cannot snapshot bundle SHA256SUMS"
  ASCF_REQUIRED_PATHS="$(required_manifest_paths)" \
    /usr/bin/python3 - "$bundle" "$out/SHA256SUMS.checked" <<'PY' \
    || die "bundle SHA256SUMS has unsafe, missing or unexpected members"
import os
from pathlib import Path, PurePosixPath
import re
import sys

root = Path(sys.argv[1])
expected = set(os.environ["ASCF_REQUIRED_PATHS"].splitlines())
manifest = Path(sys.argv[2])
if not expected:
    sys.exit("missing expected files or symlinked manifest")
seen = set()
for line in manifest.read_text(encoding="utf-8").splitlines():
    # Our packager emits only ordinary two-space shasum records.
    match = re.fullmatch(r"[0-9a-fA-F]{64}  (.+)", line)
    if not match:
        sys.exit("noncanonical SHA256SUMS entry")
    member = match.group(1)
    path = PurePosixPath(member)
    if (member not in expected or member in seen or path.is_absolute()
            or any(part in (".", "..") for part in path.parts)):
        sys.exit("unexpected or duplicate SHA256SUMS path: " + member)
    cursor = root
    for component in path.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            sys.exit("symlink in signed bundle member: " + member)
    if not cursor.is_file():
        sys.exit("missing regular bundle member: " + member)
    seen.add(member)
if seen != expected:
    sys.exit("bundle manifest omits required members")
PY
  # Verify exactly the checked snapshot, then discard our temporary copy.
  (cd "$bundle" && /usr/bin/shasum -a 256 -c "$out/SHA256SUMS.checked") \
    > "$out/manifest-verified.log" 2>&1 \
    || die "bundle hash verification failed; see $out/manifest-verified.log"
  /bin/rm -f "$out/SHA256SUMS.checked"
}
# A bundle is self-contained, and its manifest authenticates the actual
# verifier scripts. When invoked from a checkout with a different version of
# the helper, fail before running acceptance so a report cannot be attributed
# to signed packaged code while executing a different implementation.
require_matching_bundle_helper() {
  local bundle="$1"
  test -f "$bundle/fskit/signed_acceptance.sh" \
    && test ! -L "$bundle/fskit/signed_acceptance.sh" \
    || die "bundled acceptance helper missing or symlinked"
  /usr/bin/cmp -s "$ROOT/fskit/signed_acceptance.sh" "$bundle/fskit/signed_acceptance.sh" \
    || die "acceptance helper differs from signed bundle; run the bundle's fskit/signed_acceptance.sh instead"
}
# Stamp successful mounted readbacks with unique run identities. The
# unmount verifier binds to that exact first readback; a reused JSON report
# cannot masquerade as evidence of a second, independent remount.
# A Finder copy can outlive the mount that produced the first POSIX readback.
# Recheck real VFS identity after Finder returns before stamping the evidence.
stamp_readback() {
  test "$#" -eq 4 || die "stamp_readback needs FIRST_JSON SECOND_JSON FINDER_COPY HELPER"
  /usr/bin/python3 "$4" --first "$1" --after "$2" --copy "$3" \
    || die "Finder copy-out and signed FSKit mount identity could not be bound"
}

if test "$#" -eq 0; then usage; exit 2; fi
case "$1" in
  preflight)
    test "$#" -eq 1 || die "preflight takes no arguments"
    signing_preflight
    ;;
  manifest-paths)
    # Stable machine-readable list for the handoff validator's CI regression.
    test "$#" -eq 1 || die "manifest-paths takes no arguments"
    required_manifest_paths
    ;;
  manifest-check)
    test "$#" -eq 2 || die "manifest-check requires BUNDLE_DIR"
    # SHA-256 authentication is portable. Allow independent verification of
    # a signed Mac-generated handoff on Linux, including before transfer.
    need shasum
    test -d "$2" || die "missing bundle directory: $2"
    out="$(mktemp -d /tmp/ascf-manifest-check.XXXXXXXX)"
    verify_package_manifest "$(cd "$2" && pwd -P)" "$out"
    printf 'Verified mandatory signed-handoff bundle bytes; evidence: %s\n' "$out"
    ;;
  bundle-code-check)
    test "$#" -eq 2 || die "bundle-code-check requires BUNDLE_DIR"
    need shasum
    test -d "$2" || die "missing bundle directory: $2"
    bundle="$(cd "$2" && pwd -P)"
    out="$(mktemp -d /tmp/ascf-bundle-code.XXXXXXXX)"
    verify_package_manifest "$bundle" "$out"
    require_matching_bundle_helper "$bundle"
    printf 'Verified manifest-covered bundle and matching executable acceptance helper; evidence: %s\n' "$out"
    ;;
  cli-mount)
    test "$#" -eq 3 || die "cli-mount requires BUNDLE_DIR lzraven|lzmesh"
    mac_only
    test "${EUID:-$(id -u)}" -ne 0 \
      || die "cli-mount refuses root; use a normal account on a disposable Mac"
    codec="$3"
    case "$codec" in lzraven|lzmesh) ;; *) die "invalid codec";; esac
    for t in python3 shasum codesign security; do need "$t"; done
    test -x /sbin/mount || die "system mount command unavailable"
    test -d "$2" || die "missing bundle directory: $2"
    bundle="$(cd "$2" && pwd -P)"
    archive="$bundle/source.$codec.ascf"
    original="$bundle/source.$codec.jsonl"
    test -f "$archive" && test ! -L "$archive" \
      && test -f "$original" && test ! -L "$original" \
      || die "synthetic source or archive is absent or a symlink"
    # Only the freshly created mount directory is ever passed to mount(8).
    # There is no user-selected destination, sudo, forced unmount or APFS
    # attribute operation. Keep the directory and logs if a real mount fails.
    out="$(mktemp -d /private/tmp/ascf-cli-mount.XXXXXXXX)" \
      || die "cannot allocate private CLI mount stage"
    /bin/mkdir "$out/mount"
    verify_package_manifest "$bundle" "$out"
    require_matching_bundle_helper "$bundle"
    verify_host "$bundle/ASCFHost.app" "$out" "$bundle"
    /usr/bin/sw_vers > "$out/macos.txt"
    /sbin/mount > "$out/mounts-before.txt"
    # -F selects the registered FSKit module, avoiding mount_ascf helper
    # lookup. -k refuses a substituted symlink at the private mountpoint;
    # -r requests a kernel-level read-only VFS mount independently of the
    # extension's requestedMountOptions. Never retry without these flags.
    printf '/sbin/mount -F -k -r -t ascf %q %q\n' "$archive" "$out/mount" \
      > "$out/mount-command.txt"
    if ! /sbin/mount -F -k -r -t ascf "$archive" "$out/mount" \
        > "$out/mount-command.log" 2>&1; then
      die "FSKit Terminal mount failed; see $out/mount-command.txt and $out/mount-command.log. Check extension activation/permissions; the host UI remains available."
    fi
    /sbin/mount > "$out/mounts-after.txt"
    if ! /usr/bin/python3 "$bundle/fskit/verify_mount.py" \
        --mount "$out/mount" --original "$original" > "$out/terminal-readback.json"; then
      die "a mount exists but failed real ASCF read-only/SHA-256/random-read acceptance; inspect $out and unmount the private stage normally"
    fi
    cat "$out/terminal-readback.json"
    printf 'CLI-mounted ASCF: %s\nEvidence: %s\n' "$out/mount" "$out"
    printf 'Finder copy-out proof: bash fskit/signed_acceptance.sh bundle-readback %q %q %q\n' \
      "$bundle" "$out/mount" "$codec"
    printf 'After acceptance, unmount ONLY this private stage: /sbin/umount %q\n' "$out/mount"
    ;;
  package)
    test "$#" -eq 1 || die "package takes no arguments"
    mac_only
    for t in cargo shasum ditto python3 git; do need "$t"; done
    # Snapshot the exact source revision before building. Untracked Swift/Rust
    # inputs are as dangerous to provenance as modified tracked files.
    source_sha="$(/usr/bin/python3 "$ROOT/fskit/source_provenance.py" --check "$ROOT")" \
      || die "package requires a clean, fully tracked checkout"
    # Explicit single-command handoff. Every input is generated from synthetic
    # data. A signed app is copied intact, preserving its embedded extension.
    out="$(mktemp -d /tmp/ascf-acceptance.XXXXXXXX)"
    record_build_tools > "$out/build-tools.txt" \
      || die "could not capture Cargo, Rust, Xcode SDK and generator toolchain provenance"
    host_log="$out/signed-build.log"
    if ! bash "$ROOT/fskit/signed_acceptance.sh" signed-build > "$host_log" 2>&1; then
      die "signed build failed; full diagnostics: $host_log"
    fi
    built="$(/usr/bin/awk '/^Signed host: / {sub(/^Signed host: /, ""); print; exit}' "$host_log")"
    test -d "$built" || die "signed-build did not produce an app; see $host_log"
    /usr/bin/ditto "$built" "$out/ASCFHost.app"
    verify_host "$out/ASCFHost.app" "$out"
    reference_sha=""
    for codec in lzmesh lzraven; do
      log="$out/$codec.fixture.log"
      if ! bash "$ROOT/fskit/signed_acceptance.sh" fixture "$codec" > "$log" 2>&1; then
        die "$codec fixture failed; details: $log"
      fi
      original="$(/usr/bin/awk '/^Original: / {sub(/^Original: /, ""); print; exit}' "$log")"
      archive="$(/usr/bin/awk '/^ASCF: / {sub(/^ASCF: /, ""); print; exit}' "$log")"
      test -f "$original" && test -f "$archive" || die "$codec fixture paths missing; see $log"
      checksum="$(/usr/bin/shasum -a 256 "$original" | /usr/bin/awk '{print $1}')"
      if test -n "$reference_sha" && test "$checksum" != "$reference_sha"; then
        die "independent generated fixture sources disagree"
      fi
      reference_sha="$checksum"
      /bin/cp "$original" "$out/source.$codec.jsonl"
      /bin/cp "$archive" "$out/source.$codec.ascf"
      # Damage precisely one payload byte in a NEW COPY. The header and
      # index remain parseable, making this a genuine decode/digest refusal
      # test instead of only a magic-header failure.
      /usr/bin/python3 - "$out/source.$codec.ascf" "$out/source.$codec.corrupt.ascf" <<'PY'
import struct
import sys
from pathlib import Path
source = Path(sys.argv[1]).read_bytes()
assert source[:8] == b"ASCF0001"
offset, stored = struct.unpack_from("<QI", source, 64)
assert stored > 0 and 112 <= offset < len(source)
assert offset + stored <= len(source)
damaged = bytearray(source)
damaged[offset] ^= 0x80
Path(sys.argv[2]).write_bytes(damaged)
PY
      if "$ROOT/target/release/applesauce" archive verify "$out/source.$codec.corrupt.ascf" \
        > "$out/$codec.corrupt-refusal.log" 2>&1; then
        die "$codec corrupted payload unexpectedly passed archive verification"
      fi
    done
    # The owner can run acceptance from the copied bundle without cloning
    # this repository or installing a Rust toolchain on the destination Mac.
    /bin/mkdir "$out/fskit"
    /bin/cp "$ROOT/fskit/signed_acceptance.sh" "$out/fskit/signed_acceptance.sh"
    /bin/cp "$ROOT/fskit/verify_mount.py" "$out/fskit/verify_mount.py"
    /bin/cp "$ROOT/fskit/finder_mount_witness.py" "$out/fskit/finder_mount_witness.py"
    /bin/cp "$ROOT/fskit/unmount_acceptance.py" "$out/fskit/unmount_acceptance.py"
    /bin/cp "$ROOT/fskit/acceptance_evidence.py" "$out/fskit/acceptance_evidence.py"
    /bin/cp "$ROOT/fskit/signing_profile.py" "$out/fskit/signing_profile.py"
    /bin/cp "$ROOT/fskit/source_provenance.py" "$out/fskit/source_provenance.py"
    /bin/cp "$ROOT/fskit/build_toolchain.py" "$out/fskit/build_toolchain.py"
    /bin/cp "$ROOT/fskit/replacement_acceptance.py" "$out/fskit/replacement_acceptance.py"
    /bin/cp "$ROOT/fskit/finder_readback.applescript" "$out/fskit/finder_readback.applescript"
    /usr/bin/python3 "$out/fskit/verify_mount.py" --self-test \
      > "$out/portable-verifier-tests.log" 2>&1 \
      || die "packaged verifier self-tests failed; see $out/portable-verifier-tests.log"
    /usr/bin/python3 "$out/fskit/finder_mount_witness.py" --self-test \
      > "$out/finder-witness-tests.log" 2>&1 \
      || die "packaged Finder mount witness self-tests failed; see $out/finder-witness-tests.log"
    /usr/bin/python3 "$out/fskit/unmount_acceptance.py" --self-test \
      > "$out/portable-unmount-tests.log" 2>&1 \
      || die "packaged kernel unmount tests failed; see $out/portable-unmount-tests.log"
    /usr/bin/python3 "$out/fskit/acceptance_evidence.py" --self-test \
      > "$out/portable-evidence-tests.log" 2>&1 \
      || die "packaged evidence self-tests failed; see $out/portable-evidence-tests.log"
    /usr/bin/python3 "$out/fskit/signing_profile.py" --self-test \
      > "$out/signing-profile-tests.log" 2>&1 \
      || die "packaged signing-profile self-tests failed; see $out/signing-profile-tests.log"
    /usr/bin/python3 "$out/fskit/source_provenance.py" --self-test \
      > "$out/source-provenance-tests.log" 2>&1 \
      || die "packaged source-provenance tests failed; see $out/source-provenance-tests.log"
    /usr/bin/python3 "$out/fskit/build_toolchain.py" --self-test \
      > "$out/build-toolchain-tests.log" 2>&1 \
      || die "packaged build-toolchain tests failed; see $out/build-toolchain-tests.log"
    /usr/bin/python3 "$out/fskit/replacement_acceptance.py" --self-test \
      > "$out/replacement-tests.log" 2>&1 \
      || die "packaged replacement-control tests failed; see $out/replacement-tests.log"
    # Carry the exact clean source commit; the manifest authenticates the
    # signed binaries, app/extension provisioning and all test scripts.
    # The build must still belong to the exact SHA observed before signing.
    /usr/bin/python3 "$ROOT/fskit/source_provenance.py" --check "$ROOT" \
      --expected-sha "$source_sha" > "$out/source-check-before-manifest.txt" \
      || die "source tree or HEAD changed during signed build"
    printf 'repository=chriscoveriesorg/applesauce\ncommit=%s\n' \
      "$source_sha" > "$out/source-provenance.txt"
    /usr/bin/sw_vers > "$out/macos.txt"
    record_build_tools > "$out/.build-tools-final.txt" \
      || die "could not recheck signed-build toolchain provenance"
    /usr/bin/cmp -s "$out/build-tools.txt" "$out/.build-tools-final.txt" \
      || die "signed-build toolchain changed during packaging; reject provenance"
    /bin/rm "$out/.build-tools-final.txt"
    cat > "$out/NEXT-STEPS.txt" <<'STEPS'
These files are synthetic. Preserve the originals and the signed app.
1. Copy this entire folder onto an authorized disposable macOS 27+ Mac.
2. Install ASCFHost.app and enable its extension in System Settings >
   General > Login Items & Extensions > File System Extensions.
   For a second Terminal-driven FSKit mount path, run:
   bash fskit/signed_acceptance.sh cli-mount . lzmesh
   It uses a NEW private /private/tmp mountpoint and proves actual ascf
   read-only statfs, logical SHA-256, random reads and EOF. It prints the
   exact Finder-check and normal unmount commands; never run with sudo.
   If CLI dispatch is unavailable, retain its diagnostic and use the host UI.
3. Launch the host and mount source.lzmesh.ascf, then from THIS folder run:
   bash fskit/signed_acceptance.sh bundle-readback . "/Volumes/Applesauce ASCF" lzmesh
4. Unmount using host/Finder. Confirm it with the resulting readback.json:
   bash fskit/signed_acceptance.sh bundle-unmounted . "/Volumes/Applesauce ASCF" /path/to/readback.json
   Then remount and repeat bundle-readback.
5. Repeat steps 3-4 with source.lzraven.ascf and codec lzraven.
6. In ASCFHost choose "Test corrupted archive mount refusal" and select
   source.lzmesh.corrupt.ascf. Use "Copy mount diagnostic" to save the result.
   Repeat for source.lzraven.corrupt.ascf. A returned mount is a hard failure.
   Require CORRUPT_REFUSAL_CONFIRMED with FSKit resourceDamaged for
   each fixture. The copied diagnostic must include sha256=<digest> for
   the exact manifest-covered corrupted archive. Any missing/mismatched hash
   fails acceptance. CORRUPT_REFUSAL_INCONCLUSIVE means diagnose provisioning,
   permissions, sandbox or activation before claiming corruption refusal.
   Keep the signed host diagnostic and the unchanged ASCF mount listing.
7. After normally unmounting, stage an independent archive-replacement test:
   bash fskit/signed_acceptance.sh replacement-stage . lzmesh
   Select the EXACT generated /tmp/.../source.lzmesh.<16-hex>.ascf
   COPY printed by replacement-stage in the signed host. The unique archive
   basename must become the mounted restored filename. A bundle-fixture
   mount cannot certify this separate replacement control.
   Once mounted, run:
   bash fskit/signed_acceptance.sh replacement-check STAGE_DIR "/Volumes/Applesauce ASCF" ./source.lzmesh.jsonl
   The report binds the nonce, archive filename, restored filename and
   signed bundle digests. Preserve replacement.json and unmount normally.
   Repeat for lzraven. Only the private synthetic /tmp copy is replaced.
   Any cached read or unrelated permission failure blocks acceptance.
8. For each codec, run acceptance-check with first readback.json,
   unmounted.json, remount readback.json, the CORRUPT_REFUSAL_CONFIRMED
   diagnostic and replacement.json.
   Run acceptance-all with both five-file evidence groups (Raven then Mesh).
   Preserve the combined acceptance.json and the individual reports for review.
The bundle hashes the signed host and extension binaries and provisioning
profiles alongside every fixture and verifier; source-provenance.txt records
the clean source commit. build-tools.txt captures compiler, SDK and XcodeGen
identity across the signed build. Rust is not needed on the receiving Mac.
Keep the signed readback, unmount, mount, and rejection evidence.
No data on the target Mac is automatically mounted or overwritten.
STEPS
    # Authenticate operator instructions and recorded build OS too. Hash
    # after ALL mandatory members have been created, then verify in place.
    (cd "$out" && required_manifest_paths | while IFS= read -r path; do
      /usr/bin/shasum -a 256 "$path"
    done > SHA256SUMS)
    verify_package_manifest "$out" "$out"
    /usr/bin/python3 "$ROOT/fskit/source_provenance.py" --check "$ROOT" \
      --expected-sha "$source_sha" > "$out/source-check-final.txt" \
      || die "source tree or HEAD changed while packaging signed evidence"
    printf 'Signed acceptance bundle: %s\nSource SHA: %s\nSHA-256: %s/SHA256SUMS\n' \
      "$out" "$source_sha" "$out"
    ;;
  signed-build)
    test "$#" -eq 1 || die "signed-build takes no arguments"
    signing_preflight
    # A standalone signed-build must meet the same source/toolchain integrity
    # contract as package. Otherwise its printed "Signed host" path could be
    # mistaken for a reproducible artifact built from uncommitted local bytes.
    source_sha="$(/usr/bin/python3 "$ROOT/fskit/source_provenance.py" --check "$ROOT")" \
      || die "signed-build requires a clean, fully tracked source checkout"
    team="${ASCFSKIT_TEAM_ID}"
    out="$(mktemp -d /tmp/ascf-signed.XXXXXXXX)"
    printf 'repository=chriscoveriesorg/applesauce\ncommit=%s\n' \
      "$source_sha" > "$out/source-provenance.txt"
    record_build_tools > "$out/build-tools.txt" \
      || die "cannot attest signed-build tools and compiler environment"
    cargo build --locked --release -p applesauce-fskit-bridge
    xcodegen generate --spec fskit/project.yml
    xcodebuild -project fskit/ApplesauceASCF.xcodeproj \
      -scheme ASCFHost -configuration Release \
      -destination 'generic/platform=macOS' \
      -derivedDataPath "$out/DerivedData" \
      CODE_SIGNING_ALLOWED=YES CODE_SIGN_STYLE=Automatic \
      DEVELOPMENT_TEAM="$team" CODE_SIGN_IDENTITY='Apple Development' \
      build 2>&1 | tee "$out/xcodebuild.log"
    # Reinspect after BOTH Rust and Xcode generation/compilation. Package
    # later repeats this at its own final manifest boundary.
    /usr/bin/python3 "$ROOT/fskit/source_provenance.py" --check "$ROOT" \
      --expected-sha "$source_sha" > "$out/source-check-after-build.txt" \
      || die "source changed during standalone signed-build; see $out"
    record_build_tools > "$out/build-tools-after.txt" \
      || die "cannot recheck signed-build toolchain"
    /usr/bin/cmp -s "$out/build-tools.txt" "$out/build-tools-after.txt" \
      || die "signed-build toolchain or compiler environment changed; see $out"
    built="$out/DerivedData/Build/Products/Release/ASCFHost.app"
    verify_host "$built" "$out"
    /usr/bin/ditto "$built" "$out/ASCFHost.app"
    printf 'Signed host: %s\nSource SHA: %s\nEvidence: %s\n' \
      "$out/ASCFHost.app" "$source_sha" "$out"
    printf 'Install on disposable Mac; enable File System Extensions in Settings.\n'
    ;;
  fixture)
    test "$#" -le 2 || die "fixture accepts one optional codec"
    mac_only
    codec=lzmesh
    if test "$#" -eq 2; then codec="$2"; fi
    case "$codec" in lzraven|lzmesh) ;; *) die "invalid codec";; esac
    out="$(mktemp -d /tmp/ascf-fixture.XXXXXXXX)"
    /usr/bin/python3 - "$out/source.jsonl" <<'PY'
import json
import sys
with open(sys.argv[1], "wb") as fd:
    for i in range(12000):
        value = {"i": i, "kind": ["chat", "binary", "mixed"][i % 3],
                 "text": ("synthetic " + str(i % 100) + " " + "abcdef0123456789" * 43)}
        fd.write((json.dumps(value, separators=(",", ":")) + "\n").encode())
PY
    test "$(wc -c < "$out/source.jsonl" | tr -d ' ')" -gt 8388608 \
      || die "fixture did not cross the 8 MiB boundary"
    cargo build --locked --release -p applesauce-cli
    "$ROOT/target/release/applesauce" archive create \
      "$out/source.jsonl" "$out/source.$codec.ascf" --codec "$codec"
    "$ROOT/target/release/applesauce" archive verify "$out/source.$codec.ascf"
    /usr/bin/shasum -a 256 "$out/source.jsonl" "$out/source.$codec.ascf" \
      > "$out/fixture.sha256"
    printf 'Original: %s\nASCF: %s\nHashes: %s\n' \
      "$out/source.jsonl" "$out/source.$codec.ascf" "$out/fixture.sha256"
    ;;
  bundle-readback)
    test "$#" -eq 4 || die "bundle-readback requires BUNDLE_DIR MOUNT_DIR CODEC"
    mac_only
    codec="$4"
    case "$codec" in lzraven|lzmesh) ;; *) die "invalid codec";; esac
    test -d "$2" || die "missing bundle directory: $2"
    bundle="$(cd "$2" && pwd -P)"
    test -f "$bundle/source.$codec.jsonl" || die "bundle source for $codec missing"
    test -f "$bundle/source.$codec.ascf" || die "bundle archive for $codec missing"
    out="$(mktemp -d /tmp/ascf-bundle-readback.XXXXXXXX)"
    verify_package_manifest "$bundle" "$out"
    require_matching_bundle_helper "$bundle"
    verify_host "$bundle/ASCFHost.app" "$out" "$bundle"
    /usr/bin/sw_vers > "$out/macos.txt"
    /sbin/mount > "$out/mounts-before.txt"
    /usr/bin/python3 "$bundle/fskit/verify_mount.py" \
      --mount "$3" --original "$bundle/source.$codec.jsonl" \
      > "$out/readback.json" \
      || die "FSKit bundle readback failed; see $out"
    /usr/bin/python3 - "$out/readback.json" "$codec" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    evidence = json.load(source)
expected = "source." + sys.argv[2]
if evidence.get("result") != "pass" or evidence.get("restored_file") != expected:
    sys.exit("FSKit mounted file is not the expected archive member " + expected)
PY
    # Independent Finder metadata enumeration, rather than assuming a good
    # POSIX readback also means ordinary GUI applications see the volume.
    # An Apple Events permission failure blocks mounted acceptance explicitly.
    /bin/mkdir "$out/finder-copy"
    /usr/bin/osascript "$bundle/fskit/finder_readback.applescript" "$3" \
      "source.$codec" "$(/usr/bin/stat -f %z "$bundle/source.$codec.jsonl")" \
      "$out/finder-copy" \
      > "$out/finder-readback.txt" 2> "$out/finder-error.txt" \
      || die "Finder could not copy mounted ASCF bytes; diagnostics: $out/finder-error.txt"
    /usr/bin/cmp -s "$out/finder-copy/source.$codec" "$bundle/source.$codec.jsonl" \
      || die "Finder-copied logical bytes differ from the original source"
    /usr/bin/shasum -a 256 "$out/finder-copy/source.$codec" \
      "$bundle/source.$codec.jsonl" > "$out/finder-copy.sha256"
    /usr/bin/python3 "$bundle/fskit/verify_mount.py" \
      --mount "$3" --original "$bundle/source.$codec.jsonl" \
      > "$out/post-finder-readback.json" \
      || die "ASCF mount failed its full post-Finder recheck; see $out"
    stamp_readback "$out/readback.json" "$out/post-finder-readback.json" \
      "$out/finder-copy/source.$codec" "$bundle/fskit/finder_mount_witness.py"
    /sbin/mount > "$out/mounts-after.txt"
    cat "$out/readback.json"
    cat "$out/finder-readback.txt"
    printf 'Bundle readback evidence: %s\n' "$out"
    ;;
  readback)
    test "$#" -eq 4 || die "readback requires signed app, mount path, original"
    mac_only
    need python3
    test -f "$4" || die "original fixture absent"
    out="$(mktemp -d /tmp/ascf-readback.XXXXXXXX)"
    verify_host "$2" "$out"
    /usr/bin/sw_vers > "$out/macos.txt"
    /sbin/mount > "$out/mounts-before.txt"
    /usr/bin/python3 "$ROOT/fskit/verify_mount.py" --mount "$3" --original "$4" \
      > "$out/readback.json" || die "mounted readback failed; see $out"
    # The report stays provisional until Finder copies the restored file and
    # cmp verifies every logical byte. Stamp exactly once after that check.
    restored_name="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["restored_file"])' "$out/readback.json")"
    /bin/mkdir "$out/finder-copy"
    /usr/bin/osascript "$ROOT/fskit/finder_readback.applescript" "$3" \
      "$restored_name" "$(/usr/bin/stat -f %z "$4")" \
      "$out/finder-copy" \
      > "$out/finder-readback.txt" 2> "$out/finder-error.txt" \
      || die "Finder could not copy mounted ASCF bytes; diagnostics: $out/finder-error.txt"
    /usr/bin/cmp -s "$out/finder-copy/$restored_name" "$4" \
      || die "Finder-copied logical bytes differ from the original source"
    /usr/bin/shasum -a 256 "$out/finder-copy/$restored_name" "$4" \
      > "$out/finder-copy.sha256"
    /usr/bin/python3 "$ROOT/fskit/verify_mount.py" \
      --mount "$3" --original "$4" \
      > "$out/post-finder-readback.json" \
      || die "ASCF mount failed its full post-Finder recheck; see $out"
    stamp_readback "$out/readback.json" "$out/post-finder-readback.json" \
      "$out/finder-copy/$restored_name" "$ROOT/fskit/finder_mount_witness.py"
    /sbin/mount > "$out/mounts-after.txt"
    cat "$out/readback.json"
    cat "$out/finder-readback.txt"
    printf 'Readback evidence: %s\n' "$out"
    ;;
  acceptance-check)
    test "$#" -eq 8 || die "acceptance-check requires BUNDLE_DIR CODEC FIRST_JSON UNMOUNT_JSON REMOUNT_JSON REFUSAL_TXT REPLACEMENT_JSON"
    mac_only
    bundle="$(cd "$2" && pwd -P)" || die "missing bundle: $2"
    codec="$3"
    case "$codec" in lzraven|lzmesh) ;; *) die "invalid codec";; esac
    out="$(mktemp -d /tmp/ascf-evidence.XXXXXXXX)"
    verify_package_manifest "$bundle" "$out"
    require_matching_bundle_helper "$bundle"
    verify_host "$bundle/ASCFHost.app" "$out" "$bundle"
    /usr/bin/python3 "$bundle/fskit/acceptance_evidence.py" \
      --bundle "$bundle" --codec "$codec" --first "$4" \
      --unmounted "$5" --remounted "$6" --refusal "$7" --replacement "$8" \
      > "$out/acceptance.json" \
      || die "acceptance chain failed; diagnostics: $out/acceptance.json"
    cat "$out/acceptance.json"
    printf 'Acceptance evidence chain: %s\n' "$out"
    ;;
  acceptance-all)
    test "$#" -eq 12 || die "acceptance-all requires BUNDLE_DIR and five evidence files per codec (Raven first, Mesh second)"
    mac_only
    bundle="$(cd "$2" && pwd -P)" || die "missing bundle: $2"
    out="$(mktemp -d /tmp/ascf-both-codecs.XXXXXXXX)"
    verify_package_manifest "$bundle" "$out"
    require_matching_bundle_helper "$bundle"
    verify_host "$bundle/ASCFHost.app" "$out" "$bundle"
    /usr/bin/python3 "$bundle/fskit/acceptance_evidence.py" --both \
      --bundle "$bundle" \
      --raven-first "$3" --raven-unmounted "$4" \
      --raven-remounted "$5" --raven-refusal "$6" --raven-replacement "$7" \
      --mesh-first "$8" --mesh-unmounted "$9" \
      --mesh-remounted "${10}" --mesh-refusal "${11}" --mesh-replacement "${12}" \
      > "$out/acceptance.json" \
      || die "both-codec acceptance chain failed; diagnostics: $out/acceptance.json"
    cat "$out/acceptance.json"
    printf 'Combined signed-mount evidence chain: %s\n' "$out"
    ;;
  replacement-stage)
    test "$#" -eq 3 || die "replacement-stage requires BUNDLE_DIR CODEC"
    mac_only
    out="$(mktemp -d /tmp/ascf-replacement-preflight.XXXXXXXX)"
    bundle="$(cd "$2" && pwd -P)" || die "missing signed bundle"
    verify_package_manifest "$bundle" "$out"
    require_matching_bundle_helper "$bundle"
    verify_host "$bundle/ASCFHost.app" "$out" "$bundle"
    /usr/bin/python3 "$bundle/fskit/replacement_acceptance.py" stage "$bundle" "$3"
    ;;
  replacement-check)
    test "$#" -eq 4 || die "replacement-check requires STAGE_DIR MOUNT_DIR ORIGINAL_JSONL"
    mac_only
    # The staged copy records the exact signed package that generated it.
    # Authenticate that package before replacing even a synthetic archive.
    # Running a different checkout's verifier would undermine the evidence.
    bundle="$(/usr/bin/python3 - "$2" <<'PY'
import json
from pathlib import Path
import sys

stage = Path(sys.argv[1])
with (stage / "stage.json").open(encoding="utf-8") as stream:
    data = json.load(stream)
bundle = data.get("bundle")
if not isinstance(bundle, str) or not bundle.startswith("/"):
    sys.exit("stage metadata lacks an absolute signed-bundle path")
print(bundle)
PY
)" || die "replacement stage lacks a valid original signed bundle"
    test -d "$bundle" || die "original signed bundle no longer exists: $bundle"
    out="$(mktemp -d /tmp/ascf-replacement-evidence.XXXXXXXX)"
    verify_package_manifest "$bundle" "$out"
    require_matching_bundle_helper "$bundle"
    verify_host "$bundle/ASCFHost.app" "$out" "$bundle"
    if ! /usr/bin/python3 "$bundle/fskit/replacement_acceptance.py" check "$2" "$3" "$4" > "$out/replacement.json"; then
      die "replacement refusal failed; staged archive may be replaced; see $out"
    fi
    cat "$out/replacement.json"
    printf 'Replacement evidence: %s/replacement.json\n' "$out"
    ;;
  bundle-unmounted)
    test "$#" -eq 4 || die "bundle-unmounted requires BUNDLE_DIR MOUNT_DIR READBACK_JSON"
    mac_only
    need python3
    test -f "$4" && test ! -L "$4" || die "missing or symlinked prior readback: $4"
    bundle="$(cd "$2" && pwd -P)" || die "missing signed bundle: $2"
    out="$(mktemp -d /tmp/ascf-bundle-unmounted.XXXXXXXX)"
    verify_package_manifest "$bundle" "$out"
    require_matching_bundle_helper "$bundle"
    verify_host "$bundle/ASCFHost.app" "$out" "$bundle"
    /usr/bin/sw_vers > "$out/macos.txt"
    /sbin/mount > "$out/mounts-after-unmount.txt"
    /usr/bin/python3 "$bundle/fskit/unmount_acceptance.py" \
      --bundle "$bundle" --mount "$3" --first "$4" > "$out/unmounted.json" \
      || die "signed-bundle kernel unmount witness failed; see $out"
    cat "$out/unmounted.json"
    printf 'Signed-bundle unmount evidence: %s\n' "$out"
    ;;
  unmounted)
    test "$#" -eq 3 || die "unmounted requires MOUNT_DIR READBACK_JSON"
    mac_only
    need python3
    test -f "$3" && test ! -L "$3" || die "missing or symlinked previous readback: $3"
    out="$(mktemp -d /tmp/ascf-unmounted.XXXXXXXX)"
    /usr/bin/sw_vers > "$out/macos.txt"
    /sbin/mount > "$out/mounts-after-unmount.txt"
    # A missing original pathname does not establish a successful unmount:
    # inspect Darwin's complete mount table and refuse relocated/other ASCF
    # volumes, as well as a different filesystem using the same mountpoint.
    /usr/bin/python3 "$ROOT/fskit/unmount_acceptance.py" \
      --mount "$2" --first "$3" > "$out/unmounted.json" \
      || die "kernel mount-table unmount witness failed; see $out"
    cat "$out/unmounted.json"
    printf 'Unmount evidence: %s\n' "$out"
    ;;
  --help|-h|help) usage ;;
  *) usage; exit 2 ;;
esac
