#!/usr/bin/env bash
# Owner-run acceptance. Never writes APFS xattrs, mounted data or unknown decmpfs types.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
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
  bash fskit/signed_acceptance.sh bundle-readback BUNDLE_DIR MOUNT_DIR lzraven|lzmesh
  bash fskit/signed_acceptance.sh acceptance-check BUNDLE_DIR CODEC FIRST_JSON UNMOUNT_JSON REMOUNT_JSON REFUSAL_TXT REPLACEMENT_JSON
  bash fskit/signed_acceptance.sh readback SIGNED_HOST_APP MOUNT_DIR ORIGINAL
  bash fskit/signed_acceptance.sh unmounted MOUNT_DIR READBACK_JSON
  bash fskit/signed_acceptance.sh replacement-stage BUNDLE_DIR lzraven|lzmesh
  bash fskit/signed_acceptance.sh replacement-check STAGE_DIR MOUNT_DIR ORIGINAL_JSONL

preflight: verify macOS 27+, matching SDK, local tools and an unlocked
Apple Development signing identity for ASCFSKIT_TEAM_ID. Read-only checks.
signed-build: set ASCFSKIT_TEAM_ID to your Apple Developer Team ID, with
FSKit mount and module capabilities enabled for their respective App IDs.
The local Xcode account must already have matching provisioning profiles.
The script requires XcodeGen, Rust and the macOS 27 SDK.
fixture: creates an independent, synthetic >8 MiB original and verified ASCF.
package: builds signed host + BOTH codecs and prepares a portable acceptance
bundle with SHA-256 manifest, its own verifier, and negative fixtures.
manifest-check: independently verify all critical bundle bytes and coverage
before installation; does not require signing or attempt to mount anything.
bundle-readback: verify the portable bundle manifest, signed host, restored
filename, full logical SHA-256, random reads, Finder copy/readback and FSKit mount identity.
readback: checks signed host + extension provisioned capabilities and runs
actual statfs, SHA-256, unaligned reads, EOF, Finder-copied byte comparison and denied write-open acceptance.
unmounted: after normal host/Finder unmount, prove a previously verified
ASCF mount is gone using its successful readback JSON as evidence.
acceptance-check: validate a complete two-mount and corruption-control evidence
chain for one codec, with signed bundle and source hashes checked first.
Each command uses a new temporary directory and preserves existing data.
No installation, elevation, mounting, unmounting or APFS writes are automated.
replacement-stage creates private synthetic /tmp archive copies. replacement-check
only atomically replaces the copy after real mounted readback.
HELP
}
# Fail early with a useful local diagnosis before compiling Rust or creating
# signed build artifacts. The actual entitlement/profile grant is independently
# checked against the finished bundles by verify_host().
signing_preflight() {
  mac_only
  local tool product major sdk sdk_major team identities
  for tool in cargo xcodegen xcodebuild xcrun codesign security python3 shasum ditto git; do
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
  identities="$(/usr/bin/security find-identity -v -p codesigning)" \
    || die "cannot inspect local code-signing identities"
  if ! /usr/bin/grep -E "Apple Development:.*\\($team\\)" <<< "$identities" >/dev/null; then
    die "no available Apple Development signing identity for team $team; install/unlock its certificate before signed-build"
  fi
  printf 'Signing preflight: macOS %s, SDK %s, developer team %s, tools and signing identity present.\n' \
    "$product" "$sdk" "$team"
  printf 'FSKit entitlement grants still require signed-build profile validation.\n'
}
verify_bundle() {
  local bundle="$1" key="$2" name="$3" out="$4"
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
  /usr/bin/python3 "$ROOT/fskit/signing_profile.py" \
    "$out/$name.entitlements.plist" "$out/$name.provisioning.plist" \
    "$key" "$name" "$signing_team" "$bundle_id" \
    || die "$name code signature and provisioning profile disagree"
}
verify_host() {
  local host="$1" out="$2"
  verify_bundle "$host" com.apple.developer.fskit.mount host "$out"
  verify_bundle "$host/Contents/Extensions/ASCFExtension.appex" \
    com.apple.developer.fskit.fsmodule extension "$out"
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
NEXT-STEPS.txt
fskit/signed_acceptance.sh
fskit/verify_mount.py
fskit/acceptance_evidence.py
fskit/signing_profile.py
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
# Stamp successful mounted readbacks with unique run identities. The
# unmount verifier binds to that exact first readback; a reused JSON report
# cannot masquerade as evidence of a second, independent remount.
stamp_readback() {
  test "$#" -eq 2 || die "stamp_readback requires REPORT_JSON and FINDER_COPIED_FILE"
  /usr/bin/python3 - "$1" "$2" <<'PY'
import datetime
import json
from pathlib import Path
import sys
import uuid

path = Path(sys.argv[1])
report = json.loads(path.read_text(encoding="utf-8"))
if report.get("result") != "pass":
    sys.exit("cannot stamp a failed mounted-readback report")
copied = Path(sys.argv[2])
if not copied.is_file():
    sys.exit("Finder copy-out missing from completed mounted acceptance")
import hashlib
copy_sha256 = hashlib.sha256(copied.read_bytes()).hexdigest()
if copy_sha256 != report.get("sha256"):
    sys.exit("Finder copy-out digest does not match mounted logical digest")
report["finder_copy_verified"] = True
report["finder_copy_sha256"] = copy_sha256
report["verification_id"] = str(uuid.uuid4())
report["verified_at_utc"] = datetime.datetime.now(
    datetime.timezone.utc).isoformat()
path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                encoding="utf-8")
PY
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
  package)
    test "$#" -eq 1 || die "package takes no arguments"
    mac_only
    for t in cargo shasum ditto python3 git; do need "$t"; done
    git diff --quiet && git diff --cached --quiet \
      || die "package requires a clean tracked source checkout for reproducible provenance"
    # Explicit single-command handoff. Every input is generated from synthetic
    # data. A signed app is copied intact, preserving its embedded extension.
    out="$(mktemp -d /tmp/ascf-acceptance.XXXXXXXX)"
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
    /bin/cp "$ROOT/fskit/acceptance_evidence.py" "$out/fskit/acceptance_evidence.py"
    /bin/cp "$ROOT/fskit/signing_profile.py" "$out/fskit/signing_profile.py"
    /bin/cp "$ROOT/fskit/replacement_acceptance.py" "$out/fskit/replacement_acceptance.py"
    /bin/cp "$ROOT/fskit/finder_readback.applescript" "$out/fskit/finder_readback.applescript"
    /usr/bin/python3 "$out/fskit/verify_mount.py" --self-test \
      > "$out/portable-verifier-tests.log" 2>&1 \
      || die "packaged verifier self-tests failed; see $out/portable-verifier-tests.log"
    /usr/bin/python3 "$out/fskit/acceptance_evidence.py" --self-test \
      > "$out/portable-evidence-tests.log" 2>&1 \
      || die "packaged evidence self-tests failed; see $out/portable-evidence-tests.log"
    /usr/bin/python3 "$out/fskit/signing_profile.py" --self-test \
      > "$out/signing-profile-tests.log" 2>&1 \
      || die "packaged signing-profile self-tests failed; see $out/signing-profile-tests.log"
    /usr/bin/python3 "$out/fskit/replacement_acceptance.py" --self-test \
      > "$out/replacement-tests.log" 2>&1 \
      || die "packaged replacement-control tests failed; see $out/replacement-tests.log"
    # Carry the exact clean source commit; the manifest authenticates the
    # signed binaries, app/extension provisioning and all test scripts.
    printf 'repository=chriscoveriesorg/applesauce\ncommit=%s\n' \
      "$(git rev-parse --verify HEAD)" > "$out/source-provenance.txt"
    /usr/bin/sw_vers > "$out/macos.txt"
    cat > "$out/NEXT-STEPS.txt" <<'STEPS'
These files are synthetic. Preserve the originals and the signed app.
1. Copy this entire folder onto an authorized disposable macOS 27+ Mac.
2. Install ASCFHost.app and enable its extension in System Settings >
   General > Login Items & Extensions > File System Extensions.
3. Launch the host and mount source.lzmesh.ascf, then from THIS folder run:
   bash fskit/signed_acceptance.sh bundle-readback . "/Volumes/Applesauce ASCF" lzmesh
4. Unmount using host/Finder. Confirm it with the resulting readback.json:
   bash fskit/signed_acceptance.sh unmounted "/Volumes/Applesauce ASCF" /path/to/readback.json
   Then remount and repeat bundle-readback.
5. Repeat steps 3-4 with source.lzraven.ascf and codec lzraven.
6. In ASCFHost choose "Test corrupted archive mount refusal" and select
   source.lzmesh.corrupt.ascf. Use "Copy mount diagnostic" to save the result.
   Repeat for source.lzraven.corrupt.ascf. A returned mount is a hard failure.
   Require CORRUPT_REFUSAL_CONFIRMED with FSKit resourceDamaged for
   each fixture. CORRUPT_REFUSAL_INCONCLUSIVE means diagnose provisioning,
   permissions, sandbox or activation before claiming corruption refusal.
   Keep the signed host diagnostic and the unchanged ASCF mount listing.
7. After normally unmounting, stage an independent archive-replacement test:
   bash fskit/signed_acceptance.sh replacement-stage . lzmesh
   Select its generated /tmp/.../source.lzmesh.ascf COPY in the signed host.
   Once mounted, run:
   bash fskit/signed_acceptance.sh replacement-check STAGE_DIR "/Volumes/Applesauce ASCF" ./source.lzmesh.jsonl
   Preserve the printed replacement.json path and unmount normally.
   Repeat for lzraven. Only the private synthetic /tmp copy is replaced.
   Any cached read or unrelated permission failure blocks acceptance.
8. For each codec, run acceptance-check with first readback.json,
   unmounted.json, remount readback.json, the CORRUPT_REFUSAL_CONFIRMED
   diagnostic and replacement.json. Preserve the complete result for review.
The bundle hashes the signed host and extension binaries and provisioning
profiles alongside every fixture and verifier; source-provenance.txt records
the clean source checkout commit. It does not need Rust on the receiving Mac.
Keep the signed readback, unmount, mount, and rejection evidence.
No data on the target Mac is automatically mounted or overwritten.
STEPS
    # Authenticate operator instructions and recorded build OS too. Hash
    # after ALL mandatory members have been created, then verify in place.
    (cd "$out" && required_manifest_paths | while IFS= read -r path; do
      /usr/bin/shasum -a 256 "$path"
    done > SHA256SUMS)
    verify_package_manifest "$out" "$out"
    printf 'Signed acceptance bundle: %s\nSHA-256: %s/SHA256SUMS\n' "$out" "$out"
    ;;
  signed-build)
    test "$#" -eq 1 || die "signed-build takes no arguments"
    signing_preflight
    team="${ASCFSKIT_TEAM_ID}"
    out="$(mktemp -d /tmp/ascf-signed.XXXXXXXX)"
    cargo build --locked --release -p applesauce-fskit-bridge
    xcodegen generate --spec fskit/project.yml
    xcodebuild -project fskit/ApplesauceASCF.xcodeproj \
      -scheme ASCFHost -configuration Release \
      -destination 'generic/platform=macOS' \
      -derivedDataPath "$out/DerivedData" \
      CODE_SIGNING_ALLOWED=YES CODE_SIGN_STYLE=Automatic \
      DEVELOPMENT_TEAM="$team" CODE_SIGN_IDENTITY='Apple Development' \
      build 2>&1 | tee "$out/xcodebuild.log"
    built="$out/DerivedData/Build/Products/Release/ASCFHost.app"
    verify_host "$built" "$out"
    /usr/bin/ditto "$built" "$out/ASCFHost.app"
    printf 'Signed host: %s\nEvidence: %s\n' "$out/ASCFHost.app" "$out"
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
    verify_host "$bundle/ASCFHost.app" "$out"
    /usr/bin/sw_vers > "$out/macos.txt"
    /sbin/mount > "$out/mounts-before.txt"
    /usr/bin/python3 "$ROOT/fskit/verify_mount.py" \
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
    /usr/bin/osascript "$ROOT/fskit/finder_readback.applescript" "$3" \
      "source.$codec" "$(/usr/bin/stat -f %z "$bundle/source.$codec.jsonl")" \
      "$out/finder-copy" \
      > "$out/finder-readback.txt" 2> "$out/finder-error.txt" \
      || die "Finder could not copy mounted ASCF bytes; diagnostics: $out/finder-error.txt"
    /usr/bin/cmp -s "$out/finder-copy/source.$codec" "$bundle/source.$codec.jsonl" \
      || die "Finder-copied logical bytes differ from the original source"
    /usr/bin/shasum -a 256 "$out/finder-copy/source.$codec" \
      "$bundle/source.$codec.jsonl" > "$out/finder-copy.sha256"
    stamp_readback "$out/readback.json" "$out/finder-copy/source.$codec"
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
    stamp_readback "$out/readback.json" "$out/finder-copy/$restored_name"
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
    verify_host "$bundle/ASCFHost.app" "$out"
    /usr/bin/python3 "$ROOT/fskit/acceptance_evidence.py" \
      --bundle "$bundle" --codec "$codec" --first "$4" \
      --unmounted "$5" --remounted "$6" --refusal "$7" --replacement "$8" \
      > "$out/acceptance.json" \
      || die "acceptance chain failed; diagnostics: $out/acceptance.json"
    cat "$out/acceptance.json"
    printf 'Acceptance evidence chain: %s\n' "$out"
    ;;
  replacement-stage)
    test "$#" -eq 3 || die "replacement-stage requires BUNDLE_DIR CODEC"
    mac_only
    out="$(mktemp -d /tmp/ascf-replacement-preflight.XXXXXXXX)"
    bundle="$(cd "$2" && pwd -P)" || die "missing signed bundle"
    verify_package_manifest "$bundle" "$out"
    verify_host "$bundle/ASCFHost.app" "$out"
    /usr/bin/python3 "$ROOT/fskit/replacement_acceptance.py" stage "$bundle" "$3"
    ;;
  replacement-check)
    test "$#" -eq 4 || die "replacement-check requires STAGE_DIR MOUNT_DIR ORIGINAL_JSONL"
    mac_only
    out="$(mktemp -d /tmp/ascf-replacement-evidence.XXXXXXXX)"
    if ! /usr/bin/python3 "$ROOT/fskit/replacement_acceptance.py" check "$2" "$3" "$4" > "$out/replacement.json"; then
      die "replacement refusal failed; staged archive may be replaced; see $out"
    fi
    cat "$out/replacement.json"
    printf 'Replacement evidence: %s/replacement.json\n' "$out"
    ;;
  unmounted)
    test "$#" -eq 3 || die "unmounted requires MOUNT_DIR READBACK_JSON"
    mac_only
    need python3
    test -f "$3" || die "previous readback report missing: $3"
    out="$(mktemp -d /tmp/ascf-unmounted.XXXXXXXX)"
    /usr/bin/sw_vers > "$out/macos.txt"
    /sbin/mount > "$out/mounts-after-unmount.txt"
    /usr/bin/python3 - "$2" "$3" > "$out/unmounted.json" <<'PY'
import datetime
import json
import os
import sys

mount = os.path.abspath(os.path.normpath(sys.argv[1]))
if not mount.startswith("/Volumes/"):
    sys.exit("unmounted: expected an FSKit mount path under /Volumes")
with open(sys.argv[2], encoding="utf-8") as source:
    previous = json.load(source)
if previous.get("result") != "pass" or previous.get("filesystem_type") != "ascf":
    sys.exit("unmounted: previous report did not pass the real ASCF mount gate")
if not previous.get("verification_id") or previous.get("finder_copy_verified") is not True:
    sys.exit("unmounted: previous readback lacks independent Finder copy and verification ID")
if os.path.abspath(os.path.normpath(previous.get("mount", ""))) != mount:
    sys.exit("unmounted: path differs from the verified ASCF mount")
if os.path.ismount(mount):
    sys.exit("unmounted: FSKit volume is still mounted")
print(json.dumps({"result": "pass", "mount": mount,
                  "previous_sha256": previous.get("sha256"),
                  "previous_verification_id": previous["verification_id"],
                  "verified_at_utc": datetime.datetime.now(
                      datetime.timezone.utc).isoformat(),
                  "unmounted": True}, sort_keys=True, indent=2))
PY
    cat "$out/unmounted.json"
    printf 'Unmount evidence: %s\n' "$out"
    ;;
  --help|-h|help) usage ;;
  *) usage; exit 2 ;;
esac
