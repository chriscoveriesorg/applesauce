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
  bash fskit/signed_acceptance.sh signed-build
  bash fskit/signed_acceptance.sh fixture [lzraven|lzmesh]
  bash fskit/signed_acceptance.sh package
  bash fskit/signed_acceptance.sh bundle-readback BUNDLE_DIR MOUNT_DIR lzraven|lzmesh
  bash fskit/signed_acceptance.sh readback SIGNED_HOST_APP MOUNT_DIR ORIGINAL
  bash fskit/signed_acceptance.sh unmounted MOUNT_DIR READBACK_JSON

signed-build: set ASCFSKIT_TEAM_ID to your Apple Developer Team ID, with
FSKit mount and module capabilities enabled for their respective App IDs.
The local Xcode account must already have matching provisioning profiles.
The script requires XcodeGen, Rust and the macOS 27 SDK.
fixture: creates an independent, synthetic >8 MiB original and verified ASCF.
package: builds signed host + BOTH codecs and prepares a portable acceptance
bundle with SHA-256 manifest, its own verifier, and negative fixtures.
bundle-readback: verify the portable bundle manifest, signed host, restored
filename, full logical SHA-256, random reads, Finder enumeration and FSKit mount identity.
readback: checks signed host + extension provisioned capabilities and runs
actual statfs, SHA-256, unaligned reads, EOF, Finder and denied write-open acceptance.
unmounted: after normal host/Finder unmount, prove a previously verified
ASCF mount is gone using its successful readback JSON as evidence.
Each command uses a new temporary directory and preserves existing data.
No installation, elevation, mounting, unmounting or APFS writes are automated.
HELP
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
  /usr/bin/python3 - "$out/$name.entitlements.plist" \
    "$out/$name.provisioning.plist" "$key" "$name" <<'PY'
import plistlib
import sys
signed, provision, key, name = sys.argv[1:]
with open(signed, "rb") as fd:
    ent = plistlib.load(fd)
with open(provision, "rb") as fd:
    allowed = plistlib.load(fd).get("Entitlements", {})
if ent.get(key) is not True or allowed.get(key) is not True:
    sys.exit(f"{name}: {key} must be present in BOTH the code signature "
             "and the developer provisioning profile")
print(f"{name}: signing and restricted FSKit entitlement validated")
PY
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
if test "$#" -eq 0; then usage; exit 2; fi
case "$1" in
  package)
    test "$#" -eq 1 || die "package takes no arguments"
    mac_only
    for t in cargo shasum ditto python3; do need "$t"; done
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
    /bin/cp "$ROOT/fskit/finder_readback.applescript" "$out/fskit/finder_readback.applescript"
    /usr/bin/python3 "$out/fskit/verify_mount.py" --self-test \
      > "$out/portable-verifier-tests.log" 2>&1 \
      || die "packaged verifier self-tests failed; see $out/portable-verifier-tests.log"
    # Relative paths survive moving the bundle. Hash the executable acceptance
    # harness as well as the valid and deliberately corrupted synthetic inputs.
    (cd "$out" && /usr/bin/shasum -a 256 source.*.jsonl source.*.ascf fskit/*.sh fskit/*.py fskit/*.applescript > SHA256SUMS)
    (cd "$out" && /usr/bin/shasum -a 256 -c SHA256SUMS) > "$out/manifest-verified.log"
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
6. Attempt to mount each source.<codec>.corrupt.ascf. Each MUST be refused;
   do not record a passed acceptance if any corrupted archive mounts.
The bundle includes its own verification scripts. It does not need the
original checkout or Rust to check mounted readback.
Keep the signed readback, unmount, mount, and rejection evidence.
No data on the target Mac is automatically mounted or overwritten.
STEPS
    printf 'Signed acceptance bundle: %s\nSHA-256: %s/SHA256SUMS\n' "$out" "$out"
    ;;
  signed-build)
    test "$#" -eq 1 || die "signed-build takes no arguments"
    mac_only
    for t in cargo xcodegen xcodebuild codesign security python3; do need "$t"; done
    team="$(printenv ASCFSKIT_TEAM_ID || true)"
    test -n "$team" || die "ASCFSKIT_TEAM_ID must specify the provisioned team"
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
    test -f "$bundle/SHA256SUMS" || die "bundle SHA256SUMS missing"
    test -f "$bundle/source.$codec.jsonl" || die "bundle source for $codec missing"
    test -f "$bundle/source.$codec.ascf" || die "bundle archive for $codec missing"
    out="$(mktemp -d /tmp/ascf-bundle-readback.XXXXXXXX)"
    (cd "$bundle" && /usr/bin/shasum -a 256 -c SHA256SUMS) \
      > "$out/manifest-verified.log" 2>&1 \
      || die "bundle contents changed; see $out/manifest-verified.log"
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
    /usr/bin/osascript "$ROOT/fskit/finder_readback.applescript" "$3" \
      "source.$codec" "$(/usr/bin/stat -f %z "$bundle/source.$codec.jsonl")" \
      > "$out/finder-readback.txt" 2> "$out/finder-error.txt" \
      || die "Finder could not enumerate mounted ASCF bytes; diagnostics: $out/finder-error.txt"
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
    restored_name="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["restored_file"])' "$out/readback.json")"
    /usr/bin/osascript "$ROOT/fskit/finder_readback.applescript" "$3" \
      "$restored_name" "$(/usr/bin/stat -f %z "$4")" \
      > "$out/finder-readback.txt" 2> "$out/finder-error.txt" \
      || die "Finder could not enumerate mounted ASCF bytes; diagnostics: $out/finder-error.txt"
    /sbin/mount > "$out/mounts-after.txt"
    cat "$out/readback.json"
    cat "$out/finder-readback.txt"
    printf 'Readback evidence: %s\n' "$out"
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
if os.path.abspath(os.path.normpath(previous.get("mount", ""))) != mount:
    sys.exit("unmounted: path differs from the verified ASCF mount")
if os.path.ismount(mount):
    sys.exit("unmounted: FSKit volume is still mounted")
print(json.dumps({"result": "pass", "mount": mount,
                  "previous_sha256": previous.get("sha256"),
                  "unmounted": True}, sort_keys=True, indent=2))
PY
    cat "$out/unmounted.json"
    printf 'Unmount evidence: %s\n' "$out"
    ;;
  --help|-h|help) usage ;;
  *) usage; exit 2 ;;
esac
