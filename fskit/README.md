# ASCF FSKit extension, experimental

The ASCF volume exposes **one restored logical file** under a **separate mount
point**. It is read-only. The filename is derived from the archive basename,
because the v1 archive does not store its original filename. macOS 26+ FSKit
and the macOS 27+ Raven/Mesh public buffer decoders are required.

The FSKit module uses Apple's \`FSUnaryFileSystem\` and \`FSVolume.Operations\`
APIs, with a security-scoped \`FSPathURLResource\`. Before publishing the
volume it opens the source O_RDONLY/O_NOFOLLOW, asks the Rust bridge to verify
**every chunk plus the whole-file SHA-256**, and exposes a single deterministic
root/file directory. Reads are bounded to 8 MiB per call, support EOF and
random offsets, and reject corruption. Mutations return EROFS. The separate
mount point does not alter the original path or provide native APFS
\`decmpfs\` Raven/Mesh compression.

Build an unsigned development host and extension on a Mac with a compatible
Xcode/macOS SDK:

    cargo build --locked --release -p applesauce-fskit-bridge
    xcodegen generate --spec fskit/project.yml
    xcodebuild -project fskit/ApplesauceASCF.xcodeproj \
      -scheme ASCFHost -configuration Debug CODE_SIGNING_ALLOWED=NO build

The volume identifier is derived deterministically from the verified logical digest,
codec selector, and selected archive URL. FSKit sees the same container/volume
identity at probe and load, and remounting the same archive preserves its
identity. Distinct Raven and Mesh archives remain distinguishable even when
they restore identical logical bytes. Unload resets the container readiness.

The module's built `Info.plist` includes the FSKit activation, check, and
format **option syntax metadata** from Apple's extension template. Those
dictionaries configure FSKit command parsing, rather than enabling format
operations; the module remains read-only and does not implement formatting.
The CI build checks the *processed extension bundle* and the signed host
preflight checks its actual activation syntax. This addresses a reported
runtime probe failure when `FSActivateOptionSyntax.shortOptions` is missing.
It does not establish successful signed mounting.

Installing and mounting requires a valid developer signing identity,
FSKit entitlement and explicit local extension enablement. The CI build
type-checks the extension but does not install, approve, or mount it. End-to-end
mounted readback needs an authorized disposable macOS host. The ASCF format
is experimental and must not be the only copy of important files.

References: Apple's "Building a passthrough file system" sample and
https://developer.apple.com/documentation/fskit/fsunaryfilesystemoperations .

## User-initiated mounting on macOS 27+

After signing and installing `ASCFHost.app` with the authorized FSKit
module and mount entitlements, enable its filesystem extension in System
Settings > General > Login Items & Extensions > File System Extensions.
Launch the host, choose an `.ascf` file and select **Mount**. The host
passes a read-only, security-scoped path resource to
`FSClient.mountSingleVolume`. FSKit verifies the logical archive before
publishing a volume under `/Volumes`, where Finder and ordinary apps can
read the restored file. The host shows the resulting path and can reveal it
in Finder. The original source path and attributes stay untouched.

Provisioning must authorize both `com.apple.developer.fskit.fsmodule`
(for the extension) and `com.apple.developer.fskit.mount` (for the host);
unsigned development builds validate compilation only. A complete signed
install, extension enablement, mounted listing and SHA-256 comparison on
an authorized disposable Mac remain required before claiming runtime
compatibility. If the host lacks either entitlement, expect mount failure.

## Signed negative control for corrupted archives

The signed host exposes **Test corrupted archive mount refusal** alongside the
normal mount button. Use it on the authorized disposable Mac after the
extension has been installed and enabled. Select each generated
`source.<codec>.corrupt.ascf` file from the portable acceptance bundle.
The host calls the same real `FSClient.mountSingleVolume` API as the normal
mount path and keeps the full rejection diagnostic visible and copyable.
A returned mount is reported as `CORRUPT_REFUSAL_FAIL` and blocks acceptance;
the host never silently unmounts an unexpected result.

`CORRUPT_REFUSAL_CONFIRMED` now requires the signed FSKit probe to return
`FSKitErrorDomain` / `FSError.Code.resourceDamaged`, with no surviving ASCF
volume. The extension emits this typed error only when a recognized ASCF
header/index fails full codec or SHA-256 verification. Any other rejection,
including permission, entitlement, sandbox or activation errors, produces
`CORRUPT_REFUSAL_INCONCLUSIVE`. Capture diagnostics for **both** codecs.
CLI verification alone does not prove mounted-path corruption refusal.

## Terminal-driven FSKit mount on a provisioned disposable Mac

Apple's FSKit passthrough sample documents dispatching a registered filesystem
extension through `mount -t <filesystem>`. With the **signed** ASCF extension
installed and enabled, the acceptance bundle now provides an explicit owner-run
path using the registered `ascf` short name:

```sh
cd /path/to/ascf-acceptance.XXXXXXXX
bash fskit/signed_acceptance.sh cli-mount . lzraven
# Follow the printed Finder readback and normal unmount commands.
```

This invokes macOS `mount -F -k -r -t ascf` on a newly created private
directory under `/private/tmp`. The `-F` flag selects the registered FSKit
module instead of a traditional `mount_ascf` helper; `-k` refuses symlink
substitution of the mountpoint, and `-r` requests a read-only kernel mount.
The script checks the signed host and extension, provisioning profiles,
handoff manifest and selected synthetic archive before the mount request.
It retains the exact invocation in `mount-command.txt`, together with
`mount-command.log`. An independent reader then verifies actual ASCF VFS
identity, whole-file SHA-256, unaligned/random reads, EOF and denied write-opens.
The command never elevates privileges, overwrites an existing path, changes
APFS metadata or forces unmount.

The signed host UI remains the required path for the full mount/unmount/remount,
source-replacement and corrupt-mount refusal evidence chain. Terminal mounting
is a second integration path; a system mount failure establishes only that the
specific host, permission or extension setup rejected it. Finder acceptance
uses the separate `bundle-readback` command printed by `cli-mount`.

## Reproducible mounted-file acceptance

The unsigned build and Swift typecheck cannot prove that macOS will register
an extension or serve bytes through the actual mount. On an **authorized
disposable** macOS 27+ host, sign and enable the module, then use the host UI
to mount an ASCF archive created from a retained, uncompressed test fixture.

Run from the repository checkout with the separate volume's actual mount
point and that fixture:

```sh
python3 fskit/verify_mount.py --mount "/Volumes/Applesauce ASCF" --original "/path/to/fixture"
```

On macOS, the signed acceptance gate confirms the actual filesystem type is\n`ascf` using Darwin `statfs(2)` and its `f_fstypename` field and records the macOS product version and build\nin its JSON evidence. An ordinary APFS/disk-image mount with matching bytes\nwill fail this gate. Synthetic tests deliberately bypass the real mount check.\n\nThe verifier refuses an unmounted directory, symlinks, multi-file mounts,
unexpected writable opens and any mismatched logical bytes. It reads the whole
restored file for SHA-256, samples bounded, evenly distributed offsets throughout the logical file,
including 4 KiB, 64 KiB and 8 MiB boundaries, and rejects reads that return
bytes at or beyond EOF. Its negative read-only check tries both **O_WRONLY**
and **O_RDWR** opens without issuing any writes. It never changes the mounted
file, source, ASCF archive or APFS metadata.
Store the JSON report alongside the signed extension identity, macOS build,
archive creation command, mount/unmount evidence and CLI verification output.
A passing synthetic unit test does not qualify the FSKit runtime.

Portable acceptance harness tests (also run in FSKit CI):

```sh
python3 fskit/verify_mount.py --self-test
```

The host now keeps track of the single active mount. Use **Unmount read-only
volume** to request a normal macOS unmount; the UI reports busy-volume or
permission errors rather than forcing an eject. Finder-initiated unmounts also
clear the host's mounted state. Mounting another archive is disabled while a
mount or unmount is underway or an archive remains mounted. A successful
compile does not establish that signed installation and unmount work on a
real macOS host; both remain part of end-to-end acceptance.


## Signed, provisioned owner-run acceptance (disposable Mac)

The compile workflow checks Swift and the bridge but cannot approve Apple's
restricted entitlements or mount a real FSKit volume. This script makes those
missing steps executable without changing APFS metadata:

```sh
# On a macOS 27+ Mac signed into a provisioned Apple Developer team:
export ASCFSKIT_TEAM_ID=YOUR_10_CHARACTER_TEAM_ID
bash fskit/signed_acceptance.sh signed-build
bash fskit/signed_acceptance.sh fixture lzmesh
# Optional second fixture with: fixture lzraven

# Install the resulting ASCFHost.app on the authorized disposable Mac.
# Enable the extension in System Settings > General > Login Items & Extensions.
# Open ASCFHost.app and select the generated source.lzmesh.ascf archive.
bash fskit/signed_acceptance.sh readback \
  "/path/to/ASCFHost.app" "/Volumes/Applesauce ASCF" \
  "/path/to/generated/source.jsonl"
```

For a single signed handoff containing both independently verified codecs,
use:

```sh
export ASCFSKIT_TEAM_ID=YOUR_10_CHARACTER_TEAM_ID
bash fskit/signed_acceptance.sh package
```

The `package` command builds and verifies a signed host and extension,
generates matching synthetic cleartext plus LZRaven/LZMesh archives, creates
one payload-corrupted ASCF fixture per codec, and confirms both corrupted
fixtures fail CLI verification. It writes an isolated directory with
`ASCFHost.app`, `SHA256SUMS`, fixture generation/build logs,
`NEXT-STEPS.txt`, the original test data and **copies of both acceptance scripts**.
The manifest includes all acceptance scripts, the Finder AppleScript, the recorded macOS build, authenticated operator instructions and every fixture,
plus the exact signed host and extension executables, their Info.plists,
code-signing resource seals and embedded provisioning profiles. The bundle
records the clean source HEAD in `source-provenance.txt`. Packaging refuses
tracked source modifications to keep that attribution reproducible. Run
`bash fskit/signed_acceptance.sh manifest-check /path/to/bundle` before
installing to verify every mandatory member and its SHA-256 independently.
Run `bash fskit/signed_acceptance.sh bundle-code-check /path/to/bundle`
from the selected package to also require that the running operator script is
identical to the manifest-covered script. Every signed-bundle action now runs
its packaged Python verifier, including the signing-profile check. A checkout
whose acceptance script differs from the package stops before mount or
replacement operations; use the package's own `fskit/signed_acceptance.sh`.
a copied folder can be verified without Rust or the original repository checkout. Test the two valid
files for mounted readback, normal unmount and remount; then attempt to mount
both damaged archives and retain macOS rejection evidence. CLI verification proves that
damaged data fails the archive decoder; only a real FSKit mount refusal
qualifies the signed integration. The command itself never mounts anything.

To run acceptance on a separate authorized Mac, copy the generated directory
as a unit, install/enable the included signed host, and mount the archive from
the host UI. Then use the **bundled** script from inside that copied directory:

```sh
cd /path/to/ascf-acceptance.XXXXXXXX
bash fskit/signed_acceptance.sh bundle-readback . \
  "/Volumes/Applesauce ASCF" lzmesh
```

The command validates the relative SHA256SUMS manifest, signed host and
extension entitlements, the actual `ascf` mount type, SHA-256, random reads,
EOF, denied write-open and the expected restored filename `source.lzmesh`.
It also asks Finder through Apple Events to enumerate the one restored file and
confirm its name and logical size. Keep the `finder-readback.txt` result beside
the SHA-256 evidence. macOS may ask the invoking Terminal for permission to
control Finder; a denial fails acceptance and is logged to `finder-error.txt`.
The test opens no user files in Finder and makes no write requests.
Repeat using `lzraven` after remounting its archive. The result includes the
path to `readback.json` for subsequent `unmounted` verification. Neither
`bundle-readback` nor `unmounted` installs, mounts or edits a volume.

The owner-run signing check also binds each provisioning profile to the signed
bundle identifier and code-signing team. It rejects expired profiles and
profiles that grant FSKit to another app, before extension installation.
These checks run on the packaged helper without requiring the original checkout.

The script verifies the host and extension code signatures **and** checks
that both signed entitlements are allowed in their embedded provisioning
profiles. A development/ad-hoc signature without those capabilities fails.
It generates deterministic synthetic input above 8 MiB; archive construction
and `archive verify` must succeed before mounting. The mounted acceptance
uses the existing Python verifier for actual FSKit identity, complete logical
SHA-256, randomized/boundary/EOF reads and denied write-opens. Each command
writes evidence to a unique temporary directory and prints its path.
Never use private source files for this test.

After successful `readback`, use **Unmount read-only volume** in the host or
Finder's normal eject action, then prove that the previously verified mount
has disappeared. This command requires the successful `readback.json` from
that same volume. It inspects Darwin's complete `getmntinfo` kernel mount table\nfor FSKit mounts, including private Terminal mountpoints, and rejects any\nsurviving ASCF volume, relocated mount or filesystem still using the prior\nmountpoint. A disappeared directory alone cannot qualify as a successful\nunmount. The witness binds the prior Finder-verified readback ID, SHA-256 and\nmacOS build to the observed zero-ASCF state:

```sh
bash fskit/signed_acceptance.sh unmounted \
  "/Volumes/Applesauce ASCF" "/tmp/ascf-readback.EXAMPLE/readback.json"
```

Remount the original synthetic archive through the host UI and run `readback`
again, retaining both JSON reports and the unmount evidence. The host uses
FileManager's asynchronous volume unmount API rather than device ejection,
so busy volumes are reported without a forced unmount or device action.
The portable unmount checker has nine synthetic regressions and a macOS 27
CI check that calls the real Darwin `getmntinfo` ABI. Those checks validate
the witness code; only a signed, mounted physical lifecycle can satisfy
PR #86 acceptance.
Collect the Xcode build logs, signed entitlement/profile snapshots, and
macOS build with the complete lifecycle evidence. Signing requires the Apple Developer
team to provision `com.apple.developer.fskit.mount` and
`com.apple.developer.fskit.fsmodule`. The script intentionally does not install
an extension, request privileges, mount or force-unmount it. Owner-run
acceptance is **still pending** until a signed disposable Mac demonstrates
the full lifecycle; synthetic CI remains only a prerequisite.

### Real mounted archive-replacement refusal on disposable test copies

A valid ASCF archive must refuse fresh reads when its underlying pathname
has been replaced after mounting. Test this separately from the corrupted
payload control, using only private synthetic copies. On the authorized
disposable macOS host, inside the signed acceptance bundle:

```sh
bash fskit/signed_acceptance.sh replacement-stage . lzmesh
# Select the printed /tmp/ascf-replacement-.../source.lzmesh.ascf
# in the signed host and mount it. Then execute with that stage path:
bash fskit/signed_acceptance.sh replacement-check \
  /tmp/ascf-replacement-XXXXXXXX "/Volumes/Applesauce ASCF" \
  ./source.lzmesh.jsonl
# Unmount normally, then repeat with lzraven.
```

The first command checks the signed bundle and copies its intact archive and
independently damaged replacement into a private mode-0700 temporary directory.
Its stage metadata records the canonical original signed bundle path. Keep
that bundle in place until replacement-check finishes: the check reauthenticates
the bundle manifest, selected helper, signed host and original fixture hashes
before changing the staged copy. The second authenticates the **real mounted ASCF VFS** and whole logical
SHA-256 before atomically replacing only the staged copy. It requires a fresh
open/read of the mounted file to fail with ESTALE, EIO or ENODEV. Readable
cached data or an unrelated access error fails the test. Save its JSON,
source hashes and signed-host diagnostics for independent review. This check
never installs, mounts, unmounts, changes xattrs or touches the source bundle.
The operator must unmount normally after the negative-control attempt.

The replacement-check command saves its verified report as
/tmp/ascf-replacement-evidence.XXXXXXXX/replacement.json. Pass that file to
acceptance-check as the last argument, after recording the first mount,
witnessed unmount and remount. The final evidence gate binds both archive
SHA-256 values, restored logical bytes, actual ASCF read-only VFS identity,
macOS build, stale-read errno and event ordering to the signed bundle.
Archive replacement refusal is required for both Raven and Mesh.

Tests of this helper run as part of the macOS FSKit compile workflow and the
signed acceptance package. A successful synthetic test never establishes
actual mounted acceptance.

### Machine-check the full signed lifecycle evidence

For each codec, run `bundle-readback` on its first mount and again after
a normal unmount confirmed with `unmounted`. Capture the host's
`CORRUPT_REFUSAL_CONFIRMED` diagnostic as a text file after selecting the
matching damaged fixture. The portable bundle contains a final check:

```sh
bash fskit/signed_acceptance.sh acceptance-check . lzmesh \
  /path/first/readback.json /path/unmount/unmounted.json \
  /path/remount/readback.json /path/corrupt-refusal.txt \
  /path/replacement/replacement.json
# Repeat for lzraven with its own five evidence files.
```

After obtaining all five evidence files for **both** codecs, run the combined
signed-host acceptance gate. Supply Raven's first/readback, unmount, remount,
corrupt-refusal and replacement evidence paths, followed by Mesh's five paths:

```sh
bash fskit/signed_acceptance.sh acceptance-all . \
  /raven/first.json /raven/unmounted.json /raven/remount.json \
  /raven/corrupt-refusal.txt /raven/replacement.json \
  /mesh/first.json /mesh/unmounted.json /mesh/remount.json \
  /mesh/corrupt-refusal.txt /mesh/replacement.json
```

This validates the entire per-codec chain twice, requires identical restored
logical bytes and recorded macOS build, and rejects reused verification IDs
between the four mounted-readback events. A successful combined report still
needs independent review of real signed installation and mounts. The
verification code has portable synthetic tests; the signed-host command has
not been exercised on a provisioned Mac.

The command rechecks the SHA-256 manifest, signing identities, the archived
source and both readback JSON reports, the intervening unmount, kernel-level
read-only VFS flags, random/EOF evidence and the typed corruption-refusal
diagnostic. It emits a JSON summary with hashes of all four evidence files.
Its success establishes **internal consistency of operator-supplied evidence**, including the staged archive-replacement refusal;
the captured host diagnostic is not a signed machine attestation. Independent
review of the authorized Mac's actual installed extension and mounted
readback remains mandatory before merging PR #86. The gate can be regression
tested separately with `python3 fskit/acceptance_evidence.py --self-test`.
