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
