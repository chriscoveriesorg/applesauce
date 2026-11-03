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
