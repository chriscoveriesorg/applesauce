# FSKit read-only archive bridge (experimental)

This crate exposes the existing versioned LZRAVEN/LZMESH cold-archive reader
through a stable, bounded C ABI for a future *separately mounted* FSKit
filesystem. It is **not** an FSKit app extension and does **not** provide
same-path transparent APFS compression. Native Raven/Mesh writes remain closed.

The FSKit extension must implement the mount, file enumeration, metadata,
security-scoped resource access, read-only permissions, stable backing identity,
entitlements, signing and clean unmount lifecycle. Apple documents the
FSUnaryFileSystem/FSVolume.ReadWriteOperations approach:
https://developer.apple.com/documentation/fskit/building-a-passthrough-file-system

A caller supplies a dedicated O_RDONLY regular archive descriptor. The bridge
duplicates it and retains indexed metadata. ascf_pread returns verified logical
bytes with ordinary EOF semantics, at most 8 MiB per call; corrupt later chunks
never leak partially verified output. Cross-thread calls use one decoder mutex
and its reusable scratch. ascf_info supplies the logical size, public buffer
codec selector and whole-file SHA-256. ascf_verify_all checks every chunk before
publication; the mount must ensure backing archives remain immutable afterward.

The C header is include/applesauce_fskit_bridge.h. Build with:

    cargo test --locked -p applesauce-fskit-bridge
    cargo build --locked --release -p applesauce-fskit-bridge

The resulting libapplesauce_fskit_bridge.a can be linked into a signed FSKit
extension. The extension and end-to-end mounted-file tests remain future
milestones. No filesystem attributes, live user files or unknown kernel types
are modified by this bridge. The experimental ASCF format is not a sole backup.
