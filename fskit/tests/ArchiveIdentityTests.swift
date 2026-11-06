// Executable source-replacement tests on macOS; no FSKit mount or xattrs.
import Foundation
import Darwin

@main
struct ASCFArchiveIdentityTests {
    static func main() throws {
        let manager = FileManager.default
        let root = manager.temporaryDirectory.appendingPathComponent("ascf-identity-\(UUID().uuidString)")
        try manager.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: root) }
        let selected = root.appendingPathComponent("source.ascf")
        let moved = root.appendingPathComponent("moved.ascf")
        let content = Data(repeating: 0x41, count: 65_536)
        try content.write(to: selected)
        let fd: Int32 = selected.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return Darwin.open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        precondition(fd >= 0, "failed to open source")
        defer { _ = Darwin.close(fd) }
        let verified = try ASCFArchiveIdentity.capture(openDescriptor: fd)
        precondition(verified.matchesPath(selected), "unchanged archive rejected")

        // Rename with the old FD held open, then replace with identical bytes.
        try manager.moveItem(at: selected, to: moved)
        try content.write(to: selected)
        precondition(!verified.matchesPath(selected), "byte-identical replacement accepted")
        // macOS may update ctime on rename, which must invalidate a
        // previous path-bound verification even for the same pinned inode.
        precondition(!verified.matchesPath(moved), "archive rename accepted")
        try manager.removeItem(at: selected)
        try manager.createSymbolicLink(at: selected, withDestinationURL: moved)
        precondition(!verified.matchesPath(selected), "symlink replacement accepted")
        try manager.removeItem(at: selected)

        // Capture a fresh unchanged descriptor, then change one byte in
        // place without replacing the inode or changing the file length.
        let cleanFD: Int32 = moved.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return Darwin.open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        precondition(cleanFD >= 0, "cannot reopen moved archive")
        let cleanIdentity = try ASCFArchiveIdentity.capture(openDescriptor: cleanFD)
        _ = Darwin.close(cleanFD)
        precondition(cleanIdentity.matchesPath(moved), "fresh archive identity rejected")
        let writer = try FileHandle(forWritingTo: moved)
        try writer.write(contentsOf: Data([0x42]))
        try writer.synchronize()
        try writer.close()
        precondition(!cleanIdentity.matchesPath(moved), "same-size in-place edit accepted")
        precondition(!verified.matchesPath(selected), "missing source accepted")
        print("ASCF source identity gate: replacement, symlink, and edits refused")
    }
}
