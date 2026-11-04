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
        precondition(verified.matchesPath(moved), "original pinned inode rejected")
        try manager.removeItem(at: selected)
        try manager.createSymbolicLink(at: selected, withDestinationURL: moved)
        precondition(!verified.matchesPath(selected), "symlink replacement accepted")
        try manager.removeItem(at: selected)

        // In-place same-size edits must also invalidate the prior digest gate.
        try Data(repeating: 0x42, count: content.count).write(to: moved)
        precondition(!verified.matchesPath(moved), "same-size edit accepted")
        precondition(!verified.matchesPath(selected), "missing source accepted")
        print("ASCF source identity gate: replacement, symlink, and edits refused")
    }
}
