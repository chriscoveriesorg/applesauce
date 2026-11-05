// Authenticate the selected synthetic corruption-control fixture.
// A typed FSKit error is useful only when tied to the signed bundle's bytes.
import Foundation
import CryptoKit
import Darwin

enum ASCFCorruptFixtureProof {
    static func sha256(_ url: URL) throws -> String {
        let fd: Int32 = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return Darwin.open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        }
        guard fd >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno == 0 ? EINVAL : errno))
        }
        defer { _ = Darwin.close(fd) }

        var before = stat()
        guard Darwin.fstat(fd, &before) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        guard (before.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
        }

        let reader = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        var digest = SHA256()
        while let bytes = try reader.read(upToCount: 1024 * 1024), !bytes.isEmpty {
            digest.update(data: bytes)
        }
        var after = stat()
        var current = stat()
        guard Darwin.fstat(fd, &after) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        let pathValid: Bool = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return false }
            return Darwin.lstat(path, &current) == 0
        }
        // A read can advance atime. Compare the metadata that distinguishes
        // file replacement, shortening and ordinary in-place modifications.
        func same(_ a: stat, _ b: stat) -> Bool {
            a.st_dev == b.st_dev && a.st_ino == b.st_ino
                && a.st_size == b.st_size && a.st_mode == b.st_mode
                && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec
                && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
                && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec
                && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
        }
        guard pathValid && same(before, after) && same(after, current) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(ESTALE))
        }
        return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
