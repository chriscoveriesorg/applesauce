// Authenticate the selected synthetic corruption-control fixture.
// A typed FSKit error is useful only when tied to the signed bundle's bytes.
import Foundation
import CryptoKit
import Darwin

enum ASCFCorruptFixtureProof {
    // Keep the verified file identity alongside the digest. Identical bytes
    // at a newly substituted pathname are still a changed mount source.
    struct Fingerprint: Equatable {
        let sha256: String
        let sourceIdentity: String
    }

    static func sha256(_ url: URL) throws -> String {
        try fingerprint(url).sha256
    }

    // Keep this pure reader boundary independently testable. Some virtual
    // filesystems may return EOF while fstat still reports logical bytes.
    // A partial digest must never certify a damaged fixture for FSKit.
    static func hashStream(expectedSize: Int64,
                           readChunk: () throws -> Data?) throws -> String {
        guard expectedSize >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(EIO))
        }
        var digest = SHA256()
        var hashedBytes: Int64 = 0
        while let bytes = try readChunk(), !bytes.isEmpty {
            let (next, overflow) = hashedBytes.addingReportingOverflow(Int64(bytes.count))
            guard !overflow && next <= expectedSize else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(EIO))
            }
            hashedBytes = next
            digest.update(data: bytes)
        }
        guard hashedBytes == expectedSize else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(EIO))
        }
        return digest.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func fingerprint(_ url: URL) throws -> Fingerprint {
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
        let checksum = try hashStream(expectedSize: Int64(before.st_size)) {
            try reader.read(upToCount: 1024 * 1024)
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
        return Fingerprint(
            sha256: checksum,
            sourceIdentity: [
                String(after.st_dev), String(after.st_ino), String(after.st_size),
                String(after.st_mode), String(after.st_mtimespec.tv_sec),
                String(after.st_mtimespec.tv_nsec), String(after.st_ctimespec.tv_sec),
                String(after.st_ctimespec.tv_nsec)
            ].joined(separator: ":")
        )
    }
}
