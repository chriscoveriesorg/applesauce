// Pin the verified ASCF archive to its pathname. Reject in-place edits,
// replacement, rename, and symlink substitution before serving mounted data.
// Access time is excluded because normal reads may change it.
import Foundation
import Darwin

struct ASCFArchiveIdentity: Equatable {
    private let device: dev_t
    private let inode: ino_t
    private let size: off_t
    private let modifiedSeconds: time_t
    private let modifiedNanoseconds: Int
    private let changedSeconds: time_t
    private let changedNanoseconds: Int

    private init(_ info: stat) {
        device = info.st_dev
        inode = info.st_ino
        size = info.st_size
        modifiedSeconds = info.st_mtimespec.tv_sec
        modifiedNanoseconds = info.st_mtimespec.tv_nsec
        changedSeconds = info.st_ctimespec.tv_sec
        changedNanoseconds = info.st_ctimespec.tv_nsec
    }

    static func capture(openDescriptor fd: Int32) throws -> ASCFArchiveIdentity {
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        guard (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
        }
        return ASCFArchiveIdentity(info)
    }

    func matchesPath(_ url: URL) -> Bool {
        var info = stat()
        let status: Int32 = url.withUnsafeFileSystemRepresentation { path in
            guard let path else { return -1 }
            return Darwin.lstat(path, &info)
        }
        return status == 0
            && (info.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG)
            && self == ASCFArchiveIdentity(info)
    }
}
