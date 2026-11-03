// Experimental, separately mounted, read-only FSKit view of an ASCF archive.
// Native APFS decmpfs Raven/Mesh writing is deliberately outside this module.
import Foundation
import FSKit
import Darwin

@main
struct ASCFExtension: UnaryFileSystemExtension {
    var fileSystem: FSUnaryFileSystem & FSUnaryFileSystemOperations {
        ASCFFileSystem()
    }
}

final class ASCFFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations {
    private var volume: ASCFVolume?
    private var scopedURL: URL?

    private static func error(_ code: Int32) -> Error {
        fs_errorForPOSIXError(code)
    }

    // The bridge takes ownership only of its duplicate FD. The original
    // descriptor is opened O_RDONLY/O_NOFOLLOW and always closed here.
    private static func openArchive(_ url: URL, verify: Bool) throws -> (OpaquePointer, AscfInfo) {
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw error(errno) }
        defer { _ = Darwin.close(fd) }
        var handle: OpaquePointer?
        let openStatus = ascf_open_fd(fd, &handle)
        guard openStatus == 0, let handle else { throw error(openStatus == 0 ? EIO : openStatus) }
        do {
            var info = AscfInfo()
            let infoStatus = ascf_info(handle, &info)
            guard infoStatus == 0 else { throw error(infoStatus) }
            if verify {
                let checkStatus = ascf_verify_all(handle)
                guard checkStatus == 0 else { throw error(checkStatus) }
            }
            return (handle, info)
        } catch {
            ascf_close(handle)
            throw error
        }
    }

    // Derive a stable container ID from the verified logical-content digest.
    // A volume exposes exactly one file and does not invent filesystem paths.
    private static func identifier(for info: AscfInfo) -> FSContainerIdentifier {
        let bytes = withUnsafeBytes(of: info.logical_sha256) { Array($0.prefix(16)) }
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        let uuid = String(hex.prefix(8)) + "-" + String(hex.dropFirst(8).prefix(4))
            + "-" + String(hex.dropFirst(12).prefix(4)) + "-"
            + String(hex.dropFirst(16).prefix(4)) + "-" + String(hex.dropFirst(20))
        return FSContainerIdentifier(uuid: UUID(uuidString: uuid)!)
    }

    func probeResource(
        resource: FSResource,
        replyHandler: @escaping (FSProbeResult?, (any Error)?) -> Void
    ) {
        guard let path = resource as? FSPathURLResource else {
            replyHandler(.notRecognized, nil)
            return
        }
        let url = path.url
        guard url.startAccessingSecurityScopedResource() else {
            replyHandler(nil, Self.error(EACCES))
            return
        }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            // Do not advertise a malformed or corrupted archive as mountable.
            // The mount path independently verifies again before publication.
            let (handle, info) = try Self.openArchive(url, verify: true)
            defer { ascf_close(handle) }
            replyHandler(.usable(name: "Applesauce ASCF", containerID: Self.identifier(for: info)), nil)
        } catch {
            replyHandler(.notRecognized, nil)
        }
    }

    func loadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler: @escaping (FSVolume?, (any Error)?) -> Void
    ) {
        guard let path = resource as? FSPathURLResource else {
            replyHandler(nil, Self.error(EINVAL))
            return
        }
        guard volume == nil else {
            replyHandler(nil, Self.error(EBUSY))
            return
        }
        if options.taskOptions.contains("-f") {
            replyHandler(nil, Self.error(ENOTSUP))
            return
        }
        let url = path.url
        guard url.startAccessingSecurityScopedResource() else {
            replyHandler(nil, Self.error(EACCES))
            return
        }
        do {
            // Full verification is a mandatory pre-publication gate.
            let (handle, info) = try Self.openArchive(url, verify: true)
            let mounted = ASCFVolume(
                handle: handle, info: info, archiveName: url.deletingPathExtension().lastPathComponent
            )
            volume = mounted
            scopedURL = url
            containerStatus = .ready
            replyHandler(mounted, nil)
        } catch {
            url.stopAccessingSecurityScopedResource()
            replyHandler(nil, error)
        }
    }

    func unloadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler reply: @escaping ((any Error)?) -> Void
    ) {
        // FSKit deactivates the volume and finishes its operations before
        // unload. ASCFVolume releases the duplicated FD in deinit.
        volume = nil
        scopedURL?.stopAccessingSecurityScopedResource()
        scopedURL = nil
        reply(nil)
    }

    func didFinishLoading() {}
}
