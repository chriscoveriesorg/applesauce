// Experimental, separately mounted, read-only FSKit view of an ASCF archive.
// Native APFS decmpfs Raven/Mesh writing is deliberately outside this module.
import Foundation
import FSKit
import Darwin
import CryptoKit

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
    private static func openArchive(_ url: URL, verify: Bool) throws -> (OpaquePointer, AscfInfo, ASCFArchiveIdentity) {
        // Opening a FIFO named *.ascf must never block FSKit's probe or load.
        // The bridge rejects every nonregular descriptor before parsing it.
        let fd = Darwin.open(url.path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw error(errno) }
        defer { _ = Darwin.close(fd) }
        let identity = try ASCFArchiveIdentity.capture(openDescriptor: fd)
        var handle: OpaquePointer?
        let openStatus = ascf_open_fd(fd, &handle)
        guard openStatus == 0, let handle else { throw error(openStatus == 0 ? EIO : openStatus) }
        do {
            var info = AscfInfo()
            let infoStatus = ascf_info(handle, &info)
            guard infoStatus == 0 else { throw error(infoStatus) }
            if verify {
                let checkStatus = ascf_verify_all(handle)
                guard checkStatus == 0 else {
                    // The magic/header and chunk table parsed successfully.
                    // A decode or SHA-256 failure means an ASCF resource was
                    // recognized but is damaged. Report a distinct FSKit
                    // error so a signed negative mount can distinguish a
                    // corrupt archive from signing/extension failures.
                    if checkStatus == EIO {
                        throw NSError(domain: FSKitErrorDomain,
                                      code: FSError.Code.resourceDamaged.rawValue,
                                      userInfo: [NSLocalizedDescriptionKey:
                                          "Recognized ASCF failed full codec/digest verification"])
                    }
                    throw error(checkStatus)
                }
            }
            guard identity.matchesPath(url) else { throw error(ESTALE) }
            return (handle, info, identity)
        } catch {
            ascf_close(handle)
            throw error
        }
    }

    // A unary FSKit container and its volume must advertise the SAME UUID.
    // Make it stable across probe/load and unmount/remount, and distinguish
    // two archives with identical logical bytes but different codecs or paths.
    // Random volume IDs break the identity FSKit established during probe.
    private static func identifier(for info: AscfInfo, archiveURL: URL) -> UUID {
        var material = Data("applesauce-ascf-volume-v1".utf8)
        var codec = info.codec_selector.littleEndian
        withUnsafeBytes(of: &codec) { material.append(contentsOf: $0) }
        withUnsafeBytes(of: info.logical_sha256) { material.append(contentsOf: $0) }
        material.append(contentsOf: archiveURL.standardizedFileURL.path.utf8)
        let hex = SHA256.hash(data: material).prefix(16)
            .map { String(format: "%02x", $0) }.joined()
        let uuid = String(hex.prefix(8)) + "-" + String(hex.dropFirst(8).prefix(4))
            + "-" + String(hex.dropFirst(12).prefix(4)) + "-"
            + String(hex.dropFirst(16).prefix(4)) + "-" + String(hex.dropFirst(20))
        return UUID(uuidString: uuid)!
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
            // Report access failures for selected ASCF candidates, but do
            // not claim errors while probing unrelated unreadable formats.
            if url.pathExtension.lowercased() == "ascf" {
                replyHandler(nil, Self.error(EACCES))
            } else {
                replyHandler(.notRecognized, nil)
            }
            return
        }
        defer { url.stopAccessingSecurityScopedResource() }
        do {
            // Do not advertise a malformed or corrupted archive as mountable.
            // The mount path independently verifies again before publication.
            let (handle, info, _) = try Self.openArchive(url, verify: true)
            defer { ascf_close(handle) }
            replyHandler(.usable(name: "Applesauce ASCF", containerID: FSContainerIdentifier(uuid: Self.identifier(for: info, archiveURL: url))), nil)
        } catch {
            let nsError = error as NSError
            if nsError.domain == FSKitErrorDomain
                && nsError.code == FSError.Code.resourceDamaged.rawValue {
                // A recognized ASCF payload failed codec or SHA-256 verification.
                // Preserve the typed failure for the host's negative control.
                replyHandler(nil, error)
            } else if url.pathExtension.lowercased() == "ascf"
                && nsError.domain == NSPOSIXErrorDomain
                && [Int(EACCES), Int(EPERM), Int(ESTALE), Int(EMFILE),
                    Int(ENFILE), Int(ENOMEM)].contains(nsError.code) {
                // Probe can run with a security-scoped resource that was
                // revoked, moved or blocked by a sandbox/signing restriction.
                // Report those operational failures to FSClient. Masking them
                // as notRecognized makes a correctly selected .ascf archive
                // indistinguishable from an unsupported file.
                replyHandler(nil, error)
            } else {
                // Other formats and unparseable ASCF headers remain ordinary
                // probe misses, avoiding claimed support for random files.
                replyHandler(.notRecognized, nil)
            }
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
            let (handle, info, identity) = try Self.openArchive(url, verify: true)
            let mounted = ASCFVolume(
                handle: handle, info: info, archiveName: url.deletingPathExtension().lastPathComponent,
                identifier: Self.identifier(for: info, archiveURL: url),
                selectedArchiveURL: url, sourceIdentity: identity
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
        // FSKit's notReady state requires a reason on the macOS 27 SDK.
        containerStatus = .notReady(status: Self.error(ENODEV))
        reply(nil)
    }

    func didFinishLoading() {}
}
