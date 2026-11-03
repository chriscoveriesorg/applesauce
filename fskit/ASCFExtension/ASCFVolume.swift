// Single-file, read-only FSKit volume. All logical bytes come from the
// SHA-256-verified ASCF bridge; directory operations never visit host paths.
import Foundation
import FSKit
import Darwin

final class ASCFItem: FSItem {
    let name: FSFileName
    let attributes: FSItem.Attributes

    init(name: FSFileName, fileID: FSItem.Identifier, parentID: FSItem.Identifier,
         type: FSItem.ItemType, size: UInt64) {
        self.name = name
        let a = FSItem.Attributes()
        a.fileID = fileID
        a.parentID = parentID
        a.type = type
        a.uid = getuid()
        a.gid = getgid()
        a.linkCount = 1
        a.size = size
        // This is logical allocation, not a claim about compressed APFS blocks.
        a.allocSize = size
        a.mode = type == .directory ? UInt32(S_IFDIR | 0o555) : UInt32(S_IFREG | 0o444)
        a.flags = UInt32(UF_IMMUTABLE)
        self.attributes = a
        super.init()
    }
}

final class ASCFVolume: FSVolume {
    private let handle: OpaquePointer
    private let root: ASCFItem
    private let file: ASCFItem

    init(handle: OpaquePointer, info: AscfInfo, archiveName: String, identifier: UUID) {
        self.handle = handle
        let safeName = archiveName.isEmpty || archiveName == "." || archiveName == ".."
            ? "restored" : archiveName
        root = ASCFItem(name: FSFileName(string: "/"),
                        fileID: .rootDirectory, parentID: .parentOfRoot,
                        type: .directory, size: 1)
        file = ASCFItem(name: FSFileName(string: safeName),
                        fileID: FSItem.Identifier(rawValue: FSItem.Identifier.rootDirectory.rawValue + 1) ?? .invalid,
                        parentID: .rootDirectory, type: .file, size: info.logical_size)
        super.init(volumeID: FSVolume.Identifier(uuid: identifier),
                   volumeName: FSFileName(string: "Applesauce ASCF"))
    }

    deinit { ascf_close(handle) }

    private func failure(_ code: Int32) -> Error { fs_errorForPOSIXError(code) }
    private func isRoot(_ item: FSItem) -> Bool { item === root }
    private func isFile(_ item: FSItem) -> Bool { item === file }
}

extension ASCFVolume: FSVolume.PathConfOperations {
    var maximumLinkCount: Int { 1 }
    var maximumNameLength: Int { 255 }
    var restrictsOwnershipChanges: Bool { true }
    var truncatesLongNames: Bool { false }
    var maximumXattrSize: Int { 0 }
    var maximumFileSize: UInt64 { file.attributes.size }
}

extension ASCFVolume: FSVolume.Operations {
    // Ask FSKit to mount the volume read-only at the VFS layer as well as
    // rejecting every modifying operation. FSKit samples this property after
    // mount(options:) returns; a client-supplied mount option is insufficient.
    var requestedMountOptions: FSVolume.MountOptions { .readOnly }

    var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        let capabilities = FSVolume.SupportedCapabilities()
        capabilities.supportsPersistentObjectIDs = true
        capabilities.supports64BitObjectIDs = true
        capabilities.doesNotSupportVolumeSizes = true
        capabilities.caseFormat = .sensitive
        return capabilities
    }

    var volumeStatistics: FSStatFSResult {
        let stats = FSStatFSResult(fileSystemTypeName: "ascf")
        stats.blockSize = 4096
        stats.ioSize = 1024 * 1024
        stats.totalBlocks = 0
        stats.availableBlocks = 0
        stats.freeBlocks = 0
        stats.totalFiles = 2
        stats.freeFiles = 0
        return stats
    }

    func activate(options: FSTaskOptions) async throws -> FSItem { root }
    func deactivate(options: FSDeactivateOptions = []) async throws {}
    func mount(options: FSTaskOptions) async throws {}
    func unmount() async {}
    func synchronize(flags: FSSyncFlags) async throws {}

    func attributes(_ requested: FSItem.GetAttributesRequest,
                    of item: FSItem) async throws -> FSItem.Attributes {
        guard let entry = item as? ASCFItem, isRoot(item) || isFile(item) else {
            throw failure(ENOENT)
        }
        return entry.attributes
    }

    func setAttributes(_ requested: FSItem.SetAttributesRequest,
                       on item: FSItem) async throws -> FSItem.Attributes {
        throw failure(EROFS)
    }

    func lookupItem(named name: FSFileName,
                    inDirectory directory: FSItem) async throws -> (FSItem, FSFileName) {
        guard isRoot(directory), name == file.name else { throw failure(ENOENT) }
        return (file, file.name)
    }

    func reclaimItem(_ item: FSItem) async throws {}
    func readSymbolicLink(_ item: FSItem) async throws -> FSFileName { throw failure(EINVAL) }

    func enumerateDirectory(_ directory: FSItem, startingAt cookie: FSDirectoryCookie,
                            verifier: FSDirectoryVerifier,
                            attributes: FSItem.GetAttributesRequest?,
                            packer: FSDirectoryEntryPacker) async throws -> FSDirectoryVerifier {
        guard isRoot(directory) else { throw failure(ENOTDIR) }
        // FSKit requires "." and ".." when attributes are not requested,
        // while requests with attributes should enumerate ordinary items only.
        // Cookies identify a position in the canonical [., .., file] sequence.
        // A failed pack does not advance it, so FSKit can retry with more room.
        let includeDotEntries = attributes == nil
        let start: Int
        switch cookie {
        case .initial:
            start = includeDotEntries ? 0 : 2
        case FSDirectoryCookie(1) where includeDotEntries:
            start = 1
        case FSDirectoryCookie(2) where includeDotEntries:
            start = 2
        case FSDirectoryCookie(3):
            return FSDirectoryVerifier(1)
        default:
            // FSKit requires its specific invalid-cookie error here; EINVAL
            // prevents callers from distinguishing a stale directory cursor.
            throw NSError(domain: FSKitErrorDomain,
                          code: FSError.Code.invalidDirectoryCookie.rawValue)
        }
        for index in start..<3 {
            let name: FSFileName
            let kind: FSItem.ItemType
            let identifier: FSItem.Identifier
            if index == 0 {
                name = FSFileName(string: ".")
                kind = .directory
                identifier = root.attributes.fileID
            } else if index == 1 {
                name = FSFileName(string: "..")
                kind = .directory
                identifier = root.attributes.fileID
            } else {
                name = file.name
                kind = .file
                identifier = file.attributes.fileID
            }
            let packed = packer.packEntry(name: name, itemType: kind,
                                          itemID: identifier,
                                          nextCookie: FSDirectoryCookie(UInt64(index + 1)),
                                          attributes: index == 2 ? (attributes == nil ? nil : file.attributes) : nil)
            if !packed { break }
        }
        // A fixed, nonzero verifier represents this immutable directory.
        return FSDirectoryVerifier(1)
    }

    func createItem(named name: FSFileName, type: FSItem.ItemType, inDirectory directory: FSItem,
                    attributes requested: FSItem.SetAttributesRequest) async throws -> (FSItem, FSFileName) {
        throw failure(EROFS)
    }

    func createSymbolicLink(named name: FSFileName, inDirectory directory: FSItem,
                            attributes requested: FSItem.SetAttributesRequest,
                            linkContents: FSFileName) async throws -> (FSItem, FSFileName) {
        throw failure(EROFS)
    }

    func createLink(to item: FSItem, named name: FSFileName,
                    inDirectory directory: FSItem) async throws -> FSFileName {
        throw failure(EROFS)
    }

    func removeItem(_ item: FSItem, named name: FSFileName,
                    fromDirectory directory: FSItem) async throws { throw failure(EROFS) }

    func renameItem(_ item: FSItem, inDirectory sourceDirectory: FSItem,
                    named sourceName: FSFileName, to destinationName: FSFileName,
                    inDirectory destinationDirectory: FSItem, overItem: FSItem?) async throws -> FSFileName {
        throw failure(EROFS)
    }
}

extension ASCFVolume: FSVolume.OpenCloseOperations {
    func openItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        guard isRoot(item) || isFile(item) else { throw failure(ENOENT) }
        if modes.contains(.write) { throw failure(EROFS) }
    }
    func closeItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {}
}

extension ASCFVolume: FSVolume.ReadWriteOperations {
    func read(from item: FSItem, at offset: off_t, length: Int,
              into buffer: FSMutableFileDataBuffer) async throws -> Int {
        guard isFile(item) else { throw failure(EISDIR) }
        guard offset >= 0, length >= 0 else { throw failure(EINVAL) }
        // A short read is valid. The bridge bounds each request to 8 MiB and
        // leaves the output unchanged on corrupt chunk or decoder failure.
        let count = min(length, buffer.length, 8 * 1024 * 1024)
        var actual = 0
        let status: Int32 = buffer.withUnsafeMutableBytes { bytes in
            ascf_pread(handle, UInt64(offset),
                       bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                       count, &actual)
        }
        guard status == 0 else { throw failure(status) }
        return actual
    }

    func write(contents: Data, to item: FSItem, at offset: off_t) async throws -> Int {
        throw failure(EROFS)
    }
}
