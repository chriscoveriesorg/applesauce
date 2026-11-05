// The host deliberately mounts a separate read-only volume. It never alters
// the original file's APFS xattrs or asserts native decmpfs support.
import AppKit
import Combine
import Darwin
import FSKit
import SwiftUI
import UniformTypeIdentifiers

@main
@MainActor
struct ApplesauceASCFHost: App {
    // App ownership survives closing a window and is shared by every window.
    // A view-owned @State lock would allow simultaneous FSClient requests.
    @StateObject private var controller = ASCFMountController()

    var body: some Scene {
        WindowGroup {
            ASCFMountView().environmentObject(controller)
        }
    }
}

@MainActor
private struct ASCFMountView: View {
    @EnvironmentObject private var controller: ASCFMountController
    @State private var selectingArchive = false
    @State private var selectingCorruptArchive = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Applesauce ASCF").font(.title2)
            Text("Read-only LZRaven / LZMesh archive mount")
            Text(controller.status).textSelection(.enabled)
            Button("Choose .ascf archive and mount") {
                selectingArchive = true
            }
            .disabled(controller.isWorking || controller.mountedURL != nil || controller.multipleASCFMounts)
            // This is an explicit user-driven negative control on the signed
            // host. It runs the actual FSClient mount path against a generated
            // corrupted copy, rather than substituting a decoder unit test.
            Button("Test corrupted archive mount refusal") {
                selectingCorruptArchive = true
            }
            .disabled(controller.isWorking || controller.mountedURL != nil || controller.multipleASCFMounts)
            Button("Copy mount diagnostic") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(controller.status, forType: .string)
            }
            Button("Open File System Extensions settings") {
                controller.openExtensionSettings()
            }
            .disabled(controller.isWorking)
            if let mountedURL = controller.mountedURL {
                Button("Reveal mounted archive in Finder") {
                    NSWorkspace.shared.open(mountedURL)
                }
                Button("Unmount read-only volume") {
                    controller.unmount(mountedURL)
                }
                .disabled(controller.isWorking)
            }
        }
        .padding(24)
        .frame(minWidth: 460, minHeight: 220)
        .onAppear { controller.reconcileMountedVolumes() }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didUnmountNotification)) { _ in
            // Finder or a different process may unmount an archive after the
            // host's last successful mount. Rebuild state from the VFS rather
            // than trusting the last button action.
            controller.reconcileMountedVolumes()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didMountNotification)) { _ in
            controller.reconcileMountedVolumes()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didRenameVolumeNotification)) { _ in
            controller.reconcileMountedVolumes()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didActivateApplicationNotification)) { _ in
            controller.reconcileMountedVolumes()
        }
        .fileImporter(
            isPresented: $selectingArchive,
            allowedContentTypes: [UTType(filenameExtension: "ascf") ?? .data],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                guard url.pathExtension.lowercased() == "ascf" else {
                    controller.showIdleStatus("Select a .ascf archive.")
                    return
                }
                controller.mount(url, expectCorruptRefusal: false)
            case .failure(let error):
                controller.showIdleStatus("Archive selection failed: \(error.localizedDescription)")
            }
        }
        .fileImporter(
            isPresented: $selectingCorruptArchive,
            allowedContentTypes: [UTType(filenameExtension: "ascf") ?? .data],
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                guard let url = urls.first else { return }
                guard url.lastPathComponent.hasSuffix(".corrupt.ascf") else {
                    controller.showIdleStatus("Select the generated source.<codec>.corrupt.ascf negative-control fixture.")
                    return
                }
                controller.mount(url, expectCorruptRefusal: true)
            case .failure(let error):
                controller.showIdleStatus("Corruption-control selection failed: \(error.localizedDescription)")
            }
        }
    }
}

// One main-actor controller owns FSClient requests for the entire process.
// Windows only own their file pickers; closing one cannot discard an operation.
@MainActor
private final class ASCFMountController: ObservableObject {
    @Published private(set) var status = "Select a verified ASCF archive to mount separately."
    @Published private(set) var mountedURL: URL?
    @Published private(set) var multipleASCFMounts = false
    @Published private var operations = ASCFOperationGate()

    var isWorking: Bool { operations.isBusy }
    private var mountedVolumeCount: Int { multipleASCFMounts ? 2 : (mountedURL == nil ? 0 : 1) }

    func showIdleStatus(_ message: String) {
        // A cancelled picker in another window must not replace live diagnostics.
        guard !isWorking else { return }
        status = message
    }

    func openExtensionSettings() {
        guard !isWorking else { return }
        if !FSClient.shared.openFileSystemExtensionsSettings() {
            status = "macOS could not open File System Extensions settings."
        }
    }

    // Treat an FSClient mount callback as provisional until the VFS reports
    // the actual ASCF filesystem with the kernel's read-only flag. A successful
    // callback alone does not establish that the expected extension mounted.
    // Reuse this gate when recovering mounts after a host relaunch.
    private func isVerifiedReadOnlyASCFMount(_ volume: URL) -> Bool {
        guard ASCFMountLocation.isAllowed(volume.path) else { return false }
        // Swift imports Darwin's statfs structure with the same name as its
        // C function. fstatfs binds the check to the directory we opened.
        let fd = volume.withUnsafeFileSystemRepresentation { path -> Int32 in
            guard let path else { return -1 }
            return Darwin.open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard fd >= 0 else { return false }
        defer { _ = Darwin.close(fd) }
        var opened = stat()
        guard Darwin.fstat(fd, &opened) == 0 else { return false }
        // An open directory can outlive the pathname that selected it.
        // Match the live pathname to the descriptor on both sides of fstatfs,
        // so an unmounted/replaced volume cannot be reported as mounted.
        func pathMatchesDescriptor() -> Bool {
            var current = stat()
            let inspected = volume.withUnsafeFileSystemRepresentation { path -> Bool in
                guard let path else { return false }
                return Darwin.lstat(path, &current) == 0
            }
            return inspected && current.st_dev == opened.st_dev
                && current.st_ino == opened.st_ino
        }
        guard pathMatchesDescriptor() else { return false }
        var info = statfs()
        guard Darwin.fstatfs(fd, &info) == 0 else { return false }
        guard pathMatchesDescriptor() else { return false }
        let type = withUnsafeBytes(of: info.f_fstypename) { bytes in
            String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
        return type == "ascf" && (info.f_flags & UInt32(MNT_RDONLY)) != 0
    }

    // Read the kernel's complete mount table, including the private /private/tmp
    // location used by signed_acceptance.sh cli-mount. FileManager's visible
    // volume list can omit that mount. Never treat discovery failure as zero
    // mounts, or another host window could launch a conflicting FSClient call.
    private func mountedASCFVolumes() -> [URL]? {
        var table: UnsafeMutablePointer<statfs>?
        let count = Darwin.getmntinfo(&table, Int32(MNT_NOWAIT))
        guard count > 0, let table else { return nil }
        var verified: [URL] = []
        for index in 0..<Int(count) {
            let entry = table[index]
            let kind = withUnsafeBytes(of: entry.f_fstypename) { bytes in
                String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self)
            }
            guard kind == "ascf" else { continue }
            let path = withUnsafeBytes(of: entry.f_mntonname) { bytes in
                String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self)
            }
            // If ANY ASCF mount is unknown, inaccessible or writable,
            // block additional mounts instead of silently losing track of it.
            guard ASCFMountLocation.isAllowed(path) else { return nil }
            let url = URL(fileURLWithPath: path, isDirectory: true)
            guard isVerifiedReadOnlyASCFMount(url) else { return nil }
            verified.append(url)
        }
        return verified
    }

    func reconcileMountedVolumes() {
        guard !isWorking else { return }
        guard let volumes = mountedASCFVolumes() else {
            multipleASCFMounts = true
            mountedURL = nil
            status = "Cannot verify the kernel ASCF mount table. Further mounting is blocked; inspect mounted volumes in Terminal."
            return
        }
        multipleASCFMounts = volumes.count > 1
        if volumes.count > 1 {
            mountedURL = nil
            status = "Multiple ASCF volumes found. Unmount extras in Finder before selecting another archive."
        } else if let volume = volumes.first {
            // Includes volumes mounted before this host window was opened.
            if mountedURL?.standardizedFileURL != volume.standardizedFileURL {
                mountedURL = volume
                status = "Existing read-only ASCF volume at \(volume.path)"
            }
        } else if mountedURL != nil {
            mountedURL = nil
            status = "ASCF volume is no longer mounted."
        }
    }

    func mount(_ url: URL, expectCorruptRefusal: Bool) {
        guard !isWorking else { return }
        // The picker may have stayed open while another window/process mounted.
        reconcileMountedVolumes()
        guard let ticket = operations.begin(.mount, mountedVolumeCount: mountedVolumeCount) else { return }
        status = expectCorruptRefusal
            ? "Checking installed FSKit extension before corrupted mount attempt..."
            : "Checking installed FSKit extension..."
        // A valid signed app may still have an extension that macOS has not
        // registered or that the user has disabled. Show the actionable cause
        // before opening the security-scoped archive or requesting a mount.
        FSClient.shared.fetchInstalledExtensions { [self] modules, error in
            DispatchQueue.main.async { [self] in
                guard operations.isCurrent(ticket) else { return }
                if let error {
                    operations.finish(ticket)
                    status = "FSKit extension discovery failed: \(error.localizedDescription)"
                    return
                }
                let moduleID = "org.chriscoveries.applesauce.ascfhost.ascfextension"
                guard let module = modules?.first(where: { $0.bundleIdentifier == moduleID }) else {
                    operations.finish(ticket)
                    status = "ASCF extension is not installed. Install the signed host, then enable its extension in System Settings."
                    return
                }
                guard module.isEnabled else {
                    operations.finish(ticket)
                    status = "ASCF extension is disabled. Enable it in File System Extensions settings."
                    return
                }
                beginMount(url, expectCorruptRefusal: expectCorruptRefusal, ticket: ticket)
            }
        }
    }

    private func beginMount(_ url: URL, expectCorruptRefusal: Bool,
                            ticket: ASCFOperationGate.Ticket) {
        guard operations.isCurrent(ticket) else { return }
        // Discovery is asynchronous. Recheck external mounts before FSClient.
        guard let existing = mountedASCFVolumes() else {
            operations.finish(ticket)
            multipleASCFMounts = true
            mountedURL = nil
            status = "Cannot verify the ASCF mount table after extension discovery. Mounting is blocked."
            return
        }
        guard existing.isEmpty else {
            operations.finish(ticket)
            reconcileMountedVolumes()
            return
        }
        // The picker supplies a security-scoped URL. FSKit conveys the scope
        // to the extension; neither process needs write access to the archive.
        guard url.startAccessingSecurityScopedResource() else {
            operations.finish(ticket)
            status = "macOS did not grant read access to the selected archive."
            return
        }
        status = expectCorruptRefusal
            ? "Attempting generated corrupt archive through the signed FSKit mount path..."
            : "Verifying archive before read-only mount..."
        let resource = FSPathURLResource(url: url, writable: false)
        FSClient.shared.mountSingleVolume(
            resource: resource,
            bundleID: "org.chriscoveries.applesauce.ascfhost.ascfextension",
            options: []
        ) { [self] mounted, error in
            url.stopAccessingSecurityScopedResource()
            DispatchQueue.main.async { [self] in
                guard operations.finish(ticket) else { return }
                // A failed callback can still leave a mounted VFS volume.
                // Reconcile both observations before reporting failure or
                // allowing a second mount. The callback path is never trusted
                // without its independent read-only ASCF statfs check.
                guard let observed = mountedASCFVolumes() else {
                    multipleASCFMounts = true
                    mountedURL = nil
                    status = "MOUNT_INCONCLUSIVE: kernel ASCF mount discovery failed after FSClient. Inspect all mounts before retrying."
                    return
                }
                let verifiedReturned = mounted.flatMap {
                    isVerifiedReadOnlyASCFMount($0) ? $0.path : nil
                }
                let outcome = ASCFMountPostflight(
                    returnedMount: mounted != nil, callbackError: error != nil,
                    verifiedReturnedPath: verifiedReturned,
                    observedVerifiedPaths: observed.map(\.path)
                )
                multipleASCFMounts = outcome.verifiedPaths.count > 1
                if let path = outcome.singleVerifiedPath {
                    // Only use a path in the live VFS snapshot; an FSClient
                    // callback may refer to a volume that has already gone.
                    mountedURL = observed.first(where: { $0.path == path })
                } else {
                    mountedURL = nil
                }
                if expectCorruptRefusal {
                    if let mounted {
                        status = "CORRUPT_REFUSAL_FAIL: FSKit returned a mount at \(mounted.path). Unmount it and reject acceptance."
                    } else if outcome.hasOrphanedMount {
                        status = "CORRUPT_REFUSAL_INCONCLUSIVE: FSKit returned an error but an ASCF volume remains at \(outcome.verifiedPaths.joined(separator: ", ")). Unmount normally; acceptance is blocked."
                    } else if let error {
                        let actualError = error as NSError
                        let detail = "\(actualError.domain) code \(actualError.code): \(actualError.localizedDescription)"
                        if actualError.domain == FSKitErrorDomain
                            && actualError.code == FSError.Code.resourceDamaged.rawValue {
                            status = "CORRUPT_REFUSAL_CONFIRMED: \(url.lastPathComponent): signed FSKit probe rejected the recognized ASCF payload: \(detail)"
                        } else {
                            status = "CORRUPT_REFUSAL_INCONCLUSIVE: mount failed without a verified ASCF damage error: \(detail). Check activation, entitlements and access."
                        }
                    } else {
                        status = "CORRUPT_REFUSAL_INCONCLUSIVE: FSClient returned neither mount nor error."
                    }
                    return
                }
                if outcome.cleanSuccess, let path = outcome.singleVerifiedPath {
                    status = "Verified read-only ASCF mount at \(path)"
                } else if outcome.hasOrphanedMount {
                    status = "MOUNT_INCONCLUSIVE: FSClient callback disagreed with the live VFS. Read-only ASCF mount(s) at \(outcome.verifiedPaths.joined(separator: ", ")). Unmount normally before retrying."
                } else if verifiedReturned != nil && observed.isEmpty {
                    status = "MOUNT_INCONCLUSIVE: FSClient returned a verified ASCF mount which disappeared before the kernel mount-table check. Inspect the mount lifecycle before retrying."
                } else if let error {
                    status = "Mount failed: \(error.localizedDescription)"
                } else if let mounted {
                    status = "FSKit returned a mount without verified ASCF read-only VFS identity at \(mounted.path). Inspect the mount manually; acceptance is blocked."
                } else {
                    status = "FSKit returned no mounted volume."
                }
            }
        }
    }

    func unmount(_ url: URL) {
        guard !isWorking else { return }
        reconcileMountedVolumes()
        guard mountedURL?.standardizedFileURL == url.standardizedFileURL,
              let ticket = operations.begin(.unmount, mountedVolumeCount: mountedVolumeCount) else { return }
        status = "Unmounting the read-only volume..."
        // FSKit publishes a logical volume, not an ejectable disk device.
        // FileManager's asynchronous volume unmount handles virtual mounts,
        // reports busy-volume failures and never requests forced ejection.
        FileManager.default.unmountVolume(at: url, options: []) { [self] error in
            DispatchQueue.main.async { [self] in
                guard operations.finish(ticket) else { return }
                if let error {
                    // Reconcile a concurrent Finder unmount while retaining
                    // the OS error for troubleshooting and acceptance.
                    guard let remaining = mountedASCFVolumes() else {
                        multipleASCFMounts = true
                        mountedURL = nil
                        status = "UNMOUNT_INCONCLUSIVE: \(error.localizedDescription); kernel mount discovery also failed."
                        return
                    }
                    multipleASCFMounts = remaining.count > 1
                    mountedURL = remaining.first
                    status = "Unmount failed: \(error.localizedDescription). Remaining ASCF volumes: \(remaining.count)."
                } else {
                    // An asynchronous success callback is not proof that the
                    // volume disappeared. Reinspect the live VFS before
                    // telling the operator that unmount acceptance passed.
                    guard let remaining = mountedASCFVolumes() else {
                        multipleASCFMounts = true
                        mountedURL = nil
                        status = "UNMOUNT_INCONCLUSIVE: macOS reported success but the ASCF mount table cannot be verified."
                        return
                    }
                    if isVerifiedReadOnlyASCFMount(url) || !remaining.isEmpty {
                        multipleASCFMounts = remaining.count > 1
                        mountedURL = remaining.first ?? url
                        status = "UNMOUNT_INCONCLUSIVE: macOS reported success, but a read-only ASCF volume is still mounted. Inspect Finder and retry."
                    } else {
                        mountedURL = nil
                        multipleASCFMounts = false
                        status = "Unmounted read-only archive; VFS confirms no ASCF volume remains."
                    }
                }
            }
        }
    }
}
