// The host deliberately mounts a separate read-only volume. It never alters
// the original file's APFS xattrs or asserts native decmpfs support.
import AppKit
import Darwin
import FSKit
import SwiftUI
import UniformTypeIdentifiers

@main
struct ApplesauceASCFHost: App {
    var body: some Scene {
        WindowGroup {
            ASCFMountView()
        }
    }
}

private struct ASCFMountView: View {
    @State private var selectingArchive = false
    @State private var selectingCorruptArchive = false
    @State private var status = "Select a verified ASCF archive to mount separately."
    @State private var mountedURL: URL?
    @State private var isWorking = false
    @State private var multipleASCFMounts = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Applesauce ASCF").font(.title2)
            Text("Read-only LZRaven / LZMesh archive mount")
            Text(status).textSelection(.enabled)
            Button("Choose .ascf archive and mount") {
                selectingArchive = true
            }
            .disabled(isWorking || mountedURL != nil || multipleASCFMounts)
            // This is an explicit user-driven negative control on the signed
            // host. It runs the actual FSClient mount path against a generated
            // corrupted copy, rather than substituting a decoder unit test.
            Button("Test corrupted archive mount refusal") {
                selectingCorruptArchive = true
            }
            .disabled(isWorking || mountedURL != nil || multipleASCFMounts)
            Button("Copy mount diagnostic") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(status, forType: .string)
            }
            Button("Open File System Extensions settings") {
                if !FSClient.shared.openFileSystemExtensionsSettings() {
                    status = "macOS could not open File System Extensions settings."
                }
            }
            .disabled(isWorking)
            if let mountedURL {
                Button("Reveal mounted archive in Finder") {
                    NSWorkspace.shared.open(mountedURL)
                }
                Button("Unmount read-only volume") {
                    unmount(mountedURL)
                }
                .disabled(isWorking)
            }
        }
        .padding(24)
        .frame(minWidth: 460, minHeight: 220)
        .onAppear { reconcileMountedVolumes() }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didUnmountNotification)) { _ in
            // Finder or a different process may unmount an archive after the
            // host's last successful mount. Rebuild state from the VFS rather
            // than trusting the last button action.
            reconcileMountedVolumes()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didMountNotification)) { _ in
            reconcileMountedVolumes()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didRenameVolumeNotification)) { _ in
            reconcileMountedVolumes()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didActivateApplicationNotification)) { _ in
            reconcileMountedVolumes()
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
                    status = "Select a .ascf archive."
                    return
                }
                mount(url, expectCorruptRefusal: false)
            case .failure(let error):
                status = "Archive selection failed: \(error.localizedDescription)"
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
                    status = "Select the generated source.<codec>.corrupt.ascf negative-control fixture."
                    return
                }
                mount(url, expectCorruptRefusal: true)
            case .failure(let error):
                status = "Corruption-control selection failed: \(error.localizedDescription)"
            }
        }
    }

    // Treat an FSClient mount callback as provisional until the VFS reports
    // the actual ASCF filesystem with the kernel's read-only flag. A successful
    // callback alone does not establish that the expected extension mounted.
    // Reuse this gate when recovering mounts after a host relaunch.
    private func isVerifiedReadOnlyASCFMount(_ volume: URL) -> Bool {
        guard volume.path.hasPrefix("/Volumes/") else { return false }
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

    // A host restart must not strand an already mounted archive. Recover
    // only kernel-confirmed read-only ASCF volumes, never a matching label.
    private func mountedASCFVolumes() -> [URL] {
        let mounted = FileManager.default.mountedVolumeURLs(
            includingResourceValuesForKeys: nil, options: []
        ) ?? []
        return mounted.filter { isVerifiedReadOnlyASCFMount($0) }
    }

    private func reconcileMountedVolumes() {
        guard !isWorking else { return }
        let volumes = mountedASCFVolumes()
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

    private func mount(_ url: URL, expectCorruptRefusal: Bool) {
        guard !isWorking, mountedURL == nil else { return }
        isWorking = true
        status = expectCorruptRefusal
            ? "Checking installed FSKit extension before corrupted mount attempt..."
            : "Checking installed FSKit extension..."
        // A valid signed app may still have an extension that macOS has not
        // registered or that the user has disabled. Show the actionable cause
        // before opening the security-scoped archive or requesting a mount.
        FSClient.shared.fetchInstalledExtensions { modules, error in
            DispatchQueue.main.async {
                if let error {
                    isWorking = false
                    status = "FSKit extension discovery failed: \(error.localizedDescription)"
                    return
                }
                let moduleID = "org.chriscoveries.applesauce.ascfhost.ascfextension"
                guard let module = modules?.first(where: { $0.bundleIdentifier == moduleID }) else {
                    isWorking = false
                    status = "ASCF extension is not installed. Install the signed host, then enable its extension in System Settings."
                    return
                }
                guard module.isEnabled else {
                    isWorking = false
                    status = "ASCF extension is disabled. Enable it in File System Extensions settings."
                    return
                }
                beginMount(url, expectCorruptRefusal: expectCorruptRefusal)
            }
        }
    }

    private func beginMount(_ url: URL, expectCorruptRefusal: Bool) {
        // The picker supplies a security-scoped URL. FSKit conveys the scope
        // to the extension; neither process needs write access to the archive.
        guard url.startAccessingSecurityScopedResource() else {
            isWorking = false
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
        ) { mounted, error in
            url.stopAccessingSecurityScopedResource()
            DispatchQueue.main.async {
                isWorking = false
                if expectCorruptRefusal {
                    // An error is evidence of refusal only after successful
                    // extension discovery and an actual FSClient callback.
                    // The specific reason must be retained for the operator.
                    // Denial from sandbox/provisioning alone is inconclusive.
                    if let mounted {
                        if isVerifiedReadOnlyASCFMount(mounted) { mountedURL = mounted }
                        status = "CORRUPT_REFUSAL_FAIL: FSKit returned a mount at \(mounted.path). Unmount it and reject acceptance."
                    } else if let error {
                        let remaining = mountedASCFVolumes()
                        if remaining.isEmpty {
                            let actualError = error as NSError
                            let detail = "\(actualError.domain) code \(actualError.code): \(actualError.localizedDescription)"
                            if actualError.domain == FSKitErrorDomain
                                && actualError.code == FSError.Code.resourceDamaged.rawValue {
                                status = "CORRUPT_REFUSAL_CONFIRMED: signed FSKit probe rejected the recognized ASCF payload: \(detail)"
                            } else {
                                status = "CORRUPT_REFUSAL_INCONCLUSIVE: mount failed without a verified ASCF damage error: \(detail). Check activation, entitlements and access."
                            }
                        } else {
                            status = "CORRUPT_REFUSAL_INCONCLUSIVE: FSClient returned an error but ASCF volumes remain mounted: \(remaining.map(\.path).joined(separator: ", "))"
                        }
                    } else {
                        status = "CORRUPT_REFUSAL_INCONCLUSIVE: FSClient returned neither mount nor error."
                    }
                    return
                }
                if let error {
                    status = "Mount failed: \(error.localizedDescription)"
                } else if let mounted {
                    guard isVerifiedReadOnlyASCFMount(mounted) else {
                        mountedURL = nil
                        status = "FSKit returned a mount without verified ASCF read-only VFS identity at \(mounted.path). Inspect the mount manually; acceptance is blocked."
                        return
                    }
                    mountedURL = mounted
                    status = "Verified read-only ASCF mount at \(mounted.path)"
                } else {
                    status = "FSKit returned no mounted volume."
                }
            }
        }
    }

    private func unmount(_ url: URL) {
        guard !isWorking, mountedURL?.standardizedFileURL == url.standardizedFileURL else { return }
        isWorking = true
        status = "Unmounting the read-only volume..."
        // FSKit publishes a logical volume, not an ejectable disk device.
        // FileManager's asynchronous volume unmount handles virtual mounts,
        // reports busy-volume failures and never requests forced ejection.
        FileManager.default.unmountVolume(at: url, options: []) { error in
            DispatchQueue.main.async {
                isWorking = false
                if let error {
                    status = "Unmount failed: \(error.localizedDescription)"
                } else {
                    mountedURL = nil
                    status = "Unmounted read-only archive."
                }
            }
        }
    }
}
