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
                mount(url)
            case .failure(let error):
                status = "Archive selection failed: \(error.localizedDescription)"
            }
        }
    }

    // A host restart must not strand an already mounted archive. Recover
    // active volumes by the kernel filesystem type and read-only mount flag;
    // the volume label alone is user-controlled and is not an identity test.
    private func mountedASCFVolumes() -> [URL] {
        let mounted = FileManager.default.mountedVolumeURLs(
            includingResourceValuesForKeys: nil, options: []
        ) ?? []
        return mounted.filter { volume in
            guard volume.path.hasPrefix("/Volumes/") else { return false }
            var info = statfs()
            let result = volume.withUnsafeFileSystemRepresentation { path -> Int32 in
                guard let path else { return -1 }
                return Darwin.statfs(path, &info)
            }
            guard result == 0 else { return false }
            let type = withUnsafeBytes(of: info.f_fstypename) { bytes in
                String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self)
            }
            return type == "ascf" && (info.f_flags & UInt32(MNT_RDONLY)) != 0
        }
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

    private func mount(_ url: URL) {
        guard !isWorking, mountedURL == nil else { return }
        isWorking = true
        status = "Checking installed FSKit extension..."
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
                beginMount(url)
            }
        }
    }

    private func beginMount(_ url: URL) {
        // The picker supplies a security-scoped URL. FSKit conveys the scope
        // to the extension; neither process needs write access to the archive.
        guard url.startAccessingSecurityScopedResource() else {
            isWorking = false
            status = "macOS did not grant read access to the selected archive."
            return
        }
        status = "Verifying archive before read-only mount..."
        let resource = FSPathURLResource(url: url, writable: false)
        FSClient.shared.mountSingleVolume(
            resource: resource,
            bundleID: "org.chriscoveries.applesauce.ascfhost.ascfextension",
            options: []
        ) { mounted, error in
            url.stopAccessingSecurityScopedResource()
            DispatchQueue.main.async {
                isWorking = false
                if let error {
                    status = "Mount failed: \(error.localizedDescription)"
                } else if let mounted {
                    mountedURL = mounted
                    status = "Mounted at \(mounted.path)"
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
