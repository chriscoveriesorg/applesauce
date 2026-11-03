// The host deliberately mounts a separate read-only volume. It never alters
// the original file's APFS xattrs or asserts native decmpfs support.
import AppKit
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

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Applesauce ASCF").font(.title2)
            Text("Read-only LZRaven / LZMesh archive mount")
            Text(status).textSelection(.enabled)
            Button("Choose .ascf archive and mount") {
                selectingArchive = true
            }
            .disabled(isWorking || mountedURL != nil)
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
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.didUnmountNotification)) { note in
            // Finder may eject the separate volume without using this window.
            guard let mountedURL,
                  let path = note.userInfo?["NSDevicePath"] as? String,
                  URL(fileURLWithPath: path).standardizedFileURL == mountedURL.standardizedFileURL
            else { return }
            self.mountedURL = nil
            status = "Volume unmounted."
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
                    status = "FSKit extension discovery failed: \\(error.localizedDescription)"
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
                    status = "Mount failed: \\(error.localizedDescription)"
                } else if let mounted {
                    mountedURL = mounted
                    status = "Mounted at \\(mounted.path)"
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
