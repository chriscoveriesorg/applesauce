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

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Applesauce ASCF").font(.title2)
            Text("Read-only LZRaven / LZMesh archive mount")
            Text(status).textSelection(.enabled)
            Button("Choose .ascf archive and mount") {
                selectingArchive = true
            }
            if let mountedURL {
                Button("Reveal mounted archive in Finder") {
                    NSWorkspace.shared.open(mountedURL)
                }
            }
        }
        .padding(24)
        .frame(minWidth: 460, minHeight: 220)
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
        // The picker supplies a security-scoped URL. FSKit conveys the scope
        // to the extension; neither process needs write access to the archive.
        guard url.startAccessingSecurityScopedResource() else {
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
}
