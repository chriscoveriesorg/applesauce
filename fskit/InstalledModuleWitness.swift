// Read-only witness for the FSKit module the *kernel* will dispatch.
// FSClient's installedExtensions list exposes the registered extension URL.
// It may point to an old, still-enabled installation after re-signing an app.
import Foundation
import FSKit

private enum InstalledASCF {
    static let identifier = "org.chriscoveries.applesauce.ascfhost.ascfextension"

    static func host(for moduleURL: URL) -> URL? {
        guard moduleURL.isFileURL else { return nil }
        let module = moduleURL.resolvingSymlinksInPath().standardizedFileURL
        guard module.lastPathComponent == "ASCFExtension.appex" else { return nil }
        let extensions = module.deletingLastPathComponent()
        guard extensions.lastPathComponent == "Extensions" else { return nil }
        let contents = extensions.deletingLastPathComponent()
        guard contents.lastPathComponent == "Contents" else { return nil }
        let host = contents.deletingLastPathComponent()
        guard host.lastPathComponent == "ASCFHost.app" else { return nil }
        return host
    }

    static func selfTest() {
        let host = URL(fileURLWithPath: "/tmp/ascf-witness/ASCFHost.app", isDirectory: true)
        let extensionURL = host.appendingPathComponent(
            "Contents/Extensions/ASCFExtension.appex", isDirectory: true)
        precondition(self.host(for: extensionURL)?.path == host.path)
        precondition(self.host(for: URL(string: "https://example.invalid/ASCFExtension.appex")!) == nil)
        precondition(self.host(for: host.appendingPathComponent(
            "Contents/PlugIns/ASCFExtension.appex")) == nil)
        precondition(self.host(for: host.appendingPathComponent(
            "Contents/Extensions/WrongExtension.appex")) == nil)
        precondition(self.host(for: host.appendingPathComponent(
            "Contents/Extensions/ASCFExtension.appex/../stale.appex")) == nil)
        print("PASS: FSKit registry witness rejects wrong and non-file module locations")
    }
}

@main
struct ASCFInstalledModuleWitness {
    static func main() async {
        do {
            guard CommandLine.arguments.count == 2 else {
                throw NSError(domain: "ASCFWitness", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "use --self-test or --installed-host"])
            }
            if CommandLine.arguments[1] == "--self-test" {
                InstalledASCF.selfTest()
                return
            }
            guard CommandLine.arguments[1] == "--installed-host" else {
                throw NSError(domain: "ASCFWitness", code: 2,
                              userInfo: [NSLocalizedDescriptionKey: "invalid witness mode"])
            }
            let modules = try await FSClient.shared.installedExtensions
            let found = modules.filter { $0.bundleIdentifier == InstalledASCF.identifier }
            guard found.count == 1, let module = found.first else {
                throw NSError(domain: "ASCFWitness", code: 3, userInfo: [
                    NSLocalizedDescriptionKey:
                        "expected one installed ASCF module; found \(found.count). Check FSKit extension registration."
                ])
            }
            guard module.isEnabled else {
                throw NSError(domain: "ASCFWitness", code: 4, userInfo: [
                    NSLocalizedDescriptionKey: "registered ASCF module is disabled"
                ])
            }
            guard let host = InstalledASCF.host(for: module.url) else {
                throw NSError(domain: "ASCFWitness", code: 5, userInfo: [
                    NSLocalizedDescriptionKey: "FSKit registered an unexpected ASCF extension URL"
                ])
            }
            let evidence: [String: Any] = [
                "schema_version": 1,
                "bundle_id": InstalledASCF.identifier,
                "module_url": module.url.resolvingSymlinksInPath().standardizedFileURL.path,
                "installed_host": host.path,
                "enabled": true
            ]
            let json = try JSONSerialization.data(withJSONObject: evidence, options: [.sortedKeys])
            FileHandle.standardOutput.write(json)
            FileHandle.standardOutput.write(Data([10]))
        } catch {
            FileHandle.standardError.write(Data(("FSKit registered-module refusal: " +
                error.localizedDescription + "\n").utf8))
            exit(1)
        }
    }
}
