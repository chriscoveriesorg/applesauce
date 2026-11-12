// The name exported by the FSKit volume is derived from a source pathname.
// Reject path components Finder and the independent signed-acceptance verifier
// cannot safely copy. Do not silently rewrite them and risk a wrong-file copy.
import Foundation

enum ASCFMountedMemberName {
    static func fromArchiveURL(_ url: URL) -> String? {
        validated(url.deletingPathExtension().lastPathComponent)
    }

    static func validated(_ name: String) -> String? {
        guard !name.isEmpty, name != ".", name != "..", name.utf8.count <= 255 else {
            return nil
        }
        for scalar in name.unicodeScalars {
            switch scalar.value {
            case 0...31, 127, 47, 58, 92: // controls, DEL, /, :, backslash
                return nil
            default:
                break
            }
        }
        return name
    }
}
