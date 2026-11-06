import Foundation

@main
struct ASCFMountedMemberNameTests {
    static func main() {
        for (archive, expected) in [
            ("source.ascf", "source"),
            ("source.ASCF", "source"),
            ("source.part.ascf", "source.part"),
            ("café data.ascf", "café data"),
            (".hidden.ascf", ".hidden")
        ] {
            let name = ASCFMountedMemberName.fromArchiveURL(
                URL(fileURLWithPath: "/tmp/" + archive))
            precondition(name == expected, "legitimate source rejected: \(archive)")
        }
        for name in ["", ".", "..", "a/b", "a:b", "a\\b", "line\nfeed", "tab\tname", "del\u{7f}", "nul\u{0}", String(repeating: "x", count: 256)] {
            precondition(ASCFMountedMemberName.validated(name) == nil,
                         "unsafe mounted member admitted: \(name.debugDescription)")
        }
        for archive in ["bad:name.ascf", "bad\\name.ascf", "bad\nname.ascf", "bad\u{7f}name.ascf"] {
            precondition(ASCFMountedMemberName.fromArchiveURL(URL(fileURLWithPath: "/tmp/" + archive)) == nil,
                         "unsafe source name admitted: \(archive.debugDescription)")
        }
        precondition(ASCFMountedMemberName.validated(String(repeating: "x", count: 255)) != nil)
        precondition(ASCFMountedMemberName.validated(String(repeating: "é", count: 128)) == nil,
                     "maximum name length must count UTF-8 bytes")
        print("ASCF FSKit member names: Finder safety and UTF-8 boundary checks passed")
    }
}
