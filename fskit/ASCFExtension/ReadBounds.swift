// Overflow-safe read boundaries for the read-only ASCF FSKit volume.
// Kept independent of FSKit so these conditions can run as a native Swift
// executable on the macOS CI runner before any extension is installed.
enum ASCFReadBounds {
    static let maximumBytes = 8 * 1024 * 1024

    // Nil means invalid caller parameters; zero means an ordinary EOF or
    // empty request. Never convert a negative offset into an unsigned index.
    static func count(offset: Int64, requested: Int, bufferLength: Int,
                      logicalSize: UInt64) -> Int? {
        guard offset >= 0, requested >= 0, bufferLength >= 0 else { return nil }
        let start = UInt64(offset)
        guard requested > 0, bufferLength > 0, start < logicalSize else { return 0 }
        let bounded = min(requested, bufferLength, maximumBytes)
        return Int(min(UInt64(bounded), logicalSize - start))
    }

    // The bridge's ascf_pread contract is exact on success. Unlike a generic
    // POSIX read, it must return every requested byte after clipping at the
    // logical EOF. A positive short read indicates a broken bridge contract
    // and must fail closed rather than silently truncate Finder copy-out.
    static func isValidReadResult(_ actual: Int, expected: Int) -> Bool {
        expected > 0 && actual == expected
    }
}
