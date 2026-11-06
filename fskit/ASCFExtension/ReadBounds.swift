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
        guard requested > 0, start < logicalSize else { return 0 }
        // A short FSKit buffer is a caller-contract error, never EOF or a
        // successful short read before EOF. That would silently truncate a
        // Finder copy even though the bridge authenticated its returned bytes.
        // Large requests are served in successive 8 MiB reads. Capacity is
        // required only for the bytes legally available in this invocation,
        // including the final partial request at logical EOF.
        let bounded = min(requested, maximumBytes)
        let count = Int(min(UInt64(bounded), logicalSize - start))
        guard bufferLength >= count else { return nil }
        return count
    }

    // The bridge's ascf_pread contract is exact on success. Unlike a generic
    // POSIX read, it must return every requested byte after clipping at the
    // logical EOF. A positive short read indicates a broken bridge contract
    // and must fail closed rather than silently truncate Finder copy-out.
    static func isValidReadResult(_ actual: Int, expected: Int) -> Bool {
        expected > 0 && actual == expected
    }
}
