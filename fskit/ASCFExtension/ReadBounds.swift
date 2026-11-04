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

    // For a positive in-range request the bridge must make progress. It may
    // report fewer bytes than requested but must never exceed buffer bounds.
    static func isValidReadResult(_ actual: Int, capacity: Int) -> Bool {
        capacity > 0 && actual > 0 && actual <= capacity
    }
}
