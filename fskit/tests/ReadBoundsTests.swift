// Real Swift boundary tests for FSKit's read-to-bridge byte limits.
// No archive writes, FSKit mount, entitlements or native APFS probes.
@main
struct ASCFReadBoundsTests {
    static func main() {
        func expect(_ offset: Int64, _ length: Int, _ buffer: Int,
                    _ size: UInt64, _ result: Int?) {
            precondition(ASCFReadBounds.count(offset: offset, requested: length,
                        bufferLength: buffer, logicalSize: size) == result)
        }

        expect(-1, 1, 1, 100, nil)
        expect(0, -1, 1, 100, nil)
        expect(0, 1, -1, 100, nil)
        expect(0, 0, 100, 100, 0)
        expect(0, 100, 0, 100, 0)
        expect(0, 100, 100, 0, 0)
        expect(99, 100, 100, 100, 1)
        expect(100, 100, 100, 100, 0)
        expect(101, 100, 100, 100, 0)
        expect(0, 100, 3, 100, 3)
        expect(0, Int.max, Int.max, UInt64.max, 8 * 1024 * 1024)
        expect(Int64.max, Int.max, Int.max, UInt64.max, 8 * 1024 * 1024)
        expect(Int64.max, 4, 4, UInt64(Int64.max), 0)
        expect(Int64.max - 1, 4, 4, UInt64(Int64.max), 1)
        // ascf_pread guarantees an exact-length read when successful, since
        // ASCFReadBounds.count already clips every request at the true EOF.
        // Positive short reads must not silently truncate Finder readback.
        for expected in [1, 2, 4096, 8 * 1024 * 1024] {
            precondition(ASCFReadBounds.isValidReadResult(expected, expected: expected))
            for actual in [-1, 0, expected - 1, expected + 1, Int.max] where actual != expected {
                precondition(!ASCFReadBounds.isValidReadResult(actual, expected: expected))
            }
        }
        precondition(!ASCFReadBounds.isValidReadResult(0, expected: 0))
        precondition(!ASCFReadBounds.isValidReadResult(1, expected: 0))
        precondition(!ASCFReadBounds.isValidReadResult(1, expected: -1))
        print("ASCF FSKit read bounds: negative, EOF, zero, huge, and exact bridge reads passed")
    }
}
