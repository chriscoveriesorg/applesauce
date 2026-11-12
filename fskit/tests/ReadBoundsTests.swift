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
        expect(0, 100, 0, 100, nil)
        expect(0, 100, 100, 0, 0)
        expect(99, 100, 100, 100, 1)
        expect(100, 100, 100, 100, 0)
        expect(101, 100, 100, 100, 0)
        expect(0, 100, 3, 100, nil)
        expect(0, Int.max, Int.max, UInt64.max, 8 * 1024 * 1024)
        expect(Int64.max, Int.max, Int.max, UInt64.max, 8 * 1024 * 1024)
        // Capacity must cover the requested in-range bytes. A partial
        // buffer must never masquerade as successful early EOF in Finder.
        expect(0, 1, 0, 100, nil)
        expect(0, 2, 1, 100, nil)
        expect(0, 100, 99, 100, nil)
        expect(0, 100, 100, 100, 100)
        expect(0, 100, 101, 100, 100)
        expect(99, 100, 0, 100, nil)
        expect(99, 100, 1, 100, 1)
        expect(100, 100, 0, 100, 0)
        expect(101, 100, 0, 100, 0)
        expect(0, 0, 0, 100, 0)
        // A >8 MiB request is segmented; capacity for that first segment
        // suffices, and the last logical byte only needs a one-byte buffer.
        let limit = ASCFReadBounds.maximumBytes
        expect(0, Int.max, limit - 1, UInt64.max, nil)
        expect(0, Int.max, limit, UInt64.max, limit)
        expect(0, Int.max, limit + 1, UInt64.max, limit)
        expect(Int64.max, Int.max, limit - 1, UInt64.max, nil)
        expect(Int64.max, Int.max, limit, UInt64.max, limit)
        expect(99, Int.max, 1, 100, 1)
        // Exhaustively check all small in-range offsets and buffer sizes;
        // a success must return the entire bounded, EOF-clipped request.
        for size in 0...18 {
            for offset in 0...20 {
                for request in 0...20 {
                    for capacity in 0...20 {
                        let available = max(size - offset, 0)
                        let required = min(request, available)
                        let expected: Int? = capacity >= required ? required : nil
                        expect(Int64(offset), request, capacity, UInt64(size), expected)
                    }
                }
            }
        }
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
