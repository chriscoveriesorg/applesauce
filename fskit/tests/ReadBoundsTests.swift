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
        precondition(!ASCFReadBounds.isValidReadResult(0, capacity: 1))
        precondition(!ASCFReadBounds.isValidReadResult(-1, capacity: 1))
        precondition(!ASCFReadBounds.isValidReadResult(2, capacity: 1))
        precondition(!ASCFReadBounds.isValidReadResult(0, capacity: 0))
        precondition(ASCFReadBounds.isValidReadResult(1, capacity: 1))
        precondition(ASCFReadBounds.isValidReadResult(1, capacity: 8 * 1024 * 1024))
        print("ASCF FSKit read bounds: negative, EOF, zero, huge and partial reads passed")
    }
}
