// Portable regression of probe handle lifetime around preemption.
// Uses synthetic pointer values; no C memory is dereferenced or freed.
import Foundation

final class ASCFCancelCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    func record() {
        lock.lock()
        value += 1
        lock.unlock()
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

@main
struct ASCFProbeCancellationTests {
    static func main() {
        let syntheticHandle = OpaquePointer(bitPattern: 0x1234)!

        // A mount can arrive before the active probe has opened its archive.
        // Remember cancellation, then notify the bridge on registration.
        let before = ASCFCancelCounter()
        let early = ASCFProbeCancellation(cancelHandle: { _ in before.record() })
        early.cancel()
        precondition(early.isCancelled)
        precondition(before.count == 0)
        early.register(syntheticHandle)
        precondition(before.count == 1)
        early.register(nil)
        early.cancel()
        precondition(before.count == 1, "duplicate cancellation after close")

        // When the handle is live, cancel under the same lock that guards
        // unregister-before-close. Repeated requests are idempotent.
        let during = ASCFCancelCounter()
        let live = ASCFProbeCancellation(cancelHandle: { _ in during.record() })
        live.register(syntheticHandle)
        live.cancel()
        live.cancel()
        precondition(during.count == 1, "live handle cancelled twice")
        live.register(nil)
        live.cancel()
        precondition(during.count == 1, "closed handle touched after cancellation")

        // Once unregistered, a late mount cannot touch a freed pointer.
        let after = ASCFCancelCounter()
        let closed = ASCFProbeCancellation(cancelHandle: { _ in after.record() })
        closed.register(syntheticHandle)
        closed.register(nil)
        closed.cancel()
        precondition(closed.isCancelled && after.count == 0)

        print("ASCF probe cancellation: early, live, duplicate and closed-handle paths passed")
    }
}
