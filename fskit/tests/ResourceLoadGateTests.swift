// Portable lifecycle concurrency regressions. No FSKit installation needed.
import Foundation
import Dispatch

@main
struct ASCFResourceLoadGateTests {
    static func main() {
        var gate = ASCFResourceLoadGate()
        let first = gate.begin()!
        precondition(gate.begin() == nil, "concurrent load allowed")
        precondition(gate.publish(first))
        precondition(gate.loaded && gate.begin() == nil)
        precondition(!gate.publish(first), "duplicate publication accepted")
        gate.unload()
        precondition(!gate.loaded)
        let second = gate.begin()!
        gate.cancel(first)
        precondition(!gate.publish(first), "stale load accepted")
        precondition(gate.publish(second), "cancelling stale ticket affected active load")
        gate.unload()

        let delayed = gate.begin()!
        gate.unload()
        let fresh = gate.begin()!
        precondition(!gate.publish(delayed), "load published after unload")
        precondition(gate.publish(fresh), "current load rejected")
        gate.unload()
        precondition(!gate.loaded)

        let cancelled = gate.begin()!
        gate.cancel(cancelled)
        precondition(gate.begin() != nil, "failed verification blocked retry")
        gate.unload()

        for _ in 0..<1000 {
            let one = gate.begin()!
            precondition(gate.publish(one))
            gate.unload()
            precondition(!gate.publish(one))
        }

        // Multiple callbacks contend for exactly one reservation under the
        // same NSLock used by the extension. Only one ticket may win.
        let lock = NSLock()
        var winners = [UUID]()
        DispatchQueue.concurrentPerform(iterations: 32) { _ in
            lock.lock()
            if let ticket = gate.begin() { winners.append(ticket) }
            lock.unlock()
        }
        precondition(winners.count == 1, "multiple concurrent loads reserved")
        lock.lock()
        precondition(gate.publish(winners[0]))
        gate.unload()
        lock.unlock()
        print("ASCF FSKit resource load gate: concurrent, cancellation, unload and 1000 remount cycles passed")
    }
}
