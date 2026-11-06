// Portable queue saturation and mount-priority tests. No mounted disks or FSKit needed.
import Foundation
import Dispatch

final class ASCFVerificationSchedulerEvents: @unchecked Sendable {
    private let lock = NSLock()
    private var records: [String] = []
    func add(_ event: String) {
        lock.lock()
        records.append(event)
        lock.unlock()
    }
    func snapshot() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return records
    }
}

@main
struct ASCFVerificationSchedulerTests {
    static func main() {
        let scheduler = ASCFVerificationScheduler(maxPendingProbes: 8)
        let started = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let completed = DispatchGroup()
        let events = ASCFVerificationSchedulerEvents()

        completed.enter()
        precondition(scheduler.submit(.probe) {
            events.add("active")
            started.signal()
            precondition(release.wait(timeout: .now() + 10) == .success)
            completed.leave()
        })
        precondition(started.wait(timeout: .now() + 10) == .success)
        // Eight pending probes are admitted; the ninth is rejected rather
        // than retaining an unbounded number of security-scoped resources.
        for index in 0..<8 {
            completed.enter()
            precondition(scheduler.submit(.probe) {
                events.add("probe\(index)")
                completed.leave()
            })
        }
        precondition(!scheduler.submit(.probe) {
            events.add("overflow")
        }, "probe backlog was unbounded")

        completed.enter()
        precondition(scheduler.submit(.mount) {
            events.add("mount")
            completed.leave()
        }, "mount should never be refused for a full probe backlog")
        release.signal()
        precondition(completed.wait(timeout: .now() + 10) == .success,
                     "verification worker stalled")
        let expected = ["active", "mount"] + (0..<8).map { "probe\($0)" }
        precondition(events.snapshot() == expected,
                     "load did not overtake pending probes in FIFO order")

        // A probe submitted after draining must start a fresh worker.
        let reused = DispatchSemaphore(value: 0)
        precondition(scheduler.submit(.probe) { reused.signal() })
        precondition(reused.wait(timeout: .now() + 10) == .success)
        print("ASCF verification scheduler: priority, bounded admission and reuse passed")
    }
}
