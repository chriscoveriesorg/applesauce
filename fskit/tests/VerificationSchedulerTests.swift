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
        // A user-requested mount preempts only the currently verifying
        // Finder probe. Pending probes remain queued, then run afterwards.
        let scheduler2 = ASCFVerificationScheduler(maxPendingProbes: 2)
        let activeStarted = DispatchSemaphore(value: 0)
        let activeReleased = DispatchSemaphore(value: 0)
        let probePreempted = DispatchSemaphore(value: 0)
        let probeEvents = ASCFVerificationSchedulerEvents()
        let probeGroup = DispatchGroup()
        probeGroup.enter()
        precondition(scheduler2.submit(.probe, onPreempt: {
            probePreempted.signal()
        }) {
            probeEvents.add("active-probe")
            activeStarted.signal()
            precondition(activeReleased.wait(timeout: .now() + 10) == .success)
            probeGroup.leave()
        })
        precondition(activeStarted.wait(timeout: .now() + 10) == .success)
        probeGroup.enter()
        precondition(scheduler2.submit(.probe) {
            probeEvents.add("queued-probe")
            probeGroup.leave()
        })
        probeGroup.enter()
        precondition(scheduler2.submit(.mount) {
            probeEvents.add("requested-mount")
            probeGroup.leave()
        })
        precondition(probePreempted.wait(timeout: .now() + 10) == .success,
                     "mount did not preempt the running probe")
        activeReleased.signal()
        precondition(probeGroup.wait(timeout: .now() + 10) == .success)
        precondition(probeEvents.snapshot() ==
                     ["active-probe", "requested-mount", "queued-probe"],
                     "preemption did not preserve mount priority")
        print("ASCF verification scheduler: priority, bounded admission, preemption and reuse passed")
    }
}
