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
        // Finder may probe thousands of unrelated URLs. They must be rejected
        // before the bounded verification queue and security-scope acquisition,
        // while selected archives remain eligible regardless of name casing.
        for filename in ["notes.jsonl", "notes.ascf.tmp", "readme", ".ascf-backup",
                         "notes.ASCF.backup", "notes.txt", "folder.ascf/file", ".ascf"] {
            let url = URL(fileURLWithPath: "/tmp/" + filename)
            precondition(!ASCFProbeAdmission.shouldProbe(url),
                         "unrelated Finder resource entered ASCF verifier: \(filename)")
        }
        for filename in ["notes.ascf", "notes.ASCF", "mixed.AsCf"] {
            let url = URL(fileURLWithPath: "/tmp/" + filename)
            precondition(ASCFProbeAdmission.shouldProbe(url),
                         "legitimate ASCF resource was not probed: \(filename)")
        }
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
        // Separate FSKit instances share a scheduler. An active verifier
        // must not allow unbounded selected mounts to retain security scopes.
        let bounded = ASCFVerificationScheduler(maxPendingProbes: 1,
                                                 maxPendingMounts: 2)
        let boundedStarted = DispatchSemaphore(value: 0)
        let boundedRelease = DispatchSemaphore(value: 0)
        let boundedGroup = DispatchGroup()
        let boundedEvents = ASCFVerificationSchedulerEvents()
        boundedGroup.enter()
        precondition(bounded.submit(.probe) {
            boundedEvents.add("active-probe")
            boundedStarted.signal()
            precondition(boundedRelease.wait(timeout: .now() + 10) == .success)
            boundedGroup.leave()
        })
        precondition(boundedStarted.wait(timeout: .now() + 10) == .success)
        for index in 0..<2 {
            boundedGroup.enter()
            precondition(bounded.submit(.mount) {
                boundedEvents.add("mount\(index)")
                boundedGroup.leave()
            })
        }
        precondition(!bounded.submit(.mount) { boundedEvents.add("overflow-mount") },
                     "mount backlog was unbounded")
        boundedRelease.signal()
        precondition(boundedGroup.wait(timeout: .now() + 10) == .success)
        precondition(boundedEvents.snapshot() ==
                     ["active-probe", "mount0", "mount1"],
                     "bounded mount backlog lost priority or ran refused work")
        let boundedReuse = DispatchSemaphore(value: 0)
        precondition(bounded.submit(.mount) { boundedReuse.signal() },
                     "completed mount queue did not admit new work")
        precondition(boundedReuse.wait(timeout: .now() + 10) == .success)
        // Simulate the FSKit scope lifetime: pending/rejected requests must
        // not start access. Only the admitted worker may enter and then exit
        // its scope. This guards the deferred acquisition contract used by
        // both probeResource and loadResource.
        let scopeScheduler = ASCFVerificationScheduler(maxPendingProbes: 1,
                                                        maxPendingMounts: 1)
        let scopeBlocked = DispatchSemaphore(value: 0)
        let scopeRelease = DispatchSemaphore(value: 0)
        let scopeGroup = DispatchGroup()
        let scopeEvents = ASCFVerificationSchedulerEvents()
        scopeGroup.enter()
        precondition(scopeScheduler.submit(.probe) {
            scopeBlocked.signal()
            precondition(scopeRelease.wait(timeout: .now() + 10) == .success)
            scopeGroup.leave()
        })
        precondition(scopeBlocked.wait(timeout: .now() + 10) == .success)
        scopeGroup.enter()
        precondition(scopeScheduler.submit(.mount) {
            scopeEvents.add("scope-start")
            scopeEvents.add("scope-stop")
            scopeGroup.leave()
        })
        precondition(!scopeScheduler.submit(.mount) {
            scopeEvents.add("rejected-scope-start")
        }, "rejected mount unexpectedly scheduled scope access")
        precondition(scopeEvents.snapshot().isEmpty,
                     "queued or rejected mount started security scope early")
        scopeRelease.signal()
        precondition(scopeGroup.wait(timeout: .now() + 10) == .success)
        precondition(scopeEvents.snapshot() == ["scope-start", "scope-stop"],
                     "admitted worker did not own the scope lifecycle")
        // An unloaded FSKit instance must give up its queue slot while a
        // different probe still occupies the worker. Otherwise canceled
        // requests from many instances can block a new user mount with EBUSY.
        let stale = ASCFVerificationScheduler(maxPendingProbes: 1, maxPendingMounts: 1)
        let staleStarted = DispatchSemaphore(value: 0)
        let staleRelease = DispatchSemaphore(value: 0)
        let staleDone = DispatchGroup()
        let staleEvents = ASCFVerificationSchedulerEvents()
        staleDone.enter()
        precondition(stale.submit(.probe) {
            staleStarted.signal()
            precondition(staleRelease.wait(timeout: .now() + 10) == .success)
            staleDone.leave()
        })
        precondition(staleStarted.wait(timeout: .now() + 10) == .success)
        let abandoned = ASCFVerificationCancellation()
        staleDone.enter()
        precondition(stale.submit(.mount, cancellation: abandoned,
                                  onCancellation: {
            staleEvents.add("abandoned-canceled")
            staleDone.leave()
        }) {
            staleEvents.add("abandoned-work")
            staleDone.leave()
        })
        abandoned.cancel()
        precondition(abandoned.isCancelled, "unload cancellation was not recorded")
        // Pruning must send the canceled mount exactly one completion while
        // leaving the original worker unexecuted and its scope unopened.
        staleDone.enter()
        precondition(stale.submit(.mount) {
            staleEvents.add("fresh")
            staleDone.leave()
        }, "stale queued mount consumed the only admission slot")
        staleRelease.signal()
        precondition(staleDone.wait(timeout: .now() + 10) == .success)
        precondition(staleEvents.snapshot() == ["abandoned-canceled", "fresh"],
                     "canceled queued mount lost its completion or executed work")

        // Without another mount arriving, the worker must also skip a
        // canceled reservation when it finally drains after the probe.
        let skip = ASCFVerificationScheduler(maxPendingProbes: 1, maxPendingMounts: 1)
        let skipStarted = DispatchSemaphore(value: 0)
        let skipRelease = DispatchSemaphore(value: 0)
        let skipDone = DispatchSemaphore(value: 0)
        let skipEvents = ASCFVerificationSchedulerEvents()
        precondition(skip.submit(.probe) {
            skipStarted.signal()
            precondition(skipRelease.wait(timeout: .now() + 10) == .success)
            skipDone.signal()
        })
        precondition(skipStarted.wait(timeout: .now() + 10) == .success)
        let canceled = ASCFVerificationCancellation()
        let cancelDelivered = DispatchSemaphore(value: 0)
        precondition(skip.submit(.mount, cancellation: canceled,
                                 onCancellation: {
            skipEvents.add("canceled-completion")
            cancelDelivered.signal()
        }) {
            skipEvents.add("should-not-run")
        })
        canceled.cancel()
        skipRelease.signal()
        precondition(skipDone.wait(timeout: .now() + 10) == .success)
        precondition(cancelDelivered.wait(timeout: .now() + 10) == .success,
                     "worker failed to complete a canceled mount")
        // Enqueue a sentinel and wait for the same serial worker to reach it.
        let skipSentinel = DispatchSemaphore(value: 0)
        precondition(skip.submit(.mount) { skipSentinel.signal() })
        precondition(skipSentinel.wait(timeout: .now() + 10) == .success)
        precondition(skipEvents.snapshot() == ["canceled-completion"],
                     "drain lost or duplicated canceled mount completion")

        print("ASCF verification scheduler: priority, bounded admission, stale unload cancellation and reuse passed")
    }
}
