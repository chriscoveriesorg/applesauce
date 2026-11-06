// Bound queued FSKit requests without starving an explicitly requested mount.
// A single worker owns decoder scratch at any one time. New load requests run
// ahead of already queued probes; an active probe can be cancelled at a chunk boundary.
import Foundation
import Dispatch

// Automatic Finder discovery only needs to inspect selected .ascf files.
// Without this admission check, every unrelated file probe reserves a slot
// in the single full-file SHA-256 verifier, can exhaust Finder's probe queue,
// and can delay an explicit user mount. A manually selected FSPathURLResource
// remains independently verified by loadResource regardless of its suffix.
enum ASCFProbeAdmission {
    static func shouldProbe(_ url: URL) -> Bool {
        url.pathExtension.lowercased() == "ascf"
    }
}

// The load lifecycle can invalidate a queued mount while another archive is
// being verified. Read this token without acquiring the FSKit lifecycle lock,
// so stale work can be reclaimed without lock inversion or sandbox access.
final class ASCFVerificationCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

final class ASCFVerificationScheduler: @unchecked Sendable {
    enum Priority { case mount, probe }
    private typealias Job = @Sendable () -> Void
    private let lock = NSLock()
    private let worker: DispatchQueue
    private let maxPendingProbes: Int
    private let maxPendingMounts: Int
    private var active = false
    private struct ScheduledProbe {
        let work: Job
        let cancel: Job?
    }
    private struct ScheduledMount {
        let work: Job
        let cancellation: ASCFVerificationCancellation?
        // Every admitted FSKit load must receive exactly one reply, even
        // when its queued worker is reclaimed before opening the archive.
        let onCancellation: Job?
    }
    private var pendingMounts: [ScheduledMount] = []
    private var pendingProbes: [ScheduledProbe] = []
    // Only the actively executing probe may be preempted by a new mount.
    private var activeProbeCancellation: Job?

    init(label: String = "org.chriscoveries.applesauce.ascf.verification",
         maxPendingProbes: Int = 8, maxPendingMounts: Int = 16) {
        precondition(maxPendingProbes > 0 && maxPendingMounts > 0)
        self.maxPendingProbes = maxPendingProbes
        self.maxPendingMounts = maxPendingMounts
        worker = DispatchQueue(label: label, qos: .userInitiated)
    }

    // Returning false means the bounded probe or mount backlog is full.
    // Callers cancel rejected load tickets; they must acquire security
    // scopes only after their admitted worker begins.
    @discardableResult
    func submit(_ priority: Priority,
                cancellation: ASCFVerificationCancellation? = nil,
                onCancellation: (@Sendable () -> Void)? = nil,
                onPreempt: (@Sendable () -> Void)? = nil,
                _ work: @escaping @Sendable () -> Void) -> Bool {
        lock.lock()
        let interruptActiveProbe: Job?
        var reclaimedMounts: [ScheduledMount] = []
        switch priority {
        case .mount:
            // An unload invalidates its token immediately, but an occupied
            // worker may not reach that queued closure for a long time.
            // Reclaim those stale reservations before enforcing the bound.
            // Token lookup never calls back into a filesystem lifecycle lock.
            reclaimedMounts = pendingMounts.filter {
                $0.cancellation?.isCancelled == true
            }
            pendingMounts.removeAll { $0.cancellation?.isCancelled == true }
            guard pendingMounts.count < maxPendingMounts else {
                lock.unlock()
                return false
            }
            pendingMounts.append(ScheduledMount(
                work: work, cancellation: cancellation,
                onCancellation: onCancellation
            ))
            interruptActiveProbe = activeProbeCancellation
        case .probe:
            guard pendingProbes.count < maxPendingProbes else {
                lock.unlock()
                return false
            }
            pendingProbes.append(ScheduledProbe(work: work, cancel: onPreempt))
            interruptActiveProbe = nil
        }
        let needsWorker = !active
        if needsWorker { active = true }
        lock.unlock()
        // Reclaimed loads still require their FSKit completion handler.
        // Reply outside the scheduler lock to permit reentrant callbacks.
        // The optional fallback preserves the original one-reply contract
        // for callers whose worker itself handles a canceled reservation.
        for mount in reclaimedMounts {
            (mount.onCancellation ?? mount.work)()
        }
        // Never invoke a cancellation callback while holding the scheduler
        // lock. It can synchronously acquire the probe's handle-lifetime lock.
        interruptActiveProbe?()
        if needsWorker { worker.async { [self] in drain() } }
        return true
    }

    private func drain() {
        while true {
            lock.lock()
            let next: Job
            let cancellation: ASCFVerificationCancellation?
            let onCancellation: Job?
            let runningProbe: Bool
            if !pendingMounts.isEmpty {
                let mount = pendingMounts.removeFirst()
                next = mount.work
                cancellation = mount.cancellation
                onCancellation = mount.onCancellation
                activeProbeCancellation = nil
                runningProbe = false
            } else if !pendingProbes.isEmpty {
                let probe = pendingProbes.removeFirst()
                next = probe.work
                cancellation = nil
                onCancellation = nil
                activeProbeCancellation = probe.cancel
                runningProbe = true
            } else {
                active = false
                activeProbeCancellation = nil
                lock.unlock()
                return
            }
            lock.unlock()
            // A canceled mount was dequeued between unload and the next
            // admission. Still deliver its completion, without archive I/O.
            if cancellation?.isCancelled == true {
                (onCancellation ?? next)()
                continue
            }
            next()
            if runningProbe {
                lock.lock()
                activeProbeCancellation = nil
                lock.unlock()
            }
        }
    }
}
