// Bound queued FSKit requests without starving an explicitly requested mount.
// A single worker owns decoder scratch at any one time. New load requests run
// ahead of already queued probes; an active probe can be cancelled at a chunk boundary.
import Foundation
import Dispatch

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
    private var pendingMounts: [Job] = []
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
    // A rejected caller must release its security scope and reservation.
    @discardableResult
    func submit(_ priority: Priority, onPreempt: (@Sendable () -> Void)? = nil,
                _ work: @escaping @Sendable () -> Void) -> Bool {
        lock.lock()
        let interruptActiveProbe: Job?
        switch priority {
        case .mount:
            // Many FSKit instances share this scheduler. Per-instance load
            // gates cannot bound queued mounts or retained security scopes.
            guard pendingMounts.count < maxPendingMounts else {
                lock.unlock()
                return false
            }
            pendingMounts.append(work)
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
            let runningProbe: Bool
            if !pendingMounts.isEmpty {
                next = pendingMounts.removeFirst()
                activeProbeCancellation = nil
                runningProbe = false
            } else if !pendingProbes.isEmpty {
                let probe = pendingProbes.removeFirst()
                next = probe.work
                activeProbeCancellation = probe.cancel
                runningProbe = true
            } else {
                active = false
                activeProbeCancellation = nil
                lock.unlock()
                return
            }
            lock.unlock()
            next()
            if runningProbe {
                lock.lock()
                activeProbeCancellation = nil
                lock.unlock()
            }
        }
    }
}
