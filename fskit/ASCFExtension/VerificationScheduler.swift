// Bound background archive probes without starving an explicitly requested FSKit mount.
// A single worker owns decoder scratch at any one time. New load requests run
// ahead of already queued probes, while the active probe completes normally.
import Foundation
import Dispatch

final class ASCFVerificationScheduler: @unchecked Sendable {
    enum Priority { case mount, probe }
    private typealias Job = @Sendable () -> Void
    private let lock = NSLock()
    private let worker: DispatchQueue
    private let maxPendingProbes: Int
    private var active = false
    private var pendingMounts: [Job] = []
    private var pendingProbes: [Job] = []

    init(label: String = "org.chriscoveries.applesauce.ascf.verification",
         maxPendingProbes: Int = 8) {
        precondition(maxPendingProbes > 0)
        self.maxPendingProbes = maxPendingProbes
        worker = DispatchQueue(label: label, qos: .userInitiated)
    }

    // Returning false means the bounded probe backlog is full. Mount loads
    // are reserved by ASCFResourceLoadGate and always admitted here.
    @discardableResult
    func submit(_ priority: Priority, _ work: @escaping @Sendable () -> Void) -> Bool {
        lock.lock()
        switch priority {
        case .mount:
            pendingMounts.append(work)
        case .probe:
            guard pendingProbes.count < maxPendingProbes else {
                lock.unlock()
                return false
            }
            pendingProbes.append(work)
        }
        let needsWorker = !active
        if needsWorker { active = true }
        lock.unlock()
        if needsWorker { worker.async { [self] in drain() } }
        return true
    }

    private func drain() {
        while true {
            lock.lock()
            let next: Job?
            if !pendingMounts.isEmpty {
                next = pendingMounts.removeFirst()
            } else if !pendingProbes.isEmpty {
                next = pendingProbes.removeFirst()
            } else {
                active = false
                next = nil
            }
            lock.unlock()
            guard let next else { return }
            next()
        }
    }
}
