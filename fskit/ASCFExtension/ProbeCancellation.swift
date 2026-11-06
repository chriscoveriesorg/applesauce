// A mount request may preempt a long-running Finder probe. The bridge's
// cancellation operation is an atomic flag store, but it still needs a
// lock around handle registration/unregistration to prevent use-after-free.
import Foundation

final class ASCFProbeCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private let cancelHandle: @Sendable (OpaquePointer) -> Void
    private var activeHandle: OpaquePointer?
    private var cancelled = false

    init(cancelHandle: @escaping @Sendable (OpaquePointer) -> Void) {
        self.cancelHandle = cancelHandle
    }

    // The bridge calls this with nil BEFORE closing the C handle. A preempt
    // arriving before registration is remembered and delivered immediately.
    func register(_ handle: OpaquePointer?) {
        lock.lock()
        if let handle {
            if cancelled {
                cancelHandle(handle)
            } else {
                activeHandle = handle
            }
        } else {
            activeHandle = nil
        }
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        guard !cancelled else {
            lock.unlock()
            return
        }
        cancelled = true
        if let activeHandle { cancelHandle(activeHandle) }
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}
